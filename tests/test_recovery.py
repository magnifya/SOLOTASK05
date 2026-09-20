"""服务级故障恢复与跨进程并发测试（可独立运行）。

覆盖：
- 双进程并发：同一 data-dir 上两个服务进程并发建钱包/签名/激活，
  每类操作只有一个首次提交，重放幂等；
- 故障点重启：激活各环节崩溃后的启动回滚与清理；
- 轮换残留有效性判定：仅完整有效的 prepared 暂存保留，其余安全删除；
- 私钥边界：清理后磁盘上不留任何被删份额的私钥副本；
- 审计连续性：seq 按钱包连续升序、跨重启接续、重放与孤儿清理不记事件。

运行：python -m unittest tests.test_recovery -v
"""

from __future__ import annotations

import json
import multiprocessing
import os
import queue as queue_module
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

from threshold_wallet import crypto
from threshold_wallet import audit as audit_mod
from threshold_wallet.audit import AuditStore
from threshold_wallet.flock import FileLock, wallet_lock_path
from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import RecoveryError, WalletStore


# ---- 子进程 worker（模块级，可 pickle） ------------------------------------


def _make_service(data_dir: str) -> WalletService:
    return WalletService(WalletStore(data_dir))


def _child_create_wallet(data_dir, wallet_id, result_queue):
    """子进程：建钱包，回报状态码。"""
    service = _make_service(data_dir)
    try:
        service.create_wallet(wallet_id, 2)
        result_queue.put(201)
    except ServiceError as exc:
        result_queue.put(exc.status)


def _child_sign(data_dir, wallet_id, request_id, message, signatures,
                result_queue):
    """子进程：提交两份额签名，回报 (状态码, 签名 hex)。"""
    service = _make_service(data_dir)
    try:
        status, body = service.sign(
            wallet_id, request_id, message, signatures
        )
        result_queue.put((status, body["signature"]))
    except ServiceError as exc:
        result_queue.put((exc.status, None))


def _child_activate(data_dir, wallet_id, rotation_id, result_queue):
    """子进程：激活轮换，回报状态码。"""
    service = _make_service(data_dir)
    try:
        status, _ = service.activate_share_rotation(wallet_id, rotation_id)
        result_queue.put(status)
    except ServiceError as exc:
        result_queue.put(exc.status)


def _child_hold_lock(data_dir, wallet_id, ready_queue):
    """子进程：持有某钱包的跨进程锁直到被杀（模拟异常退出）。"""
    with FileLock(wallet_lock_path(data_dir, wallet_id)):
        ready_queue.put("held")
        time.sleep(60)


def _child_crash_mid_activation(data_dir, wallet_id, rotation_id, point,
                                ready_event):
    """子进程：把激活推进到指定故障点后 os._exit 模拟崩溃（不清理）。

    point="after_marker"：activating 标记 + 备份落盘后崩溃；
    point="after_swap"：新份额已换入、钱包元数据已改、旧份额已删后崩溃；
    point="after_commit"：轮换状态已提交 active，但激活事件尚未落盘（按事件
                            为提交点的新语义，重启须回滚 prepared）；
    point="after_event"：active 状态与 share_rotation_activated 事件均已
                            落盘，仅暂存/备份未清理（重启须保持 active）。

    就绪通知用 Event（信号量语义，立即对父进程可见）；不能用
    multiprocessing.Queue——os._exit 会跳过后台 feeder 线程的冲刷。
    """
    service = _make_service(data_dir)
    store = WalletStore(data_dir)
    service.create_share_rotation(wallet_id, rotation_id)
    record = store.get_rotation(wallet_id, rotation_id)
    wallet = store.get_wallet(wallet_id)
    old_shares = [
        store.get_share(wallet_id, s["share_id"]) for s in wallet["shares"]
    ]
    activating = dict(record)
    activating["state"] = "activating"
    activating["previous_public_key"] = wallet["public_key"]
    store.update_rotation(wallet_id, rotation_id, activating)
    store.save_activation_backups(wallet_id, rotation_id, old_shares, wallet)
    if point == "after_marker":
        ready_event.set()
        os._exit(1)
    new_records = [
        store.get_staging_share(wallet_id, rotation_id, sid)
        for sid in record["share_ids"]
    ]
    for share_record in new_records:
        store.save_share(wallet_id, share_record)
    new_meta = dict(wallet)
    new_meta["shares"] = [
        {"share_id": r["share_id"], "public_key": r["public_key"]}
        for r in new_records
    ]
    new_meta["public_key"] = record["public_key"]
    store.save_wallet_meta(wallet_id, new_meta)
    for share_record in old_shares:
        store.delete_share(wallet_id, share_record["share_id"])
    if point == "after_swap":
        ready_event.set()
        os._exit(1)
    if point == "after_event_activating":
        # 极端窗口：新份额/元数据已换入、记录仍为 activating，但激活事件
        # 已落盘（状态推进与事件非原子）。事件即提交点：重启须前滚为
        # active 并清理，不得回滚。
        AuditStore(data_dir).append_event(
            wallet_id,
            {
                "type": audit_mod.TYPE_SHARE_ROTATION_ACTIVATED,
                "at": "2026-09-20T00:00:00Z",
                "request_id": None,
                "actor_id": None,
                "reason": None,
                "details": {
                    "rotation_id": rotation_id,
                    "share_ids": list(record["share_ids"]),
                    "public_key": record["public_key"],
                    "previous_public_key": wallet["public_key"],
                },
            },
        )
        ready_event.set()
        os._exit(1)
    active = dict(record)
    active["state"] = "active"
    active["previous_public_key"] = wallet["public_key"]
    store.update_rotation(wallet_id, rotation_id, active)
    if point == "after_commit":
        ready_event.set()
        os._exit(1)
    # after_event：提交点事件已落盘，暂存/备份尚未清理
    AuditStore(data_dir).append_event(
        wallet_id,
        {
            "type": audit_mod.TYPE_SHARE_ROTATION_ACTIVATED,
            "at": "2026-09-20T00:00:00Z",
            "request_id": None,
            "actor_id": None,
            "reason": None,
            "details": {
                "rotation_id": rotation_id,
                "share_ids": list(record["share_ids"]),
                "public_key": record["public_key"],
                "previous_public_key": wallet["public_key"],
            },
        },
    )
    ready_event.set()
    os._exit(1)


def _run_children(targets_args, timeout=30):
    """启动若干子进程并全部 join，返回各进程退出码列表。"""
    ctx = multiprocessing.get_context("fork")
    procs = [ctx.Process(target=t, args=a) for t, a in targets_args]
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join(timeout)
    for proc in procs:
        if proc.is_alive():
            proc.terminate()
            proc.join(5)
    return [proc.exitcode for proc in procs]


def _collect(queue, count, timeout=30):
    """从队列收 count 个结果，超时即失败。"""
    results = []
    for _ in range(count):
        results.append(queue.get(timeout=timeout))
    return results


class CrossProcessConcurrencyTest(unittest.TestCase):
    """同一 data-dir 上两个服务进程的并发提交。"""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.data_dir, ignore_errors=True)
        self.ctx = multiprocessing.get_context("fork")

    def _new_queue(self):
        return self.ctx.Queue()

    def _seed_wallet(self, wallet_id="w1"):
        service = _make_service(self.data_dir)
        service.create_wallet(wallet_id, 2)
        return service

    def _signatures(self, wallet_id, request_id, message,
                    share_ids=("share-1", "share-2")):
        store = WalletStore(self.data_dir)
        payload = crypto.build_payload(request_id, message)
        return [
            {
                "share_id": sid,
                "signature": crypto.sign_share(
                    bytes.fromhex(
                        store.get_share(wallet_id, sid)["private_key"]
                    ),
                    payload,
                ).hex(),
            }
            for sid in share_ids
        ]

    def test_concurrent_create_wallet_only_one_wins(self):
        queue = self._new_queue()
        exits = _run_children([
            (_child_create_wallet, (self.data_dir, "w1", queue)),
            (_child_create_wallet, (self.data_dir, "w1", queue)),
        ])
        self.assertEqual(sorted(exits), [0, 0])
        statuses = sorted(_collect(queue, 2))
        # 恰有一个首次创建成功，另一个 409；钱包文件只有一份完整内容
        self.assertEqual(statuses, [201, 409])
        wallet = WalletStore(self.data_dir).get_wallet("w1")
        self.assertEqual(len(wallet["shares"]), 2)

    def test_concurrent_sign_only_one_first_commit(self):
        self._seed_wallet()
        signatures = self._signatures("w1", "req-1", "pay-100")
        queue = self._new_queue()
        args = (self.data_dir, "w1", "req-1", "pay-100", signatures, queue)
        exits = _run_children([
            (_child_sign, args),
            (_child_sign, args),
        ])
        self.assertEqual(sorted(exits), [0, 0])
        results = _collect(queue, 2)
        statuses = sorted(status for status, _ in results)
        # 只能一个首次提交（201），另一个是幂等重放（200）
        self.assertEqual(statuses, [200, 201])
        # 两者返回的签名完全一致：不存在半签名或混合结果
        self.assertEqual(results[0][1], results[1][1])
        # 磁盘上的签名与返回一致
        stored = WalletStore(self.data_dir).get_signature("w1", "req-1")
        self.assertEqual(stored["signature"], results[0][1])
        # 审计只记一次 request_signed，seq 连续无重号
        service = _make_service(self.data_dir)
        events = service.get_audit_events("w1")["events"]
        self.assertEqual([e["type"] for e in events], ["request_signed"])
        self.assertEqual([e["seq"] for e in events], [1])

    def test_concurrent_activate_only_one_first_commit(self):
        service = self._seed_wallet()
        service.create_share_rotation("w1", "rot-1")
        queue = self._new_queue()
        args = (self.data_dir, "w1", "rot-1", queue)
        exits = _run_children([
            (_child_activate, args),
            (_child_activate, args),
        ])
        self.assertEqual(sorted(exits), [0, 0])
        statuses = sorted(_collect(queue, 2))
        # 恰有一个首次激活（201），另一个幂等重放（200）
        self.assertEqual(statuses, [200, 201])
        # 轮换状态只提交一次，审计只记一条激活事件
        service = _make_service(self.data_dir)
        view = service.get_share_rotation("w1", "rot-1")
        self.assertEqual(view["state"], "active")
        events = service.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["type"] for e in events],
            ["share_rotation_prepared", "share_rotation_activated"],
        )
        self.assertEqual([e["seq"] for e in events], [1, 2])
        # 暂存目录已清理
        self.assertFalse(
            os.path.exists(
                os.path.join(
                    self.data_dir, "rotation-staging", "w1", "rot-1"
                )
            )
        )

    def test_sign_and_activate_interleaved_across_processes(self):
        """激活与签名跨进程交错：激活前已首签的请求可重放；
        未首签的请求激活后只接受新 share_ids，旧份额 400。"""
        service = self._seed_wallet()
        # 进程 A 完成 req-old 的首签
        old_sigs = self._signatures("w1", "req-old", "m-old")
        queue = self._new_queue()
        _run_children([
            (_child_sign, (self.data_dir, "w1", "req-old", "m-old",
                           old_sigs, queue)),
        ])
        status, signature = queue.get(timeout=30)
        self.assertEqual(status, 201)
        # 准备轮换并由另一进程激活
        _, prepared = service.create_share_rotation("w1", "rot-1")
        _run_children([
            (_child_activate, (self.data_dir, "w1", "rot-1", queue)),
        ])
        self.assertEqual(queue.get(timeout=30), 201)
        # 激活前已完成的签名仍可按原请求重放（200，同签名）
        _run_children([
            (_child_sign, (self.data_dir, "w1", "req-old", "m-old",
                           old_sigs, queue)),
        ])
        replay_status, replay_sig = queue.get(timeout=30)
        self.assertEqual(replay_status, 200)
        self.assertEqual(replay_sig, signature)
        # 未首签的请求：旧份额提交 400
        _run_children([
            (_child_sign, (self.data_dir, "w1", "req-new", "m-new",
                           old_sigs, queue)),
        ])
        rejected_status, _ = queue.get(timeout=30)
        self.assertEqual(rejected_status, 400)
        # 新份额提交 201；钱包公钥已整体切换，不存在混合公钥
        new_sigs = self._signatures(
            "w1", "req-new", "m-new", share_ids=prepared["share_ids"]
        )
        _run_children([
            (_child_sign, (self.data_dir, "w1", "req-new", "m-new",
                           new_sigs, queue)),
        ])
        new_status, new_sig = queue.get(timeout=30)
        self.assertEqual(new_status, 201)
        service = _make_service(self.data_dir)
        wallet = service.get_wallet("w1")
        self.assertEqual(wallet["public_key"], prepared["public_key"])
        # 聚合签名可用新公钥拆半独立验证
        full_pub = bytes.fromhex(wallet["public_key"])
        full_sig = bytes.fromhex(new_sig)
        payload = crypto.build_payload("req-new", "m-new")
        for half in range(2):
            self.assertTrue(
                crypto.verify_share(
                    full_pub[half * 32:(half + 1) * 32],
                    payload,
                    full_sig[half * 64:(half + 1) * 64],
                )
            )

    def test_killed_process_leaves_no_stale_lock(self):
        """持有锁的进程被 SIGKILL 后，后续进程不被陈旧锁阻塞。"""
        self._seed_wallet()
        ready = self._new_queue()
        ctx = self.ctx
        proc = ctx.Process(
            target=_child_hold_lock, args=(self.data_dir, "w1", ready)
        )
        proc.start()
        self.assertEqual(ready.get(timeout=30), "held")
        proc.kill()
        proc.join(timeout=30)
        # 新进程立即能拿到锁并完成业务操作
        queue = self._new_queue()
        signatures = self._signatures("w1", "req-1", "pay-100")
        _run_children([
            (_child_sign, (self.data_dir, "w1", "req-1", "pay-100",
                           signatures, queue)),
        ], timeout=30)
        status, _ = queue.get(timeout=30)
        self.assertEqual(status, 201)


class FaultPointRestartTest(unittest.TestCase):
    """激活各故障点崩溃后，新进程启动恢复的表现。"""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.data_dir, ignore_errors=True)
        self.ctx = multiprocessing.get_context("fork")
        service = _make_service(self.data_dir)
        service.create_wallet("w1", 2)
        self.wallet_before = WalletStore(self.data_dir).get_wallet("w1")
        self.old_shares = {
            sid: WalletStore(self.data_dir).get_share("w1", sid)
            for sid in ("share-1", "share-2")
        }

    def _crash_at(self, point):
        ready = self.ctx.Event()
        proc = self.ctx.Process(
            target=_child_crash_mid_activation,
            args=(self.data_dir, "w1", "rot-1", point, ready),
        )
        proc.start()
        self.assertTrue(ready.wait(timeout=30))
        proc.join(timeout=30)
        self.assertNotEqual(proc.exitcode, 0)

    def _staging_dir(self):
        return os.path.join(self.data_dir, "rotation-staging", "w1", "rot-1")

    def test_crash_after_marker_rolls_back_to_prepared(self):
        self._crash_at("after_marker")
        # 重启恢复：activating 回滚为 prepared，钱包与旧份额原样
        service = _make_service(self.data_dir)
        view = service.get_share_rotation("w1", "rot-1")
        self.assertEqual(view["state"], "prepared")
        store = WalletStore(self.data_dir)
        self.assertEqual(store.get_wallet("w1"), self.wallet_before)
        for sid, record in self.old_shares.items():
            self.assertEqual(store.get_share("w1", sid), record)
        # 备份已清理，暂存新份额保留（有效 prepared），可重新激活
        self.assertEqual(
            sorted(os.listdir(self._staging_dir())),
            ["rot-1-share-1.json", "rot-1-share-2.json"],
        )
        status, active = service.activate_share_rotation("w1", "rot-1")
        self.assertEqual(status, 201)
        self.assertEqual(active["state"], "active")

    def test_crash_after_swap_restores_wallet_and_old_shares(self):
        self._crash_at("after_swap")
        # 崩溃现场：新份额已换入、元数据已改、旧份额已删
        store = WalletStore(self.data_dir)
        self.assertIsNone(store.get_share("w1", "share-1"))
        service = _make_service(self.data_dir)
        # 恢复后：原钱包、旧份额、prepared 状态全部还原
        self.assertEqual(store.get_wallet("w1"), self.wallet_before)
        for sid, record in self.old_shares.items():
            self.assertEqual(store.get_share("w1", sid), record)
        for sid in ("rot-1-share-1", "rot-1-share-2"):
            self.assertIsNone(store.get_share("w1", sid))
        view = service.get_share_rotation("w1", "rot-1")
        self.assertEqual(view["state"], "prepared")
        # 无半签名/混合公钥：公钥仍是原钱包公钥
        self.assertEqual(
            store.get_wallet("w1")["public_key"],
            self.wallet_before["public_key"],
        )
        # 恢复不新增审计事件（只有准备期那一条）
        events = service.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["type"] for e in events], ["share_rotation_prepared"]
        )

    def test_crash_after_state_but_before_event_rolls_back_to_prepared(self):
        # 轮换状态已写 active，但 share_rotation_activated 事件尚未落盘：
        # 事件才是提交点，重启必须恢复旧公钥/旧份额、置回 prepared，
        # 保留经校验有效的暂存份额，且不产生激活事件。
        self._crash_at("after_commit")
        service = _make_service(self.data_dir)
        view = service.get_share_rotation("w1", "rot-1")
        self.assertEqual(view["state"], "prepared")
        store = WalletStore(self.data_dir)
        self.assertEqual(store.get_wallet("w1"), self.wallet_before)
        for sid, record in self.old_shares.items():
            self.assertEqual(store.get_share("w1", sid), record)
        self.assertEqual(
            sorted(os.listdir(self._staging_dir())),
            ["rot-1-share-1.json", "rot-1-share-2.json"],
        )
        events = service.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["type"] for e in events], ["share_rotation_prepared"]
        )
        # 回滚后可重新激活（首提 201）
        status, active = service.activate_share_rotation("w1", "rot-1")
        self.assertEqual(status, 201)
        self.assertEqual(active["state"], "active")

    def test_crash_after_event_keeps_active_and_cleans_staging(self):
        # 激活事件已落盘：即使暂存/备份尚未清理，也必须保持 active，
        # 前滚补齐并清理全部残留，且不重复记事件。
        self._crash_at("after_event")
        service = _make_service(self.data_dir)
        view = service.get_share_rotation("w1", "rot-1")
        self.assertEqual(view["state"], "active")
        self.assertFalse(os.path.exists(self._staging_dir()))
        store = WalletStore(self.data_dir)
        wallet = store.get_wallet("w1")
        self.assertEqual(wallet["public_key"], view["public_key"])
        self.assertEqual(
            [s["share_id"] for s in wallet["shares"]],
            ["rot-1-share-1", "rot-1-share-2"],
        )
        # 激活重放 200，状态不倒退、不重复记事件
        status, again = service.activate_share_rotation("w1", "rot-1")
        self.assertEqual(status, 200)
        self.assertEqual(again["state"], "active")
        events = service.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["type"] for e in events],
            ["share_rotation_prepared", "share_rotation_activated"],
        )

    def test_crash_event_landed_while_activating_forwards_to_active(self):
        # 记录仍为 activating 但激活事件已落盘：事件是提交点，必须
        # 前滚为唯一 active 结果（而非回滚），且不重复记事件。
        self._crash_at("after_event_activating")
        service = _make_service(self.data_dir)
        view = service.get_share_rotation("w1", "rot-1")
        self.assertEqual(view["state"], "active")
        self.assertFalse(os.path.exists(self._staging_dir()))
        store = WalletStore(self.data_dir)
        wallet = store.get_wallet("w1")
        self.assertEqual(wallet["public_key"], view["public_key"])
        self.assertEqual(
            [s["share_id"] for s in wallet["shares"]],
            ["rot-1-share-1", "rot-1-share-2"],
        )
        for sid in ("share-1", "share-2"):
            self.assertIsNone(store.get_share("w1", sid))
        events = service.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["type"] for e in events],
            ["share_rotation_prepared", "share_rotation_activated"],
        )
        self.assertEqual(
            service.activate_share_rotation("w1", "rot-1")[0], 200
        )
        self.assertEqual(
            len(service.get_audit_events("w1")["events"]), 2
        )


class StagingLeftoverValidityTest(unittest.TestCase):
    """启动恢复对轮换残留的判定：仅完整有效的 prepared 暂存保留。"""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.data_dir, ignore_errors=True)
        self.service = _make_service(self.data_dir)
        self.service.create_wallet("w1", 2)
        self.store = WalletStore(self.data_dir)
        self.wallet_before = self.store.get_wallet("w1")
        self.shares_before = {
            sid: self.store.get_share("w1", sid)
            for sid in ("share-1", "share-2")
        }

    def _staging_dir(self, wallet_id="w1", rotation_id="rot-1"):
        return os.path.join(
            self.data_dir, "rotation-staging", wallet_id, rotation_id
        )

    def _prepare(self, rotation_id="rot-1"):
        status, view = self.service.create_share_rotation("w1", rotation_id)
        self.assertEqual(status, 201)
        return view

    def _restart(self):
        self.service = _make_service(self.data_dir)
        return self.service

    def _assert_rotation_gone(self, rotation_id="rot-1"):
        with self.assertRaises(ServiceError) as ctx:
            self.service.get_share_rotation("w1", rotation_id)
        self.assertEqual(ctx.exception.status, 404)
        self.assertFalse(os.path.exists(self._staging_dir("w1", rotation_id)))

    def _assert_wallet_untouched(self):
        self.assertEqual(self.store.get_wallet("w1"), self.wallet_before)
        for sid, record in self.shares_before.items():
            self.assertEqual(self.store.get_share("w1", sid), record)

    def test_valid_prepared_staging_is_kept(self):
        prepared = self._prepare()
        service = self._restart()
        view = service.get_share_rotation("w1", "rot-1")
        self.assertEqual(view["state"], "prepared")
        self.assertEqual(view["public_key"], prepared["public_key"])
        self.assertEqual(
            sorted(os.listdir(self._staging_dir())),
            ["rot-1-share-1.json", "rot-1-share-2.json"],
        )
        # 保留的轮换仍可正常激活
        status, active = service.activate_share_rotation("w1", "rot-1")
        self.assertEqual(status, 201)
        self.assertEqual(active["state"], "active")

    def test_missing_share_file_drops_record_and_staging(self):
        self._prepare()
        os.unlink(os.path.join(self._staging_dir(), "rot-1-share-2.json"))
        service = self._restart()
        self._assert_rotation_gone()
        self._assert_wallet_untouched()
        # 记录被清理后可以重新准备同名轮换（不再 409）
        status, _ = service.create_share_rotation("w1", "rot-1")
        self.assertEqual(status, 201)

    def test_corrupt_json_share_file_dropped(self):
        self._prepare()
        with open(
            os.path.join(self._staging_dir(), "rot-1-share-1.json"), "w"
        ) as f:
            f.write("{not json")
        self._restart()
        self._assert_rotation_gone()
        self._assert_wallet_untouched()

    def test_extra_file_in_staging_dropped(self):
        self._prepare()
        with open(os.path.join(self._staging_dir(), "extra.json"), "w") as f:
            json.dump({"share_id": "extra"}, f)
        self._restart()
        self._assert_rotation_gone()
        self._assert_wallet_untouched()

    def test_mismatched_private_key_dropped(self):
        self._prepare()
        path = os.path.join(self._staging_dir(), "rot-1-share-1.json")
        with open(path, encoding="utf-8") as f:
            record = json.load(f)
        # 换成另一把合法但与不匹配 public_key 的 32 字节私钥
        record["private_key"] = crypto.generate_share_key(
            "rot-1-share-1"
        ).private_bytes.hex()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(record, f)
        self._restart()
        self._assert_rotation_gone()
        self._assert_wallet_untouched()

    def test_wrong_length_private_key_dropped(self):
        self._prepare()
        path = os.path.join(self._staging_dir(), "rot-1-share-2.json")
        with open(path, encoding="utf-8") as f:
            record = json.load(f)
        record["private_key"] = record["private_key"][:62]  # 31 字节
        with open(path, "w", encoding="utf-8") as f:
            json.dump(record, f)
        self._restart()
        self._assert_rotation_gone()
        self._assert_wallet_untouched()

    def test_orphan_staging_dir_without_record_dropped(self):
        # 无轮换记录的孤儿暂存目录（含完整有效的份额文件）
        orphan = self._staging_dir("w1", "rot-orphan")
        os.makedirs(orphan)
        for sid in ("rot-orphan-share-1", "rot-orphan-share-2"):
            key = crypto.generate_share_key(sid)
            with open(os.path.join(orphan, sid + ".json"), "w") as f:
                json.dump(
                    {
                        "share_id": sid,
                        "public_key": key.public_bytes.hex(),
                        "private_key": key.private_bytes.hex(),
                    },
                    f,
                )
        self._restart()
        self.assertFalse(os.path.exists(orphan))
        self._assert_wallet_untouched()

    def test_invalid_rotation_record_dropped(self):
        self._prepare()
        record = self.store.get_rotation("w1", "rot-1")
        record["state"] = "bogus-state"
        self.store.update_rotation("w1", "rot-1", record)
        self._restart()
        self._assert_rotation_gone()
        self._assert_wallet_untouched()

    def test_staging_of_wallet_without_rotation_file_dropped(self):
        # 钱包存在但从未有过轮换记录文件：暂存残留照样清理，钱包不动
        self.service.create_wallet("w2", 2)
        wallet2_before = self.store.get_wallet("w2")
        orphan = self._staging_dir("w2", "rot-x")
        os.makedirs(orphan)
        with open(os.path.join(orphan, "rot-x-share-1.json"), "w") as f:
            json.dump({"share_id": "rot-x-share-1"}, f)
        self._restart()
        self.assertFalse(os.path.exists(orphan))
        self.assertEqual(self.store.get_wallet("w2"), wallet2_before)


class PrivateKeyBoundaryTest(unittest.TestCase):
    """恢复清理后的私钥边界：被删残留不留任何私钥副本。"""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.data_dir, ignore_errors=True)
        self.service = _make_service(self.data_dir)
        self.service.create_wallet("w1", 2)
        self.store = WalletStore(self.data_dir)

    def _iter_files(self):
        for base, _, files in os.walk(self.data_dir):
            for name in files:
                yield os.path.join(base, name)

    def test_cleanup_leaves_no_private_key_copies(self):
        _, prepared = self.service.create_share_rotation("w1", "rot-1")
        staging = os.path.join(
            self.data_dir, "rotation-staging", "w1", "rot-1"
        )
        staged_privates = []
        for sid in prepared["share_ids"]:
            staged_privates.append(
                self.store.get_staging_share("w1", "rot-1", sid)["private_key"]
            )
        # 让暂存失效（多出一个文件），触发恢复时的安全删除
        with open(os.path.join(staging, "junk.json"), "w") as f:
            json.dump({"share_id": "junk"}, f)
        self.service = _make_service(self.data_dir)
        self.assertFalse(os.path.exists(staging))
        # 全盘扫描：被删暂存份额的私钥不出现在任何文件中
        for path in self._iter_files():
            with open(path, "rb") as f:
                raw = f.read()
            for priv in staged_privates:
                self.assertNotIn(priv.encode(), raw, path)

    def test_disk_layout_keeps_private_key_boundary_after_recovery(self):
        # 制造混合现场：有效 prepared（保留）+ 孤儿目录（删除）+ 完成签名
        self.service.create_share_rotation("w1", "rot-keep")
        orphan = os.path.join(
            self.data_dir, "rotation-staging", "w1", "rot-drop"
        )
        os.makedirs(orphan)
        drop_key = crypto.generate_share_key("rot-drop-share-1")
        with open(os.path.join(orphan, "rot-drop-share-1.json"), "w") as f:
            json.dump(
                {
                    "share_id": "rot-drop-share-1",
                    "public_key": drop_key.public_bytes.hex(),
                    "private_key": drop_key.private_bytes.hex(),
                },
                f,
            )
        store = WalletStore(self.data_dir)
        payload = crypto.build_payload("r1", "m1")
        signatures = [
            {
                "share_id": sid,
                "signature": crypto.sign_share(
                    bytes.fromhex(
                        store.get_share("w1", sid)["private_key"]
                    ),
                    payload,
                ).hex(),
            }
            for sid in ("share-1", "share-2")
        ]
        status, _ = self.service.sign("w1", "r1", "m1", signatures)
        self.assertEqual(status, 201)

        self.service = _make_service(self.data_dir)
        self.assertFalse(os.path.exists(orphan))
        # 有效 prepared 保留
        self.assertEqual(
            self.service.get_share_rotation("w1", "rot-keep")["state"],
            "prepared",
        )
        in_use_privates = [
            store.get_share("w1", sid)["private_key"]
            for sid in ("share-1", "share-2")
        ]
        full_ab = (in_use_privates[0] + in_use_privates[1]).encode()
        full_ba = (in_use_privates[1] + in_use_privates[0]).encode()
        for path in self._iter_files():
            with open(path, "rb") as f:
                raw = f.read()
            # 不存在拼接后的完整私钥
            self.assertNotIn(full_ab, raw, path)
            self.assertNotIn(full_ba, raw, path)
            # 被删孤儿份额的私钥不留副本
            self.assertNotIn(drop_key.private_bytes.hex().encode(), raw, path)
            # 每个文件至多一个份额私钥，且恰为 32 字节
            with open(path, encoding="utf-8") as f:
                record = json.load(f)
            found = []
            self._collect_private_keys(record, found)
            self.assertLessEqual(len(found), 1, path)
            for priv_hex in found:
                self.assertEqual(len(priv_hex), 64, path)
        # 钱包元数据不含任何私钥材料
        with open(
            os.path.join(self.data_dir, "wallets", "w1.json"), encoding="utf-8"
        ) as f:
            self.assertNotIn("private", f.read())

    @staticmethod
    def _collect_private_keys(obj, found):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key == "private_key" and isinstance(value, str):
                    found.append(value)
                else:
                    PrivateKeyBoundaryTest._collect_private_keys(value, found)
        elif isinstance(obj, list):
            for item in obj:
                PrivateKeyBoundaryTest._collect_private_keys(item, found)


class AuditContinuityTest(unittest.TestCase):
    """审计 seq：按钱包连续升序、跨重启接续、重放与清理不记事件。"""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.data_dir, ignore_errors=True)
        self.service = _make_service(self.data_dir)
        self.service.create_wallet("w1", 2)

    def _events(self):
        return self.service.get_audit_events("w1")["events"]

    def _assert_seq_continuous(self, events):
        self.assertEqual(
            [e["seq"] for e in events], list(range(1, len(events) + 1))
        )

    def _signatures(self, request_id, message):
        store = WalletStore(self.data_dir)
        payload = crypto.build_payload(request_id, message)
        return [
            {
                "share_id": sid,
                "signature": crypto.sign_share(
                    bytes.fromhex(
                        store.get_share("w1", sid)["private_key"]
                    ),
                    payload,
                ).hex(),
            }
            for sid in ("share-1", "share-2")
        ]

    def test_seq_continuous_across_restarts_and_replays(self):
        # 正常操作产生事件
        self.service.put_policy("w1", 2, 3600)
        self.service.create_sign_request("w1", "req-1", "pay-100")
        self.service.approve("w1", "req-1", "ops-1")
        self.service.approve("w1", "req-1", "ops-2")
        status, _ = self.service.sign(
            "w1", "req-1", "pay-100", self._signatures("req-1", "pay-100")
        )
        self.assertEqual(status, 201)
        events_before = self._events()
        self._assert_seq_continuous(events_before)
        count_before = len(events_before)

        # 重启：seq 接续文件中已有最大 seq，不重号、不回退
        self.service = _make_service(self.data_dir)
        self.service.put_policy("w1", 1, 60)  # 同值/异值更新都记一条
        events = self._events()
        self._assert_seq_continuous(events)
        self.assertEqual(len(events), count_before + 1)

        # 幂等重放不新增业务事件：签名重放、审批单创建重放、
        # 轮换准备重放、激活重放
        status, _ = self.service.sign(
            "w1", "req-1", "pay-100", self._signatures("req-1", "pay-100")
        )
        self.assertEqual(status, 200)
        status, _ = self.service.create_sign_request("w1", "req-1", "pay-100")
        self.assertEqual(status, 200)
        status, _ = self.service.create_share_rotation("w1", "rot-1")
        self.assertEqual(status, 201)
        count_with_prepare = len(self._events())
        status, _ = self.service.create_share_rotation("w1", "rot-1")
        self.assertEqual(status, 200)
        status, _ = self.service.activate_share_rotation("w1", "rot-1")
        self.assertEqual(status, 201)
        status, _ = self.service.activate_share_rotation("w1", "rot-1")
        self.assertEqual(status, 200)
        events = self._events()
        # 只新增了 prepared + activated 两条
        self.assertEqual(len(events), count_with_prepare + 1)
        self._assert_seq_continuous(events)

    def test_orphan_cleanup_and_recovery_add_no_events(self):
        self.service.put_policy("w1", 1, 3600)
        events_before = self._events()
        count_before = len(events_before)
        # 制造需要清理的现场：孤儿暂存目录 + 失效 prepared + active 残留
        store = WalletStore(self.data_dir)
        staging_root = os.path.join(self.data_dir, "rotation-staging", "w1")
        os.makedirs(os.path.join(staging_root, "rot-orphan"))
        self.service.create_share_rotation("w1", "rot-broken")
        os.unlink(
            os.path.join(staging_root, "rot-broken", "rot-broken-share-1.json")
        )
        record = store.get_rotation("w1", "rot-broken")
        # 再补一个无记录的孤儿暂存目录（含来路不明的份额文件）
        done_dir = os.path.join(staging_root, "rot-done")
        os.makedirs(done_dir)
        with open(os.path.join(done_dir, "leftover.json"), "w") as f:
            json.dump({"share_id": "leftover"}, f)
        # 重启触发恢复与清理
        self.service = _make_service(self.data_dir)
        events_after = self._events()
        # 孤儿清理与失效记录删除都不新增业务事件
        self.assertEqual(len(events_after), count_before + 1)  # 仅 prepared 一条
        self._assert_seq_continuous(events_after)
        # 清理确实发生
        self.assertFalse(os.path.exists(os.path.join(staging_root, "rot-orphan")))
        self.assertFalse(os.path.exists(os.path.join(staging_root, "rot-broken")))
        self.assertFalse(os.path.exists(done_dir))


if __name__ == "__main__":
    unittest.main()
