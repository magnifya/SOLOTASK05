"""资产提交的崩溃一致性与恢复测试。

覆盖任务契约：
- commit 是「意图 → 账本 → 事件 → 删意图」的可恢复事务：
  普通写入或事件追加失败须恢复 pending 与提交前余额/版本，不产生事件或
  seq 缺口，之后可重试（首提仍 201）；
- 任一落盘阶段被强制终止后，同一 data-dir 重启先恢复：事件已持久化则
  保留并按事件 R 前滚补齐唯一 committed 结果；事件未持久化则恢复
  pending 与提交前资产状态；无提交无事件、事件与余额相符、无重复
  version/事件；意图只含标识与整数，不含私钥；
- 运行中的进程遇到另一进程崩溃残留的意图时，在钱包事务锁内自愈；
- 余额不足 409 无副作用；恢复/提交按钱包跨进程串行，仅一个首次 201。
"""

from __future__ import annotations

import multiprocessing
import os
import shutil
import tempfile
import unittest

from threshold_wallet import audit as audit_mod
from threshold_wallet.audit import AuditStore
from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import WalletStore
from tests.helpers import make_harness


def _make_service(data_dir: str) -> WalletService:
    return WalletService(WalletStore(data_dir))


class CommitFailureRollbackTest(unittest.TestCase):
    """普通写入 / 事件追加失败：回滚 pending 与提交前余额、版本。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.h = make_harness(self.tmp)
        self.svc = self.h.service
        self.store = self.h.store
        self.svc.create_wallet("w1", 2)
        self.svc.create_asset_operation("w1", "op1", "btc", 100)

    def test_ledger_write_failure_rolls_back_and_is_retryable(self):
        original = self.store.commit_asset_operation

        def boom(*a, **k):
            raise OSError("assets disk full")

        self.store.commit_asset_operation = boom
        try:
            with self.assertRaises(OSError):
                self.svc.commit_asset_operation("w1", "op1")
        finally:
            self.store.commit_asset_operation = original
        # 无半完成：仍 pending、无资产条目、无意图、无事件
        self.assertEqual(
            self.store.get_asset_operation("w1", "op1")["state"], "pending"
        )
        self.assertIsNone(self.store.get_asset("w1", "btc"))
        self.assertIsNone(self.store.get_asset_commit_intent("w1", "op1"))
        self.assertEqual(self.svc.get_audit_events("w1")["events"], [])
        # 重试仍为首次提交 201
        code, body = self.svc.commit_asset_operation("w1", "op1")
        self.assertEqual(code, 201)
        self.assertEqual((body["balance"], body["version"]), (100, 1))

    def test_event_append_failure_rolls_back_without_seq_gap(self):
        # 先有一笔成功提交（version=1, seq=1）
        self.assertEqual(self.svc.commit_asset_operation("w1", "op1")[0], 201)
        self.svc.create_asset_operation("w1", "op2", "btc", 20)
        real_append = self.svc._audit.append_event

        def boom(wallet_id, event):
            if event.get("type") == "asset_operation_committed":
                raise OSError("audit disk full")
            return real_append(wallet_id, event)

        self.svc._audit.append_event = boom
        try:
            with self.assertRaises(OSError):
                self.svc.commit_asset_operation("w1", "op2")
        finally:
            self.svc._audit.append_event = real_append
        # 回滚到提交前：余额/版本仍是 (100,1)，op2 仍 pending
        self.assertEqual(
            self.store.get_asset_operation("w1", "op2")["state"], "pending"
        )
        self.assertEqual(self.store.get_asset("w1", "btc"),
                         {"balance": 100, "version": 1})
        self.assertIsNone(self.store.get_asset_commit_intent("w1", "op2"))
        events = self.svc.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in events], [1])
        # 重试首提 201：version 与 seq 均接续，无重号、无缺口
        code, body = self.svc.commit_asset_operation("w1", "op2")
        self.assertEqual(code, 201)
        self.assertEqual((body["balance"], body["version"]), (120, 2))
        events = self.svc.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in events], [1, 2])
        self.assertEqual(
            [e["request_id"] for e in events], ["op1", "op2"]
        )

    def test_intent_write_failure_leaves_nothing(self):
        original = self.store.write_asset_commit_intent

        def boom(*a, **k):
            raise OSError("intent disk full")

        self.store.write_asset_commit_intent = boom
        try:
            with self.assertRaises(OSError):
                self.svc.commit_asset_operation("w1", "op1")
        finally:
            self.store.write_asset_commit_intent = original
        self.assertEqual(
            self.store.get_asset_operation("w1", "op1")["state"], "pending"
        )
        self.assertEqual(self.svc.get_audit_events("w1")["events"], [])

    def test_insufficient_balance_is_side_effect_free(self):
        self.svc.commit_asset_operation("w1", "op1")
        self.svc.create_asset_operation("w1", "op2", "btc", -500)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.commit_asset_operation("w1", "op2")
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(
            self.store.get_asset_operation("w1", "op2")["state"], "pending"
        )
        self.assertEqual(self.store.get_asset("w1", "btc"),
                         {"balance": 100, "version": 1})
        self.assertEqual(self.store.list_asset_intents("w1"), [])
        self.assertEqual(
            [e for e in self.svc.get_audit_events("w1")["events"]
             if e["type"] == "asset_operation_committed"],
            [e for e in self.svc.get_audit_events("w1")["events"]
             if e["request_id"] == "op1"],
        )


def _plant_crash_scene(data_dir: str, operation_id: str, phase: int) -> None:
    """用存储层直接摆放某提交事务在 phase 阶段被强杀的现场。

    phase 1：仅意图；2：意图 + 账本已提交；3：意图 + 账本 + 事件已落盘。
    """
    store = WalletStore(data_dir)
    pending = store.get_asset_operation("w1", operation_id)
    old_asset = store.get_asset("w1", pending["asset_id"])
    old_balance = old_asset["balance"] if old_asset else 0
    old_version = old_asset["version"] if old_asset else 0
    new_balance = old_balance + pending["delta"]
    new_version = old_version + 1
    intent = {
        "operation_id": operation_id,
        "asset_id": pending["asset_id"],
        "delta": pending["delta"],
        "old_asset": old_asset,
        "pending": pending,
        "new_balance": new_balance,
        "new_version": new_version,
    }
    store.write_asset_commit_intent("w1", operation_id, intent)
    if phase >= 2:
        committed = {
            "operation_id": operation_id,
            "asset_id": pending["asset_id"],
            "state": "committed",
            "delta": pending["delta"],
            "balance": new_balance,
            "version": new_version,
        }
        store.commit_asset_operation(
            "w1", operation_id, committed,
            pending["asset_id"],
            {"balance": new_balance, "version": new_version},
        )
    if phase >= 3:
        AuditStore(data_dir).append_event("w1", {
            "type": audit_mod.TYPE_ASSET_OPERATION_COMMITTED,
            "at": "2026-09-20T00:00:00Z",
            "request_id": operation_id,
            "actor_id": None,
            "reason": None,
            "details": committed,
        })


class RestartCrashRecoveryTest(unittest.TestCase):
    """三个落盘阶段强制终止后，同一 data-dir 重启的恢复结果。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        svc = _make_service(self.tmp)
        svc.create_wallet("w1", 2)
        svc.create_asset_operation("w1", "op1", "btc", 100)
        svc.commit_asset_operation("w1", "op1")  # v1 / seq1
        svc.create_asset_operation("w1", "op2", "btc", 20)

    def _restart(self):
        return WalletStore(self.tmp), _make_service(self.tmp)

    def _assert_seq_continuous(self, events):
        self.assertEqual([e["seq"] for e in events],
                         list(range(1, len(events) + 1)))

    def test_phase1_only_intent_rolls_back_to_pending(self):
        _plant_crash_scene(self.tmp, "op2", 1)
        store, svc = self._restart()
        self.assertEqual(store.list_asset_intents("w1"), [])
        self.assertEqual(
            store.get_asset_operation("w1", "op2")["state"], "pending"
        )
        self.assertEqual(store.get_asset("w1", "btc"),
                         {"balance": 100, "version": 1})
        events = svc.get_audit_events("w1")["events"]
        self._assert_seq_continuous(events)
        self.assertEqual([e["request_id"] for e in events], ["op1"])
        # 恢复后首提 201：version/seq 接续
        code, body = svc.commit_asset_operation("w1", "op2")
        self.assertEqual(code, 201)
        self.assertEqual((body["balance"], body["version"]), (120, 2))
        self.assertEqual(
            [e["seq"] for e in svc.get_audit_events("w1")["events"]], [1, 2]
        )

    def test_phase2_ledger_without_event_rolls_back(self):
        _plant_crash_scene(self.tmp, "op2", 2)
        store, svc = self._restart()
        self.assertEqual(store.list_asset_intents("w1"), [])
        self.assertEqual(
            store.get_asset_operation("w1", "op2")["state"], "pending"
        )
        self.assertEqual(store.get_asset("w1", "btc"),
                         {"balance": 100, "version": 1})
        self.assertEqual(
            [e["request_id"] for e in svc.get_audit_events("w1")["events"]],
            ["op1"],
        )
        code, body = svc.commit_asset_operation("w1", "op2")
        self.assertEqual(code, 201)
        self.assertEqual((body["balance"], body["version"]), (120, 2))

    def test_phase3_event_persisted_rolls_forward_once(self):
        _plant_crash_scene(self.tmp, "op2", 3)
        store, svc = self._restart()
        self.assertEqual(store.list_asset_intents("w1"), [])
        self.assertEqual(store.get_asset("w1", "btc"),
                         {"balance": 120, "version": 2})
        op = store.get_asset_operation("w1", "op2")
        self.assertEqual(op["state"], "committed")
        events = svc.get_audit_events("w1")["events"]
        self._assert_seq_continuous(events)
        committed = [e for e in events
                     if e["type"] == "asset_operation_committed"]
        self.assertEqual(len(committed), 2)
        self.assertEqual(committed[1]["request_id"], "op2")
        self.assertIsNone(committed[1]["actor_id"])
        self.assertIsNone(committed[1]["reason"])
        self.assertEqual(committed[1]["details"], op)
        # 重放 200 同体，不改余额、版本、审计
        code, body = svc.commit_asset_operation("w1", "op2")
        self.assertEqual(code, 200)
        self.assertEqual(body, op)
        self.assertEqual(store.get_asset("w1", "btc"),
                         {"balance": 120, "version": 2})
        self.assertEqual(len(svc.get_audit_events("w1")["events"]), 2)

    def test_recovery_is_idempotent_across_restarts(self):
        _plant_crash_scene(self.tmp, "op2", 3)
        _, svc1 = self._restart()
        self.assertEqual(
            svc1.get_asset("w1", "btc"),
            {"asset_id": "btc", "balance": 120, "version": 2},
        )
        _, svc2 = self._restart()
        # 再次恢复无意图可处理，状态/审计不变
        self.assertEqual(
            svc2.get_asset("w1", "btc"),
            {"asset_id": "btc", "balance": 120, "version": 2},
        )
        self.assertEqual(len(svc2.get_audit_events("w1")["events"]), 2)

    def test_get_asset_shape_is_strict(self):
        _plant_crash_scene(self.tmp, "op2", 3)
        _, svc = self._restart()
        self.assertEqual(
            set(svc.get_asset("w1", "btc")),
            {"asset_id", "balance", "version"},
        )


class RunningProcessSelfHealTest(unittest.TestCase):
    """运行中的服务遇到他进程崩溃残留意图时，在锁内对账后继续。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc = _make_service(self.tmp)
        self.store = WalletStore(self.tmp)
        self.svc.create_wallet("w1", 2)
        self.svc.create_asset_operation("w1", "op1", "btc", 100)

    def test_leftover_intent_without_event_commits_fresh_201(self):
        # 另一进程崩溃在「账本已改、事件未落」：意图 + committed 账本，无事件
        _plant_crash_scene(self.tmp, "op1", 2)
        # 本进程启动恢复早已跑完；commit 需在锁内自愈
        code, body = self.svc.commit_asset_operation("w1", "op1")
        self.assertEqual(code, 201)
        self.assertEqual((body["balance"], body["version"]), (100, 1))
        self.assertEqual(self.store.list_asset_intents("w1"), [])
        events = self.svc.get_audit_events("w1")["events"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["request_id"], "op1")

    def test_leftover_intent_with_event_replays_200(self):
        # 另一进程在事件落盘后、删意图前崩溃
        _plant_crash_scene(self.tmp, "op1", 3)
        code, body = self.svc.commit_asset_operation("w1", "op1")
        self.assertEqual(code, 200)
        self.assertEqual((body["balance"], body["version"]), (100, 1))
        self.assertEqual(self.store.list_asset_intents("w1"), [])
        self.assertEqual(len(self.svc.get_audit_events("w1")["events"]), 1)


class IntentPrivacyTest(unittest.TestCase):
    """提交意图文件只含标识与整数，不含任何私钥材料。"""

    def test_intent_file_has_no_private_material(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        h = make_harness(tmp)
        h.service.create_wallet("w1", 2)
        h.service.create_asset_operation("w1", "op1", "btc", 100)
        priv_hexes = [
            h.store.get_share("w1", sid)["private_key"]
            for sid in ("share-1", "share-2")
        ]
        captured = {}
        real_append = h.service._audit.append_event

        def gate(wallet_id, event):
            if event.get("type") == "asset_operation_committed":
                path = os.path.join(
                    tmp, "asset-intents", "w1", "op1.json"
                )
                with open(path, "rb") as f:
                    captured["raw"] = f.read()
            return real_append(wallet_id, event)

        h.service._audit.append_event = gate
        h.service.commit_asset_operation("w1", "op1")
        raw = captured["raw"]
        self.assertNotIn(b"private", raw)
        for priv in priv_hexes:
            self.assertNotIn(priv.encode(), raw)


# ---- 跨进程强制终止 ---------------------------------------------------------


def _child_crash_at_phase(data_dir, phase, ready_event):
    store = WalletStore(data_dir)
    svc = WalletService(store)
    svc.create_wallet("w1", 2)
    svc.create_asset_operation("w1", "op1", "btc", 100)

    real_intent = store.write_asset_commit_intent
    real_commit = store.commit_asset_operation
    real_append = svc._audit.append_event

    def w_intent(w, o, i):
        real_intent(w, o, i)
        if phase == 1:
            ready_event.set(); os._exit(1)

    def w_commit(w, o, rec, a, ar):
        real_commit(w, o, rec, a, ar)
        if phase == 2:
            ready_event.set(); os._exit(1)

    def w_append(w, ev):
        out = real_append(w, ev)
        if phase == 3 and ev.get("type") == "asset_operation_committed":
            ready_event.set(); os._exit(1)
        return out

    store.write_asset_commit_intent = w_intent
    store.commit_asset_operation = w_commit
    svc._audit.append_event = w_append
    svc.commit_asset_operation("w1", "op1")


def _child_plant_scene_and_exit(data_dir, operation_id, phase, ready_event):
    """子进程：以存储层直接摆崩溃现场后 os._exit（模拟强杀的提交进程）。"""
    _plant_crash_scene(data_dir, operation_id, phase)
    ready_event.set()
    os._exit(1)


def _child_commit(data_dir, queue):
    svc = WalletService(WalletStore(data_dir))
    try:
        code, body = svc.commit_asset_operation("w1", "op1")
        queue.put((code, body["balance"], body["version"]))
    except ServiceError as exc:
        queue.put((exc.status, None, None))


class CrossProcessCrashRecoveryTest(unittest.TestCase):
    """子进程在各阶段被 os._exit 强杀后，新进程恢复并保证唯一首提。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.ctx = multiprocessing.get_context("fork")

    def _crash(self, phase):
        ready = self.ctx.Event()
        proc = self.ctx.Process(
            target=_child_crash_at_phase, args=(self.tmp, phase, ready)
        )
        proc.start()
        self.assertTrue(ready.wait(timeout=30))
        proc.join(timeout=30)
        self.assertNotEqual(proc.exitcode, 0)

    def test_each_phase_recovers_to_consistent_state(self):
        for phase, committed in ((1, False), (2, False), (3, True)):
            tmp = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
            ctx = multiprocessing.get_context("fork")
            ready = ctx.Event()
            proc = ctx.Process(
                target=_child_crash_at_phase, args=(tmp, phase, ready)
            )
            proc.start()
            self.assertTrue(ready.wait(timeout=30))
            proc.join(timeout=30)
            self.assertNotEqual(proc.exitcode, 0)

            store = WalletStore(tmp)
            svc = WalletService(store)  # 构造即恢复
            events = svc.get_audit_events("w1")["events"]
            self.assertEqual(
                [e["seq"] for e in events], list(range(1, len(events) + 1))
            )
            self.assertEqual(store.list_asset_intents("w1"), [])
            if committed:
                self.assertEqual(store.get_asset("w1", "btc"),
                                 {"balance": 100, "version": 1})
                self.assertEqual(
                    store.get_asset_operation("w1", "op1")["state"],
                    "committed",
                )
                code, body = svc.commit_asset_operation("w1", "op1")
                self.assertEqual(code, 200)
            else:
                self.assertIsNone(store.get_asset("w1", "btc"))
                self.assertEqual(
                    store.get_asset_operation("w1", "op1")["state"], "pending"
                )
                code, body = svc.commit_asset_operation("w1", "op1")
                self.assertEqual(code, 201)
                self.assertEqual((body["balance"], body["version"]), (100, 1))
            self.assertEqual(len(svc.get_audit_events("w1")["events"]), 1)

    def test_simultaneous_processes_after_crash_single_first_commit(self):
        # 先在事件落盘后强杀：恢复后应为 committed
        self._crash(3)
        queue = self.ctx.Queue()
        procs = [
            self.ctx.Process(target=_child_commit, args=(self.tmp, queue))
            for _ in range(2)
        ]
        for proc in procs:
            proc.start()
        for proc in procs:
            proc.join(timeout=30)
        results = [queue.get(timeout=30) for _ in procs]
        # 恢复已前滚补齐，两个提交均为 200 重放，同体
        self.assertEqual(sorted(r[0] for r in results), [200, 200])
        self.assertEqual(results[0][1:], results[1][1:])
        svc = WalletService(WalletStore(self.tmp))
        events = svc.get_audit_events("w1")["events"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["seq"], 1)

    def test_long_running_process_heals_foreign_crash_before_query(self):
        """常驻进程（启动恢复早已结束）遇到他进程 phase-2 崩溃现场：
        查询在锁内先回滚，绝不读到半完成余额。"""
        svc = WalletService(WalletStore(self.tmp))
        svc.create_wallet("w1", 2)
        svc.create_asset_operation("w1", "op1", "btc", 100)

        # 他进程直接摆出「账本已提交、事件未落」的强杀现场后退出
        ready = self.ctx.Event()
        planter = self.ctx.Process(
            target=_child_plant_scene_and_exit,
            args=(self.tmp, "op1", 2, ready),
        )
        planter.start()
        self.assertTrue(ready.wait(timeout=30))
        planter.join(timeout=30)
        self.assertNotEqual(planter.exitcode, 0)

        # 常驻进程的查询不得看到 100/1 的半完成余额：锁内自愈回滚后
        # 资产恢复为提交前的「不存在」（404）
        with self.assertRaises(ServiceError) as ctx:
            svc.get_asset("w1", "btc")
        self.assertEqual(ctx.exception.status, 404)
        self.assertEqual(
            WalletStore(self.tmp).get_asset_operation("w1", "op1")["state"],
            "pending",
        )
        # 随后首提成功 201，恰一条事件
        code, body = svc.commit_asset_operation("w1", "op1")
        self.assertEqual(code, 201)
        self.assertEqual((body["balance"], body["version"]), (100, 1))
        events = svc.get_audit_events("w1")["events"]
        self.assertEqual(len(events), 1)

    def test_long_running_process_heals_foreign_committed_scene(self):
        """常驻进程遇到他进程 phase-3（事件已落盘）现场：前滚补齐后
        查询与重放均为一致的 committed，余额/审计不被重放改动。"""
        svc = WalletService(WalletStore(self.tmp))
        svc.create_wallet("w1", 2)
        svc.create_asset_operation("w1", "op1", "btc", 100)

        ready = self.ctx.Event()
        planter = self.ctx.Process(
            target=_child_plant_scene_and_exit,
            args=(self.tmp, "op1", 3, ready),
        )
        planter.start()
        self.assertTrue(ready.wait(timeout=30))
        planter.join(timeout=30)
        self.assertNotEqual(planter.exitcode, 0)

        self.assertEqual(
            svc.get_asset("w1", "btc"),
            {"asset_id": "btc", "balance": 100, "version": 1},
        )
        code, body = svc.commit_asset_operation("w1", "op1")
        self.assertEqual(code, 200)
        self.assertEqual((body["balance"], body["version"]), (100, 1))
        events = svc.get_audit_events("w1")["events"]
        self.assertEqual(len(events), 1)
        self.assertEqual(
            WalletStore(self.tmp).list_asset_intents("w1"), []
        )


if __name__ == "__main__":
    unittest.main()
