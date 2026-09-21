"""共享 data-dir 的跨进程并发线性化测试。

test_consistency.py 只用线程（同一进程内的 threading.Lock 即足以串行），
无法证明 fcntl.flock 的跨进程互斥。本模块用 fork 出多个**操作系统进程**，
各自构造独立的 WalletStore/WalletService（进程内锁互不共享），共用同一
data-dir，验证：

- 同一首签 / 同一资产提交跨进程恰一个首次结果（201），其余 200 同体，
  失败不产生额外事件或 seq 缺口；
- 并发建钱包恰一个成功，其余 409；并发策略首设恰一个 created；
- cold 模式首签门控在锁内按已生效策略判定，未知单稳定 409；
- 份额轮换激活与首签/重放交错：激活前已首签请求稳定 200 重放，激活后
  未首签请求旧 share_id 一律 400、仅当前 share_ids 能首签一次；
- 全部并发结束后重启：余额/version/幂等记录/审计 seq 连续一致。
"""

from __future__ import annotations

import multiprocessing
import shutil
import tempfile
import unittest

from threshold_wallet import crypto
from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import WalletStore


# ---- 跨进程 worker（必须定义在模块级以便 fork）-----------------------------


def _share_sigs(store, wallet, share_ids, rid, message):
    out = []
    payload = crypto.build_payload(rid, message)
    for sid in share_ids:
        share = store.get_share(wallet, sid)
        out.append(
            {
                "share_id": sid,
                "signature": crypto.sign_share(
                    bytes.fromhex(share["private_key"]), payload
                ).hex(),
            }
        )
    return out


def _child_sign(data_dir, wallet, rid, message, share_ids, tag, queue):
    try:
        store = WalletStore(data_dir)
        svc = WalletService(store)
        sigs = _share_sigs(store, wallet, share_ids, rid, message)
        status, body = svc.sign(wallet, rid, message, sigs)
        queue.put((tag, status, body.get("signature")))
    except ServiceError as exc:
        queue.put((tag, exc.status, None))
    except BaseException as exc:  # 不应有任何未预期异常
        queue.put((tag, "ERR", repr(exc)))


def _child_sign_dummy(data_dir, wallet, rid, message, share_ids, tag, queue):
    """用占位签名首签：share_id 未知时在校验阶段即 400，无需真实私钥。"""
    try:
        svc = WalletService(WalletStore(data_dir))
        sigs = [
            {"share_id": sid, "signature": "00" * 64} for sid in share_ids
        ]
        status, body = svc.sign(wallet, rid, message, sigs)
        queue.put((tag, status, body.get("signature")))
    except ServiceError as exc:
        queue.put((tag, exc.status, None))
    except BaseException as exc:
        queue.put((tag, "ERR", repr(exc)))


def _child_commit(data_dir, queue):
    try:
        svc = WalletService(WalletStore(data_dir))
        status, body = svc.commit_asset_operation("w1", "op1")
        queue.put((status, body["balance"], body["version"]))
    except ServiceError as exc:
        queue.put((exc.status, None, None))
    except BaseException as exc:
        queue.put(("ERR", repr(exc), None))


def _child_create_wallet(data_dir, queue):
    try:
        WalletService(WalletStore(data_dir)).create_wallet("w1", 2)
        queue.put(201)
    except ServiceError as exc:
        queue.put(exc.status)
    except BaseException as exc:
        queue.put(("ERR", repr(exc)))


def _child_create_wallet_barrier(data_dir, barrier, queue):
    try:
        barrier.wait()
        WalletService(WalletStore(data_dir)).create_wallet("w1", 2)
        queue.put(201)
    except ServiceError as exc:
        queue.put(exc.status)
    except BaseException as exc:
        queue.put(("ERR", repr(exc)))


def _child_put_policy(data_dir, required, timeout, queue):
    try:
        body = WalletService(WalletStore(data_dir)).put_policy(
            "w1", required, timeout
        )
        queue.put(("ok", body["required_approvals"], body["timeout_seconds"]))
    except ServiceError as exc:
        queue.put((exc.status, None, None))
    except BaseException as exc:
        queue.put(("ERR", repr(exc), None))


def _child_put_policy_barrier(data_dir, required, timeout, barrier, queue):
    barrier.wait()
    _child_put_policy(data_dir, required, timeout, queue)


def _child_create_request(data_dir, rid, barrier, queue):
    try:
        svc = WalletService(WalletStore(data_dir))
        barrier.wait()
        status, body = svc.create_sign_request("w1", rid, "m")
        queue.put((status, body["state"]))
    except ServiceError as exc:
        queue.put((exc.status, None))
    except BaseException as exc:
        queue.put(("ERR", repr(exc)))


def _child_activate(data_dir, rotation_id, wait_event, done_event):
    svc = WalletService(WalletStore(data_dir))
    wait_event.wait()
    svc.activate_share_rotation("w1", rotation_id)
    done_event.set()


def _child_approve(data_dir, rid, approver, queue):
    try:
        body = WalletService(WalletStore(data_dir)).approve(
            "w1", rid, approver
        )
        queue.put((approver, 200, body["state"], body["count"]))
    except ServiceError as exc:
        queue.put((approver, exc.status, None, None))
    except BaseException as exc:
        queue.put((approver, "ERR", repr(exc), None))


def _child_toggle_assets_policy(data_dir, rounds, queue):
    """在 max_delta 5<->8 间切换（始终允许 btc/eth）：delta=3 恒合法、
    delta=9 恒超限，制造与创建并发的锁内策略读取交错而结果仍确定。"""
    svc = WalletService(WalletStore(data_dir))
    for i in range(rounds):
        try:
            svc.put_transaction_policy(
                "w1", "hot", 5 if i % 2 else 8, ["btc", "eth"]
            )
        except ServiceError as exc:
            queue.put(("policy-ERR", exc.status, None))
            return
    queue.put(("policy-done", None, None))


def _child_create_asset(data_dir, op_id, asset_id, delta, queue):
    try:
        status, body = WalletService(
            WalletStore(data_dir)
        ).create_asset_operation("w1", op_id, asset_id, delta)
        queue.put((status, op_id, body.get("state")))
    except ServiceError as exc:
        queue.put((exc.status, op_id, None))
    except BaseException as exc:
        queue.put(("ERR", op_id, repr(exc)))


def _child_toggle_tx_policy(data_dir, rounds, barrier, queue):
    """反复 hot<->cold 切换交易策略（无审批策略）。"""
    svc = WalletService(WalletStore(data_dir))
    barrier.wait()
    for i in range(rounds):
        try:
            svc.put_transaction_policy(
                "w1", "cold" if i % 2 else "hot", 100, ["btc"]
            )
        except ServiceError as exc:
            queue.put(("policy", exc.status))
            return
    queue.put(("policy-done", None))


def _child_sign_retry(data_dir, rounds, barrier, queue):
    """在策略反复切换期间反复首签同一请求：cold 且无单 -> 409；
    hot（无审批策略）-> 首签 201；其后线性化的尝试 -> 200 重放。"""
    store = WalletStore(data_dir)
    svc = WalletService(store)
    barrier.wait()
    for _ in range(rounds):
        try:
            sigs = _share_sigs(
                store, "w1", ("share-1", "share-2"), "r1", "m"
            )
            status, _ = svc.sign("w1", "r1", "m", sigs)
            queue.put(("sign", status))
        except ServiceError as exc:
            queue.put(("sign", exc.status))
        except BaseException as exc:
            queue.put(("sign-ERR", repr(exc)))


# ---- 测试用例 ---------------------------------------------------------------


class CrossProcessLinearizationTest(unittest.TestCase):
    N = 8

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.ctx = multiprocessing.get_context("fork")

    def _fresh(self):
        """模拟另一进程/重启：全新 store + service（无内存锁状态）。"""
        return WalletService(WalletStore(self.tmp))

    def _drain(self, queue, count):
        return [queue.get(timeout=30) for _ in range(count)]

    def test_concurrent_first_sign_single_result(self):
        svc = self._fresh()
        svc.create_wallet("w1", 2)
        queue = self.ctx.Queue()
        procs = [
            self.ctx.Process(
                target=_child_sign,
                args=(self.tmp, "w1", "r1", "pay-100",
                      ("share-1", "share-2"), "first", queue),
            )
            for _ in range(self.N)
        ]
        for p in procs:
            p.start()
        results = self._drain(queue, self.N)
        for p in procs:
            p.join(timeout=30)
            self.assertEqual(p.exitcode, 0)

        statuses = [r[1] for r in results]
        self.assertEqual(statuses.count(201), 1, results)
        self.assertEqual(statuses.count(200), self.N - 1, results)
        signatures = {r[2] for r in results}
        self.assertEqual(len(signatures), 1, results)

        # 重启后：重放 200 同体，仅一条 request_signed，无 seq 缺口
        svc2 = self._fresh()
        store = WalletStore(self.tmp)
        sigs = _share_sigs(store, "w1", ("share-1", "share-2"), "r1", "pay-100")
        code, body = svc2.sign("w1", "r1", "pay-100", sigs)
        self.assertEqual(code, 200)
        self.assertEqual(body["signature"], next(iter(signatures)))
        events = svc2.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in events], [1])
        self.assertEqual(events[0]["type"], "request_signed")

    def test_concurrent_approved_sign_single_result(self):
        # hot + 审批策略：approved 单的首签跨进程仍只一个 201
        svc = self._fresh()
        svc.create_wallet("w1", 2)
        svc.put_policy("w1", 1, 3600)
        svc.create_sign_request("w1", "r1", "m")
        svc.approve("w1", "r1", "alice")
        queue = self.ctx.Queue()
        procs = [
            self.ctx.Process(
                target=_child_sign,
                args=(self.tmp, "w1", "r1", "m",
                      ("share-1", "share-2"), "approved", queue),
            )
            for _ in range(self.N)
        ]
        for p in procs:
            p.start()
        results = self._drain(queue, self.N)
        for p in procs:
            p.join(timeout=30)
            self.assertEqual(p.exitcode, 0)

        statuses = [r[1] for r in results]
        self.assertEqual(statuses.count(201), 1, results)
        self.assertEqual(statuses.count(200), self.N - 1, results)
        svc2 = self._fresh()
        self.assertEqual(
            WalletStore(self.tmp).get_request("w1", "r1")["state"], "signed"
        )
        events = svc2.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["seq"] for e in events], list(range(1, len(events) + 1))
        )
        self.assertEqual(
            [e["type"] for e in events],
            [
                "policy_updated",
                "request_created",
                "request_approved",
                "request_signed",
            ],
        )

    def test_concurrent_cold_sign_unknown_request_stable_409(self):
        # cold 模式：无对应审批单的首签跨进程稳定 409，不产生任何事件/签名
        svc = self._fresh()
        svc.create_wallet("w1", 2)
        svc.put_policy("w1", 1, 3600)
        svc.put_transaction_policy("w1", "cold", 100, ["btc"])
        queue = self.ctx.Queue()
        procs = [
            self.ctx.Process(
                target=_child_sign,
                args=(self.tmp, "w1", "ghost", "m",
                      ("share-1", "share-2"), "cold", queue),
            )
            for _ in range(self.N)
        ]
        for p in procs:
            p.start()
        results = self._drain(queue, self.N)
        for p in procs:
            p.join(timeout=30)
            self.assertEqual(p.exitcode, 0)
        self.assertTrue(all(r[1] == 409 for r in results), results)
        self.assertIsNone(
            WalletStore(self.tmp).get_signature("w1", "ghost")
        )
        events = self._fresh().get_audit_events("w1")["events"]
        # 只有策略相关事件，seq 连续，没有任何 ghost 的 signed 事件
        self.assertEqual(
            [e["seq"] for e in events], list(range(1, len(events) + 1))
        )
        self.assertFalse(
            any(e.get("request_id") == "ghost" for e in events)
        )

    def test_concurrent_asset_commit_single_result(self):
        svc = self._fresh()
        svc.create_wallet("w1", 2)
        svc.create_asset_operation("w1", "op1", "btc", 100)
        queue = self.ctx.Queue()
        procs = [
            self.ctx.Process(target=_child_commit, args=(self.tmp, queue))
            for _ in range(self.N)
        ]
        for p in procs:
            p.start()
        results = self._drain(queue, self.N)
        for p in procs:
            p.join(timeout=30)
            self.assertEqual(p.exitcode, 0)

        statuses = [r[0] for r in results]
        self.assertEqual(statuses.count(201), 1, results)
        self.assertEqual(statuses.count(200), self.N - 1, results)
        # 所有 200 重放与 201 同体：balance=100, version=1
        self.assertTrue(all(r[1:] == (100, 1) for r in results), results)

        svc2 = self._fresh()
        self.assertEqual(
            WalletStore(self.tmp).get_asset("w1", "btc"),
            {"balance": 100, "version": 1},
        )
        events = svc2.get_audit_events("w1")["events"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["seq"], 1)
        self.assertEqual(events[0]["type"], "asset_operation_committed")
        self.assertEqual(
            WalletStore(self.tmp).list_asset_intents("w1"), []
        )
        # 再提交仍幂等 200，不新增事件
        self.assertEqual(svc2.commit_asset_operation("w1", "op1")[0], 200)
        self.assertEqual(
            len(svc2.get_audit_events("w1")["events"]), 1
        )

    def test_concurrent_create_wallet_single_success(self):
        queue = self.ctx.Queue()
        barrier = self.ctx.Barrier(self.N)
        procs = [
            self.ctx.Process(
                target=_child_create_wallet_barrier,
                args=(self.tmp, barrier, queue),
            )
            for _ in range(self.N)
        ]
        for p in procs:
            p.start()
        results = self._drain(queue, self.N)
        for p in procs:
            p.join(timeout=30)
            self.assertEqual(p.exitcode, 0)
        self.assertEqual(results.count(201), 1, results)
        self.assertEqual(results.count(409), self.N - 1, results)
        # 钱包元数据与两个份额齐备且一致
        store = WalletStore(self.tmp)
        self.assertIsNotNone(store.get_wallet("w1"))
        self.assertIsNotNone(store.get_share("w1", "share-1"))
        self.assertIsNotNone(store.get_share("w1", "share-2"))

    def test_concurrent_first_policy_single_created(self):
        self._fresh().create_wallet("w1", 2)
        queue = self.ctx.Queue()
        barrier = self.ctx.Barrier(self.N)
        procs = [
            self.ctx.Process(
                target=_child_put_policy_barrier,
                args=(
                    self.tmp,
                    1 if i % 2 else 2,
                    100 + i,
                    barrier,
                    queue,
                ),
            )
            for i in range(self.N)
        ]
        for p in procs:
            p.start()
        results = self._drain(queue, self.N)
        for p in procs:
            p.join(timeout=30)
            self.assertEqual(p.exitcode, 0)
        self.assertTrue(all(r[0] == "ok" for r in results), results)

        events = self._fresh().get_audit_events("w1")["events"]
        self.assertEqual(len(events), self.N)
        self.assertEqual(
            [e["seq"] for e in events], list(range(1, self.N + 1))
        )
        operations = [
            e["details"]["operation"] for e in events
            if e["type"] == "policy_updated"
        ]
        self.assertEqual(operations.count("created"), 1, operations)
        self.assertEqual(operations.count("updated"), self.N - 1, operations)
        # created 必为线性化顺序中的第一条
        self.assertEqual(operations[0], "created")

    def test_concurrent_create_request_single_201(self):
        svc = self._fresh()
        svc.create_wallet("w1", 2)
        svc.put_policy("w1", 1, 3600)
        queue = self.ctx.Queue()
        barrier = self.ctx.Barrier(self.N)
        procs = [
            self.ctx.Process(
                target=_child_create_request,
                args=(self.tmp, "rc", barrier, queue),
            )
            for _ in range(self.N)
        ]
        for p in procs:
            p.start()
        results = self._drain(queue, self.N)
        for p in procs:
            p.join(timeout=30)
            self.assertEqual(p.exitcode, 0)
        statuses = [r[0] for r in results]
        self.assertEqual(statuses.count(201), 1, results)
        self.assertEqual(statuses.count(200), self.N - 1, results)
        self.assertTrue(all(s in (200, 201) for s in statuses), results)
        events = self._fresh().get_audit_events("w1")["events"]
        # 仅 rc 首次创建一条 request_created 事件（策略事件另计）
        self.assertEqual(
            [e["request_id"] for e in events if e["type"] == "request_created"],
            ["rc"],
        )
        self.assertEqual(
            [e["seq"] for e in events], list(range(1, len(events) + 1))
        )

    def test_rotation_interleaved_with_sign(self):
        svc = self._fresh()
        svc.create_wallet("w1", 2)
        # 激活前先对 pre 完成首签（旧 share_ids）
        pre_sigs = _share_sigs(
            WalletStore(self.tmp), "w1", ("share-1", "share-2"), "pre", "m"
        )
        self.assertEqual(svc.sign("w1", "pre", "m", pre_sigs)[0], 201)
        # 准备轮换（不激活）
        code, rot = svc.create_share_rotation("w1", "rot-1")
        self.assertEqual(code, 201)
        new_ids = tuple(rot["share_ids"])

        wait_activate = self.ctx.Event()
        activated = self.ctx.Event()
        activator = self.ctx.Process(
            target=_child_activate,
            args=(self.tmp, "rot-1", wait_activate, activated),
        )
        activator.start()
        wait_activate.set()
        self.assertTrue(activated.wait(timeout=30))
        activator.join(timeout=30)
        self.assertEqual(activator.exitcode, 0)

        # 激活后：钱包在用份额已是新 share_ids
        meta = WalletStore(self.tmp).get_wallet("w1")
        self.assertEqual(
            [s["share_id"] for s in meta["shares"]], list(new_ids)
        )

        queue = self.ctx.Queue()
        # 1) pre 已首签：重放稳定 200，且返回激活前的同一签名
        replay_old = self.ctx.Process(
            target=_child_sign_dummy,
            args=(self.tmp, "w1", "pre", "m",
                  ("share-1", "share-2"), "pre", queue),
        )
        # 2) 未首签 post 用旧 share_id：首签前 400，首签后 200 重放（见下）
        old_attempts = [
            self.ctx.Process(
                target=_child_sign_dummy,
                args=(self.tmp, "w1", "post", "m",
                      ("share-1", "share-2"), "post-old", queue),
            )
            for _ in range(4)
        ]
        # 3) 未首签 post 用新 share_ids：恰一个 201
        new_attempts = [
            self.ctx.Process(
                target=_child_sign,
                args=(self.tmp, "w1", "post", "m", new_ids, "post-new", queue),
            )
            for _ in range(4)
        ]
        all_procs = [replay_old] + old_attempts + new_attempts
        for p in all_procs:
            p.start()
        results = self._drain(queue, len(all_procs))
        for p in all_procs:
            p.join(timeout=30)
            self.assertEqual(p.exitcode, 0)

        # Queue 顺序不保证，按 tag 分类断言
        pre_results = [r for r in results if r[0] == "pre"]
        old_results = [r for r in results if r[0] == "post-old"]
        new_results = [r for r in results if r[0] == "post-new"]
        self.assertEqual(len(pre_results), 1)
        self.assertEqual(len(old_results), 4)
        self.assertEqual(len(new_results), 4)
        self.assertEqual(pre_results[0][1], 200)
        self.assertEqual(
            pre_results[0][2],
            WalletStore(self.tmp).get_signature("w1", "pre")["signature"],
        )
        # 旧 share_id 提交者：首签提交前线性化 -> 400；首签提交后线性化
        # -> 200 幂等重放（重放不再校验份额）。两种都合法，但它们绝不
        # 可能产生 201——用旧份额永远无法完成首签。
        old_status = [r[1] for r in old_results]
        self.assertTrue(
            all(s in (400, 200) for s in old_status), old_results
        )
        self.assertNotIn(201, old_status)
        new_status = [r[1] for r in new_results]
        self.assertEqual(new_status.count(201), 1, new_results)
        self.assertEqual(new_status.count(200), 3, new_results)
        # 全钱包恰一个首签 201（来自当前 share_ids），其余全是重放 200/400
        self.assertEqual(old_status.count(201) + new_status.count(201), 1)
        # 所有重放/首签返回的签名都是同一个（激活后的新聚合签名）
        replay_sigs = {
            r[2]
            for r in (old_results + new_results)
            if r[1] in (200, 201)
        }
        self.assertEqual(len(replay_sigs), 1)

        # 重启后：轮换 active 保持，pre/post 幂等记录在，审计 seq 连续
        svc2 = self._fresh()
        self.assertEqual(
            svc2.get_share_rotation("w1", "rot-1")["state"], "active"
        )
        self.assertEqual(
            svc2.get_wallet("w1")["public_key"],
            WalletStore(self.tmp).get_wallet("w1")["public_key"],
        )
        events = svc2.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["seq"] for e in events], list(range(1, len(events) + 1))
        )
        self.assertEqual(
            [e["type"] for e in events],
            [
                "request_signed",       # pre 首签（无策略）
                "share_rotation_prepared",
                "share_rotation_activated",
                "request_signed",       # post 首签
            ],
        )
        # 暂存私钥已清理，不留副本
        import os

        staging = os.path.join(
            self.tmp, "rotation-staging", "w1", "rot-1"
        )
        self.assertFalse(os.path.exists(staging))

    def test_policy_toggle_interleaved_with_first_sign(self):
        """无审批策略下，一个进程反复 hot<->cold 切换交易策略，多个进程
        并发反复首签同一请求：门控严格按各请求线性化时刻已生效的策略
        判定（cold 无单 409，hot 可首签），恰一个 201，其余 200/409；
        绝不出现 400/5xx、矛盾状态或 seq 缺口；重启后策略与幂等一致。"""
        svc = self._fresh()
        svc.create_wallet("w1", 2)
        n_signers, rounds = 4, 40
        queue = self.ctx.Queue()
        barrier = self.ctx.Barrier(1 + n_signers)
        procs = [
            self.ctx.Process(
                target=_child_toggle_tx_policy,
                args=(self.tmp, 60, barrier, queue),
            )
        ]
        procs += [
            self.ctx.Process(
                target=_child_sign_retry,
                args=(self.tmp, rounds, barrier, queue),
            )
            for _ in range(n_signers)
        ]
        for p in procs:
            p.start()
        # 1 个 policy-done + n_signers*rounds 个 sign 结果
        results = self._drain(queue, 1 + n_signers * rounds)
        for p in procs:
            p.join(timeout=30)
            self.assertEqual(p.exitcode, 0)

        tags = [r[0] for r in results]
        self.assertEqual(tags.count("policy-done"), 1, results)
        self.assertNotIn("policy", tags)
        self.assertFalse(any(t.endswith("-ERR") for t in tags), results)
        sign_status = [r[1] for r in results if r[0] == "sign"]
        # 不允许任何 400（旧/坏公钥、份额误判）、5xx 或未预期错误
        self.assertTrue(
            all(s in (200, 201, 409) for s in sign_status), results
        )
        # 恰一个首签 201；它必然线性化在某个 hot 窗口内（cold 必 409）
        self.assertEqual(sign_status.count(201), 1, results)

        # 最终策略文件形状完好（hot 或 cold），GET 200 同体恰三项
        final_policy = svc.get_transaction_policy("w1")
        self.assertIn(final_policy["mode"], ("hot", "cold"))
        self.assertEqual(set(final_policy), {"mode", "max_delta", "allowed_assets"})

        # 审计 seq 连续；恰一条 request_signed；60 条 transaction_policy_updated
        events = self._fresh().get_audit_events("w1")["events"]
        self.assertEqual(
            [e["seq"] for e in events], list(range(1, len(events) + 1))
        )
        self.assertEqual(
            [e["type"] for e in events].count("request_signed"), 1
        )
        self.assertEqual(
            [e["type"] for e in events].count("transaction_policy_updated"),
            60,
        )
        # 重启后重放稳定 200，策略持久
        svc2 = self._fresh()
        store = WalletStore(self.tmp)
        sigs = _share_sigs(store, "w1", ("share-1", "share-2"), "r1", "m")
        self.assertEqual(svc2.sign("w1", "r1", "m", sigs)[0], 200)
        self.assertIn(svc2.get_transaction_policy("w1")["mode"], ("hot", "cold"))

    def test_concurrent_two_approvals_reaches_threshold_once(self):
        # required_approvals=2：两个不同审批人跨进程并发批准 -> 都 200，
        # 最终 approved、count=2、恰两条 request_approved（每审批人一条），
        # 审计 seq 连续。
        svc = self._fresh()
        svc.create_wallet("w1", 2)
        svc.put_policy("w1", 2, 3600)
        svc.create_sign_request("w1", "r1", "m")
        queue = self.ctx.Queue()
        procs = [
            self.ctx.Process(
                target=_child_approve, args=(self.tmp, "r1", who, queue)
            )
            for who in ("alice", "bob")
        ]
        for p in procs:
            p.start()
        results = self._drain(queue, 2)
        for p in procs:
            p.join(timeout=30)
            self.assertEqual(p.exitcode, 0)
        self.assertTrue(all(r[1] == 200 for r in results), results)
        approvers = {r[0] for r in results}
        self.assertEqual(approvers, {"alice", "bob"})
        req = WalletStore(self.tmp).get_request("w1", "r1")
        self.assertEqual(req["state"], "approved")
        self.assertEqual(len(req["approvers"]), 2)
        events = self._fresh().get_audit_events("w1")["events"]
        self.assertEqual(
            [e["seq"] for e in events], list(range(1, len(events) + 1))
        )
        approved = [e for e in events if e["type"] == "request_approved"]
        self.assertEqual(len(approved), 2)
        self.assertEqual(
            {e["actor_id"] for e in approved}, {"alice", "bob"}
        )
        # 阈值后再批准（终态）稳定 409，不记事件
        with self.assertRaises(ServiceError) as ctx:
            svc.approve("w1", "r1", "carol")
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(
            len(self._fresh().get_audit_events("w1")["events"]), len(events)
        )

    def test_concurrent_duplicate_approver_counts_once(self):
        # 同一审批人跨进程重复批准不计数：req=2 时仍 pending、count=1、
        # 只记一条 request_approved。
        svc = self._fresh()
        svc.create_wallet("w1", 2)
        svc.put_policy("w1", 2, 3600)
        svc.create_sign_request("w1", "r1", "m")
        queue = self.ctx.Queue()
        procs = [
            self.ctx.Process(
                target=_child_approve, args=(self.tmp, "r1", "alice", queue)
            )
            for _ in range(4)
        ]
        for p in procs:
            p.start()
        results = self._drain(queue, 4)
        for p in procs:
            p.join(timeout=30)
            self.assertEqual(p.exitcode, 0)
        self.assertTrue(all(r[1] == 200 for r in results), results)
        req = WalletStore(self.tmp).get_request("w1", "r1")
        self.assertEqual(req["state"], "pending")
        self.assertEqual(len(req["approvers"]), 1)
        events = self._fresh().get_audit_events("w1")["events"]
        self.assertEqual(
            [e["type"] for e in events].count("request_approved"), 1
        )
        self.assertEqual(
            [e["seq"] for e in events], list(range(1, len(events) + 1))
        )

    def test_asset_create_interleaved_with_policy_toggle(self):
        # 固定白名单/上限的确定性门控 + 与策略并发更新交错：
        # delta 超限一律 409（不写账本/version/状态），白名单内 distinct
        # 操作一律 201 pending；并发切换 allowed_assets/max_delta 期间不
        # 允许 5xx 或半完成账本，全部 pending、资产余额为空、version=0。
        svc = self._fresh()
        svc.create_wallet("w1", 2)
        svc.put_transaction_policy("w1", "hot", 5, ["btc", "eth"])

        queue = self.ctx.Queue()
        # 一个进程反复在 max_delta 5<->8 间切换，制造与创建并发的锁内
        # 策略读取交错（creators 与其并发启动，天然交叠在 60 次切换窗口内）
        toggler = self.ctx.Process(
            target=_child_toggle_assets_policy,
            args=(self.tmp, 60, queue),
        )
        # 3 个白名单内合法创建（delta=3），3 个超限/越界创建（delta=9）
        creators = []
        for i in range(3):
            creators.append(
                self.ctx.Process(
                    target=_child_create_asset,
                    args=(self.tmp, f"ok-{i}", "btc", 3, queue),
                )
            )
        for i in range(3):
            creators.append(
                self.ctx.Process(
                    target=_child_create_asset,
                    args=(self.tmp, f"big-{i}", "btc", 9, queue),
                )
            )
        all_procs = [toggler] + creators
        for p in all_procs:
            p.start()
        results = self._drain(queue, 1 + 6)
        for p in all_procs:
            p.join(timeout=30)
            self.assertEqual(p.exitcode, 0)

        created = [r for r in results if r[1] and str(r[1]).startswith("ok-")]
        rejected = [r for r in results if r[1] and str(r[1]).startswith("big-")]
        self.assertEqual(len(created), 3)
        self.assertEqual(len(rejected), 3)
        # 合法的：201 pending（首次，distinct）；超限的：409
        self.assertTrue(all(r[0] == 201 and r[2] == "pending" for r in created), created)
        self.assertTrue(all(r[0] == 409 for r in rejected), rejected)
        # 账本：3 条 pending，资产余额未改（无提交）、version 全 0
        store = WalletStore(self.tmp)
        for i in range(3):
            rec = store.get_asset_operation("w1", f"ok-{i}")
            self.assertEqual(rec["state"], "pending")
            self.assertEqual(rec["balance"], 0)
            self.assertEqual(rec["version"], 0)
        for i in range(3):
            self.assertIsNone(store.get_asset_operation("w1", f"big-{i}"))
        # 审计：只有 transaction_policy_updated（资产创建不记事件），seq 连续
        events = self._fresh().get_audit_events("w1")["events"]
        self.assertTrue(
            all(e["type"] == "transaction_policy_updated" for e in events)
        )
        # 初始首设 1 条 + 60 次切换
        self.assertEqual(len(events), 61)
        self.assertEqual(
            [e["seq"] for e in events], list(range(1, 62))
        )


if __name__ == "__main__":
    unittest.main()
