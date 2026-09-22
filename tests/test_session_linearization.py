"""可恢复签名会话的跨进程线性化测试。

fork 多个独立 WalletService 进程共用同一 data-dir，验证：

- 齐份后首次聚合跨进程恰一个 201，其余重放 200 同体，只有一条
  action=signed 事件，审计 seq 连续无缺口；
- 到点的 ready 会话跨进程只有一个首次状态推进（一条 expired 事件），
  其余投递 409；
- 轮换激活与在途会话交错跨进程：迁移只发生一次，旧份额投递稳定 400，
  新份额恰两份首收 201 并完成唯一 signed。
"""

from __future__ import annotations

import multiprocessing
import shutil
import tempfile
import time
import unittest

from threshold_wallet import crypto
from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import WalletStore


def _share_sig(store, wallet_id, share_id, session_id, message):
    share = store.get_share(wallet_id, share_id)
    payload = crypto.build_payload(session_id, message)
    return crypto.sign_share(
        bytes.fromhex(share["private_key"]), payload
    ).hex()


def _child_deliver(data_dir, wallet_id, session_id, share_id, queue,
                   message="m", signature=None):
    try:
        store = WalletStore(data_dir)
        svc = WalletService(store)
        if signature is None:
            signature = _share_sig(
                store, wallet_id, share_id, session_id, message
            )
        status, body = svc.submit_sign_session_share(
            wallet_id, session_id, share_id, signature
        )
        queue.put((share_id, status, body.get("aggregate_signature")))
    except ServiceError as exc:
        queue.put((share_id, exc.status, None))
    except BaseException as exc:  # 不应有任何未预期异常
        queue.put((share_id, "ERR", repr(exc)))


class CrossProcessSessionLinearizationTest(unittest.TestCase):
    N = 8

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.ctx = multiprocessing.get_context("fork")

    def _fresh(self):
        return WalletService(WalletStore(self.tmp))

    def _drain(self, queue, count):
        return [queue.get(timeout=30) for _ in range(count)]

    def test_concurrent_completion_single_signed(self):
        svc = self._fresh()
        svc.create_wallet("w1", 2)
        svc.create_sign_session("w1", "cc1", "m", 600)
        store = WalletStore(self.tmp)
        # share-1 先在本进程收妥，再让 N 个进程抢投 share-2
        svc.submit_sign_session_share(
            "w1", "cc1", "share-1",
            _share_sig(store, "w1", "share-1", "cc1", "m"),
        )
        queue = self.ctx.Queue()
        procs = [
            self.ctx.Process(
                target=_child_deliver,
                args=(self.tmp, "w1", "cc1", "share-2", queue),
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
        aggregates = {r[2] for r in results if r[2]}
        self.assertEqual(len(aggregates), 1, results)

        svc2 = self._fresh()
        events = [
            e for e in svc2.get_audit_events("w1")["events"]
            if e["type"] == "session_event"
        ]
        self.assertEqual(
            [e["seq"] for e in events], [1, 2, 3, 4]
        )
        self.assertEqual(
            [e["details"]["action"] for e in events],
            ["created", "share_received", "share_received", "signed"],
        )
        self.assertEqual(
            svc2.get_sign_session("w1", "cc1")["state"], "signed"
        )

    def test_concurrent_ready_expiry_single_transition(self):
        svc = self._fresh()
        svc.create_wallet("w1", 2)
        # hot 门控无审批单 -> 齐份后停在 ready
        svc.put_policy("w1", 1, 3600)
        svc.create_sign_session("w1", "ex1", "msg", 1)
        store = WalletStore(self.tmp)
        for sid in ("share-1", "share-2"):
            svc.submit_sign_session_share(
                "w1", "ex1", sid,
                _share_sig(store, "w1", sid, "ex1", "msg"),
            )
        self.assertEqual(svc.get_sign_session("w1", "ex1")["state"], "ready")
        time.sleep(1.1)
        queue = self.ctx.Queue()
        procs = [
            self.ctx.Process(
                target=_child_deliver,
                args=(self.tmp, "w1", "ex1", "share-2", queue, "msg"),
            )
            for _ in range(self.N)
        ]
        for p in procs:
            p.start()
        results = self._drain(queue, self.N)
        for p in procs:
            p.join(timeout=30)
            self.assertEqual(p.exitcode, 0)
        # 到点：全部 409，没有任何聚合
        self.assertTrue(all(r[1] == 409 for r in results), results)

        svc2 = self._fresh()
        self.assertEqual(
            svc2.get_sign_session("w1", "ex1")["state"], "expired"
        )
        actions = [
            e["details"]["action"]
            for e in svc2.get_audit_events("w1")["events"]
            if e["type"] == "session_event"
        ]
        self.assertEqual(actions.count("expired"), 1, actions)
        self.assertNotIn("signed", actions)
        self.assertEqual(len(actions), 4)  # created + 2 shares + expired

    def test_activation_interleaved_with_inflight_session(self):
        svc = self._fresh()
        svc.create_wallet("w1", 2)
        svc.create_sign_session("w1", "if1", "m", 600)
        store = WalletStore(self.tmp)
        svc.submit_sign_session_share(
            "w1", "if1", "share-1",
            _share_sig(store, "w1", "share-1", "if1", "m"),
        )
        _, rot = svc.create_share_rotation("w1", "rot-1")
        # 旧 share-2 文件激活后即删除：激活前先算好客户端已持有的旧签名
        stale_old_share2 = _share_sig(store, "w1", "share-2", "if1", "m")
        svc.activate_share_rotation("w1", "rot-1")
        new_ids = list(rot["share_ids"])

        # 多进程并发：旧 share-2 投递（稳定 400）+ 新份额投递
        queue = self.ctx.Queue()
        targets = [
            ("share-2", stale_old_share2),
        ] * 4 + [
            (new_ids[0], None),
            (new_ids[1], None),
        ]
        procs = [
            self.ctx.Process(
                target=_child_deliver,
                args=(self.tmp, "w1", "if1", sid, queue, "m", sig),
            )
            for sid, sig in targets
        ]
        for p in procs:
            p.start()
        results = self._drain(queue, len(targets))
        for p in procs:
            p.join(timeout=30)
            self.assertEqual(p.exitcode, 0)

        by_share = {}
        for sid, status, _agg in results:
            by_share.setdefault(sid, []).append(status)
        self.assertEqual(set(by_share.get("share-2", [])), {400}, results)
        self.assertEqual(by_share[new_ids[0]], [201], results)
        self.assertEqual(by_share[new_ids[1]], [201], results)

        svc2 = self._fresh()
        view = svc2.get_sign_session("w1", "if1")
        self.assertEqual(view["state"], "signed")
        self.assertEqual(view["received_shares"], new_ids)
        actions = [
            e["details"]["action"]
            for e in svc2.get_audit_events("w1")["events"]
            if e["type"] == "session_event"
        ]
        self.assertEqual(actions.count("signed"), 1, actions)


if __name__ == "__main__":
    unittest.main()
