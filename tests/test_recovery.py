"""一致性与重启恢复回归测试：

- POST sign-requests 重放原样返回磁盘状态，不改状态、不记事件；
- sign 提交序列（签名记录 / 审批单 signed / S 事件）原子：
  任一写入失败即回滚，不留半完成数据；
- 同一 data-dir 重启后审批单、过期结果、签名幂等记录、审计 seq 连续；
- 并发重放只产生一个首次结果。
"""

from __future__ import annotations

import threading
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from tests.helpers import make_harness
from threshold_wallet.service import ServiceError


def _past_iso() -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat().replace(
        "+00:00", "Z"
    )


class ReplayReturnsDiskStateTest(unittest.TestCase):
    """同 id 同文重放：原样返回磁盘中的状态，不改状态、不新增事件。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.h = make_harness(self.tmp)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 2, 3600)

    def _force_timeout(self, rid: str) -> None:
        record = dict(self.h.store.get_request("w1", rid))
        record["t1"] = _past_iso()
        self.h.store.update_request("w1", rid, record)

    def _events(self):
        return self.svc.get_audit_events("w1")["events"]

    def test_replay_of_timed_out_pending_returns_pending_as_on_disk(self):
        status, _ = self.svc.create_sign_request("w1", "r1", "pay-100")
        self.assertEqual(status, 201)
        self._force_timeout("r1")
        n_events = len(self._events())

        # 重放不是懒过期触发点：磁盘仍是 pending，响应也必须原样是 pending
        status, body = self.svc.create_sign_request("w1", "r1", "pay-100")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "pending")
        self.assertEqual(
            self.h.store.get_request("w1", "r1")["state"], "pending"
        )
        # 不得新增任何事件（尤其不能记 request_expired）
        self.assertEqual(len(self._events()), n_events)

        # GET 才是触发点：此后磁盘与响应都为 expired
        self.assertEqual(
            self.svc.get_sign_request("w1", "r1")["state"], "expired"
        )
        # 落盘为 expired 后，重放原样返回 expired
        status, body = self.svc.create_sign_request("w1", "r1", "pay-100")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "expired")
        # 全程 request_expired 只记一次
        expired = [e for e in self._events() if e["type"] == "request_expired"]
        self.assertEqual(len(expired), 1)

    def test_replay_returns_terminal_states_as_stored(self):
        self.svc.create_sign_request("w1", "ra", "m1")
        self.svc.approve("w1", "ra", "alice")
        self.svc.approve("w1", "ra", "bob")
        status, body = self.svc.create_sign_request("w1", "ra", "m1")
        self.assertEqual((status, body["state"]), (200, "approved"))

        self.svc.create_sign_request("w1", "rr", "m2")
        self.svc.reject("w1", "rr", "alice")
        status, body = self.svc.create_sign_request("w1", "rr", "m2")
        self.assertEqual((status, body["state"]), (200, "rejected"))


class SignCommitAtomicityTest(unittest.TestCase):
    """sign 首签：签名记录、审批单 signed、S 事件一致提交或整体回滚。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.h = make_harness(self.tmp)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 3600)
        self.svc.create_sign_request("w1", "r1", "pay-100")
        self.svc.approve("w1", "r1", "alice")
        self.signatures = self.h.two_signatures("w1", "r1", "pay-100")

    def _signed_events(self):
        return [
            e
            for e in self.svc.get_audit_events("w1")["events"]
            if e["type"] == "request_signed"
        ]

    def test_approval_update_failure_rolls_back_signature(self):
        # save_signature 成功后 update_request 写盘失败：
        # 签名必须被删除、审批单保持 approved、无 S 事件
        with mock.patch.object(
            self.h.store, "update_request", side_effect=OSError("disk full")
        ):
            with self.assertRaises(OSError):
                self.svc.sign("w1", "r1", "pay-100", self.signatures)
        self.assertIsNone(self.h.store.get_signature("w1", "r1"))
        self.assertEqual(
            self.h.store.get_request("w1", "r1")["state"], "approved"
        )
        self.assertEqual(self._signed_events(), [])
        # 故障恢复后可重试成功：201 且三方一致
        status, body = self.svc.sign("w1", "r1", "pay-100", self.signatures)
        self.assertEqual(status, 201)
        self.assertEqual(
            self.h.store.get_signature("w1", "r1")["signature"],
            body["signature"],
        )
        self.assertEqual(
            self.h.store.get_request("w1", "r1")["state"], "signed"
        )
        self.assertEqual(len(self._signed_events()), 1)

    def test_signature_save_failure_leaves_no_trace(self):
        with mock.patch.object(
            self.h.store, "save_signature", side_effect=OSError("disk full")
        ):
            with self.assertRaises(OSError):
                self.svc.sign("w1", "r1", "pay-100", self.signatures)
        self.assertIsNone(self.h.store.get_signature("w1", "r1"))
        self.assertEqual(
            self.h.store.get_request("w1", "r1")["state"], "approved"
        )
        self.assertEqual(self._signed_events(), [])

    def test_event_failure_rolls_back_signature_and_approval(self):
        with mock.patch.object(
            self.svc._audit, "append_event", side_effect=OSError("disk full")
        ):
            with self.assertRaises(OSError):
                self.svc.sign("w1", "r1", "pay-100", self.signatures)
        self.assertIsNone(self.h.store.get_signature("w1", "r1"))
        self.assertEqual(
            self.h.store.get_request("w1", "r1")["state"], "approved"
        )
        self.assertEqual(self._signed_events(), [])


class RestartRecoveryTest(unittest.TestCase):
    """同一 data-dir 重启：审批单、过期结果、签名幂等记录、审计 seq 连续。"""

    def test_state_and_audit_survive_restart(self):
        tmp = tempfile.mkdtemp()
        h1 = make_harness(tmp)
        svc1 = h1.service
        svc1.create_wallet("w1", 2)
        svc1.put_policy("w1", 1, 3600)

        # r1：完整走到 signed
        svc1.create_sign_request("w1", "r1", "pay-100")
        svc1.approve("w1", "r1", "alice")
        status, signed = svc1.sign(
            "w1", "r1", "pay-100", h1.two_signatures("w1", "r1", "pay-100")
        )
        self.assertEqual(status, 201)

        # r2：超时后由 GET 懒过期并持久化
        svc1.create_sign_request("w1", "r2", "pay-200")
        record = dict(h1.store.get_request("w1", "r2"))
        record["t1"] = _past_iso()
        h1.store.update_request("w1", "r2", record)
        self.assertEqual(svc1.get_sign_request("w1", "r2")["state"], "expired")

        # r3：保持 pending
        svc1.create_sign_request("w1", "r3", "pay-300")

        events_before = svc1.get_audit_events("w1")["events"]
        max_seq = events_before[-1]["seq"]

        # —— 模拟重启：同一 data-dir 上全新的 store/service ——
        h2 = make_harness(tmp)
        svc2 = h2.service

        # 审批单各态连续可读
        self.assertEqual(svc2.get_sign_request("w1", "r1")["state"], "signed")
        self.assertEqual(svc2.get_sign_request("w1", "r2")["state"], "expired")
        self.assertEqual(svc2.get_sign_request("w1", "r3")["state"], "pending")

        # 过期结果不复活、不重复记 E
        self.assertEqual(
            len(
                [
                    e
                    for e in svc2.get_audit_events("w1")["events"]
                    if e["type"] == "request_expired"
                ]
            ),
            1,
        )

        # 签名幂等记录仍在：重放 200 且签名一致
        status, replay = svc2.sign(
            "w1", "r1", "pay-100", h2.two_signatures("w1", "r1", "pay-100")
        )
        self.assertEqual(status, 200)
        self.assertEqual(replay["signature"], signed["signature"])

        # 审计 seq 连续：重启后事件完整、无跳号
        events_after = svc2.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["seq"] for e in events_after], list(range(1, max_seq + 1))
        )

        # 重启后续写：新事件接续最大 seq，不覆盖、不跳号
        svc2.approve("w1", "r3", "alice")
        svc2.sign(
            "w1", "r3", "pay-300", h2.two_signatures("w1", "r3", "pay-300")
        )
        events_final = svc2.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["seq"] for e in events_final],
            list(range(1, len(events_final) + 1)),
        )
        self.assertEqual(events_final[:max_seq], events_before)
        self.assertEqual(
            svc2.get_sign_request("w1", "r3")["state"], "signed"
        )


class ConcurrentReplayTest(unittest.TestCase):
    """并发重放只产生一个首次结果与一条首事件。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.h = make_harness(self.tmp)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 3600)

    def _run_concurrently(self, fn, n=8):
        results = [None] * n

        def worker(i):
            results[i] = fn()

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return results

    def test_concurrent_create_single_201(self):
        results = self._run_concurrently(
            lambda: self.svc.create_sign_request("w1", "r1", "pay-100")
        )
        statuses = sorted(status for status, _ in results)
        self.assertEqual(statuses, [200] * 7 + [201])
        created = [
            e
            for e in self.svc.get_audit_events("w1")["events"]
            if e["type"] == "request_created"
        ]
        self.assertEqual(len(created), 1)

    def test_concurrent_sign_single_201(self):
        self.svc.create_sign_request("w1", "r1", "pay-100")
        self.svc.approve("w1", "r1", "alice")
        signatures = self.h.two_signatures("w1", "r1", "pay-100")
        results = self._run_concurrently(
            lambda: self.svc.sign("w1", "r1", "pay-100", signatures)
        )
        statuses = sorted(status for status, _ in results)
        self.assertEqual(statuses, [200] * 7 + [201])
        # 所有响应的签名一致
        self.assertEqual(len({body["signature"] for _, body in results}), 1)
        signed = [
            e
            for e in self.svc.get_audit_events("w1")["events"]
            if e["type"] == "request_signed"
        ]
        self.assertEqual(len(signed), 1)

    def test_concurrent_create_without_policy_single_201(self):
        # 无策略钱包的 sign 并发：首签 201、重放 200，只有一个首次结果
        svc = self.svc
        svc.create_wallet("w2", 2)
        signatures = self.h.two_signatures("w2", "r9", "m")
        results = self._run_concurrently(
            lambda: svc.sign("w2", "r9", "m", signatures)
        )
        statuses = sorted(status for status, _ in results)
        self.assertEqual(statuses, [200] * 7 + [201])


if __name__ == "__main__":
    unittest.main()
