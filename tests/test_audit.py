"""审计事件测试：seq 重启续接、事件形状、各类触发、重放无事件、
懒过期只记一次、审计 GET 不触发过期、查询参数校验、状态/事件原子回滚。
"""

from __future__ import annotations

import contextlib
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from tests.helpers import http_server, make_harness
from threshold_wallet.audit import AuditStore

EVENT_KEYS = {"seq", "type", "at", "request_id", "actor_id", "reason", "details"}


class AuditStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.store = AuditStore(self.tmp)

    def _event(self, **over):
        e = {
            "type": "policy_updated",
            "at": "2026-09-19T00:00:00Z",
            "request_id": None,
            "actor_id": None,
            "reason": None,
            "details": {},
        }
        e.update(over)
        return e

    def test_seq_starts_at_one_and_monotonic(self):
        e1 = self.store.append_event("w1", self._event())
        e2 = self.store.append_event("w1", self._event(type="request_created"))
        self.assertEqual((e1["seq"], e2["seq"]), (1, 2))
        self.assertEqual([e["seq"] for e in self.store.list_events("w1")], [1, 2])

    def test_seq_continues_after_restart(self):
        self.store.append_event("w1", self._event())
        self.store.append_event("w1", self._event())
        reopened = AuditStore(self.tmp)
        e3 = reopened.append_event("w1", self._event())
        self.assertEqual(e3["seq"], 3)
        self.assertEqual([e["seq"] for e in reopened.list_events("w1")], [1, 2, 3])

    def test_list_filters_and_slices_ascending(self):
        for i in range(5):
            self.store.append_event("w1", self._event())
        self.assertEqual(
            [e["seq"] for e in self.store.list_events("w1", from_seq=3)],
            [3, 4, 5],
        )
        self.assertEqual(
            [e["seq"] for e in self.store.list_events("w1", from_seq=2, limit=2)],
            [2, 3],
        )
        self.assertEqual(self.store.list_events("w1", from_seq=99), [])
        # 钱包无日志文件
        self.assertEqual(self.store.list_events("ghost"), [])

    def test_wallets_are_separate_logs(self):
        self.store.append_event("w1", self._event())
        self.store.append_event("w2", self._event())
        self.assertEqual([e["seq"] for e in self.store.list_events("w1")], [1])
        self.assertEqual([e["seq"] for e in self.store.list_events("w2")], [1])

    def test_path_traversal_rejected(self):
        with self.assertRaises(ValueError):
            self.store.list_events("../escape")


class AuditHttpTest(unittest.TestCase):
    def setUp(self):
        self._ctx = http_server(tempfile.mkdtemp())
        self.srv = self._ctx.__enter__()
        self.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})

    def tearDown(self):
        self._ctx.__exit__(None, None, None)

    def request(self, method, path, body=None):
        return self.srv.request(method, path, body)

    def events(self, query=""):
        path = "/v1/wallets/w1/audit-events" + (("?" + query) if query else "")
        status, body = self.request("GET", path)
        self.assertEqual(status, 200, body)
        return body

    def put_policy(self, req=2, timeout=3600):
        return self.request(
            "PUT",
            "/v1/wallets/w1/approval-policy",
            {"required_approvals": req, "timeout_seconds": timeout},
        )

    def create_request(self, rid="r1", message="pay-100"):
        return self.request(
            "POST", "/v1/wallets/w1/sign-requests",
            {"id": rid, "message": message},
        )

    def approve(self, rid="r1", approver="alice", reason=None):
        body = {"approver_id": approver}
        if reason is not None:
            body["reason"] = reason
        return self.request(
            "POST", f"/v1/wallets/w1/sign-requests/{rid}/approve", body
        )

    def reject(self, rid="r1", approver="alice", reason=None):
        body = {"approver_id": approver}
        if reason is not None:
            body["reason"] = reason
        return self.request(
            "POST", f"/v1/wallets/w1/sign-requests/{rid}/reject", body
        )

    def expire(self, rid):
        """直接把存储里的 t1 改到过去，模拟 pending 单超时。"""
        store = self.srv.harness.store
        rec = store.get_request("w1", rid)
        rec = dict(rec)
        rec["t1"] = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat().replace("+00:00", "Z")
        store.update_request("w1", rid, rec)

    def sign_body(self, rid, message):
        return {
            "signing_request_id": rid,
            "message": message,
            "signatures": self.srv.harness.two_signatures("w1", rid, message),
        }

    # ---- 端点契约 -------------------------------------------------------

    def test_endpoint_envelope_and_shape(self):
        self.put_policy()
        body = self.events()
        self.assertEqual(body["wallet_id"], "w1")
        self.assertIsInstance(body["events"], list)
        event = body["events"][0]
        self.assertEqual(set(event), EVENT_KEYS)
        self.assertTrue(event["at"].endswith("Z"))
        self.assertEqual(event["type"], "policy_updated")
        self.assertIsNone(event["request_id"])
        self.assertIsNone(event["actor_id"])
        self.assertIsNone(event["reason"])
        self.assertEqual(
            event["details"],
            {"required_approvals": 2, "timeout_seconds": 3600,
             "operation": "created"},
        )

    def test_events_ascending_contiguous_seq(self):
        self.put_policy(req=1)
        self.create_request()
        self.approve()
        seqs = [e["seq"] for e in self.events()["events"]]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))

    # ---- P --------------------------------------------------------------

    def test_policy_same_value_still_recorded_as_updated(self):
        self.put_policy(req=2, timeout=3600)
        self.put_policy(req=2, timeout=3600)
        ops = [
            e["details"]["operation"]
            for e in self.events()["events"]
            if e["type"] == "policy_updated"
        ]
        self.assertEqual(ops, ["created", "updated"])

    # ---- C --------------------------------------------------------------

    def test_request_created_event_and_nulls(self):
        self.put_policy()
        self.create_request()
        c = [e for e in self.events()["events"]
             if e["type"] == "request_created"]
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0]["request_id"], "r1")
        self.assertEqual(c[0]["details"], {"message": "pay-100"})
        for key in ("actor_id", "reason"):
            self.assertIsNone(c[0][key])

    def test_request_create_replay_and_conflict_emit_nothing(self):
        self.put_policy()
        self.create_request()
        n_after_first = len(self.events()["events"])
        # 同文幂等 200、异文 409 均不记事件
        self.assertEqual(self.create_request()[0], 200)
        self.assertEqual(self.create_request(message="other")[0], 409)
        self.assertEqual(len(self.events()["events"]), n_after_first)

    # ---- A / R ----------------------------------------------------------

    def test_approve_events_and_duplicate_silent(self):
        self.put_policy(req=2)
        self.create_request()
        self.approve(approver="alice", reason="ok")
        # 同一 approver 重复批准：不计数、不记事件
        self.approve(approver="alice")
        self.approve(approver="bob")
        approved = [
            e for e in self.events()["events"]
            if e["type"] == "request_approved"
        ]
        self.assertEqual(len(approved), 2)
        self.assertEqual(
            [(e["actor_id"], e["details"]["count"], e["details"]["state"])
             for e in approved],
            [("alice", 1, "pending"), ("bob", 2, "approved")],
        )
        self.assertEqual(approved[0]["reason"], "ok")
        self.assertIsNone(approved[1]["reason"])
        self.assertEqual(
            approved[0]["details"]["req"], 2,
        )
        # 已 approved 再批准：409 且无事件
        n = len(self.events()["events"])
        self.assertEqual(self.approve(approver="carol")[0], 409)
        self.assertEqual(len(self.events()["events"]), n)

    def test_reject_event_and_terminal_silent(self):
        self.put_policy(req=2)
        self.create_request()
        self.reject(reason="nope")
        rejected = [
            e for e in self.events()["events"]
            if e["type"] == "request_rejected"
        ]
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["request_id"], "r1")
        self.assertEqual(rejected[0]["actor_id"], "alice")
        self.assertEqual(rejected[0]["reason"], "nope")
        self.assertEqual(rejected[0]["details"]["state"], "rejected")
        n = len(self.events()["events"])
        # 终态后再 reject/approve 均不记事件
        self.assertEqual(self.reject()[0], 409)
        self.assertEqual(self.approve()[0], 409)
        self.assertEqual(len(self.events()["events"]), n)

    # ---- E --------------------------------------------------------------

    def test_expire_recorded_once_on_each_trigger(self):
        self.put_policy()
        for rid in ("rg", "ra", "rr", "rs"):
            self.create_request(rid=rid)
            self.expire(rid)

        # 审计 GET 不触发过期
        self.events()
        self.assertEqual(
            self.srv.harness.store.get_request("w1", "rg")["state"], "pending"
        )
        # 普通 GET 触发：记一次 E 并持久化
        status, view = self.request("GET", "/v1/wallets/w1/sign-requests/rg")
        self.assertEqual(view["state"], "expired")
        # approve / reject / sign 也触发
        self.assertEqual(self.approve(rid="ra")[0], 409)
        self.assertEqual(self.reject(rid="rr")[0], 409)
        sign_status, _ = self.request(
            "POST", "/v1/wallets/w1/sign", self.sign_body("rs", "pay-100")
        )
        self.assertEqual(sign_status, 409)

        expired_events = [
            e for e in self.events()["events"]
            if e["type"] == "request_expired"
        ]
        self.assertEqual(
            sorted(e["request_id"] for e in expired_events),
            ["ra", "rg", "rr", "rs"],
        )
        for e in expired_events:
            self.assertEqual(e["details"], {"state": "expired"})
            self.assertIsNone(e["actor_id"])
            self.assertIsNone(e["reason"])
        # 反复 GET 已过期单：E 仍只有一条
        for _ in range(3):
            self.request("GET", "/v1/wallets/w1/sign-requests/rg")
        total_e = sum(
            1 for e in self.events()["events"]
            if e["type"] == "request_expired"
        )
        self.assertEqual(total_e, 4)

    # ---- S --------------------------------------------------------------

    def test_signed_event_and_replay_silent(self):
        self.put_policy(req=1)
        self.create_request()
        self.approve()
        status, body = self.request(
            "POST", "/v1/wallets/w1/sign", self.sign_body("r1", "pay-100")
        )
        self.assertEqual(status, 201)
        signed = [
            e for e in self.events()["events"]
            if e["type"] == "request_signed"
        ]
        self.assertEqual(len(signed), 1)
        self.assertEqual(signed[0]["request_id"], "r1")
        self.assertEqual(
            signed[0]["details"], {"message": "pay-100", "state": "signed"}
        )
        # 重放 200，无新事件
        n = len(self.events()["events"])
        status, replay = self.request(
            "POST", "/v1/wallets/w1/sign", self.sign_body("r1", "pay-100")
        )
        self.assertEqual(status, 200)
        self.assertEqual(replay["signature"], body["signature"])
        self.assertEqual(len(self.events()["events"]), n)

    # ---- 查询参数 --------------------------------------------------------

    def test_pagination_from_seq_and_limit(self):
        self.put_policy(req=1)
        self.create_request()
        self.approve()
        all_events = self.events()["events"]
        self.assertGreaterEqual(len(all_events), 3)
        page = self.events("from_seq=2&limit=1")["events"]
        self.assertEqual(len(page), 1)
        self.assertEqual(page[0]["seq"], 2)
        # 默认 from_seq=1：从头开始
        self.assertEqual(self.events("limit=1")["events"][0]["seq"], 1)

    def test_bad_query_params_400(self):
        self.put_policy()
        for query in (
            "from_seq=0",
            "from_seq=-3",
            "from_seq=abc",
            "from_seq=1.5",
            "limit=0",
            "limit=-1",
            "limit=xyz",
            "limit=1001",
            "from_seq=0&limit=10",
        ):
            status, body = self.request(
                "GET", f"/v1/wallets/w1/audit-events?{query}"
            )
            self.assertEqual(status, 400, query)
            self.assertIn("error", body)

    def test_limit_boundary_1000_accepted(self):
        status, _ = self.request(
            "GET", "/v1/wallets/w1/audit-events?limit=1000"
        )
        self.assertEqual(status, 200)

    def test_audit_events_missing_wallet_404(self):
        status, body = self.request(
            "GET", "/v1/wallets/ghost/audit-events"
        )
        self.assertEqual(status, 404)
        self.assertIn("error", body)


class AuditAtomicityTest(unittest.TestCase):
    """状态/事件原子：事件追加失败时回滚状态，且不留下事件。"""

    def setUp(self):
        self.h = make_harness(tempfile.mkdtemp())
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)

    @contextlib.contextmanager
    def failing_audit(self):
        original = self.svc._audit.append_event

        def boom(*_a, **_k):
            raise OSError("audit disk full")

        self.svc._audit.append_event = boom
        try:
            yield
        finally:
            self.svc._audit.append_event = original

    def test_policy_rolled_back_when_event_fails(self):
        with self.failing_audit():
            with self.assertRaises(OSError):
                self.svc.put_policy("w1", 1, 60)
        self.assertIsNone(self.h.store.get_policy("w1"))
        # 更新失败：回滚到旧策略
        self.svc.put_policy("w1", 1, 60)
        with self.failing_audit():
            with self.assertRaises(OSError):
                self.svc.put_policy("w1", 2, 120)
        self.assertEqual(self.h.store.get_policy("w1")["required_approvals"], 1)

    def test_request_create_rolled_back_when_event_fails(self):
        self.svc.put_policy("w1", 1, 3600)
        with self.failing_audit():
            with self.assertRaises(OSError):
                self.svc.create_sign_request("w1", "r1", "m")
        self.assertIsNone(self.h.store.get_request("w1", "r1"))

    def test_approve_rolled_back_when_event_fails(self):
        self.svc.put_policy("w1", 2, 3600)
        self.svc.create_sign_request("w1", "r1", "m")
        with self.failing_audit():
            with self.assertRaises(OSError):
                self.svc.approve("w1", "r1", "alice", None)
        rec = self.h.store.get_request("w1", "r1")
        self.assertEqual(rec["state"], "pending")
        self.assertEqual(rec["approvers"], [])

    def test_sign_rolled_back_when_event_fails(self):
        self.svc.put_policy("w1", 1, 3600)
        self.svc.create_sign_request("w1", "r1", "m")
        self.svc.approve("w1", "r1", "alice", None)
        sigs = self.h.two_signatures("w1", "r1", "m")
        with self.failing_audit():
            with self.assertRaises(OSError):
                self.svc.sign("w1", "r1", "m", sigs)
        self.assertIsNone(self.h.store.get_signature("w1", "r1"))
        # 审批单回退到 approved，而非停留在 signed
        self.assertEqual(
            self.h.store.get_request("w1", "r1")["state"], "approved"
        )

    def test_expiry_rolled_back_when_event_fails(self):
        self.svc.put_policy("w1", 1, 3600)
        self.svc.create_sign_request("w1", "r1", "m")
        rec = self.h.store.get_request("w1", "r1")
        rec["t1"] = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat().replace("+00:00", "Z")
        self.h.store.update_request("w1", "r1", rec)
        with self.failing_audit():
            with self.assertRaises(OSError):
                self.svc.get_sign_request("w1", "r1")
        # 过期状态被回滚：仍是 pending
        self.assertEqual(
            self.h.store.get_request("w1", "r1")["state"], "pending"
        )


if __name__ == "__main__":
    unittest.main()
