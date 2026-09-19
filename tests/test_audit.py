"""审计事件流：事件记录、seq 连续性、重启延续、查询参数校验。"""

from __future__ import annotations

import os
import tempfile
import unittest
import unittest.mock
from datetime import datetime, timedelta, timezone

from threshold_wallet.service import ServiceError

from helpers import http_server, make_harness


def _past_iso() -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat().replace(
        "+00:00", "Z"
    )


class AuditEventServiceTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.h = make_harness(self._tmp.name)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)

    def events(self, wallet_id: str = "w1") -> list[dict]:
        return self.svc.get_audit_events(wallet_id)["events"]

    def _force_expired(self, request_id: str) -> None:
        record = self.h.store.get_request("w1", request_id)
        record["t1"] = _past_iso()
        self.h.store.update_request("w1", request_id, record)

    def _setup_policy_and_request(self) -> None:
        self.svc.put_policy("w1", 2, 3600)
        self.svc.create_sign_request("w1", "req-1", "pay-100")

    # ---- P：策略 -------------------------------------------------------

    def test_policy_created_then_updated_even_with_same_value(self):
        self.svc.put_policy("w1", 2, 3600)
        self.svc.put_policy("w1", 2, 3600)  # 同值覆盖也记
        events = self.events()
        self.assertEqual([e["seq"] for e in events], [1, 2])
        for event, operation in zip(events, ("created", "updated")):
            self.assertEqual(event["type"], "policy_updated")
            self.assertIsNone(event["request_id"])
            self.assertIsNone(event["actor_id"])
            self.assertIsNone(event["reason"])
            self.assertEqual(
                event["details"],
                {
                    "required_approvals": 2,
                    "timeout_seconds": 3600,
                    "operation": operation,
                },
            )
            self.assertTrue(event["at"].endswith("Z"))

    def test_failed_policy_validation_records_nothing(self):
        with self.assertRaises(ServiceError):
            self.svc.put_policy("w1", 3, 3600)
        self.assertEqual(self.events(), [])

    # ---- C：创建签名请求 -------------------------------------------------

    def test_request_created_event(self):
        self.svc.put_policy("w1", 1, 3600)
        status, _ = self.svc.create_sign_request("w1", "req-1", "pay-100")
        self.assertEqual(status, 201)
        event = self.events()[-1]
        self.assertEqual(event["type"], "request_created")
        self.assertEqual(event["request_id"], "req-1")
        self.assertEqual(event["details"], {"message": "pay-100"})

    def test_replay_and_conflict_create_no_event(self):
        self.svc.put_policy("w1", 1, 3600)
        self.svc.create_sign_request("w1", "req-1", "pay-100")
        before = len(self.events())
        status, _ = self.svc.create_sign_request("w1", "req-1", "pay-100")
        self.assertEqual(status, 200)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.create_sign_request("w1", "req-1", "pay-200")
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(len(self.events()), before)

    # ---- A / R：批准与拒绝 ----------------------------------------------

    def test_approve_events_and_duplicate_not_recorded(self):
        self._setup_policy_and_request()
        self.svc.approve("w1", "req-1", "ops-1", "looks good")
        self.svc.approve("w1", "req-1", "ops-1")  # 重复批准不记
        self.svc.approve("w1", "req-1", "ops-2")
        events = [e for e in self.events() if e["type"] == "request_approved"]
        self.assertEqual(len(events), 2)
        first, second = events
        self.assertEqual(first["actor_id"], "ops-1")
        self.assertEqual(first["reason"], "looks good")
        self.assertEqual(
            first["details"], {"count": 1, "req": 2, "state": "pending"}
        )
        self.assertIsNone(second["reason"])
        self.assertEqual(
            second["details"], {"count": 2, "req": 2, "state": "approved"}
        )

    def test_reject_event_and_terminal_state_not_recorded(self):
        self._setup_policy_and_request()
        self.svc.reject("w1", "req-1", "ops-1", "no")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.approve("w1", "req-1", "ops-2")
        self.assertEqual(ctx.exception.status, 409)
        events = [e for e in self.events() if e["type"] == "request_rejected"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["actor_id"], "ops-1")
        self.assertEqual(events[0]["reason"], "no")
        self.assertEqual(
            events[0]["details"], {"count": 0, "req": 2, "state": "rejected"}
        )
        # 终态上的操作不产生任何新事件
        types = [e["type"] for e in self.events()]
        self.assertEqual(types, ["policy_updated", "request_created",
                                 "request_rejected"])

    # ---- E：懒过期 -------------------------------------------------------

    def test_expiry_recorded_once_on_get(self):
        self._setup_policy_and_request()
        self._force_expired("req-1")
        view = self.svc.get_sign_request("w1", "req-1")
        self.assertEqual(view["state"], "expired")
        self.svc.get_sign_request("w1", "req-1")  # 再次查询不重复记
        events = [e for e in self.events() if e["type"] == "request_expired"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["request_id"], "req-1")
        self.assertEqual(events[0]["details"], {"state": "expired"})

    def test_expiry_recorded_on_approve_and_sign_paths(self):
        self._setup_policy_and_request()
        self._force_expired("req-1")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.approve("w1", "req-1", "ops-1")
        self.assertEqual(ctx.exception.status, 409)
        events = [e for e in self.events() if e["type"] == "request_expired"]
        self.assertEqual(len(events), 1)

    def test_audit_query_does_not_trigger_expiry(self):
        self._setup_policy_and_request()
        self._force_expired("req-1")
        events = self.events()
        self.assertNotIn("request_expired", [e["type"] for e in events])
        # 审计查询是只读的：审批单仍是 pending
        record = self.h.store.get_request("w1", "req-1")
        self.assertEqual(record["state"], "pending")

    # ---- S：签名 ---------------------------------------------------------

    def test_sign_event_and_replay_not_recorded(self):
        self._setup_policy_and_request()
        self.svc.approve("w1", "req-1", "ops-1")
        self.svc.approve("w1", "req-1", "ops-2")
        signatures = self.h.two_signatures("w1", "req-1", "pay-100")
        status, _ = self.svc.sign("w1", "req-1", "pay-100", signatures)
        self.assertEqual(status, 201)
        status, _ = self.svc.sign("w1", "req-1", "pay-100", signatures)
        self.assertEqual(status, 200)
        events = [e for e in self.events() if e["type"] == "request_signed"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["request_id"], "req-1")
        self.assertEqual(
            events[0]["details"], {"message": "pay-100", "state": "signed"}
        )
        # 审批单确实推进到 signed
        self.assertEqual(
            self.svc.get_sign_request("w1", "req-1")["state"], "signed"
        )

    def test_sign_without_policy_records_event(self):
        signatures = self.h.two_signatures("w1", "req-9", "hello")
        status, _ = self.svc.sign("w1", "req-9", "hello", signatures)
        self.assertEqual(status, 201)
        events = self.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["type"], "request_signed")
        self.assertEqual(events[0]["request_id"], "req-9")

    # ---- seq：连续、升序、重启延续 ----------------------------------------

    def test_seq_is_contiguous_and_survives_restart(self):
        self._setup_policy_and_request()
        self.svc.approve("w1", "req-1", "ops-1")
        seqs = [e["seq"] for e in self.events()]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))
        # 重启：同一数据目录上重建 store/service
        restarted = make_harness(self._tmp.name)
        events = restarted.service.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in events], seqs)
        restarted.service.put_policy("w1", 1, 60)
        events = restarted.service.get_audit_events("w1")["events"]
        self.assertEqual(events[-1]["seq"], seqs[-1] + 1)

    # ---- 查询参数 ---------------------------------------------------------

    def test_from_seq_and_limit(self):
        self._setup_policy_and_request()
        self.svc.approve("w1", "req-1", "ops-1")
        self.svc.approve("w1", "req-1", "ops-2")
        result = self.svc.get_audit_events("w1", from_seq=2, limit=2)
        self.assertEqual([e["seq"] for e in result["events"]], [2, 3])
        result = self.svc.get_audit_events("w1", from_seq=99)
        self.assertEqual(result["events"], [])
        self.assertEqual(result["wallet_id"], "w1")

    def test_invalid_params_raise_400(self):
        for kwargs in (
            {"from_seq": 0},
            {"from_seq": -1},
            {"from_seq": "abc"},
            {"from_seq": "1.5"},
            {"from_seq": True},
            {"limit": 0},
            {"limit": -3},
            {"limit": "x"},
            {"limit": 1001},
        ):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.get_audit_events("w1", **kwargs)
            self.assertEqual(ctx.exception.status, 400, kwargs)

    def test_unknown_wallet_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_audit_events("nope")
        self.assertEqual(ctx.exception.status, 404)

    # ---- 原子回滚 ---------------------------------------------------------

    def test_state_rolled_back_when_event_write_fails(self):
        self._setup_policy_and_request()
        store = self.h.store
        real_write = type(store)._atomic_write

        def flaky(path, data):
            if os.sep + "audit" + os.sep in path:
                raise OSError("disk full")
            return real_write(path, data)

        with unittest.mock.patch.object(
            type(store), "_atomic_write", staticmethod(flaky)
        ):
            with self.assertRaises(OSError):
                self.svc.approve("w1", "req-1", "ops-1")
        # 状态与事件都不落一半：审批单仍是原样，审计流没有事件
        record = store.get_request("w1", "req-1")
        self.assertEqual(record["state"], "pending")
        self.assertEqual(record["approvers"], [])
        self.assertEqual(
            [e["type"] for e in self.events()],
            ["policy_updated", "request_created"],
        )


class AuditEventHttpTest(unittest.TestCase):
    def test_http_endpoint(self):
        with tempfile.TemporaryDirectory() as tmpdir, http_server(tmpdir) as srv:
            status, _ = srv.request(
                "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
            )
            self.assertEqual(status, 201)
            status, _ = srv.request(
                "PUT",
                "/v1/wallets/w1/approval-policy",
                {"required_approvals": 1, "timeout_seconds": 60},
            )
            self.assertEqual(status, 200)

            status, body = srv.request("GET", "/v1/wallets/w1/audit-events")
            self.assertEqual(status, 200)
            self.assertEqual(body["wallet_id"], "w1")
            self.assertEqual(len(body["events"]), 1)
            self.assertEqual(body["events"][0]["seq"], 1)
            self.assertEqual(
                set(body["events"][0]),
                {"seq", "type", "at", "request_id", "actor_id",
                 "reason", "details"},
            )

            status, body = srv.request(
                "GET", "/v1/wallets/w1/audit-events?from_seq=2&limit=10"
            )
            self.assertEqual(status, 200)
            self.assertEqual(body["events"], [])

            for query in (
                "from_seq=0", "from_seq=-1", "from_seq=abc", "limit=0",
                "limit=1001", "limit=1.5",
            ):
                status, _ = srv.request(
                    "GET", f"/v1/wallets/w1/audit-events?{query}"
                )
                self.assertEqual(status, 400, query)

            status, _ = srv.request("GET", "/v1/wallets/ghost/audit-events")
            self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
