from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import unittest

from tests.helpers import http_server, make_harness
from threshold_wallet.audit import AuditStore
from threshold_wallet.service import WalletService
from threshold_wallet.store import RecoveryError, WalletStore


class ApprovalRosterHttpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self._ctx = http_server(self.tmp)
        self.srv = self._ctx.__enter__()
        self.addCleanup(self._ctx.__exit__, None, None, None)
        self.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})

    def request(self, method, path, body=None):
        return self.srv.request(method, path, body)

    def put_roster(self, approvers, wallet="w1"):
        return self.request(
            "PUT",
            f"/v1/wallets/{wallet}/approval-roster",
            {"allowed_approvers": approvers},
        )

    def get_roster(self, wallet="w1"):
        return self.request(
            "GET", f"/v1/wallets/{wallet}/approval-roster"
        )

    def prepare_request(self, rid="r1", req=1):
        self.request(
            "PUT",
            "/v1/wallets/w1/approval-policy",
            {"required_approvals": req, "timeout_seconds": 3600},
        )
        return self.request(
            "POST",
            "/v1/wallets/w1/sign-requests",
            {"id": rid, "message": "payload"},
        )

    def decide(self, action, rid, approver):
        return self.request(
            "POST",
            f"/v1/wallets/w1/sign-requests/{rid}/{action}",
            {"approver_id": approver},
        )

    def events(self):
        return self.request("GET", "/v1/wallets/w1/audit-events")[1]["events"]

    def test_get_default_and_put_sorting(self):
        self.assertEqual(
            self.get_roster(),
            (200, {"allowed_approvers": []}),
        )
        status, body = self.put_roster(["李", "alice", "bob"])
        self.assertEqual(status, 200)
        self.assertEqual(body, {"allowed_approvers": ["alice", "bob", "李"]})
        self.assertEqual(self.get_roster()[1], body)

    def test_put_validates_body_and_members(self):
        valid = {"allowed_approvers": ["alice"]}
        for body in (
            {},
            {"allowed_approvers": ["alice"], "extra": 1},
            {"allowed_approvers": "alice"},
            {"allowed_approvers": [None]},
            {"allowed_approvers": [1]},
            {"allowed_approvers": [True]},
            {"allowed_approvers": [""]},
            {"allowed_approvers": ["   "]},
            {"allowed_approvers": ["a" * 129]},
            {"allowed_approvers": ["alice", "alice"]},
        ):
            status, response = self.request(
                "PUT", "/v1/wallets/w1/approval-roster", body
            )
            self.assertEqual(status, 400, body)
            self.assertIn("error", response)
        self.assertEqual(self.get_roster()[1], {"allowed_approvers": []})
        self.assertEqual(valid["allowed_approvers"], ["alice"])

    def test_invalid_or_missing_wallet(self):
        self.assertEqual(
            self.request(
                "PUT",
                "/v1/wallets/bad%2Fid/approval-roster",
                {"allowed_approvers": []},
            )[0],
            400,
        )
        self.assertEqual(
            self.request("GET", "/v1/wallets/bad%2Fid/approval-roster")[0],
            400,
        )
        self.assertEqual(
            self.put_roster([], wallet="ghost")[0],
            404,
        )
        self.assertEqual(self.get_roster("ghost")[0], 404)

    def test_every_put_records_current_snapshot_and_clear_restores_default(self):
        self.put_roster(["bob", "alice"])
        self.put_roster(["bob", "alice"])
        self.put_roster(["alice"])
        self.put_roster([])
        roster_events = [
            event
            for event in self.events()
            if event["type"] == "approval_roster_updated"
        ]
        self.assertEqual(len(roster_events), 4)
        self.assertEqual(
            [event["details"] for event in roster_events],
            [
                {"allowed_approvers": ["alice", "bob"]},
                {"allowed_approvers": ["alice", "bob"]},
                {"allowed_approvers": ["alice"]},
                {"allowed_approvers": []},
            ],
        )
        self.assertTrue(
            all(
                event["request_id"] is None
                and event["actor_id"] is None
                and event["reason"] is None
                for event in roster_events
            )
        )

    def test_roster_gates_future_decisions_but_replays_and_existing_approvals(self):
        self.prepare_request("approved", req=1)
        self.decide("approve", "approved", "alice")
        self.prepare_request("pending", req=2)
        self.decide("approve", "pending", "alice")
        self.put_roster(["bob"])

        self.assertEqual(self.decide("approve", "pending", "alice")[0], 200)
        self.assertEqual(self.decide("approve", "pending", "carol")[0], 409)
        self.assertEqual(self.decide("approve", "pending", "bob")[0], 200)
        self.assertEqual(self.decide("approve", "approved", "alice")[0], 200)

        self.prepare_request("rejected", req=2)
        self.put_roster(["alice"])
        self.assertEqual(self.decide("reject", "rejected", "alice")[0], 200)
        self.put_roster(["bob"])
        self.assertEqual(self.decide("reject", "rejected", "alice")[0], 200)
        self.assertEqual(
            self.decide("approve", "rejected", "bob")[0],
            409,
        )

    def test_get_works_while_frozen_but_put_is_conflict(self):
        self.request(
            "POST", "/v1/wallets/w1/freeze", {"reason": "incident"}
        )
        self.assertEqual(self.get_roster()[0], 200)
        self.assertEqual(self.put_roster(["alice"])[0], 409)

    def test_concurrent_updates_linearize_without_loss(self):
        barrier = threading.Barrier(8)
        results = []

        def worker():
            barrier.wait()
            results.append(self.put_roster(["bob", "alice"])[0])

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(results, [200] * 8)
        self.assertEqual(
            self.get_roster()[1],
            {"allowed_approvers": ["alice", "bob"]},
        )
        self.assertEqual(
            len(
                [
                    event
                    for event in self.events()
                    if event["type"] == "approval_roster_updated"
                ]
            ),
            8,
        )

    def test_restart_rebuilds_from_last_event(self):
        self.put_roster(["bob", "alice"])
        self.put_roster(["carol"])
        self.srv.stop()

        harness = make_harness(self.tmp)
        self.assertEqual(
            harness.service.get_approval_roster("w1"),
            {"allowed_approvers": ["carol"]},
        )

    def test_malformed_roster_event_blocks_recovery(self):
        self.put_roster(["alice"])
        self.srv.stop()
        AuditStore(self.tmp).append_event(
            "w1",
            WalletService._audit_event(
                "approval_roster_updated",
                details={"allowed_approvers": ["bob", "alice"]},
            ),
        )
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmp))

    def test_corrupt_audit_json_is_503(self):
        self.put_roster(["alice"])
        path = os.path.join(self.tmp, "audit", "w1.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("{broken")
        self.assertEqual(self.get_roster()[0], 503)


if __name__ == "__main__":
    unittest.main()
