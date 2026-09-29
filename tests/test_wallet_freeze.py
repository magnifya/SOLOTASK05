from __future__ import annotations

import json
import os
import tempfile
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from threshold_wallet.audit import AuditStore
from threshold_wallet import drbackup
from threshold_wallet.service import WalletService
from threshold_wallet.store import CorruptDataError, RecoveryError, WalletStore

from tests.helpers import http_server, make_harness


class WalletFreezeHttpTest(unittest.TestCase):
    def setUp(self):
        self._ctx = http_server(tempfile.mkdtemp())
        self.srv = self._ctx.__enter__()
        self.url = self.srv.base_url
        self.assertEqual(
            self.request(
                "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
            )[0],
            201,
        )

    def tearDown(self):
        self._ctx.__exit__(None, None, None)

    def request(self, method, path, body=None):
        return self.srv.request(method, path, body)

    def raw_request(self, raw_body: bytes):
        req = urllib.request.Request(
            self.url + "/v1/wallets/w1/freeze",
            data=raw_body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_security_state_lifecycle_and_idempotency(self):
        status, state = self.request(
            "GET", "/v1/wallets/w1/security-state"
        )
        self.assertEqual(
            (status, state),
            (
                200,
                {"wallet_id": "w1", "state": "active", "reason": None},
            ),
        )

        status, frozen = self.request(
            "POST", "/v1/wallets/w1/freeze", {"reason": "incident"}
        )
        self.assertEqual(
            (status, frozen),
            (
                201,
                {"wallet_id": "w1", "state": "frozen", "reason": "incident"},
            ),
        )
        self.assertEqual(
            self.request(
                "POST", "/v1/wallets/w1/freeze", {"reason": "incident"}
            ),
            (200, frozen),
        )
        self.assertEqual(
            self.request(
                "POST", "/v1/wallets/w1/freeze", {"reason": "other"}
            )[0],
            409,
        )

        status, active = self.request(
            "POST", "/v1/wallets/w1/unfreeze", {"reason": "resolved"}
        )
        self.assertEqual(
            (status, active),
            (
                201,
                {"wallet_id": "w1", "state": "active", "reason": None},
            ),
        )
        self.assertEqual(
            self.request(
                "POST", "/v1/wallets/w1/unfreeze", {"reason": "resolved"}
            ),
            (200, active),
        )
        self.assertEqual(
            self.request(
                "POST", "/v1/wallets/w1/unfreeze", {"reason": "changed"}
            )[0],
            409,
        )

    def test_freeze_blocks_existing_writes_allows_reads_and_security_writes(self):
        self.assertEqual(
            self.request(
                "PUT",
                "/v1/wallets/w1/approval-policy",
                {"required_approvals": 1, "timeout_seconds": 60},
            )[0],
            200,
        )
        self.assertEqual(
            self.request(
                "POST", "/v1/wallets/w1/freeze", {"reason": "incident"}
            )[0],
            201,
        )

        self.assertEqual(
            self.request("GET", "/v1/wallets/w1")[0], 200
        )
        self.assertEqual(
            self.request("GET", "/v1/wallets/w1/audit-events")[0], 200
        )
        self.assertEqual(
            self.request(
                "GET", "/v1/wallets/w1/security-state"
            )[0],
            200,
        )
        self.assertEqual(
            self.request(
                "PUT",
                "/v1/wallets/w1/approval-policy",
                {"required_approvals": 2, "timeout_seconds": 60},
            )[0],
            409,
        )
        self.assertEqual(
            self.request(
                "POST",
                "/v1/wallets/w1/sign-requests",
                {"id": "r1", "message": "m"},
            )[0],
            409,
        )
        self.assertEqual(
            self.request(
                "POST", "/v1/wallets/w1/unfreeze", {"reason": "resolved"}
            )[0],
            201,
        )
        self.assertEqual(
            self.request(
                "POST",
                "/v1/wallets/w1/sign-requests",
                {"id": "r1", "message": "m"},
            )[0],
            201,
        )

    def test_invalid_freeze_bodies_are_400(self):
        invalid_bodies = (
            b"[]",
            json.dumps({}).encode(),
            json.dumps({"reason": "incident", "extra": 1}).encode(),
            json.dumps({"reason": 123}).encode(),
            json.dumps({"reason": ""}).encode(),
            json.dumps({"reason": "   "}).encode(),
            json.dumps({"reason": "x" * 1025}).encode(),
        )
        for raw_body in invalid_bodies:
            with self.subTest(raw_body=raw_body):
                self.assertEqual(self.raw_request(raw_body)[0], 400)

    def test_unknown_wallet_and_initial_unfreeze_are_404_or_409(self):
        self.assertEqual(
            self.request(
                "GET", "/v1/wallets/missing/security-state"
            )[0],
            404,
        )
        self.assertEqual(
            self.request(
                "POST",
                "/v1/wallets/missing/freeze",
                {"reason": "incident"},
            )[0],
            404,
        )
        self.assertEqual(
            self.request(
                "POST",
                "/v1/wallets/w1/unfreeze",
                {"reason": "resolved"},
            )[0],
            409,
        )

    def test_concurrent_freeze_has_one_creation_and_contiguous_audit_seq(self):
        with ThreadPoolExecutor(max_workers=16) as pool:
            responses = list(
                pool.map(
                    lambda _: self.request(
                        "POST",
                        "/v1/wallets/w1/freeze",
                        {"reason": "incident"},
                    ),
                    range(16),
                )
            )
        statuses = sorted(status for status, _ in responses)
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(200), 15)

        status, events = self.request("GET", "/v1/wallets/w1/audit-events")
        self.assertEqual(status, 200)
        events = events["events"]
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["seq"], 1)
        self.assertEqual(event["type"], "wallet_frozen")
        self.assertEqual(event["details"], {"reason": "incident"})
        self.assertIsNone(event["request_id"])
        self.assertIsNone(event["actor_id"])
        self.assertIsNone(event["reason"])


class WalletFreezeRecoveryTest(unittest.TestCase):
    def test_state_and_seq_survive_restart(self):
        tmpdir = tempfile.mkdtemp()
        harness = make_harness(tmpdir)
        harness.service.create_wallet("w1", 2)
        self.assertEqual(
            harness.service.set_wallet_frozen("w1", True, "incident")[0],
            201,
        )
        self.assertEqual(
            harness.service.set_wallet_frozen("w1", False, "resolved")[0],
            201,
        )

        restarted = make_harness(tmpdir).service
        self.assertEqual(
            restarted.get_security_state("w1"),
            {"wallet_id": "w1", "state": "active", "reason": None},
        )
        self.assertEqual(
            restarted.set_wallet_frozen("w1", True, "again"),
            (
                201,
                {
                    "wallet_id": "w1",
                    "state": "frozen",
                    "reason": "again",
                },
            ),
        )
        events = AuditStore(tmpdir).list_events("w1")
        self.assertEqual([event["seq"] for event in events], [1, 2, 3])
        self.assertEqual(
            [event["type"] for event in events],
            ["wallet_frozen", "wallet_unfrozen", "wallet_frozen"],
        )

    def test_frozen_state_survives_backup_restore(self):
        source = tempfile.mkdtemp()
        harness = make_harness(source)
        harness.service.create_wallet("w1", 2)
        harness.service.set_wallet_frozen("w1", True, "incident")
        snapshot = os.path.join(tempfile.mkdtemp(), "snapshot.tar")
        self.assertEqual(
            drbackup.backup(source, "w1", "snap1", snapshot)["status"],
            201,
        )

        target = tempfile.mkdtemp()
        self.assertEqual(
            drbackup.restore(target, "w1", snapshot)[0], 201
        )
        restored = WalletService(WalletStore(target))
        self.assertEqual(
            restored.get_security_state("w1"),
            {
                "wallet_id": "w1",
                "state": "frozen",
                "reason": "incident",
            },
        )
        self.assertEqual(
            restored.set_wallet_frozen("w1", True, "incident")[0], 200
        )

    def test_corrupt_audit_json_rejects_recovery_and_http_state(self):
        tmpdir = tempfile.mkdtemp()
        harness = make_harness(tmpdir)
        harness.service.create_wallet("w1", 2)
        harness.service.set_wallet_frozen("w1", True, "incident")
        with open(f"{tmpdir}/audit/w1.json", "w", encoding="utf-8") as f:
            f.write("{broken")

        with self.assertRaises(CorruptDataError):
            WalletService(WalletStore(tmpdir))
        with self.assertRaises(CorruptDataError):
            harness.service.get_security_state("w1")

    def test_contradictory_security_events_reject_recovery(self):
        tmpdir = tempfile.mkdtemp()
        harness = make_harness(tmpdir)
        harness.service.create_wallet("w1", 2)
        audit_store = AuditStore(tmpdir)
        event = harness.service._audit_event(
            "wallet_frozen", details={"reason": "first"}
        )
        audit_store.append_event("w1", event)
        audit_store.append_event("w1", dict(event))

        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(tmpdir))


if __name__ == "__main__":
    unittest.main()
