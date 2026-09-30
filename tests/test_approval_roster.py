"""钱包级审批人名单（approval-roster）测试。"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest

from tests.helpers import http_server, make_harness
from threshold_wallet import drbackup
from threshold_wallet.service import WalletService
from threshold_wallet.store import CorruptDataError, RecoveryError, WalletStore


class ApprovalRosterHttpTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self._ctx = http_server(self.tmpdir)
        self.srv = self._ctx.__enter__()
        self.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})

    def tearDown(self):
        self._ctx.__exit__(None, None, None)

    def request(self, method, path, body=None):
        return self.srv.request(method, path, body)

    def put_roster(self, members, wallet="w1"):
        return self.request(
            "PUT",
            f"/v1/wallets/{wallet}/approval-roster",
            {"allowed_approvers": members},
        )

    def get_roster(self, wallet="w1"):
        return self.request(
            "GET", f"/v1/wallets/{wallet}/approval-roster"
        )

    def put_policy(self, req=2, timeout=3600):
        return self.request(
            "PUT",
            "/v1/wallets/w1/approval-policy",
            {"required_approvals": req, "timeout_seconds": timeout},
        )

    def create_request(self, rid="r1", message="pay-100"):
        return self.request(
            "POST",
            "/v1/wallets/w1/sign-requests",
            {"id": rid, "message": message},
        )

    def decide(self, action, rid="r1", approver="alice"):
        return self.request(
            "POST",
            f"/v1/wallets/w1/sign-requests/{rid}/{action}",
            {"approver_id": approver},
        )

    def audit_types(self):
        status, body = self.request(
            "GET", "/v1/wallets/w1/audit-events?limit=1000"
        )
        self.assertEqual(status, 200)
        return [event["type"] for event in body["events"]]

    def test_get_unset_is_empty_list(self):
        status, body = self.get_roster()
        self.assertEqual(status, 200)
        self.assertEqual(body, {"allowed_approvers": []})

    def test_get_missing_wallet_404(self):
        status, _ = self.get_roster(wallet="ghost")
        self.assertEqual(status, 404)

    def test_invalid_wallet_id_400(self):
        status, _ = self.request(
            "GET", "/v1/wallets/bad%2Fid/approval-roster"
        )
        self.assertEqual(status, 400)
        status, _ = self.request(
            "PUT",
            "/v1/wallets/bad%2Fid/approval-roster",
            {"allowed_approvers": []},
        )
        self.assertEqual(status, 400)

    def test_put_missing_wallet_404(self):
        status, _ = self.put_roster(["alice"], wallet="ghost")
        self.assertEqual(status, 404)

    def test_put_bad_bodies_400(self):
        bodies = [
            {},
            {"allowed_approvers": ["alice"], "extra": 1},
            {"allowed_approvers": "alice"},
            {"allowed_approvers": ["alice", 42]},
            {"allowed_approvers": [True]},
            {"allowed_approsters": ["alice"]},
            {"allowed_approvers": [""]},
            {"allowed_approvers": ["   "]},
            {"allowed_approvers": ["x" * 129]},
            {"allowed_approvers": ["alice", "alice"]},
            {"allowed_approvers": [None]},
        ]
        for body in bodies:
            status, resp = self.request(
                "PUT", "/v1/wallets/w1/approval-roster", body
            )
            self.assertEqual(status, 400, body)
            self.assertIn("error", resp)

    def test_put_sorts_by_codepoint_and_persists(self):
        status, body = self.put_roster(["carol", "alice", "bob"])
        self.assertEqual(status, 200)
        self.assertEqual(
            body, {"allowed_approvers": ["alice", "bob", "carol"]}
        )
        status, body = self.get_roster()
        self.assertEqual(status, 200)
        self.assertEqual(
            body, {"allowed_approvers": ["alice", "bob", "carol"]}
        )

    def test_unicode_members_sorted_by_codepoint(self):
        members = ["审批人乙", "审批人甲", "alice"]
        status, body = self.put_roster(members)
        self.assertEqual(status, 200)
        self.assertEqual(body["allowed_approvers"], sorted(members))

    def test_every_put_logs_one_event_including_same_value_and_clear(self):
        self.put_roster(["alice"])
        self.put_roster(["alice", "bob"])
        self.put_roster(["alice", "bob"])
        self.put_roster([])
        self.assertEqual(
            self.audit_types().count("approval_roster_updated"), 4
        )
        status, body = self.get_roster()
        self.assertEqual(status, 200)
        self.assertEqual(body, {"allowed_approvers": []})

    def test_event_details_only_contain_current_roster(self):
        self.put_roster(["zoe", "alice"])
        status, body = self.request(
            "GET", "/v1/wallets/w1/audit-events?limit=1"
        )
        self.assertEqual(status, 200)
        event = body["events"][0]
        self.assertEqual(event["type"], "approval_roster_updated")
        self.assertEqual(
            event["details"], {"allowed_approvers": ["alice", "zoe"]}
        )
        self.assertIsNone(event["request_id"])
        self.assertIsNone(event["actor_id"])
        self.assertIsNone(event["reason"])

    def test_get_does_not_log_event(self):
        before = self.audit_types()
        for _ in range(3):
            status, _ = self.get_roster()
            self.assertEqual(status, 200)
        self.assertEqual(self.audit_types(), before)

    def test_frozen_wallet_blocks_put_allows_get(self):
        self.put_roster(["alice"])
        status, _ = self.request(
            "POST", "/v1/wallets/w1/freeze", {"reason": "incident"}
        )
        self.assertEqual(status, 201)
        status, _ = self.put_roster(["bob"])
        self.assertEqual(status, 409)
        status, body = self.get_roster()
        self.assertEqual(status, 200)
        self.assertEqual(body, {"allowed_approvers": ["alice"]})

    def test_off_roster_decision_409_and_not_counted(self):
        self.put_policy(req=2)
        self.put_roster(["alice"])
        self.create_request()
        status, _ = self.decide("approve", approver="mallory")
        self.assertEqual(status, 409)
        status, _ = self.decide("reject", approver="mallory")
        self.assertEqual(status, 409)
        status, body = self.request(
            "GET", "/v1/wallets/w1/sign-requests/r1"
        )
        self.assertEqual(body["state"], "pending")
        self.assertEqual(body["approvers"], [])

    def test_on_roster_decisions_succeed(self):
        self.put_policy(req=2)
        self.put_roster(["alice", "bob"])
        self.create_request()
        self.assertEqual(self.decide("approve", approver="alice")[0], 200)
        status, body = self.decide("approve", approver="bob")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "approved")

    def test_on_roster_reject_terminal(self):
        self.put_policy(req=2)
        self.put_roster(["alice"])
        self.create_request()
        status, body = self.decide("reject", approver="alice")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "rejected")

    def test_empty_roster_means_no_restriction(self):
        self.put_policy(req=1)
        self.put_roster(["alice"])
        self.put_roster([])
        self.create_request()
        status, body = self.decide("approve", approver="anyone")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "approved")

    def test_roster_change_only_binds_future_decisions(self):
        self.put_policy(req=2)
        self.create_request()
        self.assertEqual(self.decide("approve", approver="alice")[0], 200)
        self.put_roster(["bob"])
        status, body = self.decide("approve", approver="bob")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "approved")
        self.assertEqual(body["approvers"], ["alice", "bob"])

    def test_same_approver_replay_200_without_roster_recheck(self):
        self.put_policy(req=2)
        self.put_roster(["alice", "bob"])
        self.create_request()
        self.assertEqual(self.decide("approve", approver="alice")[0], 200)
        self.put_roster(["bob"])
        status, body = self.decide("approve", approver="alice")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "pending")
        self.assertEqual(body["approvers"], ["alice"])
        self.assertEqual(
            self.audit_types().count("request_approved"), 1
        )


class ApprovalRosterRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.harness = make_harness(self.tmpdir)
        self.harness.service.create_wallet("w1", 2)
        self.service = self.harness.service

    def _fresh_service(self):
        return WalletService(WalletStore(self.tmpdir))

    def _audit_path(self):
        return os.path.join(self.tmpdir, "audit", "w1.json")

    def _strip_chain(self):
        path = self._audit_path()
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        log.pop("chain", None)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        return path

    def test_roster_survives_restart(self):
        self.service.put_approval_roster("w1", ["zoe", "alice"])
        reloaded = self._fresh_service()
        self.assertEqual(
            reloaded.get_approval_roster("w1"),
            {"allowed_approvers": ["alice", "zoe"]},
        )

    def test_rebuild_roster_file_from_last_event(self):
        self.service.put_approval_roster("w1", ["alice", "bob"])
        os.unlink(
            os.path.join(self.tmpdir, "approval-rosters", "w1.json")
        )
        reloaded = self._fresh_service()
        self.assertEqual(
            reloaded.get_approval_roster("w1"),
            {"allowed_approvers": ["alice", "bob"]},
        )
        # 重建不新增事件、不改 seq
        events = self.harness.service._audit.all_events("w1")
        self.assertEqual(
            [e["type"] for e in events].count("approval_roster_updated"),
            1,
        )
        self.assertEqual(events[-1]["seq"], 1)

    def test_roster_file_without_event_is_recovery_error(self):
        self.service.put_approval_roster("w1", ["alice"])
        path = self._strip_chain()
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        log["events"] = [
            event
            for event in log["events"]
            if event["type"] != "approval_roster_updated"
        ]
        log["next_seq"] = len(log["events"]) + 1
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            self._fresh_service()

    def test_corrupt_roster_json_is_corrupt_data_error(self):
        self.service.put_approval_roster("w1", ["alice"])
        path = os.path.join(self.tmpdir, "approval-rosters", "w1.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write("{not json")
        with self.assertRaises(CorruptDataError):
            self._fresh_service().get_approval_roster("w1")

    def test_event_with_unsorted_members_is_recovery_error(self):
        self.service.put_approval_roster("w1", ["alice", "bob"])
        path = self._strip_chain()
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for event in log["events"]:
            if event["type"] == "approval_roster_updated":
                event["details"]["allowed_approvers"] = ["bob", "alice"]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            self._fresh_service()

    def test_file_event_mismatch_is_recovery_error(self):
        self.service.put_approval_roster("w1", ["alice"])
        path = os.path.join(self.tmpdir, "approval-rosters", "w1.json")
        with open(path, encoding="utf-8") as f:
            roster = json.load(f)
        roster["allowed_approvers"] = ["alice", "mallory"]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(roster, f)
        with self.assertRaises(RecoveryError):
            self._fresh_service()

    def test_concurrent_puts_linearize_and_match_last_event(self):
        candidates = [
            ["alice"],
            ["bob"],
            ["alice", "bob"],
            ["zoe"],
            [],
        ]
        errors: list[Exception] = []

        def worker(members):
            try:
                for _ in range(5):
                    self.service.put_approval_roster("w1", members)
            except Exception as exc:  # pragma: no cover - 并发不应失败
                errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(members,))
            for members in candidates
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        events = self.harness.service._audit.events_by_type(
            "w1", "approval_roster_updated"
        )
        self.assertEqual(len(events), len(candidates) * 5)
        # 现场文件与最后一条事件一致，且重启后仍一致
        expected = events[-1]["details"]["allowed_approvers"]
        self.assertEqual(
            self.service.get_approval_roster("w1"),
            {"allowed_approvers": expected},
        )
        self.assertEqual(
            self._fresh_service().get_approval_roster("w1"),
            {"allowed_approvers": expected},
        )

    def test_backup_restore_keeps_roster_and_commit_point(self):
        self.service.put_approval_roster("w1", ["zoe", "alice"])
        snap_dir = tempfile.mkdtemp()
        snapshot = os.path.join(snap_dir, "snap.tar")
        drbackup.backup(self.tmpdir, "w1", "S1", snapshot)
        target = tempfile.mkdtemp()
        try:
            drbackup.restore(target, "w1", snapshot)
            restored = WalletService(WalletStore(target))
            self.assertEqual(
                restored.get_approval_roster("w1"),
                {"allowed_approvers": ["alice", "zoe"]},
            )
            status = restored.get_audit_integrity("w1")
            self.assertEqual(status["state"], "valid")
        finally:
            import shutil

            shutil.rmtree(target, ignore_errors=True)
