"""多方审批阈值（required_approvals 1..16）测试。

覆盖：3..16 阈值的审批单生命周期、req 快照不追溯、名单/阈值可满足性
409（零副作用）、重启与备份/恢复一致性、持久化矛盾 fail-closed 503。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from tests.helpers import http_server, make_harness
from threshold_wallet import drbackup
from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import WalletStore


def _change_message(change_id, target, before, after):
    """审批单 message 的契约 ASCII 紧凑 JSON（恰四键、固定序）。"""
    return json.dumps(
        {
            "change_id": change_id,
            "target": target,
            "before": before,
            "after": after,
        },
        ensure_ascii=True,
        separators=(",", ":"),
    )


class MultiPartyApprovalHttpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self._ctx = http_server(self.tmp)
        self.srv = self._ctx.__enter__()
        self.addCleanup(self._ctx.__exit__, None, None, None)
        self.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})

    def request(self, method, path, body=None):
        return self.srv.request(method, path, body)

    def put_policy(self, req, timeout=3600):
        return self.request(
            "PUT",
            "/v1/wallets/w1/approval-policy",
            {"required_approvals": req, "timeout_seconds": timeout},
        )

    def put_roster(self, approvers):
        return self.request(
            "PUT",
            "/v1/wallets/w1/approval-roster",
            {"allowed_approvers": approvers},
        )

    def get_roster(self):
        return self.request("GET", "/v1/wallets/w1/approval-roster")

    def create_request(self, rid="r1", message="pay-100"):
        return self.request(
            "POST",
            "/v1/wallets/w1/sign-requests",
            {"id": rid, "message": message},
        )

    def get_request(self, rid="r1"):
        return self.request("GET", f"/v1/wallets/w1/sign-requests/{rid}")

    def approve(self, rid, approver):
        return self.request(
            "POST",
            f"/v1/wallets/w1/sign-requests/{rid}/approve",
            {"approver_id": approver},
        )

    def reject(self, rid, approver):
        return self.request(
            "POST",
            f"/v1/wallets/w1/sign-requests/{rid}/reject",
            {"approver_id": approver},
        )

    def events(self, event_type=None):
        body = self.request("GET", "/v1/wallets/w1/audit-events")[1]["events"]
        if event_type is None:
            return body
        return [e for e in body if e["type"] == event_type]

    # ---- 多方阈值生命周期 ------------------------------------------------

    def test_three_of_three_flow(self):
        self.assertEqual(self.put_policy(3)[0], 200)
        status, body = self.create_request()
        self.assertEqual(status, 201)
        self.assertEqual(body["req"], 3)
        self.assertEqual(body["count"], 0)
        self.assertEqual(body["state"], "pending")

        status, body = self.approve("r1", "alice")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "pending")
        self.assertEqual(body["count"], 1)
        self.assertEqual(body["approvers"], ["alice"])

        status, body = self.approve("r1", "bob")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "pending")
        self.assertEqual(body["count"], 2)
        self.assertEqual(body["approvers"], ["alice", "bob"])

        status, body = self.approve("r1", "carol")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "approved")
        self.assertEqual(body["count"], 3)
        self.assertEqual(body["req"], 3)
        self.assertEqual(body["approvers"], ["alice", "bob", "carol"])

        # request_approved 事件逐步反映累计 count/req
        approved_events = self.events("request_approved")
        self.assertEqual(len(approved_events), 3)
        self.assertEqual(
            [e["details"] for e in approved_events],
            [
                {"count": 1, "req": 3, "state": "pending"},
                {"count": 2, "req": 3, "state": "pending"},
                {"count": 3, "req": 3, "state": "approved"},
            ],
        )
        self.assertEqual(
            [e["actor_id"] for e in approved_events],
            ["alice", "bob", "carol"],
        )

    def test_duplicate_approve_idempotent_and_not_counted(self):
        self.put_policy(3)
        self.create_request()
        self.approve("r1", "alice")
        status, body = self.approve("r1", "alice")
        self.assertEqual(status, 200)
        self.assertEqual(body["count"], 1)
        self.assertEqual(body["approvers"], ["alice"])
        self.assertEqual(body["state"], "pending")
        # 重放不记事件
        self.assertEqual(len(self.events("request_approved")), 1)

    def test_reject_immediately_terminal(self):
        self.put_policy(3)
        self.create_request()
        self.approve("r1", "alice")
        status, body = self.reject("r1", "bob")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "rejected")
        # 终态后再批准 409
        self.assertEqual(self.approve("r1", "carol")[0], 409)

    def test_sixteen_of_sixteen_boundary(self):
        self.assertEqual(self.put_policy(16)[0], 200)
        self.create_request()
        approvers = [f"a{i}" for i in range(16)]
        for approver in approvers[:-1]:
            status, body = self.approve("r1", approver)
            self.assertEqual(status, 200)
            self.assertEqual(body["state"], "pending")
        status, body = self.approve("r1", approvers[-1])
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "approved")
        self.assertEqual(body["count"], 16)
        self.assertEqual(body["req"], 16)

    def test_policy_update_not_retroactive(self):
        # 建单时快照 req=2；之后策略改为 4 不影响既有请求
        self.put_policy(2)
        self.create_request("r1")
        self.approve("r1", "alice")
        self.assertEqual(self.put_policy(4)[0], 200)
        status, body = self.get_request("r1")
        self.assertEqual(body["req"], 2)
        self.assertEqual(body["state"], "pending")
        status, body = self.approve("r1", "bob")
        self.assertEqual(body["state"], "approved")
        self.assertEqual(body["req"], 2)
        # 新单采用新阈值
        status, body = self.create_request("r2")
        self.assertEqual(body["req"], 4)

    def test_sign_gate_uses_snapshot_threshold(self):
        self.put_policy(3)
        self.create_request()
        # 未达阈值：/sign 409
        self.approve("r1", "alice")
        self.approve("r1", "bob")
        sigs = self.srv.harness.two_signatures("w1", "r1", "pay-100")
        status, _ = self.request(
            "POST",
            "/v1/wallets/w1/sign",
            {"signing_request_id": "r1", "message": "pay-100",
             "signatures": sigs},
        )
        self.assertEqual(status, 409)
        # 达到阈值后首签 201
        self.approve("r1", "carol")
        status, body = self.request(
            "POST",
            "/v1/wallets/w1/sign",
            {"signing_request_id": "r1", "message": "pay-100",
             "signatures": sigs},
        )
        self.assertEqual(status, 201)
        self.assertIn("signature", body)

    # ---- 名单/阈值可满足性 ------------------------------------------------

    def test_policy_update_beyond_roster_409_zero_side_effects(self):
        self.put_policy(2)
        self.assertEqual(self.put_roster(["alice", "bob"])[0], 200)
        events_before = self.events()
        status, body = self.put_policy(3)
        self.assertEqual(status, 409)
        self.assertIn("error", body)
        # 零副作用：策略、名单、审计事件均未变
        self.assertEqual(
            self.srv.harness.store.get_policy("w1")["required_approvals"], 2
        )
        self.assertEqual(
            self.get_roster()[1], {"allowed_approvers": ["alice", "bob"]}
        )
        self.assertEqual(self.events(), events_before)

    def test_roster_shrink_below_threshold_409_zero_side_effects(self):
        self.put_policy(2)
        self.put_roster(["alice", "bob"])
        events_before = self.events()
        status, body = self.put_roster(["alice"])
        self.assertEqual(status, 409)
        self.assertIn("error", body)
        self.assertEqual(
            self.get_roster()[1], {"allowed_approvers": ["alice", "bob"]}
        )
        self.assertEqual(self.events(), events_before)

    def test_roster_equal_to_threshold_ok(self):
        self.put_policy(2)
        self.assertEqual(self.put_roster(["alice", "bob"])[0], 200)
        self.create_request()
        self.assertEqual(self.approve("r1", "carol")[0], 409)
        self.assertEqual(self.approve("r1", "alice")[0], 200)
        self.assertEqual(self.approve("r1", "bob")[0], 200)
        self.assertEqual(self.get_request()[1]["state"], "approved")

    def test_empty_roster_open_semantics(self):
        # 空名单不限制审批人，也不受阈值可满足性约束
        self.assertEqual(self.put_policy(3)[0], 200)
        self.assertEqual(self.put_roster([])[0], 200)
        self.create_request()
        for approver in ("x", "y", "z"):
            self.assertEqual(self.approve("r1", approver)[0], 200)
        self.assertEqual(self.get_request()[1]["state"], "approved")
        # 有阈值策略时清空名单同样允许
        self.put_roster(["a", "b", "c"])
        self.assertEqual(self.put_roster([])[0], 200)

    def test_multi_party_roster_gates_approvals(self):
        self.put_policy(3)
        self.put_roster(["alice", "bob", "carol"])
        self.create_request()
        self.assertEqual(self.approve("r1", "dave")[0], 409)
        self.approve("r1", "alice")
        self.approve("r1", "bob")
        self.assertEqual(self.get_request()[1]["state"], "pending")
        self.approve("r1", "carol")
        self.assertEqual(self.get_request()[1]["state"], "approved")


class MultiPartyRestartTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.h = make_harness(self.tmp)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)

    def _reopen(self):
        return make_harness(self.tmp)

    def test_restart_preserves_threshold_state_and_seq(self):
        self.svc.put_policy("w1", 4, 3600)
        self.svc.create_sign_request("w1", "r1", "m")
        self.svc.approve("w1", "r1", "alice")
        self.svc.approve("w1", "r1", "bob")
        seq_before = [
            e["seq"] for e in self.svc.get_audit_events("w1")["events"]
        ]

        svc2 = self._reopen().service
        view = svc2.get_sign_request("w1", "r1")
        self.assertEqual(view["state"], "pending")
        self.assertEqual(view["req"], 4)
        self.assertEqual(view["count"], 2)
        self.assertEqual(view["approvers"], ["alice", "bob"])
        # 重启后继续累计到阈值
        svc2.approve("w1", "r1", "carol")
        view = svc2.approve("w1", "r1", "dave")
        self.assertEqual(view["state"], "approved")
        self.assertEqual(view["count"], 4)
        events = svc2.get_audit_events("w1")["events"]
        self.assertEqual(
            [e["seq"] for e in events],
            list(range(1, len(events) + 1)),
        )
        self.assertEqual([e["seq"] for e in events[: len(seq_before)]],
                         seq_before)
        # 策略本身也在重启后保持
        self.assertEqual(
            WalletStore(self.tmp).get_policy("w1")["required_approvals"], 4
        )

    def test_backup_restore_preserves_multi_party_state(self):
        self.svc.put_policy("w1", 3, 3600)
        self.svc.create_sign_request("w1", "r1", "m")
        self.svc.approve("w1", "r1", "alice")
        self.svc.approve("w1", "r1", "bob")
        pack_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, pack_dir, ignore_errors=True)
        pack = os.path.join(pack_dir, "snap.tar")
        drbackup.backup(self.tmp, "w1", "S1", pack)
        dst = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, dst, ignore_errors=True)
        drbackup.restore(dst, "w1", pack)
        svc2 = make_harness(dst).service
        view = svc2.get_sign_request("w1", "r1")
        self.assertEqual(view["state"], "pending")
        self.assertEqual(view["req"], 3)
        self.assertEqual(view["approvers"], ["alice", "bob"])
        view = svc2.approve("w1", "r1", "carol")
        self.assertEqual(view["state"], "approved")
        self.assertEqual(
            WalletStore(dst).get_policy("w1")["required_approvals"], 3
        )


class MultiPartyFailClosedHttpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self._ctx = http_server(self.tmp)
        self.srv = self._ctx.__enter__()
        self.addCleanup(self._ctx.__exit__, None, None, None)
        self.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
        self.request(
            "PUT",
            "/v1/wallets/w1/approval-policy",
            {"required_approvals": 3, "timeout_seconds": 3600},
        )
        self.request(
            "POST",
            "/v1/wallets/w1/sign-requests",
            {"id": "r1", "message": "m"},
        )

    def request(self, method, path, body=None):
        return self.srv.request(method, path, body)

    def _plant(self, mutate):
        path = os.path.join(self.tmp, "requests", "w1.json")
        with open(path, encoding="utf-8") as handle:
            records = json.load(handle)
        mutate(records["r1"])
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(records, handle)
        return path

    def _assert_503_and_preserved(self, path):
        with open(path, encoding="utf-8") as handle:
            before = handle.read()
        status, body = self.request("GET", "/v1/wallets/w1/sign-requests/r1")
        self.assertEqual(status, 503)
        self.assertEqual(body, {"error": "service temporarily unavailable"})
        # 保留现场：文件不被改写
        with open(path, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), before)

    def test_out_of_range_req_503(self):
        for bad in (0, 17, True, "3"):
            path = self._plant(lambda rec: rec.update(req=bad))
            self._assert_503_and_preserved(path)

    def test_duplicate_approvers_503(self):
        path = self._plant(lambda rec: rec.update(approvers=["a", "a"]))
        self._assert_503_and_preserved(path)

    def test_count_exceeds_req_503(self):
        path = self._plant(
            lambda rec: rec.update(approvers=["a", "b", "c", "d"])
        )
        self._assert_503_and_preserved(path)

    def test_approved_below_quorum_503(self):
        path = self._plant(
            lambda rec: rec.update(state="approved", approvers=["a", "b"])
        )
        self._assert_503_and_preserved(path)


class MultiPartyChangeControlTest(unittest.TestCase):
    """变更控制入口下的阈值/名单可满足性约束。"""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)

    def _apply(self, change_id, target, before, after, rid):
        message = _change_message(change_id, target, before, after)
        code, _ = self.svc.create_sign_request("w1", rid, message)
        self.assertEqual(code, 201)
        self.svc.approve("w1", rid, "alice")
        self.svc.approve("w1", rid, "bob")
        return self.svc.post_policy_change(
            "w1", change_id, target, before, after, rid
        )

    def _enable(self):
        self.svc.put_policy("w1", 2, 3600)
        code, _ = self._apply(
            "cc-on", "change-control",
            {"enabled": False}, {"enabled": True}, "r-cc",
        )
        self.assertEqual(code, 201)

    def _applied_events(self):
        return [
            e
            for e in self.svc.get_audit_events("w1")["events"]
            if e["type"] == "policy_change_applied"
        ]

    def test_policy_change_to_multi_party_threshold_applies(self):
        self._enable()
        code, _ = self._apply(
            "c1", "approval-policy",
            {"required_approvals": 2, "timeout_seconds": 3600},
            {"required_approvals": 5, "timeout_seconds": 60},
            "r1",
        )
        self.assertEqual(code, 201)
        self.assertEqual(
            self.h.store.get_policy("w1"),
            {"wallet_id": "w1", "required_approvals": 5,
             "timeout_seconds": 60},
        )
        # 新审批单快照新阈值
        code, view = self.svc.create_sign_request("w1", "r2", "m")
        self.assertEqual(code, 201)
        self.assertEqual(view["req"], 5)

    def test_policy_change_beyond_roster_409_zero_side_effects(self):
        self._enable()
        code, _ = self._apply(
            "c-roster", "approval-roster",
            {"allowed_approvers": []},
            {"allowed_approvers": ["alice", "bob"]},
            "r-roster",
        )
        self.assertEqual(code, 201)
        events_before = self._applied_events()
        message = _change_message(
            "c1", "approval-policy",
            {"required_approvals": 2, "timeout_seconds": 3600},
            {"required_approvals": 3, "timeout_seconds": 3600},
        )
        code, _ = self.svc.create_sign_request("w1", "r1", message)
        self.assertEqual(code, 201)
        self.svc.approve("w1", "r1", "alice")
        self.svc.approve("w1", "r1", "bob")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "approval-policy",
                {"required_approvals": 2, "timeout_seconds": 3600},
                {"required_approvals": 3, "timeout_seconds": 3600},
                "r1",
            )
        self.assertEqual(ctx.exception.status, 409)
        # 零副作用：策略文件与已提交事件均未变
        self.assertEqual(
            self.h.store.get_policy("w1")["required_approvals"], 2
        )
        self.assertEqual(self._applied_events(), events_before)

    def test_roster_change_shrink_below_threshold_409_zero_side_effects(self):
        self._enable()
        code, _ = self._apply(
            "c-roster", "approval-roster",
            {"allowed_approvers": []},
            {"allowed_approvers": ["alice", "bob"]},
            "r-roster",
        )
        self.assertEqual(code, 201)
        events_before = self._applied_events()
        message = _change_message(
            "c1", "approval-roster",
            {"allowed_approvers": ["alice", "bob"]},
            {"allowed_approvers": ["alice"]},
        )
        code, _ = self.svc.create_sign_request("w1", "r1", message)
        self.assertEqual(code, 201)
        self.svc.approve("w1", "r1", "alice")
        self.svc.approve("w1", "r1", "bob")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "approval-roster",
                {"allowed_approvers": ["alice", "bob"]},
                {"allowed_approvers": ["alice"]},
                "r1",
            )
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(
            self.svc.get_approval_roster("w1"),
            {"allowed_approvers": ["alice", "bob"]},
        )
        self.assertEqual(self._applied_events(), events_before)


if __name__ == "__main__":
    unittest.main()
