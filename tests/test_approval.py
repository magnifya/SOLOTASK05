"""审批策略与签名请求工作流测试：HTTP 端到端 + CLI。"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from tests.helpers import http_server
from threshold_wallet.cli import main

REQUEST_KEYS = {
    "id", "message", "state", "approvers", "count", "req", "t0", "t1", "reason",
}


class ApprovalHttpTest(unittest.TestCase):
    def setUp(self):
        self._ctx = http_server(tempfile.mkdtemp())
        self.srv = self._ctx.__enter__()
        self.url = self.srv.base_url
        self.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})

    def tearDown(self):
        self._ctx.__exit__(None, None, None)

    def request(self, method, path, body=None):
        return self.srv.request(method, path, body)

    def put_policy(self, wallet="w1", req=2, timeout=3600):
        return self.request(
            "PUT",
            f"/v1/wallets/{wallet}/approval-policy",
            {"required_approvals": req, "timeout_seconds": timeout},
        )

    def create_request(self, rid="r1", message="pay-100", wallet="w1"):
        return self.request(
            "POST",
            f"/v1/wallets/{wallet}/sign-requests",
            {"id": rid, "message": message},
        )

    def approve(self, rid="r1", approver="alice", reason=None, wallet="w1"):
        body = {"approver_id": approver}
        if reason is not None:
            body["reason"] = reason
        return self.request(
            "POST", f"/v1/wallets/{wallet}/sign-requests/{rid}/approve", body
        )

    def reject(self, rid="r1", approver="alice", reason=None, wallet="w1"):
        body = {"approver_id": approver}
        if reason is not None:
            body["reason"] = reason
        return self.request(
            "POST", f"/v1/wallets/{wallet}/sign-requests/{rid}/reject", body
        )

    def cancel(
        self, rid="r1", cancel_id="c1", reason="changed my mind", wallet="w1"
    ):
        return self.request(
            "POST",
            f"/v1/wallets/{wallet}/sign-requests/{rid}/cancel",
            {"cancel_id": cancel_id, "reason": reason},
        )

    # ---- PUT approval-policy -------------------------------------------

    def test_put_policy_200(self):
        status, body = self.put_policy(req=1, timeout=60)
        self.assertEqual(status, 200)
        self.assertEqual(body["required_approvals"], 1)
        self.assertEqual(body["timeout_seconds"], 60)

    def test_put_policy_multi_party_threshold_200(self):
        for req in (2, 3, 8, 16):
            status, body = self.put_policy(req=req, timeout=60)
            self.assertEqual(status, 200, req)
            self.assertEqual(body["required_approvals"], req)
            self.assertEqual(body["timeout_seconds"], 60)

    def test_put_policy_bad_values_400(self):
        for body in (
            {"required_approvals": 0, "timeout_seconds": 60},
            {"required_approvals": -1, "timeout_seconds": 60},
            {"required_approvals": 17, "timeout_seconds": 60},
            {"required_approvals": 100, "timeout_seconds": 60},
            {"required_approvals": True, "timeout_seconds": 60},
            {"required_approvals": "2", "timeout_seconds": 60},
            {"required_approvals": 2.0, "timeout_seconds": 60},
            {"required_approvals": 2, "timeout_seconds": 0},
            {"required_approvals": 2, "timeout_seconds": -5},
            {"required_approvals": 2, "timeout_seconds": True},
            {"required_approvals": 2, "timeout_seconds": "60"},
            {"required_approvals": 2},
            {"timeout_seconds": 60},
            {},
        ):
            status, resp = self.request(
                "PUT", "/v1/wallets/w1/approval-policy", body
            )
            self.assertEqual(status, 400, body)
            self.assertIn("error", resp)

    def test_put_policy_missing_wallet_404(self):
        status, _ = self.put_policy(wallet="ghost")
        self.assertEqual(status, 404)

    # ---- POST sign-requests --------------------------------------------

    def test_create_request_without_policy_409(self):
        status, body = self.create_request()
        self.assertEqual(status, 409)
        self.assertIn("error", body)

    def test_create_request_201_contract(self):
        self.put_policy(req=2, timeout=3600)
        status, body = self.create_request()
        self.assertEqual(status, 201)
        self.assertEqual(set(body), REQUEST_KEYS)
        self.assertEqual(body["id"], "r1")
        self.assertEqual(body["message"], "pay-100")
        self.assertEqual(body["state"], "pending")
        self.assertEqual(body["approvers"], [])
        self.assertEqual(body["count"], 0)
        self.assertEqual(body["req"], 2)
        self.assertTrue(body["t0"])
        self.assertTrue(body["t1"])
        self.assertIsNone(body["reason"])

    def test_create_request_replay_200_and_conflict_409(self):
        self.put_policy()
        self.assertEqual(self.create_request()[0], 201)
        # 同 id 同文：幂等 200
        status, body = self.create_request()
        self.assertEqual(status, 200)
        self.assertEqual(body["id"], "r1")
        # 同 id 异文：409
        status, _ = self.create_request(message="pay-200")
        self.assertEqual(status, 409)

    def test_create_request_bad_body_400(self):
        self.put_policy()
        for body in (
            {"id": "", "message": "m"},
            {"id": "  ", "message": "m"},
            {"id": "r1", "message": ""},
            {"id": "r1", "message": "  "},
            {"id": "r1"},
            {"message": "m"},
            {"id": 1, "message": "m"},
            {"id": "r1", "message": 2},
            {"id": "bad/id", "message": "m"},
        ):
            status, resp = self.request(
                "POST", "/v1/wallets/w1/sign-requests", body
            )
            self.assertEqual(status, 400, body)
            self.assertIn("error", resp)

    def test_create_request_missing_wallet_404(self):
        self.put_policy()
        status, _ = self.create_request(wallet="ghost")
        self.assertEqual(status, 404)

    # ---- GET sign-requests/{id} -----------------------------------------

    def test_get_request_200_and_404(self):
        self.put_policy()
        self.create_request()
        status, body = self.request("GET", "/v1/wallets/w1/sign-requests/r1")
        self.assertEqual(status, 200)
        self.assertEqual(set(body), REQUEST_KEYS)
        status, _ = self.request("GET", "/v1/wallets/w1/sign-requests/ghost")
        self.assertEqual(status, 404)
        status, _ = self.request("GET", "/v1/wallets/ghost/sign-requests/r1")
        self.assertEqual(status, 404)

    # ---- approve ---------------------------------------------------------

    def test_approve_flow_to_approved(self):
        self.put_policy(req=2)
        self.create_request()
        status, body = self.approve(approver="alice")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "pending")
        self.assertEqual(body["count"], 1)
        self.assertEqual(body["approvers"], ["alice"])
        # 重复批准不计数
        status, body = self.approve(approver="alice")
        self.assertEqual(status, 200)
        self.assertEqual(body["count"], 1)
        self.assertEqual(body["state"], "pending")
        # 第二个审批人达到门槛
        status, body = self.approve(approver="bob")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "approved")
        self.assertEqual(body["count"], 2)
        # 已 approved 再批准：409
        status, _ = self.approve(approver="carol")
        self.assertEqual(status, 409)

    def test_approve_req1_immediately_approved(self):
        self.put_policy(req=1)
        self.create_request()
        status, body = self.approve()
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "approved")

    # ---- 多方审批阈值（3..16） ------------------------------------------

    def test_approve_req3_flow_to_approved(self):
        self.put_policy(req=3)
        self.create_request()
        status, body = self.approve(approver="alice")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "pending")
        self.assertEqual(body["count"], 1)
        self.assertEqual(body["req"], 3)
        self.assertEqual(body["approvers"], ["alice"])
        # 重复批准幂等且不计数
        status, body = self.approve(approver="alice")
        self.assertEqual(status, 200)
        self.assertEqual(body["count"], 1)
        self.assertEqual(body["state"], "pending")
        status, body = self.approve(approver="bob")
        self.assertEqual(body["state"], "pending")
        self.assertEqual(body["count"], 2)
        self.assertEqual(body["approvers"], ["alice", "bob"])
        # 第三名不同审批人达到阈值
        status, body = self.approve(approver="carol")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "approved")
        self.assertEqual(body["count"], 3)
        # 已 approved 再批准：409
        self.assertEqual(self.approve(approver="dave")[0], 409)
        # request_approved 事件反映累计 count/req
        status, events = self.request("GET", "/v1/wallets/w1/audit-events")
        approved_events = [
            event
            for event in events["events"]
            if event["type"] == "request_approved"
        ]
        self.assertEqual(len(approved_events), 3)
        self.assertEqual(
            [event["details"] for event in approved_events],
            [
                {"count": 1, "req": 3, "state": "pending"},
                {"count": 2, "req": 3, "state": "pending"},
                {"count": 3, "req": 3, "state": "approved"},
            ],
        )

    def test_approve_req16_flow(self):
        self.put_policy(req=16)
        self.create_request()
        approvers = [f"a{i}" for i in range(16)]
        for approver in approvers[:-1]:
            status, body = self.approve(approver=approver)
            self.assertEqual(status, 200)
            self.assertEqual(body["state"], "pending")
        status, body = self.approve(approver=approvers[-1])
        self.assertEqual(body["state"], "approved")
        self.assertEqual(body["count"], 16)
        self.assertEqual(body["approvers"], approvers)

    def test_req_snapshot_not_retroactive(self):
        # 建单时的阈值写入 req 快照：后续策略更新不追溯既有请求
        self.put_policy(req=3)
        self.create_request(rid="r1")
        self.put_policy(req=1)
        status, body = self.request("GET", "/v1/wallets/w1/sign-requests/r1")
        self.assertEqual(body["req"], 3)
        self.approve(rid="r1", approver="alice")
        self.approve(rid="r1", approver="bob")
        status, body = self.request("GET", "/v1/wallets/w1/sign-requests/r1")
        self.assertEqual(body["state"], "pending")
        self.approve(rid="r1", approver="carol")
        status, body = self.request("GET", "/v1/wallets/w1/sign-requests/r1")
        self.assertEqual(body["state"], "approved")
        # 新建请求采用新阈值
        self.create_request(rid="r2", message="pay-200")
        status, body = self.request("GET", "/v1/wallets/w1/sign-requests/r2")
        self.assertEqual(body["req"], 1)

    def test_reject_req3_immediately_terminal(self):
        self.put_policy(req=3)
        self.create_request()
        self.approve(approver="alice")
        status, body = self.reject(approver="bob", reason="no")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "rejected")
        self.assertEqual(body["count"], 1)
        self.assertEqual(self.approve(approver="carol")[0], 409)

    def test_sign_gate_with_req3(self):
        self.put_policy(req=3)
        self.create_request()
        self.approve(approver="alice")
        self.approve(approver="bob")
        # 未达阈值：409
        status, _ = self.request(
            "POST", "/v1/wallets/w1/sign", self._sign_body("w1", "r1", "pay-100")
        )
        self.assertEqual(status, 409)
        self.approve(approver="carol")
        status, body = self.request(
            "POST", "/v1/wallets/w1/sign", self._sign_body("w1", "r1", "pay-100")
        )
        self.assertEqual(status, 201)
        self.assertEqual(len(bytes.fromhex(body["signature"])), 128)

    # ---- 名单与阈值的可满足性约束 ----------------------------------------

    def put_roster(self, approvers, wallet="w1"):
        return self.request(
            "PUT",
            f"/v1/wallets/{wallet}/approval-roster",
            {"allowed_approvers": approvers},
        )

    def test_put_policy_above_roster_size_409_zero_side_effects(self):
        self.assertEqual(self.put_roster(["alice", "bob"])[0], 200)
        status, _ = self.put_policy(req=3)
        self.assertEqual(status, 409)
        # 零副作用：策略仍未设置、无 policy_updated 事件
        self.assertIsNone(self.srv.harness.store.get_policy("w1"))
        status, events = self.request("GET", "/v1/wallets/w1/audit-events")
        self.assertEqual(
            [
                event
                for event in events["events"]
                if event["type"] == "policy_updated"
            ],
            [],
        )
        # 阈值不超过名单规模则成功
        self.assertEqual(self.put_policy(req=2)[0], 200)
        # 已有策略时把阈值提到名单规模以上同样 409 且不改旧策略
        status, _ = self.put_policy(req=5)
        self.assertEqual(status, 409)
        self.assertEqual(
            self.srv.harness.store.get_policy("w1")["required_approvals"], 2
        )

    def test_put_policy_with_empty_roster_open_semantics(self):
        # 空名单（缺省）沿用开放审批人语义：任意阈值可设
        self.assertEqual(self.put_policy(req=16)[0], 200)
        # 显式清空名单同样不受阈值约束
        self.assertEqual(self.put_roster([])[0], 200)
        self.assertEqual(self.put_policy(req=16)[0], 200)

    def test_shrink_roster_below_threshold_409_zero_side_effects(self):
        self.put_policy(req=3)
        self.assertEqual(self.put_roster(["alice", "bob", "carol"])[0], 200)
        # 缩小到不可满足阈值：409，名单与事件均不变
        status, _ = self.put_roster(["alice", "bob"])
        self.assertEqual(status, 409)
        status, body = self.request("GET", "/v1/wallets/w1/approval-roster")
        self.assertEqual(
            body, {"allowed_approvers": ["alice", "bob", "carol"]}
        )
        status, events = self.request("GET", "/v1/wallets/w1/audit-events")
        roster_events = [
            event
            for event in events["events"]
            if event["type"] == "approval_roster_updated"
        ]
        self.assertEqual(len(roster_events), 1)
        # 清空名单（开放语义）与满足阈值的名单均成功
        self.assertEqual(
            self.put_roster(["alice", "bob", "carol", "dave"])[0], 200
        )
        self.assertEqual(self.put_roster([])[0], 200)
        # 策略仍在：非空但不足阈值的名单仍 409
        self.assertEqual(self.put_roster(["alice"])[0], 409)
        # 无策略的钱包名单不受阈值约束
        self.request("POST", "/v1/wallets", {"wallet_id": "w2", "shares": 2})
        self.assertEqual(self.put_roster(["alice"], wallet="w2")[0], 200)

    def test_roster_gates_multi_party_approvals(self):
        self.put_policy(req=3)
        self.put_roster(["alice", "bob", "carol"])
        self.create_request()
        self.assertEqual(self.approve(approver="dave")[0], 409)
        self.assertEqual(self.approve(approver="alice")[0], 200)
        self.assertEqual(self.approve(approver="bob")[0], 200)
        status, body = self.approve(approver="carol")
        self.assertEqual(body["state"], "approved")

    def test_approve_bad_approver_400(self):
        self.put_policy()
        self.create_request()
        for approver in (None, "", "   ", 1, True, ["a"]):
            body = {} if approver is None else {"approver_id": approver}
            status, resp = self.request(
                "POST", "/v1/wallets/w1/sign-requests/r1/approve", body
            )
            self.assertEqual(status, 400, approver)
            self.assertIn("error", resp)

    def test_approve_missing_request_404(self):
        self.put_policy()
        status, _ = self.approve(rid="ghost")
        self.assertEqual(status, 404)

    # ---- reject ----------------------------------------------------------

    def test_reject_200_terminal(self):
        self.put_policy(req=2)
        self.create_request()
        status, body = self.reject(reason="suspicious")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "rejected")
        self.assertEqual(body["reason"], "suspicious")
        # 同人同决定重放 200；其他人的新决定仍为终态冲突 409
        self.assertEqual(self.reject(approver="alice")[0], 200)
        self.assertEqual(self.reject(approver="bob")[0], 409)
        self.assertEqual(self.approve(approver="bob")[0], 409)

    def test_reason_validation_400(self):
        self.put_policy()
        self.create_request()
        for reason in ("", "   ", "x" * 1025, 1, True):
            status, resp = self.reject(reason=reason)
            self.assertEqual(status, 400, repr(reason)[:30])
            self.assertIn("error", resp)
        # 1024 字符恰好合法
        status, body = self.reject(reason="x" * 1024)
        self.assertEqual(status, 200)
        self.assertEqual(len(body["reason"]), 1024)

    # ---- 懒过期 -----------------------------------------------------------

    def _expire_request(self, rid="r1", wallet="w1"):
        """直接把存储里的 t1 改到过去，模拟超时。"""
        store = self.srv.harness.store
        record = store.get_request(wallet, rid)
        record = dict(record)
        record["t1"] = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat().replace("+00:00", "Z")
        store.update_request(wallet, rid, record)

    def test_lazy_expire_on_get(self):
        self.put_policy(timeout=3600)
        self.create_request()
        self._expire_request()
        status, body = self.request("GET", "/v1/wallets/w1/sign-requests/r1")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "expired")
        # 已持久化：再查仍是 expired
        status, body = self.request("GET", "/v1/wallets/w1/sign-requests/r1")
        self.assertEqual(body["state"], "expired")

    def test_expired_cannot_approve_or_reject(self):
        self.put_policy()
        self.create_request()
        self._expire_request()
        self.assertEqual(self.approve()[0], 409)
        self.assertEqual(self.reject()[0], 409)

    # ---- 撤销 ------------------------------------------------------------

    def test_cancel_pending_201_replay_200_and_audit_event(self):
        self.put_policy()
        self.create_request()
        status, body = self.cancel(reason="撤回")
        self.assertEqual(status, 201)
        self.assertEqual(body["state"], "cancelled")
        self.assertEqual(body["reason"], "撤回")
        status, body = self.cancel(reason="撤回")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "cancelled")
        status, events = self.request("GET", "/v1/wallets/w1/audit-events")
        self.assertEqual(status, 200)
        cancel_events = [
            event
            for event in events["events"]
            if event["type"] == "request_cancelled"
        ]
        self.assertEqual(len(cancel_events), 1)
        self.assertEqual(cancel_events[0]["request_id"], "r1")
        self.assertEqual(cancel_events[0]["actor_id"], "c1")
        self.assertEqual(cancel_events[0]["reason"], "撤回")
        self.assertEqual(
            cancel_events[0]["details"],
            {"cancel_id": "c1", "reason": "撤回"},
        )

    def test_cancel_conflicts_and_later_lifecycle_409(self):
        self.put_policy(req=2)
        self.create_request()
        self.assertEqual(self.cancel()[0], 201)
        self.assertEqual(self.approve(approver="alice")[0], 409)
        self.assertEqual(self.reject(approver="alice")[0], 409)
        status, _ = self.request(
            "POST", "/v1/wallets/w1/sign", self._sign_body("w1", "r1", "pay-100")
        )
        self.assertEqual(status, 409)
        self.assertEqual(self.cancel(reason="different")[0], 409)
        self.assertEqual(self.cancel(cancel_id="c2")[0], 409)

    def test_cancel_rejects_terminal_requests_and_reused_cancel_id(self):
        self.put_policy(req=1)
        self.create_request(rid="r1")
        self.create_request(rid="r2")
        self.approve(rid="r1")
        self.assertEqual(self.cancel(rid="r1")[0], 409)
        self.assertEqual(self.cancel(rid="r2", cancel_id="c2")[0], 201)
        self.create_request(rid="r3", message="pay-300")
        self.assertEqual(self.cancel(rid="r3", cancel_id="c2")[0], 409)

    def test_cancel_expired_request_is_409(self):
        self.put_policy(timeout=3600)
        self.create_request()
        self._expire_request()
        self.assertEqual(self.cancel()[0], 409)

    def test_cancel_body_validation_400(self):
        self.put_policy()
        self.create_request()
        bodies = (
            {},
            {"cancel_id": "c1"},
            {"reason": "x"},
            {"cancel_id": "c1", "reason": "x", "extra": 1},
            {"cancel_id": "bad/id", "reason": "x"},
            {"cancel_id": "c1", "reason": ""},
            {"cancel_id": "c1", "reason": "   "},
            {"cancel_id": "c1", "reason": "x" * 1025},
            {"cancel_id": 1, "reason": "x"},
        )
        for body in bodies:
            status, resp = self.request(
                "POST", "/v1/wallets/w1/sign-requests/r1/cancel", body
            )
            self.assertEqual(status, 400, body)
            self.assertIn("error", resp)

    def test_cancel_missing_wallet_or_request_404(self):
        self.put_policy()
        self.create_request()
        self.assertEqual(self.cancel(wallet="ghost")[0], 404)
        self.assertEqual(self.cancel(rid="ghost")[0], 404)

    def test_cancel_frozen_wallet_409(self):
        self.put_policy()
        self.create_request()
        self.request("POST", "/v1/wallets/w1/freeze", {"reason": "incident"})
        self.assertEqual(self.cancel()[0], 409)

    def test_request_cancel_crash_recovery_forward_and_rollback(self):
        from threshold_wallet.service import WalletService

        self.put_policy()
        self.create_request()
        store = self.srv.harness.store
        original = store.get_request("w1", "r1")
        cancelled = dict(original, state="cancelled", reason="撤回")

        store.save_request_cancel_intent("w1", "r1", "c1", "撤回", original)
        store.update_request("w1", "r1", cancelled)
        WalletService(store, recover=True)
        recovered = store.get_request("w1", "r1")
        self.assertEqual(recovered["state"], "pending")
        self.assertEqual(recovered["reason"], original["reason"])
        self.assertEqual(store.get_request_cancel_intents("w1"), {})

        store.save_request_cancel_intent("w1", "r1", "c1", "撤回", original)
        store.update_request("w1", "r1", original)
        service = WalletService(store, recover=False)
        with service._wallet_lock("w1"):
            service._emit(
                "w1",
                service._audit_event(
                    "request_cancelled",
                    request_id="r1",
                    actor_id="c1",
                    reason="撤回",
                    details={"cancel_id": "c1", "reason": "撤回"},
                ),
            )
        WalletService(store, recover=True)
        self.assertEqual(store.get_request("w1", "r1"), cancelled)
        self.assertEqual(store.get_request_cancel_intents("w1"), {})

    # ---- 签名门控 ---------------------------------------------------------

    def _sign_body(self, wallet, srid, message):
        return {
            "signing_request_id": srid,
            "message": message,
            "signatures": self.srv.harness.two_signatures(wallet, srid, message),
        }

    def test_sign_requires_approved_request(self):
        self.put_policy(req=1)
        self.create_request()
        # 未 approved：409
        status, _ = self.request(
            "POST", "/v1/wallets/w1/sign", self._sign_body("w1", "r1", "pay-100")
        )
        self.assertEqual(status, 409)
        # message 不匹配：409
        self.approve()
        status, _ = self.request(
            "POST", "/v1/wallets/w1/sign", self._sign_body("w1", "r1", "pay-200")
        )
        self.assertEqual(status, 409)
        # approved 且匹配：201，审批单推进到 signed
        status, body = self.request(
            "POST", "/v1/wallets/w1/sign", self._sign_body("w1", "r1", "pay-100")
        )
        self.assertEqual(status, 201)
        self.assertEqual(len(bytes.fromhex(body["signature"])), 128)
        _, view = self.request("GET", "/v1/wallets/w1/sign-requests/r1")
        self.assertEqual(view["state"], "signed")
        # 重放：幂等 200
        status, body2 = self.request(
            "POST", "/v1/wallets/w1/sign", self._sign_body("w1", "r1", "pay-100")
        )
        self.assertEqual(status, 200)
        self.assertEqual(body2["signature"], body["signature"])

    def test_sign_with_policy_but_unknown_request_404(self):
        self.put_policy()
        status, _ = self.request(
            "POST", "/v1/wallets/w1/sign", self._sign_body("w1", "ghost", "m")
        )
        self.assertEqual(status, 404)

    def test_sign_without_policy_unchanged(self):
        # 无策略：首签 201，重放 200
        status, body = self.request(
            "POST", "/v1/wallets/w1/sign", self._sign_body("w1", "r9", "m")
        )
        self.assertEqual(status, 201)
        status, body2 = self.request(
            "POST", "/v1/wallets/w1/sign", self._sign_body("w1", "r9", "m")
        )
        self.assertEqual(status, 200)
        self.assertEqual(body2["signature"], body["signature"])


class ApprovalCliTest(unittest.TestCase):
    def setUp(self):
        self._ctx = http_server(tempfile.mkdtemp())
        self.srv = self._ctx.__enter__()
        self.url = self.srv.base_url
        self.run_cli("create", "--url", self.url, "--wallet-id", "w1")

    def tearDown(self):
        self._ctx.__exit__(None, None, None)

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue().strip(), err.getvalue().strip()

    def test_full_approval_flow_via_cli(self):
        code, out, err = self.run_cli(
            "policy", "--url", self.url, "--wallet-id", "w1",
            "--required-approvals", "2", "--timeout-seconds", "3600",
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["required_approvals"], 2)

        code, out, err = self.run_cli(
            "request-create", "--url", self.url, "--wallet-id", "w1",
            "--signing-request-id", "r1", "--message", "pay-100",
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["state"], "pending")

        code, out, err = self.run_cli(
            "approve", "--url", self.url, "--wallet-id", "w1",
            "--signing-request-id", "r1", "--approver-id", "alice",
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["count"], 1)

        code, out, err = self.run_cli(
            "approve", "--url", self.url, "--wallet-id", "w1",
            "--signing-request-id", "r1", "--approver-id", "bob",
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["state"], "approved")

        code, out, err = self.run_cli(
            "request-show", "--url", self.url, "--wallet-id", "w1",
            "--signing-request-id", "r1",
        )
        self.assertEqual(code, 0, err)
        body = json.loads(out)
        self.assertEqual(body["state"], "approved")
        self.assertEqual(body["approvers"], ["alice", "bob"])

    def test_reject_via_cli(self):
        self.run_cli(
            "policy", "--url", self.url, "--wallet-id", "w1",
            "--required-approvals", "1", "--timeout-seconds", "60",
        )
        self.run_cli(
            "request-create", "--url", self.url, "--wallet-id", "w1",
            "--signing-request-id", "r1", "--message", "m",
        )
        code, out, err = self.run_cli(
            "reject", "--url", self.url, "--wallet-id", "w1",
            "--signing-request-id", "r1", "--approver-id", "alice",
            "--reason", "no",
        )
        self.assertEqual(code, 0, err)
        body = json.loads(out)
        self.assertEqual(body["state"], "rejected")
        self.assertEqual(body["reason"], "no")

    def test_request_cancel_via_cli(self):
        self.run_cli(
            "policy", "--url", self.url, "--wallet-id", "w1",
            "--required-approvals", "1", "--timeout-seconds", "60",
        )
        self.run_cli(
            "request-create", "--url", self.url, "--wallet-id", "w1",
            "--signing-request-id", "r1", "--message", "m",
        )
        code, out, err = self.run_cli(
            "request-cancel", "--url", self.url, "--wallet-id", "w1",
            "--signing-request-id", "r1", "--cancel-id", "c1",
            "--reason", "cancel now",
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["state"], "cancelled")

    def test_cli_error_exit_1_json_on_stderr(self):
        # 无策略时创建请求：409 -> 退出码 1，stderr 为单行 JSON
        code, out, err = self.run_cli(
            "request-create", "--url", self.url, "--wallet-id", "w1",
            "--signing-request-id", "r1", "--message", "m",
        )
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error", json.loads(err))
        # 查询不存在的审批单
        code, _, err = self.run_cli(
            "request-show", "--url", self.url, "--wallet-id", "w1",
            "--signing-request-id", "ghost",
        )
        self.assertEqual(code, 1)
        self.assertIn("error", json.loads(err))
        # 策略参数非法（阈值越界 17）
        code, _, err = self.run_cli(
            "policy", "--url", self.url, "--wallet-id", "w1",
            "--required-approvals", "17", "--timeout-seconds", "60",
        )
        self.assertEqual(code, 1)
        self.assertIn("error", json.loads(err))


if __name__ == "__main__":
    unittest.main()
