"""审批工作流测试：策略、签名请求、批准/拒绝、超时与启用策略后的签名。

同时覆盖 service 直调、真实 HTTP 端到端与 CLI 子命令。
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import time
import unittest

from tests.helpers import http_server, make_harness
from threshold_wallet.cli import main as cli_main
from threshold_wallet.service import ServiceError

REQUEST_FIELDS = {
    "id", "message", "state", "approvers", "count", "req", "t0", "t1", "reason",
}


class ApprovalServiceTest(unittest.TestCase):
    def setUp(self):
        self.h = make_harness(tempfile.mkdtemp())
        self.s = self.h.service
        self.s.create_wallet("w", 2)

    def set_policy(self, required=2, timeout=1000):
        code, view = self.s.set_approval_policy("w", required, timeout)
        self.assertEqual(code, 200)
        return view

    # ---- 策略 -----------------------------------------------------------

    def test_policy_ok_for_1_and_2(self):
        self.assertEqual(self.s.set_approval_policy("w", 1, 5)[1],
                         {"required_approvals": 1, "timeout_seconds": 5})
        self.assertEqual(self.s.set_approval_policy("w", 2, 9)[1],
                         {"required_approvals": 2, "timeout_seconds": 9})

    def test_policy_invalid_values_are_400(self):
        for required, timeout in [
            (0, 10), (3, 10), (-1, 10), (True, 10), (False, 10),
            (1, 0), (1, -3), (1, 1.0), (2.0, 10), ("1", 10),
            (None, 10), (1, None), (1, "10"),
        ]:
            with self.assertRaises(ServiceError) as ctx:
                self.s.set_approval_policy("w", required, timeout)
            self.assertEqual(ctx.exception.status, 400, (required, timeout))

    def test_policy_unknown_wallet_is_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.s.set_approval_policy("ghost", 1, 10)
        self.assertEqual(ctx.exception.status, 404)

    # ---- 创建请求 -------------------------------------------------------

    def test_create_request_without_policy_is_409(self):
        with self.assertRaises(ServiceError) as ctx:
            self.s.create_sign_request("w", "r1", "m")
        self.assertEqual(ctx.exception.status, 409)

    def test_create_request_first_201_then_same_200_then_diff_409(self):
        self.set_policy()
        code, v = self.s.create_sign_request("w", "r1", "pay")
        self.assertEqual(code, 201)
        self.assertEqual(v["state"], "pending")
        self.assertEqual(v["id"], "r1")
        code2, v2 = self.s.create_sign_request("w", "r1", "pay")
        self.assertEqual(code2, 200)
        self.assertEqual(v2, v)
        with self.assertRaises(ServiceError) as ctx:
            self.s.create_sign_request("w", "r1", "other")
        self.assertEqual(ctx.exception.status, 409)

    def test_create_request_bad_fields_are_400(self):
        self.set_policy()
        for rid, message in [
            ("", "m"), ("   ", "m"), (123, "m"), (None, "m"),
            ("r", ""), ("r", "   "), ("r", 123), ("r", True),
            ("a/b", "m"), ("a b", "m"),
        ]:
            with self.assertRaises(ServiceError) as ctx:
                self.s.create_sign_request("w", rid, message)
            self.assertEqual(ctx.exception.status, 400, (rid, message))

    def test_create_request_unknown_wallet_is_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.s.create_sign_request("ghost", "r", "m")
        self.assertEqual(ctx.exception.status, 404)

    # ---- 查询 -----------------------------------------------------------

    def test_get_request_view_contract(self):
        self.set_policy(required=2)
        self.s.create_sign_request("w", "r1", "pay")
        v = self.s.get_sign_request("w", "r1")
        self.assertEqual(set(v), REQUEST_FIELDS)
        self.assertEqual(v["approvers"], [])
        self.assertEqual(v["count"], 0)
        self.assertEqual(v["req"], 2)
        self.assertIsNotNone(v["t0"])
        self.assertIsNone(v["t1"])
        self.assertIsNone(v["reason"])

    def test_get_missing_request_is_404(self):
        self.set_policy()
        with self.assertRaises(ServiceError) as ctx:
            self.s.get_sign_request("w", "nope")
        self.assertEqual(ctx.exception.status, 404)

    # ---- 批准/拒绝 ------------------------------------------------------

    def test_approve_duplicate_approver_not_counted_then_threshold(self):
        self.set_policy(required=2)
        self.s.create_sign_request("w", "r1", "m")
        v = self.s.approve("w", "r1", "alice")
        self.assertEqual((v["state"], v["count"]), ("pending", 1))
        v = self.s.approve("w", "r1", "alice")
        self.assertEqual((v["state"], v["count"]), ("pending", 1))
        v = self.s.approve("w", "r1", "bob")
        self.assertEqual((v["state"], v["count"]), ("approved", 2))
        self.assertIsNotNone(v["t1"])

    def test_single_approval_approves_immediately(self):
        self.set_policy(required=1)
        self.s.create_sign_request("w", "r1", "m")
        v = self.s.approve("w", "r1", "alice")
        self.assertEqual(v["state"], "approved")
        self.assertEqual(v["count"], 1)

    def test_reject_sets_rejected(self):
        self.set_policy()
        self.s.create_sign_request("w", "r1", "m")
        v = self.s.reject("w", "r1", "bob", "looks wrong")
        self.assertEqual(v["state"], "rejected")
        self.assertEqual(v["reason"], "looks wrong")
        self.assertIsNotNone(v["t1"])

    def test_reject_without_reason_keeps_null(self):
        self.set_policy()
        self.s.create_sign_request("w", "r1", "m")
        v = self.s.reject("w", "r1", "bob")
        self.assertIsNone(v["reason"])

    def test_operate_on_non_pending_is_409(self):
        self.set_policy()
        self.s.create_sign_request("w", "r1", "m")
        self.s.reject("w", "r1", "bob")
        with self.assertRaises(ServiceError) as ctx:
            self.s.reject("w", "r1", "alice")
        self.assertEqual(ctx.exception.status, 409)
        with self.assertRaises(ServiceError) as ctx:
            self.s.approve("w", "r1", "alice")
        self.assertEqual(ctx.exception.status, 409)

    def test_approve_missing_request_is_404(self):
        self.set_policy()
        with self.assertRaises(ServiceError) as ctx:
            self.s.approve("w", "nope", "alice")
        self.assertEqual(ctx.exception.status, 404)

    def test_approver_validation_400(self):
        self.set_policy()
        self.s.create_sign_request("w", "r1", "m")
        for bad in ["", "   ", 123, True, None, ["a"]]:
            with self.assertRaises(ServiceError) as ctx:
                self.s.approve("w", "r1", bad)
            self.assertEqual(ctx.exception.status, 400, repr(bad))

    def test_reason_validation_400(self):
        self.set_policy()
        self.s.create_sign_request("w", "r1", "m")
        for bad in [123, True, False, ["x"], {"a": 1}, "x" * 1025]:
            with self.assertRaises(ServiceError) as ctx:
                self.s.reject("w", "r1", "alice", bad)
            self.assertEqual(ctx.exception.status, 400, repr(bad))
        # 1024 字符合法
        v = self.s.create_sign_request("w", "r2", "m")
        self.assertEqual(v[0], 201)
        v = self.s.reject("w", "r2", "alice", "x" * 1024)
        self.assertEqual(v["state"], "rejected")

    # ---- 超时 -----------------------------------------------------------

    def test_pending_expires_and_persists(self):
        self.set_policy(required=2, timeout=1)
        self.s.create_sign_request("w", "r1", "m")
        time.sleep(1.05)
        v = self.s.get_sign_request("w", "r1")
        self.assertEqual(v["state"], "expired")
        self.assertIsNotNone(v["reason"])
        self.assertIsNotNone(v["t1"])
        # 翻转后落盘：新实例也读到 expired
        reopened = make_harness(self.h.tmpdir).service
        self.assertEqual(reopened.get_sign_request("w", "r1")["state"], "expired")
        # 已过期不能再批准
        with self.assertRaises(ServiceError) as ctx:
            self.s.approve("w", "r1", "alice")
        self.assertEqual(ctx.exception.status, 409)

    # ---- 启用策略后的签名 ----------------------------------------------

    def test_sign_requires_approved_request(self):
        self.set_policy(required=1)
        self.s.create_sign_request("w", "r1", "pay")
        sigs = self.h.two_signatures("w", "r1", "pay")
        # 仍是 pending -> 409
        with self.assertRaises(ServiceError) as ctx:
            self.s.sign("w", "r1", "pay", sigs)
        self.assertEqual(ctx.exception.status, 409)
        # 批准后 -> 201 且请求变 signed
        self.s.approve("w", "r1", "alice")
        code, resp = self.s.sign("w", "r1", "pay", sigs)
        self.assertEqual(code, 201)
        self.assertEqual(len(bytes.fromhex(resp["signature"])), 128)
        self.assertEqual(self.s.get_sign_request("w", "r1")["state"], "signed")
        # 重放 200
        code, resp2 = self.s.sign("w", "r1", "pay", sigs)
        self.assertEqual(code, 200)
        self.assertEqual(resp2, resp)

    def test_sign_message_must_match_request(self):
        self.set_policy(required=1)
        self.s.create_sign_request("w", "r1", "a")
        self.s.approve("w", "r1", "alice")
        with self.assertRaises(ServiceError) as ctx:
            self.s.sign("w", "r1", "b", self.h.two_signatures("w", "r1", "b"))
        self.assertEqual(ctx.exception.status, 409)

    def test_sign_unknown_request_is_409(self):
        self.set_policy(required=1)
        with self.assertRaises(ServiceError) as ctx:
            self.s.sign("w", "zzz", "m", self.h.two_signatures("w", "zzz", "m"))
        self.assertEqual(ctx.exception.status, 409)


class ApprovalHttpTest(unittest.TestCase):
    def setUp(self):
        self._ctx = http_server(tempfile.mkdtemp())
        self.srv = self._ctx.__enter__()
        self.url = self.srv.base_url

    def tearDown(self):
        self._ctx.__exit__(None, None, None)

    def request(self, method, path, body=None):
        return self.srv.request(method, path, body)

    def test_full_http_approval_flow(self):
        self.assertEqual(self.request("POST", "/v1/wallets",
                                      {"wallet_id": "w", "shares": 2})[0], 201)
        # 策略
        st, b = self.request("PUT", "/v1/wallets/w/approval-policy",
                             {"required_approvals": 2, "timeout_seconds": 1000})
        self.assertEqual(st, 200)
        self.assertEqual(b, {"required_approvals": 2, "timeout_seconds": 1000})
        self.assertEqual(self.request("PUT", "/v1/wallets/w/approval-policy",
                                      {"required_approvals": 3,
                                       "timeout_seconds": 10})[0], 400)
        self.assertEqual(self.request("PUT", "/v1/wallets/ghost/approval-policy",
                                      {"required_approvals": 1,
                                       "timeout_seconds": 10})[0], 404)
        # 请求
        self.assertEqual(self.request("POST", "/v1/wallets/w/sign-requests",
                                      {"id": "r1", "message": "pay"})[0], 201)
        self.assertEqual(self.request("POST", "/v1/wallets/w/sign-requests",
                                      {"id": "r1", "message": "pay"})[0], 200)
        self.assertEqual(self.request("POST", "/v1/wallets/w/sign-requests",
                                      {"id": "r1", "message": "x"})[0], 409)
        # 查询契约
        st, v = self.request("GET", "/v1/wallets/w/sign-requests/r1")
        self.assertEqual(st, 200)
        self.assertEqual(set(v), REQUEST_FIELDS)
        self.assertEqual(self.request("GET", "/v1/wallets/w/sign-requests/n")[0], 404)
        # 批准到达门槛
        self.request("POST", "/v1/wallets/w/sign-requests/r1/approve",
                     {"approver_id": "alice"})
        st, v = self.request("POST", "/v1/wallets/w/sign-requests/r1/approve",
                             {"approver_id": "alice"})
        self.assertEqual(v["count"], 1)
        st, v = self.request("POST", "/v1/wallets/w/sign-requests/r1/approve",
                             {"approver_id": "bob"})
        self.assertEqual(v["state"], "approved")
        self.assertEqual(self.request(
            "POST", "/v1/wallets/w/sign-requests/r1/approve",
            {"approver_id": "x"})[0], 409)
        # 校验类 400
        self.assertEqual(self.request(
            "POST", "/v1/wallets/w/sign-requests/r1/approve",
            {"approver_id": "  "})[0], 400)
        self.assertEqual(self.request(
            "POST", "/v1/wallets/w/sign-requests/r1/approve",
            {"approver_id": True})[0], 400)
        self.assertEqual(self.request(
            "POST", "/v1/wallets/w/sign-requests/r1/reject",
            {"approver_id": "a", "reason": 9})[0], 400)
        # 启用策略后签名 -> signed，重放 200
        body = {"signing_request_id": "r1", "message": "pay",
                "signatures": self.srv.harness.two_signatures("w", "r1", "pay")}
        self.assertEqual(self.request("POST", "/v1/wallets/w/sign", body)[0], 201)
        self.assertEqual(self.request("GET", "/v1/wallets/w/sign-requests/r1")[1][
            "state"], "signed")
        self.assertEqual(self.request("POST", "/v1/wallets/w/sign", body)[0], 200)

    def test_unknown_nested_routes_are_404(self):
        self.request("POST", "/v1/wallets", {"wallet_id": "w", "shares": 2})
        self.assertEqual(self.request("GET", "/v1/wallets/w/sign-requests")[0], 404)
        self.assertEqual(self.request(
            "POST", "/v1/wallets/w/sign-requests/r1/explode", {})[0], 404)
        self.assertEqual(self.request(
            "PUT", "/v1/wallets/w/other", {})[0], 404)


class ApprovalCliTest(unittest.TestCase):
    def setUp(self):
        self._ctx = http_server(tempfile.mkdtemp())
        self.srv = self._ctx.__enter__()
        self.url = self.srv.base_url

    def tearDown(self):
        self._ctx.__exit__(None, None, None)

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli_main(list(argv))
        return code, out.getvalue().strip(), err.getvalue().strip()

    @staticmethod
    def _json(text):
        return json.loads(text)

    def test_policy_request_approve_reject_cli(self):
        self.cli("create", "--url", self.url, "--wallet-id", "w", "--shares", "2")

        code, out, err = self.cli(
            "policy", "--url", self.url, "--wallet-id", "w",
            "--required-approvals", "2", "--timeout-seconds", "1000")
        self.assertEqual(code, 0, err)
        self.assertEqual(self._json(out)["required_approvals"], 2)

        code, _, err = self.cli(
            "policy", "--url", self.url, "--wallet-id", "w",
            "--required-approvals", "3", "--timeout-seconds", "10")
        self.assertEqual(code, 1)
        self.assertIn("error", self._json(err))

        code, out, _ = self.cli(
            "request-create", "--url", self.url, "--wallet-id", "w",
            "--id", "r1", "--message", "pay")
        self.assertEqual(code, 0)
        self.assertEqual(self._json(out)["state"], "pending")

        code, out, _ = self.cli(
            "request-show", "--url", self.url, "--wallet-id", "w", "--id", "r1")
        self.assertEqual(code, 0)
        self.assertEqual(set(self._json(out)), REQUEST_FIELDS)

        code, out, _ = self.cli(
            "approve", "--url", self.url, "--wallet-id", "w",
            "--id", "r1", "--approver-id", "alice")
        self.assertEqual(code, 0)
        self.assertEqual(self._json(out)["count"], 1)
        code, out, _ = self.cli(
            "approve", "--url", self.url, "--wallet-id", "w",
            "--id", "r1", "--approver-id", "bob")
        self.assertEqual(self._json(out)["state"], "approved")
        # 重复操作 -> stderr/1
        code, _, err = self.cli(
            "approve", "--url", self.url, "--wallet-id", "w",
            "--id", "r1", "--approver-id", "carol")
        self.assertEqual(code, 1)
        self.assertIn("error", self._json(err))

        # reject
        self.cli("request-create", "--url", self.url, "--wallet-id", "w",
                 "--id", "r2", "--message", "x")
        code, out, _ = self.cli(
            "reject", "--url", self.url, "--wallet-id", "w",
            "--id", "r2", "--approver-id", "dave", "--reason", "no")
        self.assertEqual(code, 0)
        self.assertEqual(self._json(out)["state"], "rejected")


if __name__ == "__main__":
    unittest.main()
