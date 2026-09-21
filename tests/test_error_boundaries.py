"""share-sign 错误边界与全路由 503 fail-closed 回归测试。

覆盖任务契约：
- share-sign 的 WalletService 构造、懒恢复、读取当前份额与签名各阶段统一
  处理 RecoveryError/OSError/ValueError/损坏 JSON/非法私钥 hex：失败时
  stdout 为空、stderr 仅单行 JSON、退出码非零，无 traceback、不泄露私钥
  或签名载荷；成功只返回 share_id 与 signature；
- 所有访问钱包状态的 HTTP 路由（含审计查询）都在钱包事务锁内先自愈；
  无法安全对账或发生文件系统/解析异常时返回 JSON 503，不泄露半完成公钥、
  余额、version 或策略；
- 审计查询仍纯只读（不触发审批懒过期），但会在锁内自愈他进程崩溃残留，
  且自愈不新增事件；
- serve 启动遇跨切面状态文件损坏时以非零码拒绝就绪。
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest

from tests.helpers import http_server
from threshold_wallet.cli import main as cli_main
from threshold_wallet.service import RecoveryError, WalletService
from threshold_wallet.store import WalletStore


def _new_service(tmp: str) -> WalletService:
    return WalletService(WalletStore(tmp))


class ShareSignErrorBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc = _new_service(self.tmp)
        self.svc.create_wallet("w1", 2)
        self.store = WalletStore(self.tmp)
        self.share_path = os.path.join(self.tmp, "shares", "w1", "share-1.json")

    def _mutate_share(self, mutate):
        with open(self.share_path, encoding="utf-8") as f:
            rec = json.load(f)
        mutate(rec)
        with open(self.share_path, "w", encoding="utf-8") as f:
            json.dump(rec, f)

    def _run(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli_main(
                [
                    "share-sign",
                    "--data-dir", self.tmp,
                    "--wallet-id", "w1",
                    "--share-id", "share-1",
                    "--signing-request-id", "SECRET-RID",
                    "--message", "SECRET-MESSAGE",
                ]
            )
        return code, out.getvalue(), err.getvalue()

    def _assert_clean_failure(self, code, out, err):
        self.assertNotEqual(code, 0)
        self.assertEqual(out, "", "stdout must be empty on failure")
        lines = err.splitlines()
        self.assertEqual(len(lines), 1, err)
        body = json.loads(lines[0])
        self.assertIn("error", body)
        # 无 traceback、无私钥材料、无签名载荷
        self.assertNotIn("Traceback", err)
        self.assertNotIn("private_key", err)
        priv = self.store.get_share("w1", "share-2")["private_key"]
        self.assertNotIn(priv, err)
        self.assertNotIn("SECRET-MESSAGE", err)
        self.assertNotIn("SECRET-RID", err)

    def test_success_returns_only_share_id_and_signature(self):
        code, out, err = self._run()
        self.assertEqual(code, 0, err)
        body = json.loads(out.strip())
        self.assertEqual(set(body), {"share_id", "signature"})
        self.assertEqual(body["share_id"], "share-1")
        self.assertEqual(len(bytes.fromhex(body["signature"])), 64)
        self.assertEqual(err, "")

    def test_corrupt_share_json(self):
        with open(self.share_path, "w", encoding="utf-8") as f:
            f.write("{broken json")
        self._assert_clean_failure(*self._run())

    def test_private_key_not_hex(self):
        self._mutate_share(lambda rec: rec.update(private_key="zz-not-hex"))
        self._assert_clean_failure(*self._run())

    def test_private_key_wrong_length(self):
        self._mutate_share(lambda rec: rec.update(private_key="00" * 31))
        self._assert_clean_failure(*self._run())

    def test_private_key_missing(self):
        self._mutate_share(lambda rec: rec.update(private_key=None))
        self._assert_clean_failure(*self._run())

    def test_corrupt_share_record_is_not_object(self):
        with open(self.share_path, "w", encoding="utf-8") as f:
            json.dump(["not", "an", "object"], f)
        self._assert_clean_failure(*self._run())

    def test_corrupt_wallet_metadata(self):
        with open(
            os.path.join(self.tmp, "wallets", "w1.json"), "w", encoding="utf-8"
        ) as f:
            f.write("{broken")
        self._assert_clean_failure(*self._run())

    def test_service_raises_recovery_error_on_corruption(self):
        with open(self.share_path, "w", encoding="utf-8") as f:
            f.write("{broken")
        with self.assertRaises(RecoveryError):
            _new_service(self.tmp).share_sign(
                "w1", "share-1", "r", "m"
            )

    def test_unknown_share_is_service_404_not_traceback(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli_main(
                [
                    "share-sign", "--data-dir", self.tmp,
                    "--wallet-id", "w1", "--share-id", "share-9",
                    "--signing-request-id", "r", "--message", "m",
                ]
            )
        self.assertEqual(code, 1)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(len(err.getvalue().splitlines()), 1)
        self.assertNotIn("Traceback", err.getvalue())


#: 所有会读取钱包状态的 GET 路由
_GET_ROUTES = [
    "/v1/wallets/w1",
    "/v1/wallets/w1/audit-events",
    "/v1/wallets/w1/assets/btc",
    "/v1/wallets/w1/transaction-policy",
    "/v1/wallets/w1/sign-requests/r1",
    "/v1/wallets/w1/share-rotations/r1",
]

#: 会读取/变更钱包状态的 POST/PUT 路由（请求体无关紧要，恢复先于业务）
_WRITE_ROUTES = [
    ("POST", "/v1/wallets/w1/sign", {}),
    ("POST", "/v1/wallets/w1/sign-requests", {"id": "r1", "message": "m"}),
    ("POST", "/v1/wallets/w1/asset-operations",
     {"operation_id": "op1", "asset_id": "btc", "delta": 1}),
    ("POST", "/v1/wallets/w1/share-rotations", {"rotation_id": "r1"}),
    ("PUT", "/v1/wallets/w1/approval-policy",
     {"required_approvals": 1, "timeout_seconds": 60}),
    ("PUT", "/v1/wallets/w1/transaction-policy",
     {"mode": "hot", "max_delta": 10, "allowed_assets": ["btc"]}),
]


class AllRoutesFailClosedTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _start(self):
        return http_server(self.tmp)

    def _corrupt(self, *parts, text="{broken"):
        path = os.path.join(self.tmp, *parts)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)

    def _assert_generic_503(self, status, body):
        self.assertEqual(status, 503, body)
        self.assertEqual(body, {"error": "service temporarily unavailable"})
        # 不泄露半完成公钥/余额/version/策略/私钥
        blob = json.dumps(body)
        for secret_word in (
            "private", "public_key", "balance", "version",
            "allowed_assets", "max_delta",
        ):
            self.assertNotIn(secret_word, blob)

    def test_corrupt_audit_log_fails_every_route_closed(self):
        with self._start() as srv:
            srv.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
            self._corrupt("audit", "w1.json")
            for route in _GET_ROUTES:
                self._assert_generic_503(*srv.request("GET", route))
            for method, route, body in _WRITE_ROUTES:
                self._assert_generic_503(*srv.request(method, route, body))

    def test_corrupt_asset_ledger_fails_every_route_closed(self):
        with self._start() as srv:
            srv.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
            self._corrupt("assets", "w1.json", text="[1, 2, 3]")
            for route in _GET_ROUTES:
                self._assert_generic_503(*srv.request("GET", route))
            for method, route, body in _WRITE_ROUTES:
                self._assert_generic_503(*srv.request(method, route, body))

    def test_corrupt_wallet_metadata_is_503_not_404(self):
        with self._start() as srv:
            srv.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
            self._corrupt("wallets", "w1.json")
            self._assert_generic_503(
                *srv.request("GET", "/v1/wallets/w1")
            )

    def test_corrupt_signatures_and_requests_files_are_503(self):
        with self._start() as srv:
            srv.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
            self._corrupt("signatures", "w1.json")
            sig = "00" * 64
            body = {
                "signing_request_id": "r1",
                "message": "m",
                "signatures": [
                    {"share_id": "share-1", "signature": sig},
                    {"share_id": "share-2", "signature": sig},
                ],
            }
            self._assert_generic_503(
                *srv.request("POST", "/v1/wallets/w1/sign", body)
            )

    def test_corrupt_cross_cutting_and_feature_files_fail_closed(self):
        with self._start() as srv:
            srv.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})

            # 轮换记录是自愈必经的跨切面文件：损坏后任何钱包路由都 503。
            self._corrupt("rotations", "w1.json")
            self._assert_generic_503(
                *srv.request("GET", "/v1/wallets/w1/transaction-policy")
            )
            os.remove(os.path.join(self.tmp, "rotations", "w1.json"))

            # 审批策略文件损坏：读取/更新它的路由 503。
            self._corrupt("policies", "w1.json")
            self._assert_generic_503(
                *srv.request(
                    "PUT", "/v1/wallets/w1/approval-policy",
                    {"required_approvals": 1, "timeout_seconds": 60},
                )
            )
            os.remove(os.path.join(self.tmp, "policies", "w1.json"))

            # 审批单文件损坏：查询审批单 503。
            self._corrupt("requests", "w1.json")
            self._assert_generic_503(
                *srv.request(
                    "GET", "/v1/wallets/w1/sign-requests/r1"
                )
            )
            os.remove(os.path.join(self.tmp, "requests", "w1.json"))

            # 交易策略文件损坏：查询交易策略 503。
            self._corrupt("transaction-policies", "w1.json")
            self._assert_generic_503(
                *srv.request(
                    "GET", "/v1/wallets/w1/transaction-policy"
                )
            )

            # 不相关文件恢复后，GET 钱包回到正常 404/200 而非持续 503。
            status, _ = srv.request("GET", "/v1/wallets/w1")
            self.assertEqual(status, 200)

    def test_missing_wallet_still_404(self):
        with self._start() as srv:
            status, body = srv.request("GET", "/v1/wallets/ghost")
            self.assertEqual(status, 404)
            self.assertIn("error", body)
            status, _ = srv.request("GET", "/v1/wallets/ghost/audit-events")
            self.assertEqual(status, 404)


class AuditQueryHealsButStaysReadOnlyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.svc = _new_service(self.tmp)
        self.svc.create_wallet("w1", 2)

    def test_audit_get_self_heals_pending_commit_intent_without_events(self):
        store = WalletStore(self.tmp)
        # 一条 pending 操作，摆一个"他进程提交前"的意图（事件未落盘）。
        _, rec = self.svc.create_asset_operation("w1", "op1", "btc", 100)
        asset = store.get_asset("w1", "btc")
        intent = {
            "operation_id": "op1",
            "asset_id": "btc",
            "delta": 100,
            "old_asset": asset,
            "pending": rec,
            "new_balance": 100,
            "new_version": 1,
        }
        store.write_asset_commit_intent("w1", "op1", intent)

        # 审计查询在钱包锁内自愈：意图被对账回滚删除，操作仍 pending。
        result = self.svc.get_audit_events("w1")
        self.assertEqual(result["events"], [])
        self.assertIsNone(store.get_asset_commit_intent("w1", "op1"))
        self.assertEqual(
            store.get_asset_operation("w1", "op1")["state"], "pending"
        )

    def test_audit_get_does_not_trigger_request_expiry(self):
        from datetime import datetime, timedelta, timezone

        self.svc.put_policy("w1", 1, 3600)
        self.svc.create_sign_request("w1", "r1", "m")
        store = WalletStore(self.tmp)
        rec = store.get_request("w1", "r1")
        rec["t1"] = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat().replace("+00:00", "Z")
        store.update_request("w1", "r1", rec)

        # 纯只读：pending 单不被懒过期，也不产生任何新事件。
        before = self.svc.get_audit_events("w1")["events"]
        self.svc.get_audit_events("w1")
        self.assertEqual(store.get_request("w1", "r1")["state"], "pending")
        after = self.svc.get_audit_events("w1")["events"]
        self.assertEqual(after, before)
        self.assertFalse(
            any(e["type"] == "request_expired" for e in after)
        )


class ServeRefusesOnCorruptCrossCuttingStateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        _new_service(self.tmp).create_wallet("w1", 2)

    def _serve_code(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli_main(
                [
                    "serve", "--host", "127.0.0.1", "--port", "0",
                    "--data-dir", self.tmp,
                ]
            )
        return code, out.getvalue(), err.getvalue()

    def test_refuses_on_corrupt_audit_log(self):
        os.makedirs(os.path.join(self.tmp, "audit"), exist_ok=True)
        with open(os.path.join(self.tmp, "audit", "w1.json"), "w") as f:
            f.write("{broken")
        code, out, err = self._serve_code()
        self.assertNotEqual(code, 0)
        self.assertEqual(out, "")
        self.assertEqual(len(err.splitlines()), 1)
        self.assertIn("error", json.loads(err))

    def test_refuses_on_corrupt_asset_ledger(self):
        with open(os.path.join(self.tmp, "assets", "w1.json"), "w") as f:
            f.write("[1, 2, 3]")
        code, out, err = self._serve_code()
        self.assertNotEqual(code, 0)
        self.assertEqual(out, "")
        self.assertEqual(len(err.splitlines()), 1)
        self.assertIn("error", json.loads(err))


if __name__ == "__main__":
    unittest.main()
