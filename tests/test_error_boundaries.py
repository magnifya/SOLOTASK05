"""故障恢复错误边界与 share-sign 安全边界测试。

覆盖任务契约：
- share-sign 构造 WalletService、懒恢复、读取当前份额、签名四阶段统一处理
  RecoveryError/OSError/ValueError/损坏 JSON/非法私钥 hex：失败时 stdout 为
  空、stderr 仅一行 JSON、退出码非零，绝不出现 traceback、私钥或签名载荷；
  成功仍只返回 share_id 与 signature；
- 所有访问钱包状态的 HTTP 路由（含审计查询）都在钱包事务锁内先自愈；无法
  安全对账或发生文件系统/解析异常时返回 JSON 503，不暴露半完成公钥、余额、
  version 或策略；
- 审计查询纯只读：持锁自愈但不触发 pending 审批单懒过期；
- 审计查询与资产提交/轮换激活按钱包锁串行，不读到半完成状态。
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from tests.helpers import http_server
from threshold_wallet.cli import main as cli_main
from threshold_wallet.service import WalletService
from threshold_wallet.store import WalletStore


# ---- share-sign 错误边界 ---------------------------------------------------


class ShareSignErrorBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        WalletService(WalletStore(self.tmp)).create_wallet("w1", 2)
        self._share_path = os.path.join(
            self.tmp, "shares", "w1", "share-1.json"
        )
        self._wallet_path = os.path.join(self.tmp, "wallets", "w1.json")

    def _run(self, share_id="share-1", message="SECRET-PAYLOAD-Z9"):
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(
                err
            ):
                code = cli_main(
                    [
                        "share-sign",
                        "--data-dir", self.tmp,
                        "--wallet-id", "w1",
                        "--share-id", share_id,
                        "--signing-request-id", "req-1",
                        "--message", message,
                    ]
                )
            return ("returned", code, out.getvalue(), err.getvalue())
        except BaseException as exc:  # 不应有任何 traceback 逃逸
            return ("traceback:" + type(exc).__name__, None,
                    out.getvalue(), err.getvalue())

    def _rewrite_share(self, record):
        with open(self._share_path, "w", encoding="utf-8") as f:
            json.dump(record, f)

    def _assert_failure(self, result):
        kind, code, out, err = result
        self.assertEqual(kind, "returned", "不得逃逸出未捕获异常/traceback")
        self.assertNotEqual(code, 0)
        # stdout 必须为空
        self.assertEqual(out, "")
        # stderr 恰一行、可解析为 JSON 且只含 error
        lines = [l for l in err.splitlines() if l.strip()]
        self.assertEqual(len(lines), 1, err)
        payload = json.loads(lines[0])
        self.assertEqual(set(payload), {"error"})
        # 绝不泄露签名载荷或私钥
        self.assertNotIn("SECRET-PAYLOAD-Z9", err)
        priv = WalletStore(self.tmp).get_share("w1", "share-2")["private_key"]
        self.assertNotIn(priv, err)
        self.assertNotIn("private_key", err)
        self.assertNotIn("Traceback", err)
        return payload

    def test_success_returns_only_share_id_and_signature(self):
        kind, code, out, err = result = self._run()
        self.assertEqual(kind, "returned")
        self.assertEqual(code, 0, err)
        body = json.loads(out)
        self.assertEqual(set(body), {"share_id", "signature"})
        self.assertEqual(body["share_id"], "share-1")
        self.assertEqual(len(bytes.fromhex(body["signature"])), 64)
        self.assertEqual(err, "")

    def test_corrupt_json_share_file(self):
        with open(self._share_path, "w", encoding="utf-8") as f:
            f.write("{broken")
        self._assert_failure(self._run())

    def test_non_object_share_file(self):
        with open(self._share_path, "w", encoding="utf-8") as f:
            f.write("[1,2,3]")
        self._assert_failure(self._run())

    def test_missing_private_key_field(self):
        with open(self._share_path, encoding="utf-8") as f:
            record = json.load(f)
        del record["private_key"]
        self._rewrite_share(record)
        self._assert_failure(self._run())

    def test_non_hex_private_key(self):
        with open(self._share_path, encoding="utf-8") as f:
            record = json.load(f)
        record["private_key"] = "zz-not-hex"
        self._rewrite_share(record)
        self._assert_failure(self._run())

    def test_wrong_length_private_key(self):
        with open(self._share_path, encoding="utf-8") as f:
            record = json.load(f)
        record["private_key"] = "00" * 31  # 31 字节
        self._rewrite_share(record)
        self._assert_failure(self._run())

    def test_private_key_mismatches_public_key(self):
        with open(self._share_path, encoding="utf-8") as f:
            record = json.load(f)
        record["private_key"] = "11" * 32  # 合法 32B，但不对应公钥
        self._rewrite_share(record)
        # 不得基于与公钥不一致的私钥签名
        self._assert_failure(self._run())

    def test_share_public_key_mismatches_wallet_meta(self):
        # 份额记录内部自洽，但其公钥与钱包元数据中在用公钥不一致
        from threshold_wallet import crypto

        key = crypto.generate_share_key("share-1")
        self._rewrite_share(
            {
                "share_id": "share-1",
                "public_key": key.public_bytes.hex(),
                "private_key": key.private_bytes.hex(),
            }
        )
        self._assert_failure(self._run())

    def test_corrupt_wallet_meta(self):
        with open(self._wallet_path, "w", encoding="utf-8") as f:
            f.write("{broken")
        self._assert_failure(self._run())

    def test_unknown_share_is_plain_404_message(self):
        kind, code, out, err = self._run(share_id="share-9")
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("not found", json.loads(err)["error"])


# ---- HTTP 503 错误边界 -----------------------------------------------------


class HttpStateErrorBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _wallet_public(self):
        return WalletStore(self.tmp).get_wallet("w1")["public_key"]

    def test_corrupt_wallet_meta_returns_generic_503_on_state_routes(self):
        with http_server(self.tmp) as srv:
            self.assertEqual(
                srv.request("POST", "/v1/wallets",
                            {"wallet_id": "w1", "shares": 2})[0],
                201,
            )
            public_key = self._wallet_public()
            with open(
                os.path.join(self.tmp, "wallets", "w1.json"), "w"
            ) as f:
                f.write("{broken")

            paths = (
                "/v1/wallets/w1",
                "/v1/wallets/w1/audit-events",
                "/v1/wallets/w1/transaction-policy",
                "/v1/wallets/w1/assets/btc",
                "/v1/wallets/w1/share-rotations/rot-1",
                "/v1/wallets/w1/sign-requests/req-1",
            )
            for path in paths:
                status, body = srv.request("GET", path)
                self.assertEqual(status, 503, (path, body))
                blob = json.dumps(body)
                # 泛化文案，不暴露半完成公钥
                self.assertEqual(body, {"error": "service temporarily unavailable"})
                self.assertNotIn(public_key, blob)

    def test_corrupt_audit_log_makes_audit_query_503(self):
        with http_server(self.tmp) as srv:
            srv.request("POST", "/v1/wallets",
                        {"wallet_id": "w1", "shares": 2})
            os.makedirs(os.path.join(self.tmp, "audit"), exist_ok=True)
            with open(os.path.join(self.tmp, "audit", "w1.json"), "w") as f:
                f.write("{broken")
            status, body = srv.request("GET", "/v1/wallets/w1/audit-events")
            self.assertEqual(status, 503)
            self.assertEqual(body, {"error": "service temporarily unavailable"})
            # 不依赖审计日志的路由仍可用
            self.assertEqual(srv.request("GET", "/v1/wallets/w1")[0], 200)

    def test_filesystem_error_on_write_route_is_generic_503(self):
        with http_server(self.tmp) as srv:
            srv.request("POST", "/v1/wallets",
                        {"wallet_id": "w1", "shares": 2})

            def boom(*_a, **_k):
                raise OSError("audit disk full")

            srv.harness.service._audit.append_event = boom
            status, body = srv.request(
                "PUT",
                "/v1/wallets/w1/approval-policy",
                {"required_approvals": 1, "timeout_seconds": 60},
            )
            self.assertEqual(status, 503)
            self.assertEqual(body, {"error": "service temporarily unavailable"})

    def test_malformed_shape_policy_returns_503_not_500(self):
        with http_server(self.tmp) as srv:
            srv.request("POST", "/v1/wallets",
                        {"wallet_id": "w1", "shares": 2})
            srv.request(
                "PUT", "/v1/wallets/w1/transaction-policy",
                {"mode": "hot", "max_delta": 5, "allowed_assets": ["btc"]},
            )
            # JSON 可解析但形状残缺（缺 max_delta/allowed_assets）：属于
            # 无法安全对账的数据损坏，必须 503，绝不抛 traceback/断连。
            with open(
                os.path.join(
                    self.tmp, "transaction-policies", "w1.json"
                ),
                "w",
            ) as f:
                f.write('{"mode": "hot"}')
            status, body = srv.request(
                "GET", "/v1/wallets/w1/transaction-policy"
            )
            self.assertEqual(status, 503)
            self.assertEqual(body, {"error": "service temporarily unavailable"})

    def test_malformed_shape_request_returns_503(self):
        with http_server(self.tmp) as srv:
            srv.request("POST", "/v1/wallets",
                        {"wallet_id": "w1", "shares": 2})
            srv.request(
                "PUT", "/v1/wallets/w1/approval-policy",
                {"required_approvals": 1, "timeout_seconds": 60},
            )
            srv.request(
                "POST", "/v1/wallets/w1/sign-requests",
                {"id": "r1", "message": "m"},
            )
            with open(os.path.join(self.tmp, "requests", "w1.json"), "w") as f:
                f.write('{"r1": {"id": "r1"}}')
            status, body = srv.request(
                "GET", "/v1/wallets/w1/sign-requests/r1"
            )
            self.assertEqual(status, 503)
            self.assertEqual(body, {"error": "service temporarily unavailable"})


# ---- 审计查询：持锁自愈 + 纯只读 -------------------------------------------


class AuditReadSelfHealTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _plant_uncommitted_activation_with_backup(self):
        """换入已发生、事件未落盘但备份完整的崩溃现场（可安全回滚）。"""
        store = WalletStore(self.tmp)
        record = store.get_rotation("w1", "rot-1")
        wallet = store.get_wallet("w1")
        old = [
            store.get_share("w1", s["share_id"]) for s in wallet["shares"]
        ]
        activating = dict(record)
        activating["state"] = "activating"
        activating["previous_public_key"] = wallet["public_key"]
        store.update_rotation("w1", "rot-1", activating)
        store.save_activation_backups("w1", "rot-1", old, wallet)
        new = [
            store.get_staging_share("w1", "rot-1", sid)
            for sid in record["share_ids"]
        ]
        for rec in new:
            store.save_share("w1", rec)
        meta = dict(wallet)
        meta["shares"] = [
            {"share_id": r["share_id"], "public_key": r["public_key"]}
            for r in new
        ]
        meta["public_key"] = record["public_key"]
        store.save_wallet_meta("w1", meta)
        for rec in old:
            store.delete_share("w1", rec["share_id"])

    def test_audit_query_self_heals_inside_lock_without_new_events(self):
        with http_server(self.tmp) as srv:
            # 常驻服务先就绪
            self.assertEqual(
                srv.request("POST", "/v1/wallets",
                            {"wallet_id": "w1", "shares": 2})[0],
                201,
            )
            self.assertEqual(
                srv.request(
                    "POST", "/v1/wallets/w1/share-rotations",
                    {"rotation_id": "rot-1"},
                )[0],
                201,
            )
            # 他进程在服务运行期间摆出未提交（备份完整）的激活崩溃现场
            self._plant_uncommitted_activation_with_backup()

            # 审计查询在钱包事务锁内先自愈：现场回滚为 prepared
            status, body = srv.request("GET", "/v1/wallets/w1/audit-events")
            self.assertEqual(status, 200, body)
            self.assertEqual(
                [e["type"] for e in body["events"]],
                ["share_rotation_prepared"],
            )
            status, rot = srv.request(
                "GET", "/v1/wallets/w1/share-rotations/rot-1"
            )
            self.assertEqual(rot["state"], "prepared")
            # 自愈不重复/新增事件
            status, body2 = srv.request("GET", "/v1/wallets/w1/audit-events")
            self.assertEqual(
                [e["seq"] for e in body2["events"]],
                [e["seq"] for e in body["events"]],
            )

    def test_audit_query_does_not_trigger_lazy_expiry(self):
        with http_server(self.tmp) as srv:
            srv.request("POST", "/v1/wallets",
                        {"wallet_id": "w1", "shares": 2})
            srv.request(
                "PUT", "/v1/wallets/w1/approval-policy",
                {"required_approvals": 1, "timeout_seconds": 3600},
            )
            srv.request(
                "POST", "/v1/wallets/w1/sign-requests",
                {"id": "req-1", "message": "m"},
            )
            # 把 t1 改到过去（磁盘上仍是 pending）
            store = srv.harness.store
            rec = store.get_request("w1", "req-1")
            rec = dict(rec)
            rec["t1"] = (
                datetime.now(timezone.utc) - timedelta(seconds=1)
            ).isoformat().replace("+00:00", "Z")
            store.update_request("w1", "req-1", rec)

            # 审计查询是纯只读：不触发懒过期
            srv.request("GET", "/v1/wallets/w1/audit-events")
            self.assertEqual(
                store.get_request("w1", "req-1")["state"], "pending"
            )
            # 不产生 request_expired 事件
            _, body = srv.request("GET", "/v1/wallets/w1/audit-events")
            self.assertNotIn(
                "request_expired", [e["type"] for e in body["events"]]
            )


if __name__ == "__main__":
    unittest.main()
