"""资产账本 / 提交意图损坏时 fail-closed 的回归测试。

覆盖任务契约：
- assets/<wallet_id>.json 存在但 JSON 损坏、顶层不是对象、缺少 operations
  或 assets、两者类型错误、资产条目 balance/version 不是非布尔整数、操作
  条目缺合法 operation_id/asset_id/delta/state（state 仅 pending/committed）
  时，任何资产创建、提交、查询、审计读取与启动/持锁恢复都必须 fail-closed：
  统一 503 JSON / RecoveryError 阻止就绪，绝不把文件归一为空、覆盖或删除；
- asset-intents 中存在损坏 JSON、非对象或缺少恢复所需标识与整数时，
  保留现场并阻止就绪或返回 503，不能转成空意图继续提交、回滚或清理；
- 完整且合法的账本/意图行为不变（幂等、恢复、连续 seq）。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from tests.helpers import http_server
from threshold_wallet import audit as audit_mod
from threshold_wallet.audit import AuditStore
from threshold_wallet.service import WalletService
from threshold_wallet.store import CorruptDataError, RecoveryError, WalletStore


LEDGER = lambda d: os.path.join(d, "assets", "w1.json")
INTENT = lambda d, op="op1": os.path.join(
    d, "asset-intents", "w1", op + ".json"
)


def _write(path: str, payload: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(payload)


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def _seed(tmp: str) -> WalletService:
    svc = WalletService(WalletStore(tmp))
    svc.create_wallet("w1", 2)
    return svc


# ---- 存储层严格校验 --------------------------------------------------------


class LedgerShapeValidationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.store = WalletStore(self.tmp)

    def test_missing_ledger_is_normal_empty(self):
        # 文件尚不存在必须被视为正常空状态，而不是损坏
        self.store.check_asset_ledger("w1")
        self.assertEqual(
            self.store._read_asset_ledger("w1"),
            {"operations": {}, "assets": {}},
        )

    def test_corrupt_payloads_raise(self):
        bad_payloads = [
            "{broken",                          # JSON 损坏
            "[1, 2, 3]",                        # 顶层非对象
            "42",                               # 顶层非对象
            '{"operations": {}}',               # 缺 assets
            '{"assets": {}}',                   # 缺 operations
            '{"operations": [], "assets": {}}', # operations 类型错误
            '{"operations": {}, "assets": []}', # assets 类型错误
            # 资产条目 balance/version 非法
            '{"operations": {}, "assets": {"btc": {"balance": 1}}}',
            '{"operations": {}, "assets": {"btc": '
            '{"balance": true, "version": 1}}}',
            '{"operations": {}, "assets": {"btc": '
            '{"balance": 1.5, "version": 1}}}',
            '{"operations": {}, "assets": {"btc": '
            '{"balance": "1", "version": 1}}}',
            '{"operations": {}, "assets": {"btc": '
            '{"balance": 1, "version": false}}}',
            # 操作条目字段非法
            '{"operations": {"op1": {"asset_id": "btc", '
            '"delta": 5, "state": "pending"}}, "assets": {}}',
            '{"operations": {"op1": {"operation_id": "op1", '
            '"asset_id": "btc", "delta": 0, "state": "pending"}}, '
            '"assets": {}}',
            '{"operations": {"op1": {"operation_id": "op1", '
            '"asset_id": "btc", "delta": true, "state": "pending"}}, '
            '"assets": {}}',
            '{"operations": {"op1": {"operation_id": "op1", '
            '"asset_id": "btc", "delta": 5, "state": "weird"}}, '
            '"assets": {}}',
            '{"operations": {"op1": {"operation_id": "OTHER", '
            '"asset_id": "btc", "delta": 5, "state": "pending"}}, '
            '"assets": {}}',
        ]
        for payload in bad_payloads:
            _write(LEDGER(self.tmp), payload)
            with self.subTest(payload=payload):
                with self.assertRaises(CorruptDataError):
                    self.store.check_asset_ledger("w1")

    def test_valid_ledger_shapes_pass(self):
        good_payloads = [
            '{"operations": {}, "assets": {}}',
            '{"operations": {"op1": {"operation_id": "op1", '
            '"asset_id": "btc", "delta": 5, "state": "pending", '
            '"balance": 0, "version": 0}}, "assets": {}}',
            '{"operations": {"op1": {"operation_id": "op1", '
            '"asset_id": "btc", "delta": -3, "state": "committed", '
            '"balance": 7, "version": 2}}, '
            '"assets": {"btc": {"balance": 7, "version": 2}}}',
        ]
        for payload in good_payloads:
            _write(LEDGER(self.tmp), payload)
            with self.subTest(payload=payload):
                self.store.check_asset_ledger("w1")  # 不抛即可


# ---- 账本损坏：创建/提交/查询/审计全部 503，现场不动 -----------------------


class CorruptLedgerHttpFailClosedTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _corrupt(self, payload):
        _write(LEDGER(self.tmp), payload)

    def test_all_state_routes_return_503_and_preserve_file(self):
        with http_server(self.tmp) as srv:
            self.assertEqual(
                srv.request(
                    "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
                )[0],
                201,
            )
            self.assertEqual(
                srv.request(
                    "POST",
                    "/v1/wallets/w1/asset-operations",
                    {"operation_id": "op1", "asset_id": "btc", "delta": 100},
                )[0],
                201,
            )
            for payload in ("{broken", "[1,2]", '{"operations": {}}',
                            '{"operations": {}, "assets": {"btc": '
                            '{"balance": true, "version": 1}}}'):
                self._corrupt(payload)
                requests_ = [
                    ("GET", "/v1/wallets/w1/assets/btc", None),
                    ("POST", "/v1/wallets/w1/asset-operations",
                     {"operation_id": "op9", "asset_id": "btc", "delta": 1}),
                    ("POST",
                     "/v1/wallets/w1/asset-operations/op1/commit", None),
                    ("GET", "/v1/wallets/w1/audit-events", None),
                ]
                for method, path, body in requests_:
                    status, resp = srv.request(method, path, body)
                    self.assertEqual(
                        status, 503, (payload, path, status, resp)
                    )
                    self.assertEqual(
                        resp,
                        {"error": "service temporarily unavailable"},
                        (payload, path, resp),
                    )
                # 文件必须原样保留：绝未被归一为空、覆盖或删除
                self.assertEqual(
                    _read(LEDGER(self.tmp)), payload
                )

    def test_healthy_wallet_without_ledger_still_works(self):
        # 从未产生账本文件的钱包不应受影响（文件不存在即正常空状态）
        with http_server(self.tmp) as srv:
            self.assertEqual(
                srv.request(
                    "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
                )[0],
                201,
            )
            status, body = srv.request(
                "POST",
                "/v1/wallets/w1/asset-operations",
                {"operation_id": "op1", "asset_id": "btc", "delta": 100},
            )
            self.assertEqual(status, 201, body)
            self.assertEqual(
                (body["balance"], body["version"]), (0, 0)
            )


# ---- 账本损坏：启动恢复阻止就绪 --------------------------------------------


class CorruptLedgerStartupBlocksTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_constructor_blocks_readiness(self):
        _seed(self.tmp).create_asset_operation("w1", "op1", "btc", 100)
        _write(LEDGER(self.tmp), "{broken")
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmp))
        # 现场保留
        self.assertEqual(
            _read(LEDGER(self.tmp)), "{broken"
        )

    def test_serve_cli_refuses_to_start(self):
        from threshold_wallet import cli

        _seed(self.tmp).create_asset_operation("w1", "op1", "btc", 100)
        _write(LEDGER(self.tmp), '{"operations": [], "assets": {}}')
        code = cli.main(
            ["serve", "--host", "127.0.0.1", "--port", "0",
             "--data-dir", self.tmp]
        )
        self.assertNotEqual(code, 0)


# ---- 提交意图损坏：保留现场、阻止就绪 / 返回 503 ---------------------------


class CorruptIntentFailClosedTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _pending(self, operation_id="op1", delta=100):
        svc = _seed(self.tmp)
        svc.create_asset_operation("w1", operation_id, "btc", delta)
        return svc

    def test_bad_intent_payloads_block_startup_and_are_preserved(self):
        bad_intents = [
            "{broken",
            "[1, 2, 3]",
            json.dumps({"operation_id": "op1"}),          # 缺标识/整数
            json.dumps(
                {  # pending 损坏（缺 delta/state）
                    "operation_id": "op1",
                    "asset_id": "btc",
                    "delta": 100,
                    "new_balance": 100,
                    "new_version": 1,
                    "old_asset": None,
                    "pending": {"operation_id": "op1"},
                }
            ),
            json.dumps(
                {  # new_balance 为布尔
                    "operation_id": "op1",
                    "asset_id": "btc",
                    "delta": 100,
                    "new_balance": True,
                    "new_version": 1,
                    "old_asset": None,
                    "pending": {
                        "operation_id": "op1",
                        "asset_id": "btc",
                        "delta": 100,
                        "state": "pending",
                        "balance": 0,
                        "version": 0,
                    },
                }
            ),
        ]
        for raw in bad_intents:
            d = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, d, ignore_errors=True)
            WalletService(WalletStore(d)).create_wallet("w1", 2)
            WalletService(WalletStore(d)).create_asset_operation(
                "w1", "op1", "btc", 100
            )
            _write(INTENT(d), raw)
            with self.subTest(raw=raw):
                with self.assertRaises(RecoveryError):
                    WalletService(WalletStore(d))
                # 意图现场原样保留，账本未被回滚/覆盖/删除
                self.assertEqual(
                    _read(INTENT(d)), raw
                )

    def test_runtime_corrupt_intent_pending_returns_503_and_keeps_scene(self):
        raw = "{broken"
        with http_server(self.tmp) as srv:
            # 服务健康就绪后先建出 pending 操作，再由"他进程"摆出损坏意图
            self.assertEqual(
                srv.request(
                    "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
                )[0],
                201,
            )
            self.assertEqual(
                srv.request(
                    "POST",
                    "/v1/wallets/w1/asset-operations",
                    {"operation_id": "op1", "asset_id": "btc", "delta": 100},
                )[0],
                201,
            )
            _write(INTENT(self.tmp), raw)  # 账本仍 pending、无事件
            for method, path, body in [
                ("POST",
                 "/v1/wallets/w1/asset-operations/op1/commit", None),
                ("GET", "/v1/wallets/w1/assets/btc", None),
                ("POST", "/v1/wallets/w1/asset-operations",
                 {"operation_id": "op2", "asset_id": "btc", "delta": 1}),
                ("GET", "/v1/wallets/w1/audit-events", None),
            ]:
                status, resp = srv.request(method, path, body)
                self.assertEqual(status, 503, (path, status, resp))
            # 损坏意图绝不被当成空意图清理，pending 账本不被改动
            self.assertTrue(os.path.exists(INTENT(self.tmp)))
            self.assertEqual(
                _read(INTENT(self.tmp)), raw
            )
            self.assertEqual(
                WalletStore(self.tmp)
                .get_asset_operation("w1", "op1")["state"],
                "pending",
            )

    def test_corrupt_intent_with_event_still_fail_closed(self):
        # 即使 committed 事件已落盘，损坏意图也必须保留现场并 fail-closed，
        # 绝不借前滚之名把损坏意图删除。
        svc = self._pending()
        store = WalletStore(self.tmp)
        committed = {
            "operation_id": "op1",
            "asset_id": "btc",
            "state": "committed",
            "delta": 100,
            "balance": 100,
            "version": 1,
        }
        store.commit_asset_operation(
            "w1", "op1", committed, "btc",
            {"balance": 100, "version": 1},
        )
        AuditStore(self.tmp).append_event(
            "w1",
            {
                "type": audit_mod.TYPE_ASSET_OPERATION_COMMITTED,
                "at": "2026-09-20T00:00:00Z",
                "request_id": "op1",
                "actor_id": None,
                "reason": None,
                "details": committed,
            },
        )
        raw = "{broken"
        _write(INTENT(self.tmp), raw)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmp))
        self.assertEqual(
            _read(INTENT(self.tmp)), raw
        )

    def test_no_new_business_event_or_private_leak_on_failure(self):
        raw = "{broken"
        with http_server(self.tmp) as srv:
            self.assertEqual(
                srv.request(
                    "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
                )[0],
                201,
            )
            self.assertEqual(
                srv.request(
                    "POST",
                    "/v1/wallets/w1/asset-operations",
                    {"operation_id": "op1", "asset_id": "btc", "delta": 100},
                )[0],
                201,
            )
            _write(INTENT(self.tmp), raw)
            status, body = srv.request(
                "GET", "/v1/wallets/w1/audit-events"
            )
            self.assertEqual(status, 503)
            # 失败响应不含任何私钥/份额材料
            self.assertNotIn("private", json.dumps(body))
        # 恢复失败期间没有产生任何事件文件内容（无事件写入）
        audit_path = os.path.join(self.tmp, "audit", "w1.json")
        if os.path.exists(audit_path):
            self.assertNotIn(
                "asset_operation_committed",
                _read(audit_path),
            )


# ---- 合法账本/意图的既有语义保持不变（抽样）--------------------------------


class HealthySemanticsUnchangedTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_valid_intent_without_event_still_rolls_back(self):
        # 形状完整的意图 + 账本 pending、无事件：仍按既有语义安全回滚清理
        svc = _seed(self.tmp)
        svc.create_asset_operation("w1", "op1", "btc", 100)
        store = WalletStore(self.tmp)
        pending = store.get_asset_operation("w1", "op1")
        store.write_asset_commit_intent(
            "w1",
            "op1",
            {
                "operation_id": "op1",
                "asset_id": "btc",
                "delta": 100,
                "old_asset": None,
                "pending": pending,
                "new_balance": 100,
                "new_version": 1,
            },
        )
        WalletService(WalletStore(self.tmp))  # 启动恢复
        self.assertFalse(os.path.exists(INTENT(self.tmp)))
        self.assertEqual(
            store.get_asset_operation("w1", "op1")["state"], "pending"
        )
        self.assertIsNone(store.get_asset("w1", "btc"))


if __name__ == "__main__":
    unittest.main()
