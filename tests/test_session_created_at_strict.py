"""签名会话 created_at 非 UTC/朴素时间必须 fail-closed 的回归测试。

README 持久化严格加载契约：expires_at/created_at 必须是可解析的 UTC
时间（拒绝朴素时间与非零偏移）。当前实现只校验 created_at 为字符串。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from tests.helpers import http_server
from threshold_wallet.service import WalletService
from threshold_wallet.store import RecoveryError, WalletStore


def _session_path(tmp: str) -> str:
    return os.path.join(tmp, "sign-sessions", "w1.json")


def _write(path: str, payload: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(payload)


class SessionCreatedAtStrictTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _seed_session(self) -> dict:
        svc = WalletService(WalletStore(self.tmp))
        svc.create_wallet("w1", 2)
        _status, view = svc.create_sign_session(
            "w1", "sess-1", "msg", 3600
        )
        with open(_session_path(self.tmp), encoding="utf-8") as f:
            return json.load(f)

    def test_naive_created_at_blocks_startup(self):
        data = self._seed_session()
        data["sess-1"]["created_at"] = "2026-09-20T00:00:00"  # 朴素时间
        raw = json.dumps(data)
        _write(_session_path(self.tmp), raw)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmp))
        # 现场保留
        with open(_session_path(self.tmp), encoding="utf-8") as f:
            self.assertEqual(f.read(), raw)

    def test_nonzero_offset_created_at_blocks_startup(self):
        data = self._seed_session()
        data["sess-1"]["created_at"] = "2026-09-20T03:00:00+03:00"
        raw = json.dumps(data)
        _write(_session_path(self.tmp), raw)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmp))

    def test_garbage_created_at_returns_503(self):
        with http_server(self.tmp) as srv:
            # 服务健康就绪后再由"他进程"损坏会话文件
            self.assertEqual(
                srv.request(
                    "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
                )[0],
                201,
            )
            self.assertEqual(
                srv.request(
                    "POST",
                    "/v1/wallets/w1/sign-sessions",
                    {"id": "sess-1", "message": "msg", "timeout_seconds": 3600},
                )[0],
                201,
            )
            with open(_session_path(self.tmp), encoding="utf-8") as f:
                data = json.load(f)
            data["sess-1"]["created_at"] = "not-a-time"
            raw = json.dumps(data)
            _write(_session_path(self.tmp), raw)
            status, body = srv.request(
                "GET", "/v1/wallets/w1/sign-sessions/sess-1"
            )
            self.assertEqual(status, 503, body)
            self.assertEqual(
                body, {"error": "service temporarily unavailable"}
            )
        with open(_session_path(self.tmp), encoding="utf-8") as f:
            self.assertEqual(f.read(), raw)


if __name__ == "__main__":
    unittest.main()
