"""安全审计测试：磁盘、响应、日志中都不得存在"完整私钥"。

完整私钥在这里定义为两个 32 字节份额私钥的拼接（64 字节）。系统只保存
两个彼此独立的份额：每个文件至多含一个份额私钥，任何位置都不出现两者
的拼接。
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from tests.helpers import http_server


def _iter_files(root: str):
    for base, _, files in os.walk(root):
        for name in files:
            yield os.path.join(base, name)


def _collect_private_keys(obj, found: list):
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == "private_key" and isinstance(value, str):
                found.append(value)
            else:
                _collect_private_keys(value, found)
    elif isinstance(obj, list):
        for item in obj:
            _collect_private_keys(item, found)


class NoFullPrivateKeyTest(unittest.TestCase):
    def setUp(self):
        self._ctx = http_server(tempfile.mkdtemp())
        self.srv = self._ctx.__enter__()
        self.data_dir = self.srv.harness.tmpdir
        # 建钱包 + 完成一次签名，触发所有类型的落盘文件
        self.srv.request(
            "POST", "/v1/wallets", {"wallet_id": "w-audit", "shares": 2}
        )
        body = {
            "signing_request_id": "r1",
            # 独特标记：只存在于 message，绝不出现在任何 URL 路径中
            "message": "PAYLOAD-SECRET-ZX9Q-MARKER",
            "signatures": self.srv.harness.two_signatures(
                "w-audit", "r1", "PAYLOAD-SECRET-ZX9Q-MARKER"
            ),
        }
        self.srv.request("POST", "/v1/wallets/w-audit/sign", body)
        self.srv.request("GET", "/v1/wallets/w-audit")

        # 同时产生资产操作单与资产余额文件，使其纳入全盘私钥扫描
        self.srv.request(
            "POST",
            "/v1/wallets/w-audit/asset-operations",
            {"operation_id": "aop-1", "asset_id": "USD", "delta": 100},
        )
        self.srv.request(
            "POST", "/v1/wallets/w-audit/asset-operations/aop-1/commit"
        )
        self.srv.request("GET", "/v1/wallets/w-audit/assets/USD")

        self.priv1 = self.srv.harness.share_private_hex("w-audit", "share-1")
        self.priv2 = self.srv.harness.share_private_hex("w-audit", "share-2")

    def tearDown(self):
        self._ctx.__exit__(None, None, None)

    def test_no_file_contains_concatenated_full_private_key(self):
        # 64 字节完整私钥的两种排列都不得出现在任何磁盘文件中
        full_ab = self.priv1 + self.priv2
        full_ba = self.priv2 + self.priv1
        for path in _iter_files(self.data_dir):
            with open(path, "rb") as f:
                raw = f.read()
            self.assertNotIn(full_ab.encode(), raw, path)
            self.assertNotIn(full_ba.encode(), raw, path)

    def test_each_file_holds_at_most_one_share_private_key(self):
        for path in _iter_files(self.data_dir):
            with open(path, encoding="utf-8") as f:
                record = json.load(f)
            found: list = []
            _collect_private_keys(record, found)
            self.assertLessEqual(len(found), 1, path)
            for priv_hex in found:
                # 每个私钥都恰为 32 字节份额，不是 64 字节聚合
                self.assertEqual(len(priv_hex), 64, path)

    def test_share_private_keys_live_in_distinct_files(self):
        locations = {self.priv1: [], self.priv2: []}
        for path in _iter_files(self.data_dir):
            with open(path, "rb") as f:
                raw = f.read()
            if self.priv1.encode() in raw:
                locations[self.priv1].append(path)
            if self.priv2.encode() in raw:
                locations[self.priv2].append(path)
        self.assertEqual(len(locations[self.priv1]), 1)
        self.assertEqual(len(locations[self.priv2]), 1)
        self.assertNotEqual(locations[self.priv1], locations[self.priv2])

    def test_metadata_file_has_no_private_material(self):
        with open(
            os.path.join(self.data_dir, "wallets", "w-audit.json"),
            encoding="utf-8",
        ) as f:
            raw = f.read()
        self.assertNotIn(self.priv1, raw)
        self.assertNotIn(self.priv2, raw)
        self.assertNotIn("private", raw)

    def test_logs_contain_no_private_material_or_bodies(self):
        log_blob = "\n".join(self.srv.logs)
        self.assertNotIn(self.priv1, log_blob)
        self.assertNotIn(self.priv2, log_blob)
        # message 内容也不应入日志（该标记只存在于 message 中）
        self.assertNotIn("PAYLOAD-SECRET-ZX9Q-MARKER", log_blob)

    def test_share_files_contain_no_unexpected_secret_fields(self):
        # 份额文件只允许：share_id / public_key / private_key
        share_dir = os.path.join(self.data_dir, "shares", "w-audit")
        for name in os.listdir(share_dir):
            with open(os.path.join(share_dir, name), encoding="utf-8") as f:
                record = json.load(f)
            self.assertEqual(
                set(record), {"share_id", "public_key", "private_key"}
            )


if __name__ == "__main__":
    unittest.main()
