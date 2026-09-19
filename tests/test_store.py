"""store 模块单元测试：持久化布局、原子性语义与"无完整私钥"性质。"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from threshold_wallet.crypto import generate_share_key
from threshold_wallet.store import DuplicateWalletError, WalletStore


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.store = WalletStore(self.tmp)
        self.k1 = generate_share_key("share-1")
        self.k2 = generate_share_key("share-2")

    def test_create_writes_metadata_and_separate_share_files(self):
        self.store.create_wallet("w1", [self.k1, self.k2], "2026-09-19T00:00:00Z")
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "wallets", "w1.json")))
        self.assertTrue(
            os.path.exists(os.path.join(self.tmp, "shares", "w1", "share-1.json"))
        )
        self.assertTrue(
            os.path.exists(os.path.join(self.tmp, "shares", "w1", "share-2.json"))
        )

    def test_metadata_contains_no_private_key(self):
        self.store.create_wallet("w1", [self.k1, self.k2], "ts")
        with open(os.path.join(self.tmp, "wallets", "w1.json"), encoding="utf-8") as f:
            raw = f.read()
        meta = json.loads(raw)
        self.assertNotIn("private_key", raw)
        self.assertNotIn("private_key", json.dumps(meta))
        self.assertEqual(
            meta["public_key"], (self.k1.public_bytes + self.k2.public_bytes).hex()
        )
        self.assertEqual(
            [s["share_id"] for s in meta["shares"]], ["share-1", "share-2"]
        )

    def test_each_share_file_holds_only_its_own_private_key(self):
        self.store.create_wallet("w1", [self.k1, self.k2], "ts")
        s1 = self.store.get_share("w1", "share-1")
        s2 = self.store.get_share("w1", "share-2")
        self.assertEqual(s1["private_key"], self.k1.private_bytes.hex())
        self.assertEqual(s2["private_key"], self.k2.private_bytes.hex())
        # 单个文件内绝不出现两份私钥拼接（不存在"完整私钥"）
        s1_raw = json.dumps(s1)
        self.assertNotIn(self.k2.private_bytes.hex(), s1_raw)

    def test_duplicate_wallet_rejected(self):
        self.store.create_wallet("w1", [self.k1, self.k2], "ts")
        with self.assertRaises(DuplicateWalletError):
            self.store.create_wallet("w1", [self.k1, self.k2], "ts")

    def test_get_missing_wallet_and_share(self):
        self.assertIsNone(self.store.get_wallet("ghost"))
        self.assertFalse(self.store.has_wallet("ghost"))
        self.assertIsNone(self.store.get_share("ghost", "share-1"))

    def test_signature_records_are_idempotent(self):
        self.store.create_wallet("w1", [self.k1, self.k2], "ts")
        first = {"message": "m", "signature": "aa"}
        self.assertIsNone(self.store.save_signature("w1", "r1", first))
        # 重放返回已有记录且不覆盖
        existing = self.store.save_signature(
            "w1", "r1", {"message": "OTHER", "signature": "bb"}
        )
        self.assertEqual(existing, first)
        self.assertEqual(self.store.get_signature("w1", "r1"), first)
        self.assertIsNone(self.store.get_signature("w1", "other"))
        self.assertIsNone(self.store.get_signature("ghost", "r1"))

    def test_path_traversal_is_rejected(self):
        for bad in ("../x", "a/b", "", "." * 10):
            with self.assertRaises(ValueError):
                self.store.get_wallet(bad)
            with self.assertRaises(ValueError):
                self.store.get_share("w1", bad)

    def test_persistence_across_instances(self):
        self.store.create_wallet("w1", [self.k1, self.k2], "ts")
        self.store.save_signature("w1", "r1", {"signature": "ab"})
        reopened = WalletStore(self.tmp)
        self.assertEqual(reopened.get_wallet("w1")["wallet_id"], "w1")
        self.assertEqual(
            reopened.get_share("w1", "share-1")["private_key"],
            self.k1.private_bytes.hex(),
        )
        self.assertEqual(reopened.get_signature("w1", "r1")["signature"], "ab")


if __name__ == "__main__":
    unittest.main()
