"""crypto 模块单元测试。"""

from __future__ import annotations

import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from threshold_wallet import crypto


class CryptoTest(unittest.TestCase):
    def test_share_key_sizes(self):
        key = crypto.generate_share_key("share-1")
        self.assertEqual(key.share_id, "share-1")
        self.assertEqual(len(key.private_bytes), 32)
        self.assertEqual(len(key.public_bytes), 32)

    def test_share_key_is_valid_ed25519(self):
        key = crypto.generate_share_key("share-1")
        loaded = Ed25519PrivateKey.from_private_bytes(key.private_bytes)
        self.assertEqual(
            loaded.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            key.public_bytes,
        )

    def test_sign_and_verify_roundtrip(self):
        key = crypto.generate_share_key("share-1")
        payload = crypto.build_payload("req-1", "hello")
        signature = crypto.sign_share(key.private_bytes, payload)
        self.assertEqual(len(signature), 64)
        self.assertTrue(crypto.verify_share(key.public_bytes, payload, signature))

    def test_verify_rejects_wrong_key(self):
        k1 = crypto.generate_share_key("share-1")
        k2 = crypto.generate_share_key("share-2")
        payload = crypto.build_payload("req-1", "hello")
        signature = crypto.sign_share(k1.private_bytes, payload)
        self.assertFalse(crypto.verify_share(k2.public_bytes, payload, signature))

    def test_verify_rejects_tampered_payload(self):
        key = crypto.generate_share_key("share-1")
        signature = crypto.sign_share(
            key.private_bytes, crypto.build_payload("req-1", "hello")
        )
        # 改 message
        self.assertFalse(
            crypto.verify_share(
                key.public_bytes, crypto.build_payload("req-1", "hell0"), signature
            )
        )
        # 改 signing_request_id
        self.assertFalse(
            crypto.verify_share(
                key.public_bytes, crypto.build_payload("req-2", "hello"), signature
            )
        )

    def test_verify_rejects_malformed_signature(self):
        key = crypto.generate_share_key("share-1")
        payload = crypto.build_payload("req-1", "hello")
        self.assertFalse(crypto.verify_share(key.public_bytes, payload, b""))
        self.assertFalse(crypto.verify_share(key.public_bytes, payload, b"x" * 63))
        self.assertFalse(crypto.verify_share(key.public_bytes, payload, b"x" * 64))

    def test_payload_is_direct_concatenation(self):
        self.assertEqual(crypto.build_payload("ab", "cd"), b"abcd")

    def test_combine_and_split_public_keys(self):
        k1 = crypto.generate_share_key("share-1")
        k2 = crypto.generate_share_key("share-2")
        combined = crypto.combine_public_keys([k1.public_bytes, k2.public_bytes])
        self.assertEqual(len(combined), 64)
        self.assertEqual(
            crypto.split_public_key(combined), [k1.public_bytes, k2.public_bytes]
        )

    def test_combine_and_split_signatures(self):
        k1 = crypto.generate_share_key("share-1")
        k2 = crypto.generate_share_key("share-2")
        payload = crypto.build_payload("req", "msg")
        s1 = crypto.sign_share(k1.private_bytes, payload)
        s2 = crypto.sign_share(k2.private_bytes, payload)
        combined = crypto.combine_signatures([s1, s2])
        self.assertEqual(len(combined), 128)
        self.assertEqual(crypto.split_signature(combined), [s1, s2])


if __name__ == "__main__":
    unittest.main()
