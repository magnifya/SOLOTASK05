"""crypto 原语测试。"""

import unittest

from threshold_wallet import crypto


class CryptoTest(unittest.TestCase):
    def test_generate_two_distinct_shares(self):
        keys = crypto.generate_share_keys()
        self.assertEqual(len(keys), 2)
        self.assertNotEqual(keys[0].share_id, keys[1].share_id)
        self.assertNotEqual(keys[0].private_bytes, keys[1].private_bytes)
        self.assertEqual(len(keys[0].private_bytes), crypto.SEED_LENGTH)

    def test_sign_and_verify_roundtrip(self):
        privs = [k.private_bytes for k in crypto.generate_share_keys()]
        apk = crypto.aggregate_public_key(privs)
        self.assertEqual(len(apk), crypto.AGGREGATED_PUBLIC_KEY_LENGTH)
        payload = crypto.signing_payload("req", b"msg")
        agg = b"".join(crypto.sign_share(p, payload) for p in privs)
        self.assertEqual(len(agg), crypto.AGGREGATED_SIGNATURE_LENGTH)
        self.assertTrue(crypto.verify_aggregated_signature(apk, payload, agg))

    def test_payload_is_id_then_message_concatenation(self):
        self.assertEqual(
            crypto.signing_payload("id-7", b"\x00\x01"),
            b"id-7" + b"\x00\x01",
        )

    def test_tampered_message_fails(self):
        privs = [k.private_bytes for k in crypto.generate_share_keys()]
        apk = crypto.aggregate_public_key(privs)
        agg = b"".join(
            crypto.sign_share(p, crypto.signing_payload("r", b"a")) for p in privs
        )
        self.assertFalse(
            crypto.verify_aggregated_signature(
                apk, crypto.signing_payload("r", b"b"), agg
            )
        )

    def test_share_order_binding(self):
        privs = [k.private_bytes for k in crypto.generate_share_keys()]
        apk = crypto.aggregate_public_key(privs)
        payload = b"x"
        sigs = [crypto.sign_share(p, payload) for p in privs]
        swapped = sigs[1] + sigs[0]
        self.assertFalse(crypto.verify_aggregated_signature(apk, payload, swapped))

    def test_wrong_lengths_rejected(self):
        privs = [k.private_bytes for k in crypto.generate_share_keys()]
        apk = crypto.aggregate_public_key(privs)
        payload = b"x"
        self.assertFalse(crypto.verify_aggregated_signature(apk, payload, b"\x00" * 64))
        self.assertFalse(
            crypto.verify_aggregated_signature(b"\x00" * 32, payload, b"\x00" * 128)
        )

    def test_aggregate_requires_two_keys(self):
        one = crypto.generate_share_keys()[:1]
        with self.assertRaises(ValueError):
            crypto.aggregate_public_key([k.private_bytes for k in one])


if __name__ == "__main__":
    unittest.main()
