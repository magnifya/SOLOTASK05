"""聚合签名只读验真入口测试：POST /v1/wallets/<id>/signature-verifications。

覆盖：成功验真契约、valid=false、400/404/409 次序、轮换后历史公钥验真、
重复查询稳定性、冻结钱包可查、纯只读（不新增审计事件、不改状态）。
"""

from __future__ import annotations

import tempfile
import unittest

from threshold_wallet import crypto

from tests.helpers import http_server


class SignatureVerificationTest(unittest.TestCase):
    def setUp(self):
        self._ctx = http_server(tempfile.mkdtemp())
        self.srv = self._ctx.__enter__()

    def tearDown(self):
        self._ctx.__exit__(None, None, None)

    def request(self, method, path, body=None):
        return self.srv.request(method, path, body)

    def create_wallet(self, wallet_id="w1"):
        status, body = self.request(
            "POST", "/v1/wallets", {"wallet_id": wallet_id, "shares": 2}
        )
        self.assertEqual(status, 201)
        return body

    def sign(self, wallet_id, request_id, message, share_ids=("share-1", "share-2")):
        harness = self.srv.harness
        signatures = [
            {
                "share_id": sid,
                "signature": harness.share_signature(
                    wallet_id, sid, request_id, message
                ),
            }
            for sid in share_ids
        ]
        status, body = self.request(
            "POST",
            f"/v1/wallets/{wallet_id}/sign",
            {
                "signing_request_id": request_id,
                "message": message,
                "signatures": signatures,
            },
        )
        self.assertEqual(status, 201)
        return body["signature"]

    def verify(self, wallet_id, request_id, message, signature):
        return self.request(
            "POST",
            f"/v1/wallets/{wallet_id}/signature-verifications",
            {
                "signing_request_id": request_id,
                "message": message,
                "signature": signature,
            },
        )

    def audit_count(self, wallet_id):
        status, body = self.request(
            "GET", f"/v1/wallets/{wallet_id}/audit-events?limit=1000"
        )
        self.assertEqual(status, 200)
        return len(body["events"])

    # ---- 成功契约 -------------------------------------------------------

    def test_valid_aggregate_returns_200_contract(self):
        wallet = self.create_wallet()
        aggregate = self.sign("w1", "req-1", "hello")
        status, body = self.verify("w1", "req-1", "hello", aggregate)
        self.assertEqual(status, 200)
        self.assertEqual(
            set(body),
            {"wallet_id", "signing_request_id", "valid", "signed_seq",
             "public_key"},
        )
        self.assertEqual(body["wallet_id"], "w1")
        self.assertEqual(body["signing_request_id"], "req-1")
        self.assertIs(body["valid"], True)
        self.assertIsInstance(body["signed_seq"], int)
        self.assertGreaterEqual(body["signed_seq"], 1)
        # 未轮换：public_key 即钱包当前公钥（两份公钥顺序拼接的小写 hex）
        self.assertEqual(body["public_key"], wallet["public_key"])

    def test_wrong_signature_returns_200_valid_false(self):
        self.create_wallet()
        aggregate = self.sign("w1", "req-1", "hello")
        other = self.sign("w1", "req-2", "hello")
        status, body = self.verify("w1", "req-1", "hello", other)
        self.assertEqual(status, 200)
        self.assertIs(body["valid"], False)
        # 随机 128 字节同样 200 + valid=false
        status, body = self.verify("w1", "req-1", "hello", "ab" * 128)
        self.assertEqual(status, 200)
        self.assertIs(body["valid"], False)
        self.assertEqual(len(aggregate), 256)

    def test_repeat_verification_is_stable(self):
        self.create_wallet()
        aggregate = self.sign("w1", "req-1", "hello")
        first = self.verify("w1", "req-1", "hello", aggregate)[1]
        second = self.verify("w1", "req-1", "hello", aggregate)[1]
        self.assertEqual(first, second)

    # ---- 400 ------------------------------------------------------------

    def test_400_missing_extra_keys_and_bad_types(self):
        self.create_wallet()
        aggregate = self.sign("w1", "req-1", "hello")
        base = {
            "signing_request_id": "req-1",
            "message": "hello",
            "signature": aggregate,
        }
        # 缺键
        for key in base:
            body = {k: v for k, v in base.items() if k != key}
            status, _ = self.request(
                "POST", "/v1/wallets/w1/signature-verifications", body
            )
            self.assertEqual(status, 400, key)
        # 夹带键
        status, _ = self.request(
            "POST",
            "/v1/wallets/w1/signature-verifications",
            {**base, "extra": 1},
        )
        self.assertEqual(status, 400)
        # 类型非法
        for key, value in (
            ("signing_request_id", 1),
            ("message", None),
            ("message", 3),
            ("signature", 5),
        ):
            status, _ = self.request(
                "POST",
                "/v1/wallets/w1/signature-verifications",
                {**base, key: value},
            )
            self.assertEqual(status, 400, (key, value))

    def test_400_bad_signature_hex_and_length(self):
        self.create_wallet()
        self.sign("w1", "req-1", "hello")
        for bad in ("zz" * 128, "ab" * 64, "ab" * 129, "", "abc"):
            status, _ = self.verify("w1", "req-1", "hello", bad)
            self.assertEqual(status, 400, bad[:16])

    def test_400_invalid_signing_request_id(self):
        self.create_wallet()
        self.sign("w1", "req-1", "hello")
        for bad in ("", "has space", "slash/x", "x" * 129):
            status, _ = self.verify("w1", "req-1", "hello", "ab" * 128)
            self.assertEqual(status, 200)  # 合法基线
            status, _ = self.request(
                "POST",
                "/v1/wallets/w1/signature-verifications",
                {
                    "signing_request_id": bad,
                    "message": "hello",
                    "signature": "ab" * 128,
                },
            )
            self.assertEqual(status, 400, bad)

    # ---- 404 / 409 ------------------------------------------------------

    def test_404_unknown_wallet_takes_priority_over_body(self):
        status, _ = self.verify("ghost", "req-1", "hello", "ab" * 128)
        self.assertEqual(status, 404)
        # 正文本身非法（缺键/夹带/类型错）时也先 404
        for body in ({}, {"signing_request_id": 1}, {"a": 1, "b": 2}):
            status, _ = self.request(
                "POST", "/v1/wallets/ghost/signature-verifications", body
            )
            self.assertEqual(status, 404, body)

    def test_404_unknown_signing_request(self):
        self.create_wallet()
        status, _ = self.verify("w1", "req-9", "hello", "ab" * 128)
        self.assertEqual(status, 404)

    def test_409_message_mismatch(self):
        self.create_wallet()
        aggregate = self.sign("w1", "req-1", "hello")
        status, _ = self.verify("w1", "req-1", "tampered", aggregate)
        self.assertEqual(status, 409)

    # ---- 轮换后的历史公钥 -------------------------------------------------

    def rotate(self, wallet_id="w1", rotation_id="rot-1"):
        status, body = self.request(
            "POST",
            f"/v1/wallets/{wallet_id}/share-rotations",
            {"rotation_id": rotation_id},
        )
        self.assertEqual(status, 201)
        share_ids = body["share_ids"]
        status, _ = self.request(
            "POST",
            f"/v1/wallets/{wallet_id}/share-rotations/{rotation_id}/activate",
        )
        self.assertEqual(status, 201)
        return share_ids, body["public_key"]

    def test_verification_uses_historical_keys_after_rotation(self):
        wallet = self.create_wallet()
        old_aggregate = self.sign("w1", "req-old", "before rotation")
        old_result = self.verify("w1", "req-old", "before rotation",
                                 old_aggregate)[1]
        self.assertIs(old_result["valid"], True)
        self.assertEqual(old_result["public_key"], wallet["public_key"])

        new_share_ids, new_public_key = self.rotate()
        new_aggregate = self.sign(
            "w1", "req-new", "after rotation", share_ids=new_share_ids
        )

        # 旧签名：仍按签名时的两份公钥验真，signed_seq/public_key/valid
        # 不受轮换影响
        status, body = self.verify(
            "w1", "req-old", "before rotation", old_aggregate
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, old_result)
        self.assertEqual(body["public_key"], wallet["public_key"])

        # 新签名：按轮换后的两份公钥验真
        status, body = self.verify(
            "w1", "req-new", "after rotation", new_aggregate
        )
        self.assertEqual(status, 200)
        self.assertIs(body["valid"], True)
        self.assertEqual(body["public_key"], new_public_key)
        self.assertGreater(body["signed_seq"], old_result["signed_seq"])

        # 旧聚合签名不能通过新请求的验真（载荷与公钥都不同）
        status, body = self.verify(
            "w1", "req-new", "after rotation", old_aggregate
        )
        self.assertEqual(status, 200)
        self.assertIs(body["valid"], False)

    def test_second_rotation_keeps_first_result_stable(self):
        wallet = self.create_wallet()
        aggregate = self.sign("w1", "req-1", "msg")
        before = self.verify("w1", "req-1", "msg", aggregate)[1]
        ids1, _ = self.rotate(rotation_id="rot-1")
        self.sign("w1", "req-2", "msg2", share_ids=ids1)
        ids2, _ = self.rotate(rotation_id="rot-2")
        self.sign("w1", "req-3", "msg3", share_ids=ids2)
        after = self.verify("w1", "req-1", "msg", aggregate)[1]
        self.assertEqual(before, after)
        self.assertEqual(after["public_key"], wallet["public_key"])
        self.assertIs(after["valid"], True)

    # ---- 纯只读 -----------------------------------------------------------

    def test_read_only_no_new_audit_events(self):
        self.create_wallet()
        aggregate = self.sign("w1", "req-1", "hello")
        count_before = self.audit_count("w1")
        self.verify("w1", "req-1", "hello", aggregate)
        self.verify("w1", "req-1", "hello", "ab" * 128)
        self.verify("w1", "req-1", "other", aggregate)  # 409
        self.verify("w1", "req-9", "hello", "ab" * 128)  # 404
        self.assertEqual(self.audit_count("w1"), count_before)

    def test_frozen_wallet_still_verifiable(self):
        self.create_wallet()
        aggregate = self.sign("w1", "req-1", "hello")
        status, _ = self.request(
            "POST", "/v1/wallets/w1/freeze", {"reason": "audit hold"}
        )
        self.assertEqual(status, 201)
        status, body = self.verify("w1", "req-1", "hello", aggregate)
        self.assertEqual(status, 200)
        self.assertIs(body["valid"], True)

    def test_response_leaks_no_private_material(self):
        self.create_wallet()
        aggregate = self.sign("w1", "req-1", "hello")
        _, body = self.verify("w1", "req-1", "hello", aggregate)
        # 响应不含私钥、单份额签名或签名载荷
        harness = self.srv.harness
        for sid in ("share-1", "share-2"):
            private_hex = harness.share_private_hex("w1", sid)
            self.assertNotIn(private_hex, str(body))
        for half in crypto.split_signature(bytes.fromhex(aggregate)):
            self.assertNotIn(half.hex(), str(body))


if __name__ == "__main__":
    unittest.main()
