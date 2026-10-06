"""聚合签名验真（POST /v1/wallets/{id}/signature-verifications）端到端测试。

覆盖：
- 已完成 /sign 的结果验真：两半均通过 valid=true，响应固定五键；
- 格式正确但验签失败仍以 200 返回 valid=false；
- 缺键/夹带键/类型/hex 长度非法 400，且钱包不存在 404 优先于正文校验；
- 签名记录不存在 404、message 与记录原文不一致 409；
- 轮换后用签名时刻（request_signed 序号前）最后生效的两份公钥验真，
  后续轮换不改变 signed_seq/public_key/valid；
- 冻结钱包仍可查询；纯只读（不新增审计事件、不触发懒过期）；
- 签名记录/审计摘要链无法对账时 503。
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from tests.helpers import http_server
from threshold_wallet.audit import AuditStore


class SignatureVerificationTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self._ctx = http_server(self.tmpdir)
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
        signatures = [
            {
                "share_id": sid,
                "signature": self.srv.harness.share_signature(
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

    # ---- 基本验真 -------------------------------------------------------

    def test_valid_signature_contract(self):
        created = self.create_wallet()
        aggregate = self.sign("w1", "r1", "hello")
        status, body = self.verify("w1", "r1", "hello", aggregate)
        self.assertEqual(status, 200)
        self.assertEqual(
            set(body),
            {"wallet_id", "signing_request_id", "valid", "signed_seq",
             "public_key"},
        )
        self.assertEqual(body["wallet_id"], "w1")
        self.assertEqual(body["signing_request_id"], "r1")
        self.assertIs(body["valid"], True)
        self.assertIsInstance(body["signed_seq"], int)
        self.assertGreaterEqual(body["signed_seq"], 1)
        # 签名时刻的两份公钥顺序拼接（创世公钥）
        self.assertEqual(body["public_key"], created["public_key"])

    def test_tampered_signature_valid_false_still_200(self):
        self.create_wallet()
        aggregate = self.sign("w1", "r1", "hello")
        raw = bytearray(bytes.fromhex(aggregate))
        raw[0] ^= 0x01
        status, body = self.verify("w1", "r1", "hello", raw.hex())
        self.assertEqual(status, 200)
        self.assertIs(body["valid"], False)

    def test_repeat_verification_is_stable(self):
        self.create_wallet()
        aggregate = self.sign("w1", "r1", "hello")
        _, first = self.verify("w1", "r1", "hello", aggregate)
        _, second = self.verify("w1", "r1", "hello", aggregate)
        self.assertEqual(first, second)

    # ---- 请求体验证 ------------------------------------------------------

    def test_wallet_missing_404_precedes_body_validation(self):
        # 钱包不存在：即使正文缺键/夹带键也返回 404
        for bad_body in (
            {},
            {"signing_request_id": "r1"},
            {"signing_request_id": "r1", "message": "m", "signature": "zz",
             "extra": 1},
            "not-an-object",
        ):
            status, body = self.request(
                "POST", "/v1/wallets/nope/signature-verifications", bad_body
            )
            self.assertEqual(status, 404, bad_body)

    def test_wallet_missing_is_404(self):
        status, _ = self.verify("nope", "r1", "m", "00" * 128)
        self.assertEqual(status, 404)

    def test_body_key_set_errors_are_400(self):
        self.create_wallet()
        aggregate = self.sign("w1", "r1", "hello")
        good = {
            "signing_request_id": "r1",
            "message": "hello",
            "signature": aggregate,
        }
        # 缺键
        for key in ("signing_request_id", "message", "signature"):
            body = {k: v for k, v in good.items() if k != key}
            status, _ = self.request(
                "POST", "/v1/wallets/w1/signature-verifications", body
            )
            self.assertEqual(status, 400, body)
        # 夹带键
        body = dict(good, extra="x")
        status, _ = self.request(
            "POST", "/v1/wallets/w1/signature-verifications", body
        )
        self.assertEqual(status, 400)

    def test_field_type_errors_are_400(self):
        self.create_wallet()
        aggregate = self.sign("w1", "r1", "hello")
        cases = [
            {"signing_request_id": 1, "message": "hello",
             "signature": aggregate},
            {"signing_request_id": "", "message": "hello",
             "signature": aggregate},
            {"signing_request_id": "r1", "message": 2,
             "signature": aggregate},
            {"signing_request_id": "r1", "message": "hello",
             "signature": 3},
            {"signing_request_id": "r1", "message": "hello",
             "signature": "not-hex"},
        ]
        for body in cases:
            status, _ = self.request(
                "POST", "/v1/wallets/w1/signature-verifications", body
            )
            self.assertEqual(status, 400, body)

    def test_signature_length_errors_are_400(self):
        self.create_wallet()
        self.sign("w1", "r1", "hello")
        for hex_sig in ("00" * 64, "00" * 127, "00" * 129, "00" * 256):
            status, _ = self.verify("w1", "r1", "hello", hex_sig)
            self.assertEqual(status, 400, hex_sig[:16])

    def test_non_object_body_is_400(self):
        self.create_wallet()
        status, _ = self.request(
            "POST", "/v1/wallets/w1/signature-verifications", [1, 2, 3]
        )
        self.assertEqual(status, 400)

    def test_unknown_signing_request_is_404(self):
        self.create_wallet()
        status, _ = self.verify("w1", "never-signed", "m", "00" * 128)
        self.assertEqual(status, 404)

    def test_message_mismatch_is_409(self):
        self.create_wallet()
        aggregate = self.sign("w1", "r1", "hello")
        status, _ = self.verify("w1", "r1", "other", aggregate)
        self.assertEqual(status, 409)

    def test_get_on_path_is_405(self):
        self.create_wallet()
        status, _ = self.request("GET", "/v1/wallets/w1/signature-verifications")
        self.assertEqual(status, 405)

    # ---- 轮换后的历史公钥验真 ---------------------------------------------

    def rotate(self, wallet_id, rotation_id):
        status, _ = self.request(
            "POST",
            f"/v1/wallets/{wallet_id}/share-rotations",
            {"rotation_id": rotation_id},
        )
        self.assertEqual(status, 201)
        status, _ = self.request(
            "POST",
            f"/v1/wallets/{wallet_id}/share-rotations/{rotation_id}/activate",
        )
        self.assertEqual(status, 201)

    def test_verification_uses_historical_keys_after_rotation(self):
        created = self.create_wallet()
        genesis_aggregate = self.sign("w1", "r1", "genesis-message")

        # 轮换后旧请求仍按签名时刻的两份公钥验真
        self.rotate("w1", "rot1")
        _, current = self.request("GET", "/v1/wallets/w1")
        self.assertNotEqual(current["public_key"], created["public_key"])

        status, body = self.verify("w1", "r1", "genesis-message",
                                   genesis_aggregate)
        self.assertEqual(status, 200)
        self.assertIs(body["valid"], True)
        self.assertEqual(body["public_key"], created["public_key"])

        # 轮换后的新签名用新份额，验真给出轮换后的公钥
        new_aggregate = self.sign(
            "w1", "r2", "rotated-message",
            share_ids=("rot1-share-1", "rot1-share-2"),
        )
        status, body2 = self.verify("w1", "r2", "rotated-message",
                                    new_aggregate)
        self.assertEqual(status, 200)
        self.assertIs(body2["valid"], True)
        self.assertEqual(body2["public_key"], current["public_key"])
        self.assertGreater(body2["signed_seq"], body["signed_seq"])

        # 再次轮换不改变既有结果：signed_seq/public_key/valid 均稳定
        self.rotate("w1", "rot2")
        status, again = self.verify("w1", "r1", "genesis-message",
                                    genesis_aggregate)
        self.assertEqual(status, 200)
        self.assertEqual(again, body)
        status, again2 = self.verify("w1", "r2", "rotated-message",
                                     new_aggregate)
        self.assertEqual(status, 200)
        self.assertEqual(again2, body2)

    # ---- 只读语义 ---------------------------------------------------------

    def audit_event_count(self, wallet_id="w1"):
        return AuditStore(self.tmpdir).integrity(wallet_id)[0]

    def test_verification_is_read_only(self):
        self.create_wallet()
        aggregate = self.sign("w1", "r1", "hello")
        before = self.audit_event_count()
        self.verify("w1", "r1", "hello", aggregate)
        self.verify("w1", "r1", "hello", "00" * 128)
        self.assertEqual(self.audit_event_count(), before)

    def test_frozen_wallet_still_verifiable(self):
        self.create_wallet()
        aggregate = self.sign("w1", "r1", "hello")
        status, _ = self.request(
            "POST", "/v1/wallets/w1/freeze", {"reason": "audit hold"}
        )
        self.assertEqual(status, 201)
        status, body = self.verify("w1", "r1", "hello", aggregate)
        self.assertEqual(status, 200)
        self.assertIs(body["valid"], True)

    # ---- 不可对账 503 ------------------------------------------------------

    def test_tampered_audit_chain_is_503(self):
        self.create_wallet()
        aggregate = self.sign("w1", "r1", "hello")
        path = os.path.join(self.tmpdir, "audit", "w1.json")
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        data["chain"]["head"] = "0" * 64
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        status, body = self.verify("w1", "r1", "hello", aggregate)
        self.assertEqual(status, 503)
        self.assertEqual(body, {"error": "service temporarily unavailable"})

    def test_malformed_signature_record_is_503(self):
        self.create_wallet()
        aggregate = self.sign("w1", "r1", "hello")
        path = os.path.join(self.tmpdir, "signatures", "w1.json")
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        data["r1"]["message"] = 123
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        status, body = self.verify("w1", "r1", "hello", aggregate)
        self.assertEqual(status, 503)
        self.assertEqual(body, {"error": "service temporarily unavailable"})


if __name__ == "__main__":
    unittest.main()
