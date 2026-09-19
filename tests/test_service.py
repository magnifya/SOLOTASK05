"""service 模块业务规则测试（不经过 HTTP，直接调用逻辑层）。"""

from __future__ import annotations

import tempfile
import unittest

from tests.helpers import make_harness
from threshold_wallet import crypto
from threshold_wallet.service import ServiceError


class ServiceTest(unittest.TestCase):
    def setUp(self):
        self.h = make_harness(tempfile.mkdtemp())
        self.svc = self.h.service

    def create(self, wallet_id="w1"):
        return self.svc.create_wallet(wallet_id, 2)

    # ---- 建钱包 ---------------------------------------------------------

    def test_create_wallet_ok(self):
        r = self.create()
        self.assertEqual(r["wallet_id"], "w1")
        self.assertEqual(r["share_ids"], ["share-1", "share-2"])
        self.assertEqual(len(bytes.fromhex(r["public_key"])), 64)

    def test_create_shares_must_equal_2(self):
        for bad in (1, 3, 0, -1, "2", 2.0, None, [2]):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.create_wallet("wx", bad)
            self.assertEqual(ctx.exception.status, 400, bad)

    def test_create_shares_bool_rejected(self):
        # True == 1 且 isinstance(True, int)，必须显式拒绝
        with self.assertRaises(ServiceError) as ctx:
            self.svc.create_wallet("wx", True)
        self.assertEqual(ctx.exception.status, 400)

    def test_create_duplicate_is_409(self):
        self.create()
        with self.assertRaises(ServiceError) as ctx:
            self.create()
        self.assertEqual(ctx.exception.status, 409)

    def test_create_bad_wallet_id_is_400(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.create_wallet("../escape", 2)
        self.assertEqual(ctx.exception.status, 400)

    # ---- 查询 -----------------------------------------------------------

    def test_get_wallet_ok(self):
        r = self.create()
        g = self.svc.get_wallet("w1")
        self.assertEqual(g["public_key"], r["public_key"])
        self.assertIn("created_at", g)
        self.assertNotIn("private_key", g)

    def test_get_wallet_missing_is_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_wallet("ghost")
        self.assertEqual(ctx.exception.status, 404)

    # ---- 签名 -----------------------------------------------------------

    def _sign(self, wallet="w1", srid="r1", message="hello", mutate=None):
        sigs = self.h.two_signatures(wallet, srid, message)
        if mutate:
            sigs = mutate(sigs)
        return self.svc.sign(wallet, srid, message, sigs)

    def test_sign_ok_returns_201_and_128_bytes(self):
        self.create()
        code, resp = self._sign()
        self.assertEqual(code, 201)
        self.assertEqual(len(bytes.fromhex(resp["signature"])), 128)

    def test_aggregate_signature_verifies_against_public_key(self):
        r = self.create()
        code, resp = self._sign()
        self.assertEqual(code, 201)
        pks = crypto.split_public_key(bytes.fromhex(r["public_key"]))
        parts = crypto.split_signature(bytes.fromhex(resp["signature"]))
        payload = crypto.build_payload("r1", "hello")
        self.assertTrue(crypto.verify_share(pks[0], payload, parts[0]))
        self.assertTrue(crypto.verify_share(pks[1], payload, parts[1]))

    def test_sign_wallet_missing_is_404(self):
        # 钱包不存在时在校验签名前即 404，占位签名即可
        sigs = [
            {"share_id": "share-1", "signature": "00" * 64},
            {"share_id": "share-2", "signature": "00" * 64},
        ]
        with self.assertRaises(ServiceError) as ctx:
            self.svc.sign("ghost", "r1", "m", sigs)
        self.assertEqual(ctx.exception.status, 404)

    def test_sign_missing_one_share_is_400(self):
        self.create()
        sigs = self.h.two_signatures("w1", "r1", "m")[:1]
        with self.assertRaises(ServiceError) as ctx:
            self.svc.sign("w1", "r1", "m", sigs)
        self.assertEqual(ctx.exception.status, 400)

    def test_sign_duplicate_share_id_is_400(self):
        self.create()
        sigs = self.h.two_signatures("w1", "r1", "m")
        sigs[1] = dict(sigs[0])
        with self.assertRaises(ServiceError) as ctx:
            self.svc.sign("w1", "r2", "m", sigs)
        self.assertEqual(ctx.exception.status, 400)

    def test_sign_unknown_share_id_is_400(self):
        self.create()
        sigs = [
            {"share_id": "share-1", "signature": "00" * 64},
            {"share_id": "intruder", "signature": "00" * 64},
        ]
        with self.assertRaises(ServiceError) as ctx:
            self.svc.sign("w1", "r2", "m", sigs)
        self.assertEqual(ctx.exception.status, 400)

    def test_sign_bad_signature_is_400(self):
        self.create()
        sigs = self.h.two_signatures("w1", "r1", "m")
        sigs[0]["signature"] = "00" * 64
        with self.assertRaises(ServiceError) as ctx:
            self.svc.sign("w1", "r2", "m", sigs)
        self.assertEqual(ctx.exception.status, 400)

    def test_sign_wrong_message_is_400(self):
        self.create()
        # 份额签的是 m，但提交声称 message 为 other
        sigs = self.h.two_signatures("w1", "r1", "m")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.sign("w1", "r2", "other", sigs)
        self.assertEqual(ctx.exception.status, 400)

    def test_sign_non_hex_signature_is_400(self):
        self.create()
        sigs = self.h.two_signatures("w1", "r1", "m")
        sigs[0]["signature"] = "not-hex"
        with self.assertRaises(ServiceError) as ctx:
            self.svc.sign("w1", "r2", "m", sigs)
        self.assertEqual(ctx.exception.status, 400)

    def test_sign_bad_request_fields_are_400(self):
        self.create()
        good = self.h.two_signatures("w1", "r1", "m")
        for srid, message, sigs in [
            ("", "m", good),
            (123, "m", good),
            ("r", 123, good),
            ("r", "m", "not-list"),
            ("r", "m", None),
        ]:
            with self.assertRaises(ServiceError) as ctx:
                self.svc.sign("w1", srid, message, sigs)
            self.assertEqual(ctx.exception.status, 400)

    def test_sign_replay_returns_existing_signature_200(self):
        self.create()
        code1, resp1 = self._sign(srid="r1")
        self.assertEqual(code1, 201)
        # 即使重放时携带不同 message/签名，也直接返回已有结果
        code2, resp2 = self.svc.sign(
            "w1", "r1", "TAMPERED", self.h.two_signatures("w1", "r1", "m")
        )
        self.assertEqual(code2, 200)
        self.assertEqual(resp2, resp1)

    def test_distinct_requests_get_distinct_signatures(self):
        self.create()
        _, a = self._sign(srid="r1", message="a")
        _, b = self._sign(srid="r2", message="b")
        self.assertNotEqual(a["signature"], b["signature"])


if __name__ == "__main__":
    unittest.main()
