"""service 业务规则测试，覆盖全部状态码与幂等语义。"""

import base64
import tempfile
import unittest

from threshold_wallet import crypto
from threshold_wallet.service import WalletService
from threshold_wallet.store import WalletStore


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class ServiceTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.store = WalletStore(self._tmp.name)
        self.service = WalletService(self.store)

    def tearDown(self):
        self._tmp.cleanup()

    def _create(self, wallet_id="w", shares=2):
        return self.service.create_wallet(wallet_id, shares)

    def _share_signatures(self, wallet_id, request_id, message):
        wallet = self.store.get(wallet_id)
        payload = crypto.signing_payload(request_id, message)
        result = []
        for share in wallet.shares:
            priv = base64.b64decode(share.private_b64)
            result.append(
                {
                    "share_id": share.share_id,
                    "signature": b64(crypto.sign_share(priv, payload)),
                }
            )
        return result, wallet

    # -- 建钱包 ---------------------------------------------------------

    def test_create_success(self):
        status, body = self._create("w1", 2)
        self.assertEqual(status, 201)
        self.assertEqual(set(body), {"wallet_id", "public_key", "share_ids"})
        self.assertEqual(body["wallet_id"], "w1")
        self.assertEqual(len(body["share_ids"]), 2)
        self.assertEqual(len(base64.b64decode(body["public_key"])), 64)

    def test_create_shares_must_be_two(self):
        for bad in (1, 3, 0, -2):
            self.assertEqual(self._create(f"w{bad}", bad)[0], 400)
        self.assertEqual(self._create("wb", True)[0], 400)
        self.assertEqual(self._create("wf", 2.0)[0], 400)

    def test_create_duplicate_conflict(self):
        self.assertEqual(self._create("dup", 2)[0], 201)
        self.assertEqual(self._create("dup", 2)[0], 409)

    def test_create_bad_wallet_id(self):
        self.assertEqual(self._create("../escape", 2)[0], 400)
        self.assertEqual(self._create("", 2)[0], 400)

    # -- 查询 -----------------------------------------------------------

    def test_get_wallet(self):
        self._create("w1", 2)
        status, body = self.service.get_wallet("w1")
        self.assertEqual(status, 200)
        self.assertEqual(set(body), {"public_key", "created_at"})

    def test_get_missing_wallet(self):
        self.assertEqual(self.service.get_wallet("ghost")[0], 404)

    # -- 签名 -----------------------------------------------------------

    def test_sign_success_and_crypto_verifies(self):
        self._create("w1", 2)
        message = b"transfer 10"
        sigs, wallet = self._share_signatures("w1", "req-1", message)
        status, body = self.service.submit_signature(
            "w1", "req-1", b64(message), list(reversed(sigs))
        )
        self.assertEqual(status, 201)
        self.assertEqual(set(body), {"signature"})
        aggregated = base64.b64decode(body["signature"])
        apk = base64.b64decode(wallet.public_key_b64)
        self.assertTrue(
            crypto.verify_aggregated_signature(
                apk, crypto.signing_payload("req-1", message), aggregated
            )
        )

    def test_sign_missing_one_share(self):
        self._create("w1", 2)
        sigs, _ = self._share_signatures("w1", "req", b"m")
        self.assertEqual(
            self.service.submit_signature("w1", "req", b64(b"m"), sigs[:1])[0], 400
        )
        self.assertEqual(
            self.service.submit_signature("w1", "req", b64(b"m"), sigs + sigs[:1])[0],
            400,
        )

    def test_sign_unknown_share_id(self):
        self._create("w1", 2)
        sigs, _ = self._share_signatures("w1", "req", b"m")
        sigs[0]["share_id"] = "ghost"
        self.assertEqual(
            self.service.submit_signature("w1", "req", b64(b"m"), sigs)[0], 400
        )

    def test_sign_duplicate_share_id(self):
        self._create("w1", 2)
        sigs, _ = self._share_signatures("w1", "req", b"m")
        sigs[1]["share_id"] = sigs[0]["share_id"]
        self.assertEqual(
            self.service.submit_signature("w1", "req", b64(b"m"), sigs)[0], 400
        )

    def test_sign_forged_signature(self):
        self._create("w1", 2)
        sigs, _ = self._share_signatures("w1", "req", b"m")
        sigs[0]["signature"] = b64(b"\x00" * 64)
        self.assertEqual(
            self.service.submit_signature("w1", "req", b64(b"m"), sigs)[0], 400
        )

    def test_sign_wrong_message_binding(self):
        self._create("w1", 2)
        sigs, _ = self._share_signatures("w1", "req", b"m")
        # 份额签名针对 b"m"，提交时声称消息是 b"n"，应校验失败。
        self.assertEqual(
            self.service.submit_signature("w1", "req", b64(b"n"), sigs)[0], 400
        )

    def test_sign_bad_base64(self):
        self._create("w1", 2)
        self.assertEqual(
            self.service.submit_signature("w1", "req", "!!!not-b64", [])[0], 400
        )

    def test_sign_wallet_not_found(self):
        self.assertEqual(
            self.service.submit_signature("ghost", "req", b64(b"m"), [])[0], 404
        )

    def test_sign_idempotent_returns_existing(self):
        self._create("w1", 2)
        sigs, _ = self._share_signatures("w1", "req-1", b"m")
        _, first = self.service.submit_signature("w1", "req-1", b64(b"m"), sigs)
        # 即使重放只带一份签名，也返回已有聚合签名。
        status, second = self.service.submit_signature(
            "w1", "req-1", b64(b"m"), sigs[:1]
        )
        self.assertEqual(status, 201)
        self.assertEqual(second["signature"], first["signature"])

    def test_distinct_request_ids_are_independent(self):
        self._create("w1", 2)
        sigs_a, _ = self._share_signatures("w1", "a", b"m")
        sigs_b, _ = self._share_signatures("w1", "b", b"m")
        self.assertEqual(
            self.service.submit_signature("w1", "a", b64(b"m"), sigs_a)[0], 201
        )
        self.assertEqual(
            self.service.submit_signature("w1", "b", b64(b"m"), sigs_b)[0], 201
        )

    # -- 安全：存储中无完整私钥 ----------------------------------------

    def test_no_full_key_on_disk(self):
        self._create("w1", 2)
        wallet = self.store.get("w1")
        # 恰好两份独立的 32 字节份额，磁盘上不存在 64 字节"完整私钥"。
        self.assertEqual(len(wallet.shares), 2)
        for share in wallet.shares:
            self.assertEqual(len(base64.b64decode(share.private_b64)), 32)


if __name__ == "__main__":
    unittest.main()
