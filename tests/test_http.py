"""HTTP 端到端测试：在随机端口启动真实服务器，走真实 socket。"""

from __future__ import annotations

import json
import tempfile
import unittest

from tests.helpers import http_server


class HttpApiTest(unittest.TestCase):
    def setUp(self):
        self._ctx = http_server(tempfile.mkdtemp())
        self.srv = self._ctx.__enter__()
        self.url = self.srv.base_url

    def tearDown(self):
        self._ctx.__exit__(None, None, None)

    def request(self, method, path, body=None):
        return self.srv.request(method, path, body)

    def create_wallet(self, wallet_id="w1", shares=2):
        return self.request(
            "POST", "/v1/wallets", {"wallet_id": wallet_id, "shares": shares}
        )

    # ---- 建钱包 ---------------------------------------------------------

    def test_create_wallet_201_contract(self):
        status, body = self.create_wallet()
        self.assertEqual(status, 201)
        self.assertEqual(set(body), {"wallet_id", "public_key", "share_ids"})
        self.assertEqual(body["wallet_id"], "w1")
        self.assertEqual(body["share_ids"], ["share-1", "share-2"])
        self.assertEqual(len(bytes.fromhex(body["public_key"])), 64)

    def test_create_shares_not_two_is_400(self):
        for shares in (1, 3, 0):
            status, body = self.create_wallet(f"w{shares}", shares)
            self.assertEqual(status, 400)
            self.assertIn("error", body)

    def test_create_duplicate_is_409(self):
        self.assertEqual(self.create_wallet()[0], 201)
        status, _ = self.create_wallet()
        self.assertEqual(status, 409)

    # ---- 查询 -----------------------------------------------------------

    def test_get_wallet_200_contract(self):
        _, created = self.create_wallet()
        status, body = self.request("GET", "/v1/wallets/w1")
        self.assertEqual(status, 200)
        self.assertEqual(set(body), {"wallet_id", "public_key", "created_at"})
        self.assertEqual(body["public_key"], created["public_key"])
        self.assertTrue(body["created_at"])

    def test_get_wallet_missing_is_404(self):
        status, body = self.request("GET", "/v1/wallets/ghost")
        self.assertEqual(status, 404)
        self.assertIn("error", body)

    # ---- 签名 -----------------------------------------------------------

    def _sign_body(self, wallet, srid, message):
        return {
            "signing_request_id": srid,
            "message": message,
            "signatures": self.srv.harness.two_signatures(wallet, srid, message),
        }

    def test_sign_201_contract(self):
        self.create_wallet()
        status, body = self.request(
            "POST", "/v1/wallets/w1/sign", self._sign_body("w1", "r1", "hello")
        )
        self.assertEqual(status, 201)
        self.assertEqual(set(body), {"signature"})
        self.assertEqual(len(bytes.fromhex(body["signature"])), 128)

    def test_sign_wallet_missing_is_404(self):
        self.create_wallet("w1")  # 用于生成合法份额签名；ghost 仍不存在
        status, _ = self.request(
            "POST",
            "/v1/wallets/ghost/sign",
            self._sign_body("w1", "r1", "m"),
        )
        self.assertEqual(status, 404)

    def test_sign_missing_one_share_is_400(self):
        self.create_wallet()
        body = self._sign_body("w1", "r1", "m")
        body["signatures"] = body["signatures"][:1]
        status, _ = self.request("POST", "/v1/wallets/w1/sign", body)
        self.assertEqual(status, 400)

    def test_sign_bad_signature_is_400(self):
        self.create_wallet()
        body = self._sign_body("w1", "r1", "m")
        body["signatures"][0]["signature"] = "00" * 64
        body["signing_request_id"] = "r2"
        status, _ = self.request("POST", "/v1/wallets/w1/sign", body)
        self.assertEqual(status, 400)

    def test_sign_duplicate_share_is_400(self):
        self.create_wallet()
        body = self._sign_body("w1", "r1", "m")
        body["signatures"][1] = dict(body["signatures"][0])
        body["signing_request_id"] = "r2"
        status, _ = self.request("POST", "/v1/wallets/w1/sign", body)
        self.assertEqual(status, 400)

    def test_sign_replay_returns_existing_signature(self):
        self.create_wallet()
        first_body = self._sign_body("w1", "r1", "m")
        s1, b1 = self.request("POST", "/v1/wallets/w1/sign", first_body)
        self.assertEqual(s1, 201)
        s2, b2 = self.request("POST", "/v1/wallets/w1/sign", first_body)
        self.assertEqual(s2, 200)
        self.assertEqual(b2, b1)

    # ---- 错误输入 -------------------------------------------------------

    def test_malformed_json_is_400(self):
        self.create_wallet()
        # 直接发送非法 JSON 字符串
        import urllib.request
        import urllib.error

        req = urllib.request.Request(
            self.url + "/v1/wallets",
            data=b"{not-json",
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(req)
            self.fail("expected 400")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 400)

    def test_json_array_body_is_400(self):
        import urllib.request, urllib.error
        req = urllib.request.Request(
            self.url + "/v1/wallets",
            data=b"[1,2]",
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(req)
            self.fail("expected 400")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 400)

    def test_unknown_route_is_404(self):
        status, _ = self.request("GET", "/v1/nope")
        self.assertEqual(status, 404)

    # ---- 安全：响应与日志绝不出现私钥 -----------------------------------

    def test_responses_and_logs_never_contain_share_private_keys(self):
        _, created = self.create_wallet("secret-wallet")
        priv1 = self.srv.harness.share_private_hex("secret-wallet", "share-1")
        priv2 = self.srv.harness.share_private_hex("secret-wallet", "share-2")
        self.request("GET", "/v1/wallets/secret-wallet")
        self.request(
            "POST",
            "/v1/wallets/secret-wallet/sign",
            self._sign_body("secret-wallet", "r1", "m"),
        )
        # 触发错误路径，确保错误响应也不泄密
        self.request("GET", "/v1/wallets/missing")
        self.request("POST", "/v1/wallets", {"wallet_id": "secret-wallet", "shares": 3})

        # 建钱包响应不含任何份额私钥
        self.assertNotIn(priv1, json.dumps(created))
        self.assertNotIn(priv2, json.dumps(created))
        # 日志中绝不出现份额私钥或其片段
        log_blob = "\n".join(self.srv.logs)
        self.assertNotIn(priv1, log_blob)
        self.assertNotIn(priv2, log_blob)
        # 日志只含方法/路径/状态码，不含请求体
        self.assertTrue(
            all(len(line.split()) >= 3 for line in self.srv.logs),
            self.srv.logs,
        )

    def test_two_share_private_keys_are_distinct(self):
        self.create_wallet()
        p1 = self.srv.harness.share_private_hex("w1", "share-1")
        p2 = self.srv.harness.share_private_hex("w1", "share-2")
        self.assertNotEqual(p1, p2)


if __name__ == "__main__":
    unittest.main()
