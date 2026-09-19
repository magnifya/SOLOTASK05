"""HTTP 接口集成测试：在随机端口启动真实服务。"""

import base64
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from threshold_wallet import crypto
from threshold_wallet.server import build_handler
from threshold_wallet.service import WalletService
from threshold_wallet.store import WalletStore


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class HttpTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.store = WalletStore(self._tmp.name)
        service = WalletService(self.store)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(service))
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self._tmp.cleanup()

    def _url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def _call(self, method, path, obj=None, raw=None):
        data = raw if raw is not None else (
            None if obj is None else json.dumps(obj).encode()
        )
        request = urllib.request.Request(
            self._url(path),
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def _create(self, wallet_id="w1"):
        return self._call("POST", "/v1/wallets", {"wallet_id": wallet_id, "shares": 2})

    def test_full_lifecycle(self):
        status, body = self._create("w1")
        self.assertEqual(status, 201)
        self.assertEqual(set(body), {"wallet_id", "public_key", "share_ids"})
        share_ids = body["share_ids"]
        self.assertEqual(len(share_ids), 2)

        # shares != 2
        self.assertEqual(
            self._call("POST", "/v1/wallets", {"wallet_id": "w2", "shares": 1})[0],
            400,
        )
        # 重复
        self.assertEqual(
            self._call("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})[0],
            409,
        )

        # 查询
        status, shown = self._call("GET", "/v1/wallets/w1")
        self.assertEqual(status, 200)
        self.assertEqual(set(shown), {"public_key", "created_at"})
        self.assertEqual(shown["public_key"], body["public_key"])
        self.assertEqual(self._call("GET", "/v1/wallets/nope")[0], 404)

        # 签名：用磁盘份额私钥模拟两方
        wallet = self.store.get("w1")
        message = b"invoice #42"
        payload = crypto.signing_payload("sr-1", message)
        sigs = []
        for share in wallet.shares:
            priv = base64.b64decode(share.private_b64)
            sigs.append(
                {
                    "share_id": share.share_id,
                    "signature": b64(crypto.sign_share(priv, payload)),
                }
            )
        sign_body = {
            "signing_request_id": "sr-1",
            "message": b64(message),
            "signatures": list(reversed(sigs)),
        }
        status, signed = self._call("POST", "/v1/wallets/w1/sign", sign_body)
        self.assertEqual(status, 201)
        self.assertEqual(set(signed), {"signature"})
        self.assertTrue(
            crypto.verify_aggregated_signature(
                base64.b64decode(wallet.public_key_b64),
                payload,
                base64.b64decode(signed["signature"]),
            )
        )

        # 缺一份 -> 400
        bad = dict(sign_body)
        bad["signing_request_id"] = "sr-2"
        bad["signatures"] = sigs[:1]
        self.assertEqual(self._call("POST", "/v1/wallets/w1/sign", bad)[0], 400)

        # 幂等 -> 已有签名（即使只重放一份）
        replay = dict(sign_body)
        replay["signatures"] = sigs[:1]
        status, again = self._call("POST", "/v1/wallets/w1/sign", replay)
        self.assertEqual(status, 201)
        self.assertEqual(again["signature"], signed["signature"])

    def test_sign_unknown_wallet(self):
        status, _ = self._call(
            "POST",
            "/v1/wallets/ghost/sign",
            {"signing_request_id": "x", "message": b64(b"m"), "signatures": []},
        )
        self.assertEqual(status, 404)

    def test_malformed_json(self):
        self.assertEqual(self._call("POST", "/v1/wallets", raw=b"{")[0], 400)
        self.assertEqual(self._call("POST", "/v1/wallets", raw=b"[1]")[0], 400)

    def test_unknown_route(self):
        self.assertEqual(self._call("GET", "/v1/nope")[0], 404)


if __name__ == "__main__":
    unittest.main()
