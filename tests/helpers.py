"""测试辅助：在临时目录上构造 service，并启动真实 HTTP 服务器。"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from threshold_wallet import crypto
from threshold_wallet.server import create_server
from threshold_wallet.service import WalletService
from threshold_wallet.store import WalletStore


@dataclass
class Harness:
    tmpdir: str
    store: WalletStore
    service: WalletService

    def share_signature(self, wallet_id: str, share_id: str,
                        signing_request_id: str, message: str) -> str:
        """模拟某一份额持有方：用本地份额私钥对拼接载荷签名，返回 hex。"""
        share = self.store.get_share(wallet_id, share_id)
        payload = crypto.build_payload(signing_request_id, message)
        return crypto.sign_share(
            bytes.fromhex(share["private_key"]), payload
        ).hex()

    def two_signatures(self, wallet_id: str, signing_request_id: str,
                       message: str) -> list[dict]:
        return [
            {
                "share_id": sid,
                "signature": self.share_signature(
                    wallet_id, sid, signing_request_id, message
                ),
            }
            for sid in ("share-1", "share-2")
        ]

    def share_private_hex(self, wallet_id: str, share_id: str) -> str:
        return self.store.get_share(wallet_id, share_id)["private_key"]


def make_harness(tmpdir: str) -> Harness:
    store = WalletStore(tmpdir)
    return Harness(tmpdir=tmpdir, store=store, service=WalletService(store))


@dataclass
class RunningServer:
    harness: Harness
    base_url: str
    logs: list[str]
    _httpd: object

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

    def request(self, method: str, path: str, body=None):
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(
            self.base_url + path, data=data, method=method, headers=headers
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))


@contextmanager
def http_server(tmpdir: str) -> Iterator[RunningServer]:
    """在后台线程启动真实 HTTP 服务器，端口由内核分配。"""
    harness = make_harness(tmpdir)
    logs: list[str] = []
    httpd = create_server("127.0.0.1", 0, harness.service, trace=logs.append)
    port = httpd.server_address[1]
    thread = threading.Thread(
        target=httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
    )
    thread.start()
    running = RunningServer(
        harness=harness,
        base_url=f"http://127.0.0.1:{port}",
        logs=logs,
        _httpd=httpd,
    )
    try:
        yield running
    finally:
        running.stop()
        thread.join(timeout=2)
