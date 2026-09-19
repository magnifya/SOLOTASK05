"""HTTP 服务层：标准库 http.server，无第三方 Web 框架依赖。

路由：
- POST /v1/wallets                                       建钱包
- GET  /v1/wallets/<wallet_id>                           查询钱包
- PUT  /v1/wallets/<wallet_id>/approval-policy           设置审批策略
- POST /v1/wallets/<wallet_id>/sign-requests             创建签名审批请求
- GET  /v1/wallets/<wallet_id>/sign-requests/<id>        查询签名审批请求
- POST /v1/wallets/<wallet_id>/sign-requests/<id>/approve  批准
- POST /v1/wallets/<wallet_id>/sign-requests/<id>/reject   拒绝
- POST /v1/wallets/<wallet_id>/sign                      提交两份额签名

安全：访问日志只记录方法、路径与状态码，绝不读取或记录请求/响应体，
因此份额私钥不可能进入日志。
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .service import ServiceError, WalletService

#: 请求体大小上限，防止异常大 body
_MAX_BODY_BYTES = 1 * 1024 * 1024

_WALLETS_PREFIX = "/v1/wallets/"


def build_handler(service: WalletService) -> type[BaseHTTPRequestHandler]:
    """构造绑定到指定 service 的请求处理器类。"""

    class _Handler(BaseHTTPRequestHandler):
        server_version = "ThresholdWallet/1.0"

        # ---- 响应/日志辅助 ----------------------------------------------

        def _send_json(self, status: int, body: dict) -> None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _send_error(self, status: int, message: str) -> None:
            self._send_json(status, {"error": message})

        def log_message(self, fmt: str, *args: object) -> None:
            # 只记录方法、路径与状态码；不记录任何请求体/响应体
            status = args[1] if len(args) > 1 else "-"
            self.server.trace(f"{self.command} {self.path} -> {status}")

        # ---- 请求体读取 -------------------------------------------------

        def _read_json_body(self) -> dict:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                raise ServiceError(400, "invalid Content-Length")
            if length <= 0:
                raise ServiceError(400, "request body is required")
            if length > _MAX_BODY_BYTES:
                raise ServiceError(413, "request body too large")
            raw = self.rfile.read(length)
            try:
                body = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                raise ServiceError(400, "request body must be valid JSON")
            if not isinstance(body, dict):
                raise ServiceError(400, "request body must be a JSON object")
            return body

        # ---- 路由 -------------------------------------------------------

        def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
            path = urlparse(self.path).path
            try:
                wallet_id = self._match_wallet(path)
                if wallet_id is not None:
                    self._send_json(200, service.get_wallet(wallet_id))
                    return

                matched = self._match_request_subresource(path, "")
                if matched is not None:
                    wallet_id, request_id = matched
                    self._send_json(
                        200, service.get_sign_request(wallet_id, request_id)
                    )
                    return

                self._send_error(404, "not found")
            except ServiceError as exc:
                self._send_error(exc.status, exc.message)

        def do_PUT(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            try:
                wallet_id = self._match_approval_policy(path)
                if wallet_id is None:
                    self._send_error(404, "not found")
                    return
                body = self._read_json_body()
                status, result = service.set_approval_policy(
                    wallet_id,
                    body.get("required_approvals"),
                    body.get("timeout_seconds"),
                )
                self._send_json(status, result)
            except ServiceError as exc:
                self._send_error(exc.status, exc.message)

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            try:
                if path == "/v1/wallets":
                    body = self._read_json_body()
                    result = service.create_wallet(
                        body.get("wallet_id"), body.get("shares")
                    )
                    self._send_json(201, result)
                    return

                wallet_id = self._match_wallet_sign(path)
                if wallet_id is not None:
                    body = self._read_json_body()
                    status, result = service.sign(
                        wallet_id,
                        body.get("signing_request_id"),
                        body.get("message"),
                        body.get("signatures"),
                    )
                    self._send_json(status, result)
                    return

                wallet_id = self._match_sign_requests_collection(path)
                if wallet_id is not None:
                    body = self._read_json_body()
                    status, result = service.create_sign_request(
                        wallet_id, body.get("id"), body.get("message")
                    )
                    self._send_json(status, result)
                    return

                matched = self._match_request_subresource(path, "approve")
                if matched is not None:
                    wallet_id, request_id = matched
                    body = self._read_json_body()
                    self._send_json(
                        200,
                        service.approve(
                            wallet_id,
                            request_id,
                            body.get("approver_id"),
                            body.get("reason"),
                        ),
                    )
                    return

                matched = self._match_request_subresource(path, "reject")
                if matched is not None:
                    wallet_id, request_id = matched
                    body = self._read_json_body()
                    self._send_json(
                        200,
                        service.reject(
                            wallet_id,
                            request_id,
                            body.get("approver_id"),
                            body.get("reason"),
                        ),
                    )
                    return

                self._send_error(404, "not found")
            except ServiceError as exc:
                self._send_error(exc.status, exc.message)

        # ---- 路径匹配 ---------------------------------------------------

        @staticmethod
        def _match_wallet(path: str):
            """/v1/wallets/<wallet_id> -> wallet_id，否则 None。"""
            if not path.startswith(_WALLETS_PREFIX):
                return None
            tail = path[len(_WALLETS_PREFIX):]
            if tail and "/" not in tail:
                return tail
            return None

        @staticmethod
        def _match_wallet_sign(path: str):
            """/v1/wallets/<wallet_id>/sign -> wallet_id，否则 None。"""
            if not path.startswith(_WALLETS_PREFIX):
                return None
            tail = path[len(_WALLETS_PREFIX):]
            wallet_id, sep, suffix = tail.partition("/")
            if wallet_id and sep and suffix == "sign":
                return wallet_id
            return None

        @staticmethod
        def _match_approval_policy(path: str):
            """/v1/wallets/<wallet_id>/approval-policy -> wallet_id。"""
            if not path.startswith(_WALLETS_PREFIX):
                return None
            tail = path[len(_WALLETS_PREFIX):]
            wallet_id, sep, suffix = tail.partition("/")
            if wallet_id and sep and suffix == "approval-policy":
                return wallet_id
            return None

        @staticmethod
        def _match_sign_requests_collection(path: str):
            """/v1/wallets/<wallet_id>/sign-requests -> wallet_id。"""
            if not path.startswith(_WALLETS_PREFIX):
                return None
            tail = path[len(_WALLETS_PREFIX):]
            wallet_id, sep, suffix = tail.partition("/")
            if wallet_id and sep and suffix == "sign-requests":
                return wallet_id
            return None

        @staticmethod
        def _match_request_subresource(path: str, subresource: str):
            """/v1/wallets/<w>/sign-requests/<id>[/<subresource>] -> (w, id)。

            subresource 为 "" 时匹配元素本身（GET 单个请求）；
            否则匹配该元素下的动作（approve/reject）。
            """
            if not path.startswith(_WALLETS_PREFIX):
                return None
            parts = path[len(_WALLETS_PREFIX):].split("/")
            expected_len = 4 if subresource else 3
            if len(parts) != expected_len:
                return None
            wallet_id, collection, request_id = parts[0], parts[1], parts[2]
            if not wallet_id or collection != "sign-requests" or not request_id:
                return None
            if subresource and parts[3] != subresource:
                return None
            return wallet_id, request_id

    return _Handler


def _default_trace(line: str) -> None:
    import sys

    print(line, file=sys.stderr, flush=True)


def create_server(
    host: str,
    port: int,
    service: WalletService,
    trace=_default_trace,
) -> ThreadingHTTPServer:
    """创建并返回 HTTP 服务器（尚未开始服务）。"""
    handler = build_handler(service)
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.trace = trace  # type: ignore[attr-defined]
    return httpd


def serve(host: str, port: int, service: WalletService) -> None:
    """创建并运行 HTTP 服务器，直到被中断。"""
    httpd = create_server(host, port, service)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
