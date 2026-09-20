"""HTTP 服务层：标准库 http.server，无第三方 Web 框架依赖。

路由：
- POST /v1/wallets                                  建钱包
- GET  /v1/wallets/<wallet_id>                      查询钱包
- PUT  /v1/wallets/<wallet_id>/approval-policy      设置审批策略
- PUT  /v1/wallets/<wallet_id>/transaction-policy   设置冷热钱包交易策略
- GET  /v1/wallets/<wallet_id>/transaction-policy   查询冷热钱包交易策略
- POST /v1/wallets/<wallet_id>/sign                 提交两份额签名
- POST /v1/wallets/<wallet_id>/sign-requests        创建签名请求审批单
- GET  /v1/wallets/<wallet_id>/sign-requests/<id>   查询审批单
- GET  /v1/wallets/<wallet_id>/audit-events         查询审计事件（升序）
- POST /v1/wallets/<wallet_id>/sign-requests/<id>/approve  批准
- POST /v1/wallets/<wallet_id>/sign-requests/<id>/reject   拒绝
- POST /v1/wallets/<wallet_id>/share-rotations             准备份额轮换
- GET  /v1/wallets/<wallet_id>/share-rotations/<id>        查询轮换
- POST /v1/wallets/<wallet_id>/share-rotations/<id>/activate  激活轮换
- POST /v1/wallets/<wallet_id>/asset-operations            创建资产操作
- POST /v1/wallets/<wallet_id>/asset-operations/<id>/commit   提交资产操作
- GET  /v1/wallets/<wallet_id>/assets/<asset_id>           查询资产余额/版本

安全：访问日志只记录方法、路径与状态码，绝不读取或记录请求/响应体，
因此份额私钥不可能进入日志。
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .service import ServiceError, WalletService
from .store import RecoveryError

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
            parsed = urlparse(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)
            try:
                matched = self._split_wallet_path(path)
                if matched is None:
                    self._send_error(404, "not found")
                    return
                wallet_id, rest = matched
                if not rest:
                    self._send_json(200, service.get_wallet(wallet_id))
                    return
                if len(rest) == 1 and rest[0] == "transaction-policy":
                    self._send_json(
                        200, service.get_transaction_policy(wallet_id)
                    )
                    return
                if len(rest) == 2 and rest[0] == "sign-requests":
                    self._send_json(
                        200, service.get_sign_request(wallet_id, rest[1])
                    )
                    return
                if len(rest) == 2 and rest[0] == "share-rotations":
                    self._send_json(
                        200, service.get_share_rotation(wallet_id, rest[1])
                    )
                    return
                if len(rest) == 2 and rest[0] == "assets":
                    self._send_json(200, service.get_asset(wallet_id, rest[1]))
                    return
                if rest == ["audit-events"]:
                    self._send_json(
                        200,
                        service.get_audit_events(
                            wallet_id,
                            from_seq=query.get("from_seq", [None])[0],
                            limit=query.get("limit", [None])[0],
                        ),
                    )
                    return
                self._send_error(404, "not found")
            except RecoveryError as exc:
                # 崩溃现场无法对账到一致状态：拒绝暴露半完成数据
                self._send_error(503, f"recovery incomplete: {exc}")
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

                matched = self._split_wallet_path(path)
                if matched is None:
                    self._send_error(404, "not found")
                    return
                wallet_id, rest = matched

                if rest == ["sign"]:
                    body = self._read_json_body()
                    status, result = service.sign(
                        wallet_id,
                        body.get("signing_request_id"),
                        body.get("message"),
                        body.get("signatures"),
                    )
                    self._send_json(status, result)
                    return

                if rest == ["sign-requests"]:
                    body = self._read_json_body()
                    request_id = body.get("id")
                    if request_id is None:
                        request_id = body.get("signing_request_id")
                    status, result = service.create_sign_request(
                        wallet_id, request_id, body.get("message")
                    )
                    self._send_json(status, result)
                    return

                if rest == ["share-rotations"]:
                    body = self._read_json_body()
                    status, result = service.create_share_rotation(
                        wallet_id, body.get("rotation_id")
                    )
                    self._send_json(status, result)
                    return

                if rest == ["asset-operations"]:
                    body = self._read_json_body()
                    status, result = service.create_asset_operation(
                        wallet_id,
                        body.get("operation_id"),
                        body.get("asset_id"),
                        body.get("delta"),
                    )
                    self._send_json(status, result)
                    return

                if (
                    len(rest) == 3
                    and rest[0] == "asset-operations"
                    and rest[2] == "commit"
                ):
                    status, result = service.commit_asset_operation(
                        wallet_id, rest[1]
                    )
                    self._send_json(status, result)
                    return

                if (
                    len(rest) == 3
                    and rest[0] == "share-rotations"
                    and rest[2] == "activate"
                ):
                    status, result = service.activate_share_rotation(
                        wallet_id, rest[1]
                    )
                    self._send_json(status, result)
                    return

                if (
                    len(rest) == 3
                    and rest[0] == "sign-requests"
                    and rest[2] in ("approve", "reject")
                ):
                    body = self._read_json_body()
                    decide = (
                        service.approve if rest[2] == "approve" else service.reject
                    )
                    result = decide(
                        wallet_id,
                        rest[1],
                        body.get("approver_id"),
                        body.get("reason"),
                    )
                    self._send_json(200, result)
                    return

                self._send_error(404, "not found")
            except RecoveryError as exc:
                self._send_error(503, f"recovery incomplete: {exc}")
            except ServiceError as exc:
                self._send_error(exc.status, exc.message)

        def do_PUT(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            try:
                matched = self._split_wallet_path(path)
                if matched is not None:
                    wallet_id, rest = matched
                    if rest == ["approval-policy"]:
                        body = self._read_json_body()
                        result = service.put_policy(
                            wallet_id,
                            body.get("required_approvals"),
                            body.get("timeout_seconds"),
                        )
                        self._send_json(200, result)
                        return
                    if rest == ["transaction-policy"]:
                        body = self._read_json_body()
                        result = service.put_transaction_policy(
                            wallet_id,
                            body.get("mode"),
                            body.get("max_delta"),
                            body.get("allowed_assets"),
                        )
                        self._send_json(200, result)
                        return
                self._send_error(404, "not found")
            except RecoveryError as exc:
                self._send_error(503, f"recovery incomplete: {exc}")
            except ServiceError as exc:
                self._send_error(exc.status, exc.message)

        # ---- 路径匹配 ---------------------------------------------------

        @staticmethod
        def _split_wallet_path(path: str):
            """/v1/wallets/<wallet_id>/<rest...> -> (wallet_id, rest)，否则 None。"""
            if not path.startswith(_WALLETS_PREFIX):
                return None
            parts = path[len(_WALLETS_PREFIX):].split("/")
            if not parts[0]:
                return None
            return parts[0], parts[1:]

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
