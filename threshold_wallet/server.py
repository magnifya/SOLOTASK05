"""HTTP 服务：POST /v1/wallets、POST /v1/wallets/{id}/sign、GET /v1/wallets/{id}。

仅使用标准库 http.server，避免引入第三方 Web 框架。

安全约束：
- 请求体只在内存中解析后立即交给业务层，不写日志；
- 访问日志只记录方法、路径、状态码，绝不出现份额私钥或完整私钥
  （本系统本来也不存在完整私钥）；
- 通用错误不回显请求内容。

消息与签名字段均使用 base64 编码以保证二进制安全：
- sign 请求的 ``message`` 为 base64；
- signatures 元素的 ``signature`` 为 base64；
- 响应中的 public_key / signature 同为 base64。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

from .service import WalletService
from .store import WalletStore

_WALLETS_PATH = re.compile(r"^/v1/wallets$")
_WALLET_PATH = re.compile(r"^/v1/wallets/([^/]+)$")
_SIGN_PATH = re.compile(r"^/v1/wallets/([^/]+)/sign$")

# 请求体大小上限：1 MiB，防止异常大的请求耗尽内存。
_MAX_BODY_BYTES = 1 * 1024 * 1024


def build_handler(service: WalletService) -> type[BaseHTTPRequestHandler]:
    """构造绑定到给定 service 的请求处理器类。"""

    class _WalletHandler(BaseHTTPRequestHandler):
        server_version = "ThresholdWallet/0.1"

        # -- 基础工具 ---------------------------------------------------

        def _send_json(self, status: int, body: dict) -> None:
            data = json.dumps(
                body, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _read_json_body(self) -> tuple[dict | None, int | None]:
            """读取并解析 JSON 请求体。

            返回 (对象, None) 或 (None, 错误状态码)。
            """
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return None, 400
            if length <= 0 or length > _MAX_BODY_BYTES:
                return None, 400
            raw = self.rfile.read(length)
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return None, 400
            if not isinstance(parsed, dict):
                return None, 400
            return parsed, None

        # -- 路由 -------------------------------------------------------

        def do_POST(self) -> None:  # noqa: N802 - http.server 约定命名
            if _WALLETS_PATH.match(self.path):
                self._handle_create_wallet()
            else:
                match = _SIGN_PATH.match(self.path)
                if match:
                    self._handle_sign(unquote(match.group(1)))
                else:
                    self._send_json(404, {"error": "路径不存在"})

        def do_GET(self) -> None:  # noqa: N802
            match = _WALLET_PATH.match(self.path)
            if match:
                status, body = service.get_wallet(unquote(match.group(1)))
                self._send_json(status, body)
            else:
                self._send_json(404, {"error": "路径不存在"})

        # -- 接口处理 ---------------------------------------------------

        def _handle_create_wallet(self) -> None:
            body, error_status = self._read_json_body()
            if error_status is not None:
                self._send_json(error_status, {"error": "请求体必须为合法 JSON 对象"})
                return
            # 缺失字段按 400 处理；service 负责进一步校验。
            wallet_id = body.get("wallet_id")
            shares = body.get("shares")
            if not isinstance(wallet_id, str) or not isinstance(shares, int):
                self._send_json(
                    400,
                    {"error": "必须提供字符串 wallet_id 与整数 shares"},
                )
                return
            status, result = service.create_wallet(wallet_id, shares)
            self._send_json(status, result)

        def _handle_sign(self, wallet_id: str) -> None:
            body, error_status = self._read_json_body()
            if error_status is not None:
                self._send_json(error_status, {"error": "请求体必须为合法 JSON 对象"})
                return
            signing_request_id = body.get("signing_request_id")
            message = body.get("message")
            signatures = body.get("signatures")
            if not isinstance(signing_request_id, str) or not isinstance(message, str):
                self._send_json(
                    400,
                    {"error": "必须提供 signing_request_id 与 base64 编码的 message"},
                )
                return
            if not isinstance(signatures, list):
                self._send_json(400, {"error": "signatures 必须为数组"})
                return
            status, result = service.submit_signature(
                wallet_id, signing_request_id, message, signatures
            )
            self._send_json(status, result)

        # -- 日志：只含方法、路径与状态码，杜绝敏感材料 ------------------

        def log_request(self, code="-", size="-"):  # noqa: D401
            sys.stderr.write(
                f'{self.address_string()} - - "{self.requestline}" {code} {size}\n'
            )

        def log_error(self, fmt, *args):  # noqa: A002
            # 不拼接任何参数：错误细节不写日志，避免意外带入请求内容。
            sys.stderr.write(
                f'{self.address_string()} - - ERROR '
                f'"{self.command} {self.path}"\n'
            )

    return _WalletHandler


def serve(host: str, port: int, service: WalletService) -> None:
    """启动阻塞式 HTTP 服务。"""
    server = ThreadingHTTPServer((host, port), build_handler(service))
    print(f"门限签名服务监听 http://{host}:{port}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="两方门限签名托管 HTTP 服务")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument(
        "--data-dir",
        default="./data",
        help="钱包份额持久化目录（默认 ./data）",
    )
    args = parser.parse_args(argv)

    service = WalletService(WalletStore(args.data_dir))
    serve(args.host, args.port, service)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
