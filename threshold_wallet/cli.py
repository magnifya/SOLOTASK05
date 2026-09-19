"""命令行入口。

与 HTTP 接口一一对应的三个客户端子命令（均打印单行 JSON）：
- create  对应 POST /v1/wallets
- sign    对应 POST /v1/wallets/<wallet_id>/sign
- show    对应 GET  /v1/wallets/<wallet_id>

另有两个本地命令：
- serve       启动 HTTP 服务
- share-sign  份额持有方辅助命令：用本机房份额私钥生成份额签名
              （签名内容为 signing_request_id 与 message 的拼接），
              输出可直接交给 sign 子命令的 {"share_id", "signature"}

客户端命令只通过 HTTP 与服务端交互；create/show 的响应中本就不含私钥。
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence
from urllib import error as urllib_error
from urllib import request as urllib_request

from . import crypto

DEFAULT_URL = "http://127.0.0.1:8080"
DEFAULT_DATA_DIR = "./data"
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8080


def _print_json(obj: dict) -> None:
    print(json.dumps(obj, ensure_ascii=False, sort_keys=True))


def _fail(message: str) -> int:
    print(json.dumps({"error": message}, ensure_ascii=False), file=sys.stderr)
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threshold-wallet",
        description="两方门限（2-of-2）Ed25519 签名托管后端",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # serve
    p_serve = sub.add_parser("serve", help="启动 HTTP 服务")
    p_serve.add_argument("--host", default=DEFAULT_HOST)
    p_serve.add_argument("--port", type=int, default=DEFAULT_PORT)
    p_serve.add_argument("--data-dir", default=DEFAULT_DATA_DIR)

    # create  <-> POST /v1/wallets
    p_create = sub.add_parser("create", help="创建钱包（POST /v1/wallets）")
    p_create.add_argument("--url", default=DEFAULT_URL)
    p_create.add_argument("--wallet-id", required=True)
    p_create.add_argument("--shares", type=int, default=2, help="必须为 2")

    # show  <-> GET /v1/wallets/{id}
    p_show = sub.add_parser("show", help="查询钱包（GET /v1/wallets/{id}）")
    p_show.add_argument("--url", default=DEFAULT_URL)
    p_show.add_argument("--wallet-id", required=True)

    # sign  <-> POST /v1/wallets/{id}/sign
    p_sign = sub.add_parser("sign", help="提交两份份额签名（POST .../sign）")
    p_sign.add_argument("--url", default=DEFAULT_URL)
    p_sign.add_argument("--wallet-id", required=True)
    p_sign.add_argument("--signing-request-id", required=True)
    p_sign.add_argument("--message", required=True)
    p_sign.add_argument(
        "--signature",
        action="append",
        metavar="SHARE_ID=HEX",
        dest="signatures",
        required=True,
        help="份额签名，可重复两次；HEX 可由 share-sign 生成",
    )

    # share-sign（份额持有方本地辅助命令）
    p_ss = sub.add_parser(
        "share-sign",
        help="份额持有方用本地份额私钥生成份额签名（不经过网络）",
    )
    p_ss.add_argument("--data-dir", default=DEFAULT_DATA_DIR)
    p_ss.add_argument("--wallet-id", required=True)
    p_ss.add_argument("--share-id", required=True)
    p_ss.add_argument("--signing-request-id", required=True)
    p_ss.add_argument("--message", required=True)

    return parser


def _http_request(method: str, url: str, body: Optional[dict]) -> tuple[int, dict]:
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib_request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib_request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib_error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            payload = {"error": f"HTTP {exc.code}"}
        return exc.code, payload
    except urllib_error.URLError as exc:
        raise ConnectionError(f"cannot reach {url}: {exc.reason}") from exc


def _parse_share_signature(text: str) -> dict:
    if "=" not in text:
        raise ValueError(f"bad --signature {text!r}，应为 SHARE_ID=HEX")
    share_id, _, signature_hex = text.partition("=")
    share_id, signature_hex = share_id.strip(), signature_hex.strip()
    if not share_id:
        raise ValueError(f"bad --signature {text!r}：缺少 share_id")
    try:
        bytes.fromhex(signature_hex)
    except ValueError as exc:
        raise ValueError(f"signature 不是合法 hex：{text!r}") from exc
    return {"share_id": share_id, "signature": signature_hex}


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        if args.command == "serve":
            # 延迟导入：客户端命令不需要 store/server
            from .server import serve
            from .store import WalletStore
            from .service import WalletService

            service = WalletService(WalletStore(args.data_dir))
            print(
                json.dumps(
                    {
                        "event": "server_starting",
                        "host": args.host,
                        "port": args.port,
                        "data_dir": args.data_dir,
                    }
                ),
                file=sys.stderr,
                flush=True,
            )
            serve(args.host, args.port, service)
            return 0

        if args.command == "create":
            status, body = _http_request(
                "POST",
                f"{args.url}/v1/wallets",
                {"wallet_id": args.wallet_id, "shares": args.shares},
            )

        elif args.command == "show":
            status, body = _http_request(
                "GET", f"{args.url}/v1/wallets/{args.wallet_id}", None
            )

        elif args.command == "sign":
            signatures = [_parse_share_signature(s) for s in args.signatures]
            status, body = _http_request(
                "POST",
                f"{args.url}/v1/wallets/{args.wallet_id}/sign",
                {
                    "signing_request_id": args.signing_request_id,
                    "message": args.message,
                    "signatures": signatures,
                },
            )

        elif args.command == "share-sign":
            from .store import WalletStore

            store = WalletStore(args.data_dir)
            share = store.get_share(args.wallet_id, args.share_id)
            if share is None:
                return _fail(
                    f"share {args.share_id!r} of wallet "
                    f"{args.wallet_id!r} not found"
                )
            payload = crypto.build_payload(
                args.signing_request_id, args.message
            )
            signature = crypto.sign_share(
                bytes.fromhex(share["private_key"]), payload
            )
            _print_json(
                {"share_id": args.share_id, "signature": signature.hex()}
            )
            return 0

        else:  # pragma: no cover - argparse 已保证不会到达
            return _fail(f"unknown command {args.command!r}")

        # 成功响应打印单行 JSON 到 stdout；错误响应打印到 stderr 并返回非零
        if 200 <= status < 300:
            _print_json(body)
            return 0
        print(
            json.dumps(body, ensure_ascii=False, sort_keys=True),
            file=sys.stderr,
        )
        return 1

    except (ConnectionError, ValueError, OSError) as exc:
        return _fail(str(exc))


if __name__ == "__main__":
    sys.exit(main())
