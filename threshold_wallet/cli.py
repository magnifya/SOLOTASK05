"""命令行入口：create / sign / show，与 HTTP 接口一一对应。

每个子命令向服务端发请求并把响应体打印为单行 JSON：
- create: POST /v1/wallets
- sign:   POST /v1/wallets/{wallet_id}/sign
- show:   GET  /v1/wallets/{wallet_id}

sign 的份额签名通过以下可重复参数提供（份数是否齐备由服务端判定，
因此同一 signing_request_id 的幂等重放也能拿回已有签名）：
- ``--signature share_id=<base64 份额签名>``：直接提交已算好的份额签名；
- ``--share-key share_id=<base64 份额私钥>``：本地用该份额私钥当场签名
  （模拟份额持有方）。私钥只存在于本地进程，绝不写入日志或响应。

服务端地址用 ``--server`` 或环境变量 THRESHOLD_WALLET_URL 指定。
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request

from . import crypto

DEFAULT_SERVER = "http://127.0.0.1:8080"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _emit(obj: dict) -> None:
    """打印单行 JSON（不缩进、不转义非 ASCII）。"""
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")


def _request(method: str, url: str, body: dict | None) -> tuple[int, dict]:
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    request = urllib.request.Request(
        url, data=data, method=method, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            payload = {"error": f"HTTP {exc.code}"}
        return exc.code, payload
    except urllib.error.URLError as exc:
        return 0, {"error": f"无法连接服务: {exc.reason}"}


def _parse_pair(value: str) -> tuple[str, str]:
    """解析 ``share_id=payload`` 形式的参数。"""
    if "=" not in value:
        raise argparse.ArgumentTypeError("参数格式必须为 share_id=<base64 值>")
    key, _, val = value.partition("=")
    if not key or not val:
        raise argparse.ArgumentTypeError("share_id 与值均不能为空")
    return key, val


def _build_signatures(
    signing_request_id: str,
    message: bytes,
    raw_signatures: list[tuple[str, str]],
    share_keys: list[tuple[str, str]],
) -> list[dict]:
    """把命令行给出的份额签名/份额私钥汇总为签名项。

    份数是否齐备（含幂等重放）一律由服务端判定，CLI 只做透传，
    仅保证 share_id 不重复、份额私钥可用。
    """
    items: list[dict] = []
    seen: set[str] = set()
    payload = crypto.signing_payload(signing_request_id, message)

    for share_id, signature_b64 in raw_signatures:
        if share_id in seen:
            raise ValueError(f"share_id {share_id} 重复")
        seen.add(share_id)
        items.append({"share_id": share_id, "signature": signature_b64})

    for share_id, key_b64 in share_keys:
        if share_id in seen:
            raise ValueError(f"share_id {share_id} 重复")
        seen.add(share_id)
        try:
            private_bytes = base64.b64decode(key_b64, validate=True)
        except ValueError:
            raise ValueError(f"份额 {share_id} 的私钥不是合法 base64")
        try:
            signature = crypto.sign_share(private_bytes, payload)
        except ValueError:
            raise ValueError(f"份额 {share_id} 的私钥必须为 32 字节")
        items.append({"share_id": share_id, "signature": _b64(signature)})

    return items


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threshold-wallet", description="两方门限签名托管命令行"
    )
    parser.add_argument(
        "--server",
        default=os.environ.get("THRESHOLD_WALLET_URL", DEFAULT_SERVER),
        help="服务端地址（默认读 THRESHOLD_WALLET_URL 或 %(default)s）",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_create = sub.add_parser("create", help="创建钱包：POST /v1/wallets")
    p_create.add_argument("wallet_id")
    p_create.add_argument("--shares", type=int, default=2, help="必须为 2")

    p_show = sub.add_parser("show", help="查询钱包：GET /v1/wallets/{id}")
    p_show.add_argument("wallet_id")

    p_sign = sub.add_parser("sign", help="提交份额签名：POST /v1/wallets/{id}/sign")
    p_sign.add_argument("wallet_id")
    p_sign.add_argument("--signing-request-id", required=True)
    message_group = p_sign.add_mutually_exclusive_group(required=True)
    message_group.add_argument(
        "--message", help="UTF-8 文本消息，与 --message-b64 二选一"
    )
    message_group.add_argument("--message-b64", help="base64 编码的二进制消息")
    p_sign.add_argument(
        "--signature",
        action="append",
        default=[],
        type=_parse_pair,
        metavar="share_id=<base64 签名>",
        help="提交一份现成份额签名，可重复给出",
    )
    p_sign.add_argument(
        "--share-key",
        action="append",
        default=[],
        type=_parse_pair,
        metavar="share_id=<base64 私钥>",
        help="用本地份额私钥当场生成一份签名，可重复给出",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    base = args.server.rstrip("/")

    if args.command == "create":
        status, body = _request(
            "POST",
            f"{base}/v1/wallets",
            {"wallet_id": args.wallet_id, "shares": args.shares},
        )

    elif args.command == "show":
        status, body = _request(
            "GET", f"{base}/v1/wallets/{args.wallet_id}", None
        )

    else:  # sign
        if args.message_b64 is not None:
            try:
                message = base64.b64decode(args.message_b64, validate=True)
            except ValueError:
                _emit({"error": "message 不是合法的 base64"})
                return 2
        else:
            message = args.message.encode("utf-8")
        try:
            signatures = _build_signatures(
                args.signing_request_id,
                message,
                args.signature,
                args.share_key,
            )
        except ValueError as exc:
            _emit({"error": str(exc)})
            return 2
        status, body = _request(
            "POST",
            f"{base}/v1/wallets/{args.wallet_id}/sign",
            {
                "signing_request_id": args.signing_request_id,
                "message": _b64(message),
                "signatures": signatures,
            },
        )

    _emit(body)
    return 0 if 200 <= status < 300 else 1


if __name__ == "__main__":
    raise SystemExit(main())
