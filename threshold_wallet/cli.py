"""命令行入口。

与 HTTP 接口一一对应的三个客户端子命令（均打印单行 JSON）：
- create  对应 POST /v1/wallets
- sign    对应 POST /v1/wallets/<wallet_id>/sign
- show    对应 GET  /v1/wallets/<wallet_id>

另有本地命令：
- serve       启动 HTTP 服务
- share-sign  份额持有方辅助命令：用本机房份额私钥生成份额签名
              （签名内容为 signing_request_id 与 message 的拼接），
              输出可直接交给 sign 子命令的 {"share_id", "signature"}
- backup      创建单钱包灾备快照（持锁恢复对账后只打包白名单文件）
- restore     从灾备快照锁内校验并事务化恢复单钱包（幂等/冲突语义）

客户端命令只通过 HTTP 与服务端交互；create/show 的响应中本就不含私钥。
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence
from urllib import error as urllib_error
from urllib import request as urllib_request

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

    # policy  <-> PUT /v1/wallets/{id}/approval-policy
    p_policy = sub.add_parser(
        "policy", help="设置审批策略（PUT .../approval-policy）"
    )
    p_policy.add_argument("--url", default=DEFAULT_URL)
    p_policy.add_argument("--wallet-id", required=True)
    p_policy.add_argument("--required-approvals", type=int, required=True)
    p_policy.add_argument("--timeout-seconds", type=int, required=True)

    # request-create  <-> POST /v1/wallets/{id}/sign-requests
    p_rc = sub.add_parser(
        "request-create", help="创建签名请求审批单（POST .../sign-requests）"
    )
    p_rc.add_argument("--url", default=DEFAULT_URL)
    p_rc.add_argument("--wallet-id", required=True)
    p_rc.add_argument("--signing-request-id", required=True)
    p_rc.add_argument("--message", required=True)

    # request-show  <-> GET /v1/wallets/{id}/sign-requests/{rid}
    p_rs = sub.add_parser(
        "request-show", help="查询签名请求审批单（GET .../sign-requests/{id}）"
    )
    p_rs.add_argument("--url", default=DEFAULT_URL)
    p_rs.add_argument("--wallet-id", required=True)
    p_rs.add_argument("--signing-request-id", required=True)

    # approve / reject  <-> POST .../sign-requests/{rid}/approve|reject
    for name, help_text in (
        ("approve", "批准签名请求（POST .../approve）"),
        ("reject", "拒绝签名请求（POST .../reject）"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--url", default=DEFAULT_URL)
        p.add_argument("--wallet-id", required=True)
        p.add_argument("--signing-request-id", required=True)
        p.add_argument("--approver-id", required=True)
        p.add_argument("--reason", default=None)

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

    # backup / restore（本地兼容灾备命令）
    p_backup = sub.add_parser("backup", help="创建单钱包灾备快照")
    p_backup.add_argument("--data-dir", default=DEFAULT_DATA_DIR)
    p_backup.add_argument("--wallet-id", required=True)
    p_backup.add_argument("--snapshot-id", required=True)
    p_backup.add_argument("--output", required=True)

    p_restore = sub.add_parser("restore", help="从灾备快照恢复单钱包")
    p_restore.add_argument("--data-dir", default=DEFAULT_DATA_DIR)
    p_restore.add_argument("--wallet-id", required=True)
    p_restore.add_argument("--input", required=True)

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
            from .store import RecoveryError, WalletStore
            from .service import WalletService

            # 构造服务即完成启动恢复；恢复无法对账到一致状态时必须阻止
            # 服务就绪（fail-closed）：打印单行 JSON 错误并以非零码退出，
            # 绝不绑定端口对外暴露半完成状态。
            try:
                service = WalletService(WalletStore(args.data_dir))
            except RecoveryError as exc:
                return _fail(f"recovery failed, refusing to serve: {exc}")
            except OSError as exc:
                return _fail(f"cannot open data dir, refusing to serve: {exc}")
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

        elif args.command == "policy":
            status, body = _http_request(
                "PUT",
                f"{args.url}/v1/wallets/{args.wallet_id}/approval-policy",
                {
                    "required_approvals": args.required_approvals,
                    "timeout_seconds": args.timeout_seconds,
                },
            )

        elif args.command == "request-create":
            status, body = _http_request(
                "POST",
                f"{args.url}/v1/wallets/{args.wallet_id}/sign-requests",
                {
                    "id": args.signing_request_id,
                    "message": args.message,
                },
            )

        elif args.command == "request-show":
            status, body = _http_request(
                "GET",
                f"{args.url}/v1/wallets/{args.wallet_id}"
                f"/sign-requests/{args.signing_request_id}",
                None,
            )

        elif args.command in ("approve", "reject"):
            payload = {"approver_id": args.approver_id}
            if args.reason is not None:
                payload["reason"] = args.reason
            status, body = _http_request(
                "POST",
                f"{args.url}/v1/wallets/{args.wallet_id}"
                f"/sign-requests/{args.signing_request_id}/{args.command}",
                payload,
            )

        elif args.command == "share-sign":
            from .store import CorruptDataError, RecoveryError, WalletStore
            from .service import ServiceError, WalletService

            # share-sign 的统一错误边界：构造 WalletService（启动恢复）、
            # 钱包锁内懒恢复、读取当前份额、签名四个阶段都可能失败。无论
            # RecoveryError / OSError / ValueError（含损坏 JSON、非法私钥
            # hex 等 CorruptDataError）/ ServiceError 还是任何意外异常，都：
            #   - stdout 为空；
            #   - stderr 仅一行 {"error": ...}；
            #   - 退出码非零；
            #   - 绝不打印 traceback、私钥或签名载荷。
            try:
                try:
                    service = WalletService(WalletStore(args.data_dir))
                except RecoveryError as exc:
                    return _fail(
                        f"recovery failed, refusing to sign: {exc}"
                    )
                except OSError as exc:
                    return _fail(
                        f"cannot open data dir, refusing to sign: {exc}"
                    )
                except ValueError:
                    # data-dir 内持久化 JSON 损坏等：不回显解析细节
                    return _fail(
                        "wallet data is corrupt, refusing to sign"
                    )
                try:
                    result = service.share_sign(
                        args.wallet_id,
                        args.share_id,
                        args.signing_request_id,
                        args.message,
                    )
                except RecoveryError as exc:
                    return _fail(
                        f"recovery failed, refusing to sign: {exc}"
                    )
                except (OSError, CorruptDataError, ValueError):
                    # 文件系统异常 / 份额文件损坏 / 私钥 hex 或长度非法：
                    # 统一泛化信息，绝不回显底层异常、私钥或签名载荷。
                    return _fail(
                        "share is unavailable, refusing to sign"
                    )
                except ServiceError as exc:
                    return _fail(exc.message)
                _print_json(result)
                return 0
            except Exception:
                # 兜底：任何未预期异常也只落一行泛化 JSON，杜绝 traceback
                return _fail("share-sign failed, refusing to sign")

        elif args.command in ("backup", "restore"):
            from .backup import (
                BackupError,
                create_backup,
                restore_backup,
            )

            # 灾备命令的统一错误边界与 share-sign 相同：成功单行 JSON 到
            # stdout；任何失败（参数非法、钱包缺失、恢复不可对账、备份
            # 损坏、文件系统异常）都只落一行 {"error": ...} 到 stderr 并以
            # 退出码 1 结束，绝不打印 traceback、私钥或签名载荷。
            try:
                if args.command == "backup":
                    status, result = 201, create_backup(
                        args.data_dir,
                        args.wallet_id,
                        args.snapshot_id,
                        args.output,
                    )
                else:
                    status, result = restore_backup(
                        args.data_dir, args.wallet_id, args.input
                    )
            except BackupError as exc:
                print(
                    json.dumps(
                        {"error": exc.message},
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                    file=sys.stderr,
                )
                return 1
            except (OSError, ValueError):
                return _fail("disaster recovery operation failed")
            except Exception:
                return _fail("disaster recovery operation failed")
            _print_json(
                {"status": status, **result},
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
