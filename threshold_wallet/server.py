"""HTTP 服务层：标准库 http.server，无第三方 Web 框架依赖。

路由：
- POST /v1/wallets                                  建钱包
- GET  /v1/wallets/<wallet_id>                      查询钱包
- POST /v1/wallets/<wallet_id>/freeze               应急冻结钱包
- POST /v1/wallets/<wallet_id>/unfreeze             解除应急冻结
- GET  /v1/wallets/<wallet_id>/security-state       查询钱包安全状态
- GET  /v1/wallets/<wallet_id>/change-control      查询高风险配置双人变更控制开关
- POST /v1/wallets/<wallet_id>/policy-changes      双人审批统一变更受控配置
- GET  /v1/wallets/<wallet_id>/policy-changes/<id> 查询已应用的配置变更视图
- PUT  /v1/wallets/<wallet_id>/approval-policy      设置审批策略
- PUT  /v1/wallets/<wallet_id>/approval-roster      设置钱包级审批人名单
- GET  /v1/wallets/<wallet_id>/approval-roster      查询钱包级审批人名单
- PUT  /v1/wallets/<wallet_id>/transaction-policy   设置冷热钱包交易策略
- GET  /v1/wallets/<wallet_id>/transaction-policy   查询冷热钱包交易策略
- PUT  /v1/wallets/<wallet_id>/dkg-failover-policy  设置 DKG 故障审批开关
- GET  /v1/wallets/<wallet_id>/dkg-failover-policy  查询 DKG 故障审批开关
- PUT  /v1/wallets/<wallet_id>/nodes                设置 DKG 节点健康表
- GET  /v1/wallets/<wallet_id>/nodes                查询 DKG 节点健康表
- PUT  /v1/wallets/<wallet_id>/chain-adapters       设置跨链适配器健康熔断表
- GET  /v1/wallets/<wallet_id>/chain-adapters       查询跨链适配器健康熔断表
- POST /v1/wallets/<wallet_id>/nodes/<node_id>/rejoin 故障节点重新加入
- POST /v1/wallets/<wallet_id>/sign                 提交两份额签名
- POST /v1/wallets/<wallet_id>/sign-requests        创建签名请求审批单
- GET  /v1/wallets/<wallet_id>/sign-requests/<id>   查询审批单
- GET  /v1/wallets/<wallet_id>/audit-events         查询审计事件（升序）
- GET  /v1/wallets/<wallet_id>/audit-evidence       区间逐条证据（摘要+局部链头）
- POST /v1/wallets/<wallet_id>/sign-requests/<id>/approve  批准
- POST /v1/wallets/<wallet_id>/sign-requests/<id>/reject   拒绝
- POST /v1/wallets/<wallet_id>/sign-requests/<id>/cancel   撤销审批单
- POST /v1/wallets/<wallet_id>/share-rotations             准备份额轮换
- GET  /v1/wallets/<wallet_id>/share-rotations/<id>        查询轮换
- POST /v1/wallets/<wallet_id>/share-rotations/<id>/activate  激活轮换
- POST /v1/wallets/<wallet_id>/share-rotations/<id>/cancel    撤销未激活轮换
- POST /v1/wallets/<wallet_id>/asset-operations            创建资产操作
- POST /v1/wallets/<wallet_id>/asset-transfers             原子资产转账（创建即提交）
- POST /v1/wallets/<wallet_id>/asset-consistency           资产一致性校验（托管方快照核对，纯只读）
- GET  /v1/wallets/<wallet_id>/asset-operations/<id>       查询资产操作
- POST /v1/wallets/<wallet_id>/asset-operations/<id>/commit   提交资产操作
- POST /v1/wallets/<wallet_id>/asset-operations/<id>/cancel   撤销未落账操作
- GET  /v1/wallets/<wallet_id>/assets                      钱包级资产清单分页查询（at_seq/expected_head/limit/after）
- GET  /v1/wallets/<wallet_id>/assets/<asset_id>           查询资产余额/版本（可带 at_seq/expected_head 读历史状态）
- GET  /v1/wallets/<wallet_id>/assets/<asset_id>/security-state 查询资产安全状态
- POST /v1/wallets/<wallet_id>/assets/<asset_id>/freeze   应急冻结单个资产
- POST /v1/wallets/<wallet_id>/assets/<asset_id>/unfreeze 解除单个资产冻结
- PUT  /v1/wallets/<wallet_id>/chain/<asset_id>            设置跨链确认策略
- GET  /v1/wallets/<wallet_id>/chain/<asset_id>            查询跨链确认策略
- POST /v1/wallets/<wallet_id>/chain/<operation_id>/report 上报链上确认数
- PUT  /v1/wallets/<wallet_id>/chain/<asset_id>/arbitration 设置多源仲裁策略
- GET  /v1/wallets/<wallet_id>/chain/<asset_id>/arbitration 查询多源仲裁策略
- POST /v1/wallets/<wallet_id>/chain/<operation_id>/observe 多源观察上报
- POST /v1/wallets/<wallet_id>/chain/<operation_id>/dispatch 请求跨链派发
- POST /v1/wallets/<wallet_id>/chain/<operation_id>/dispatch-auto 健康感知自动派发
- POST /v1/wallets/<wallet_id>/chain/<dispatch_id>/result 上报跨链派发结果回执
- POST /v1/wallets/<wallet_id>/chain/<dispatch_id>/confirm 上报跨链派发确认进展
- POST /v1/wallets/<wallet_id>/chain/<dispatch_id>/takeover 失败派发由新适配器接管
- POST /v1/wallets/<wallet_id>/chain/<dispatch_id>/isolate 隔离显式 down 适配器的在途派发
- GET  /v1/wallets/<wallet_id>/chain/<dispatch_id>/finality 查询跨链派发最终性
- POST /v1/wallets/<wallet_id>/chain/<dispatch_id>/settle 最终性资产结算（空体）
- POST /v1/wallets/<wallet_id>/sign-sessions               创建可恢复签名会话
- GET  /v1/wallets/<wallet_id>/sign-sessions/<id>          查询签名会话
- POST /v1/wallets/<wallet_id>/sign-sessions/<id>/shares   投递份额签名
- POST /v1/wallets/<wallet_id>/sign-sessions/<id>/cancel   主动撤销签名会话
- POST /v1/wallets/<wallet_id>/sign-sessions/<id>/participants/replace  替换会话单个参与方份额
- POST /v1/wallets/<wallet_id>/sign-sessions/<id>/participants/takeover 两阶段接管会话参与方份额
- POST /v1/wallets/<wallet_id>/share-bind                      绑定 DKG 复职节点到轮换份额槽位
- POST /v1/dkg/<wallet_id>/<dkg_id>                           推进两方 DKG 一个阶段
- GET  /v1/dkg/<wallet_id>/<dkg_id>                           查询两方 DKG 会话视图
- POST /v1/dkg/<wallet_id>/<dkg_id>/failover                  提交 DKG 故障轮次

安全：访问日志只记录方法、路径与状态码，绝不读取或记录请求/响应体，
因此份额私钥不可能进入日志。
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .service import ServiceError, WalletService
from .store import CorruptDataError, RecoveryError

#: 请求体大小上限，防止异常大 body
_MAX_BODY_BYTES = 1 * 1024 * 1024

_WALLETS_PREFIX = "/v1/wallets/"
_DKG_PREFIX = "/v1/dkg/"

#: 恢复/文件系统/解析失败时对外的统一 503 文案：绝不回显内部异常细节，
#: 避免泄露半完成公钥、余额、version、策略或私钥材料。
_SERVICE_UNAVAILABLE = "service temporarily unavailable"


def build_handler(service: WalletService) -> type[BaseHTTPRequestHandler]:
    """构造绑定到指定 service 的请求处理器类。"""

    class _Handler(BaseHTTPRequestHandler):
        server_version = "ThresholdWallet/1.0"

        # ---- 响应/日志辅助 ----------------------------------------------

        def _send_json(self, status: int, body: dict) -> None:
            self._send_json_bytes(status, body)

        def _send_json_compact(self, status: int, body: dict) -> None:
            # audit-events 成功体：UTF-8 紧凑 JSON（无空白），非 ASCII
            # 不转义、无末换行。
            self._send_json_bytes(
                status, body, separators=(",", ":")
            )

        def _send_json_bytes(
            self,
            status: int,
            body: dict,
            separators=None,
        ) -> None:
            # allow_nan=False：禁止输出 NaN/Infinity（非法 JSON）等非有限
            # 值；审计事件形状已保证仅有 int/null/str/bool（整数十进制）。
            data = json.dumps(
                body,
                ensure_ascii=False,
                separators=separators,
                allow_nan=False,
            ).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _send_error(self, status: int, message: str) -> None:
            if getattr(self, "_compact_response", False):
                self._send_json_compact(status, {"error": message})
            else:
                self._send_json(status, {"error": message})

        def _send_failure(self, exc: BaseException) -> None:
            """把业务/基础设施异常统一映射为 JSON 错误响应。

            - ServiceError：按其携带的状态码与信息（400/404/409/413 等）；
            - RecoveryError / CorruptDataError / OSError / ValueError：
              无法安全对账或文件系统/解析异常，一律 503 且只回泛化文案，
              绝不泄露半完成公钥、余额、version、策略或私钥。
            任何情况下都不让异常逃逸成无响应体的 500/traceback。
            """
            if isinstance(exc, ServiceError):
                self._send_error(exc.status, exc.message)
            elif isinstance(
                exc, (RecoveryError, CorruptDataError, OSError, ValueError)
            ):
                self._send_error(503, _SERVICE_UNAVAILABLE)
            else:  # pragma: no cover - 兜底：不暴露内部细节
                self._send_error(503, _SERVICE_UNAVAILABLE)

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

        def _read_empty_body(self) -> None:
            """读取并校验空体 POST（如 settle）：请求体必须零字节；任何
            非空体（含空 JSON 对象 {}）一律 400。始终读完整个 body，避免
            keep-alive 连接上残留字节污染下一个请求。"""
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                raise ServiceError(400, "invalid Content-Length")
            if length < 0:
                raise ServiceError(400, "invalid Content-Length")
            if length > _MAX_BODY_BYTES:
                raise ServiceError(413, "request body too large")
            raw = self.rfile.read(length) if length > 0 else b""
            if raw:
                raise ServiceError(400, "request body must be empty")

        def _read_optional_expected_version(self) -> object:
            """读取人工提交的可选请求体：零字节（或缺 Content-Length）返回
            WalletService._NO_EXPECTED_VERSION，沿用旧的无条件提交语义；
            非空体必须是恰含 expected_version 的 JSON 对象，返回其原始值
            （类型由 service 校验）。非对象/缺键/夹带/非法 JSON 一律 400。
            """
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                raise ServiceError(400, "invalid Content-Length")
            if length < 0:
                raise ServiceError(400, "invalid Content-Length")
            if length > _MAX_BODY_BYTES:
                raise ServiceError(413, "request body too large")
            if length == 0:
                return WalletService._NO_EXPECTED_VERSION
            raw = self.rfile.read(length)
            try:
                body = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                raise ServiceError(400, "request body must be valid JSON")
            if not isinstance(body, dict):
                raise ServiceError(400, "request body must be a JSON object")
            # 请求体仅允许 expected_version 一键（值类型由 service 校验）；
            # 缺键/夹带一律 400
            if set(body) != {"expected_version"}:
                raise ServiceError(
                    400, "body must contain exactly expected_version"
                )
            return body["expected_version"]

        # ---- 路由 -------------------------------------------------------

        def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
            parsed = urlparse(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)
            # 每次请求重置：仅 audit-events 路由把成功/错误体切到紧凑 JSON，
            # 绝不经 keep-alive 漏给同连接上的后续请求。
            self._compact_response = False
            try:
                dkg = self._split_dkg_path(path)
                if dkg is not None:
                    wallet_id, dkg_id = dkg
                    self._send_json(
                        200,
                        service.get_dkg_session(
                            wallet_id,
                            dkg_id,
                            query.get("round", [None])[0],
                        ),
                    )
                    return
                matched = self._split_wallet_path(path)
                if matched is None:
                    self._send_error(404, "not found")
                    return
                wallet_id, rest = matched
                if not rest:
                    self._send_json(200, service.get_wallet(wallet_id))
                    return
                if rest == ["security-state"]:
                    self._send_json(
                        200, service.get_security_state(wallet_id)
                    )
                    return
                if rest == ["change-control"]:
                    # 双人变更控制开关查询：初始 {"enabled": false}
                    self._send_json(
                        200, service.get_change_control(wallet_id)
                    )
                    return
                if len(rest) == 2 and rest[0] == "policy-changes":
                    # 已应用配置变更视图
                    self._send_json(
                        200, service.get_policy_change(wallet_id, rest[1])
                    )
                    return
                if rest == ["approval-roster"]:
                    self._send_json(
                        200, service.get_approval_roster(wallet_id)
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
                if len(rest) == 3 and rest[0] == "assets" and rest[2] == "security-state":
                    # 资产粒度安全状态：{wallet_id,asset_id,state,reason}
                    self._send_json(
                        200,
                        service.get_asset_security_state(wallet_id, rest[1]),
                    )
                    return
                if rest == ["assets"]:
                    # 钱包级资产清单分页查询：at_seq 缺省取本次查询的一致
                    # 审计尾序号，显式 0 表示空前缀；expected_head 只能随
                    # 显式 at_seq 使用；limit 缺省 100；after 为排他游标。
                    # 与单资产历史查询一样以 keep_blank_values 解析，使空值
                    # （?at_seq= 等）落到 service 的 400，而不是被 parse_qs
                    # 默认丢弃后误按缺省处理。
                    asset_query = parse_qs(
                        parsed.query, keep_blank_values=True
                    )
                    self._send_json(
                        200,
                        service.list_assets(
                            wallet_id,
                            asset_query.get("at_seq"),
                            asset_query.get("expected_head"),
                            asset_query.get("limit"),
                            asset_query.get("after"),
                        ),
                    )
                    return
                if len(rest) == 2 and rest[0] == "assets":
                    # 历史资产状态查询：at_seq 提供时按审计前缀边界
                    # 重放，expected_head 只能随 at_seq 使用。该路由单独
                    # 以 keep_blank_values 解析，使空值（?at_seq=）落到
                    # service 的 400，而不是被 parse_qs 默认丢弃后误走
                    # 当前余额语义；其余路由的查询解析保持不变。
                    asset_query = parse_qs(
                        parsed.query, keep_blank_values=True
                    )
                    self._send_json(
                        200,
                        service.get_asset(
                            wallet_id,
                            rest[1],
                            asset_query.get("at_seq"),
                            asset_query.get("expected_head"),
                        ),
                    )
                    return
                if len(rest) == 2 and rest[0] == "asset-operations":
                    self._send_json(
                        200,
                        service.get_asset_operation(wallet_id, rest[1]),
                    )
                    return
                if len(rest) == 2 and rest[0] == "chain":
                    self._send_json(
                        200, service.get_chain_policy(wallet_id, rest[1])
                    )
                    return
                if (
                    len(rest) == 3
                    and rest[0] == "chain"
                    and rest[2] == "arbitration"
                ):
                    self._send_json(
                        200,
                        service.get_chain_arbitration(wallet_id, rest[1]),
                    )
                    return
                if (
                    len(rest) == 3
                    and rest[0] == "chain"
                    and rest[2] == "finality"
                ):
                    # 派发最终性：成功体与错误体均为 UTF-8 紧凑 JSON
                    # （非 ASCII 不转义、无末换行），同 confirm/result。
                    self._compact_response = True
                    result = service.get_chain_dispatch_finality(
                        wallet_id, rest[1]
                    )
                    self._send_json_compact(200, result)
                    return
                if len(rest) == 2 and rest[0] == "sign-sessions":
                    self._send_json(
                        200, service.get_sign_session(wallet_id, rest[1])
                    )
                    return
                if self._is_sign_session_cancel_path(rest):
                    # 会话撤销只接受 POST：其他方法一律 405
                    raise ServiceError(405, "method not allowed")
                if self._is_share_rotation_cancel_path(rest):
                    # 轮换撤销只接受 POST：其他方法一律 405
                    raise ServiceError(405, "method not allowed")
                if rest == ["asset-consistency"]:
                    # 资产一致性校验只接受 POST：其他方法一律 405
                    raise ServiceError(405, "method not allowed")
                if rest == ["audit-events"]:
                    # 该路由成功体与 400/404/503 错误体均为 UTF-8 紧凑
                    # JSON（非 ASCII 不转义、无末换行）；其余路由不变。
                    self._compact_response = True
                    # event_type/request_id 须区分"缺省"与"显式空值"
                    # （后者 400），故单独按保留空白值重解析取这两个键；
                    # from_seq/limit 仍用既有解析结果，行为完全不变。
                    filters = parse_qs(parsed.query, keep_blank_values=True)
                    self._send_json_compact(
                        200,
                        service.get_audit_events(
                            wallet_id,
                            from_seq=query.get("from_seq", [None])[0],
                            limit=query.get("limit", [None])[0],
                            event_type=filters.get("event_type"),
                            request_id=filters.get("request_id"),
                        ),
                    )
                    return
                if rest == ["audit-integrity"]:
                    # 审计完整性（防篡改摘要链）：仅接受 GET；
                    # expected_head 缺省只校验链，给定时比对链头（409）。
                    self._send_json(
                        200,
                        service.get_audit_integrity(
                            wallet_id,
                            query.get("expected_head", [None])[0],
                        ),
                    )
                    return
                if rest == ["audit-evidence"]:
                    # 区间逐条证据：成功体与错误体均为 UTF-8 紧凑 JSON
                    # （非 ASCII 不转义、无末换行），同 audit-events。
                    # 缺参/重复/端点非法/expected_head 格式/区间非法 400，
                    # 空钱包/越界 404，expected_head 不符 409，
                    # 不可对账 503，均由 service 抛出、统一边界映射。
                    self._compact_response = True
                    result = service.get_audit_evidence(
                        wallet_id,
                        query.get("from_seq"),
                        query.get("to_seq"),
                        query.get("expected_head"),
                    )
                    self._send_json_compact(200, result)
                    return
                if rest == ["transaction-policy"]:
                    self._send_json(
                        200, service.get_transaction_policy(wallet_id)
                    )
                    return
                if rest == ["dkg-failover-policy"]:
                    self._send_json(
                        200, service.get_dkg_failover_policy(wallet_id)
                    )
                    return
                if rest == ["nodes"]:
                    self._send_json(200, service.get_dkg_nodes(wallet_id))
                    return
                if rest == ["chain-adapters"]:
                    # 跨链适配器健康熔断表：成功体与错误体均为 UTF-8 紧凑
                    # JSON（非 ASCII 不转义、无末换行），同 dispatch 系列。
                    self._compact_response = True
                    self._send_json_compact(
                        200, service.get_chain_adapters(wallet_id)
                    )
                    return
                self._send_error(404, "not found")
            except Exception as exc:
                # fail-closed 边界：业务错误按其状态码；恢复不可对账 /
                # 文件系统 / 持久化 JSON 解析或形状异常 / 任何未预期错误
                # 都转 JSON 503 泛化文案，绝不抛 traceback 或断连，绝不
                # 暴露半完成公钥、余额、version、策略或私钥。
                self._send_failure(exc)

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)
            self._compact_response = False
            try:
                if path == "/v1/wallets":
                    body = self._read_json_body()
                    result = service.create_wallet(
                        body.get("wallet_id"), body.get("shares")
                    )
                    self._send_json(201, result)
                    return

                dkg_failover = self._split_dkg_failover_path(path)
                if dkg_failover is not None:
                    wallet_id, dkg_id = dkg_failover
                    body = self._read_json_body()
                    # 请求体为旧五键，或旧五键 + approval_request_id
                    # 六键（后者仅在 DKG 故障审批策略启用时合法，由
                    # service 按策略判定，HTTP 层不读策略状态）
                    body_keys = set(body)
                    five_keys = {
                        "round",
                        "action",
                        "node",
                        "replacement",
                        "key",
                    }
                    if body_keys != five_keys and body_keys != five_keys | {
                        "approval_request_id"
                    }:
                        raise ServiceError(
                            400,
                            "body must contain exactly round, action, "
                            "node, replacement and key, optionally with "
                            "approval_request_id",
                        )
                    status, result = service.post_dkg_failover(
                        wallet_id,
                        dkg_id,
                        body.get("round"),
                        body.get("action"),
                        body.get("node"),
                        body.get("replacement"),
                        body.get("key"),
                        body.get(
                            "approval_request_id",
                            WalletService._NO_APPROVAL,
                        ),
                    )
                    self._send_json(status, result)
                    return

                dkg = self._split_dkg_path(path)
                if dkg is not None:
                    wallet_id, dkg_id = dkg
                    body = self._read_json_body()
                    # 请求体仅允许 op/node/key/hash/peer 五键
                    if set(body) != {"op", "node", "key", "hash", "peer"}:
                        raise ServiceError(
                            400,
                            "body must contain exactly op, node, key, hash "
                            "and peer",
                        )
                    status, result = service.post_dkg_stage(
                        wallet_id,
                        dkg_id,
                        body.get("op"),
                        body.get("node"),
                        body.get("key"),
                        body.get("hash"),
                        body.get("peer"),
                        query.get("round", [None])[0],
                    )
                    self._send_json(status, result)
                    return

                matched = self._split_wallet_path(path)
                if matched is None:
                    self._send_error(404, "not found")
                    return
                wallet_id, rest = matched

                if rest == ["audit-integrity"]:
                    # audit-integrity 只接受 GET：其他方法抛 ServiceError
                    # （405），由统一失败边界按对应状态返回。
                    raise ServiceError(405, "method not allowed")

                if rest == ["audit-evidence"]:
                    # audit-evidence 只接受 GET：其他方法一律 405。
                    raise ServiceError(405, "method not allowed")

                if len(rest) == 1 and rest[0] in ("freeze", "unfreeze"):
                    # 应急冻结/解冻：请求体恰为 {"reason": "..."}，reason
                    # 须为 1..1024 字符非空白字符串（取值由 service 校验）；
                    # 缺键/夹带/非对象/非法 JSON 一律 400。frozen 期间只有
                    # 这两个写接口仍可用（闸门在 service 各写方法内）。
                    body = self._read_json_body()
                    if set(body) != {"reason"}:
                        raise ServiceError(
                            400,
                            "body must contain exactly reason",
                        )
                    if rest[0] == "freeze":
                        status, result = service.freeze_wallet(
                            wallet_id, body.get("reason")
                        )
                    else:
                        status, result = service.unfreeze_wallet(
                            wallet_id, body.get("reason")
                        )
                    self._send_json(status, result)
                    return

                if (
                    len(rest) == 3
                    and rest[0] == "assets"
                    and rest[2] in ("freeze", "unfreeze")
                ):
                    # 资产粒度应急冻结/解冻：请求体恰为 {"reason": "..."}，
                    # reason 须为 1..1024 字符非空白字符串（取值由 service
                    # 校验）；缺键/夹带/非对象/非法 JSON 一律 400。钱包冻结
                    # 闸门优先于资产冻结（由 service 判定）。
                    body = self._read_json_body()
                    if set(body) != {"reason"}:
                        raise ServiceError(
                            400,
                            "body must contain exactly reason",
                        )
                    if rest[2] == "freeze":
                        status, result = service.freeze_asset(
                            wallet_id, rest[1], body.get("reason")
                        )
                    else:
                        status, result = service.unfreeze_asset(
                            wallet_id, rest[1], body.get("reason")
                        )
                    self._send_json(status, result)
                    return

                if (
                    len(rest) == 3
                    and rest[0] == "nodes"
                    and rest[2] == "rejoin"
                ):
                    body = self._read_json_body()
                    # 请求体恰含 rejoin_id/dkg_id/round/key/
                    # approval_request_id 五键（值类型/取值由 service 校验）
                    if set(body) != {
                        "rejoin_id",
                        "dkg_id",
                        "round",
                        "key",
                        "approval_request_id",
                    }:
                        raise ServiceError(
                            400,
                            "body must contain exactly rejoin_id, dkg_id, "
                            "round, key and approval_request_id",
                        )
                    status, result = service.post_node_rejoin(
                        wallet_id,
                        rest[1],
                        body.get("rejoin_id"),
                        body.get("dkg_id"),
                        body.get("round"),
                        body.get("key"),
                        body.get("approval_request_id"),
                    )
                    self._send_json(status, result)
                    return

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

                if rest == ["policy-changes"]:
                    # 高风险配置双人变更统一入口：请求体恰为五键；
                    # target=chain-policy 时恰增 asset_id 一键（六键）。
                    # 值类型/取值/target/before/after 由 service 严格校验
                    body = self._read_json_body()
                    base_keys = {
                        "change_id",
                        "target",
                        "before",
                        "after",
                        "approval_request_id",
                    }
                    body_keys = set(body)
                    if body_keys == base_keys:
                        asset_id = None
                    elif body_keys == base_keys | {"asset_id"}:
                        asset_id = body.get("asset_id")
                    else:
                        raise ServiceError(
                            400,
                            "body must contain exactly change_id, target, "
                            "before, after and approval_request_id "
                            "(chain-policy also requires asset_id)",
                        )
                    status, result = service.post_policy_change(
                        wallet_id,
                        body.get("change_id"),
                        body.get("target"),
                        body.get("before"),
                        body.get("after"),
                        body.get("approval_request_id"),
                        asset_id,
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

                if rest == ["share-bind"]:
                    body = self._read_json_body()
                    # 请求体恰含 id/rotation/dkg/round/node/slot/approval
                    # 七键（值类型/取值由 service 校验）
                    if set(body) != {
                        "id",
                        "rotation",
                        "dkg",
                        "round",
                        "node",
                        "slot",
                        "approval",
                    }:
                        raise ServiceError(
                            400,
                            "body must contain exactly id, rotation, dkg, "
                            "round, node, slot and approval",
                        )
                    status, result = service.post_share_bind(
                        wallet_id,
                        body.get("id"),
                        body.get("rotation"),
                        body.get("dkg"),
                        body.get("round"),
                        body.get("node"),
                        body.get("slot"),
                        body.get("approval"),
                    )
                    self._send_json(status, result)
                    return

                if rest == ["sign-sessions"]:
                    body = self._read_json_body()
                    status, result = service.create_sign_session(
                        wallet_id,
                        body.get("id"),
                        body.get("message"),
                        body.get("timeout_seconds"),
                    )
                    self._send_json(status, result)
                    return

                if (
                    len(rest) == 3
                    and rest[0] == "sign-sessions"
                    and rest[2] == "shares"
                ):
                    body = self._read_json_body()
                    # 未绑定份额体恰含 share_id/signature 两键；份额槽位绑定
                    # 激活后，被绑定份额的体恰含 node/share_id/signature
                    # 三键（node 是否必填由 service 按绑定现场判定，HTTP 层
                    # 不读绑定状态）。
                    body_keys = set(body)
                    two_keys = {"share_id", "signature"}
                    if body_keys != two_keys and body_keys != two_keys | {
                        "node"
                    }:
                        raise ServiceError(
                            400,
                            "body must contain exactly share_id and "
                            "signature (bound shares also require node)",
                        )
                    status, result = service.submit_sign_session_share(
                        wallet_id,
                        rest[1],
                        body.get("share_id"),
                        body.get("signature"),
                        body.get(
                            "node", WalletService._NO_NODE
                        ),
                    )
                    self._send_json(status, result)
                    return

                if self._is_sign_session_cancel_path(rest):
                    body = self._read_json_body()
                    # 请求体仅允许 cancel_id/reason 两键（值类型/取值由
                    # service 校验）；缺键/夹带/非对象/非法 JSON 一律 400
                    if set(body) != {"cancel_id", "reason"}:
                        raise ServiceError(
                            400,
                            "body must contain exactly cancel_id and reason",
                        )
                    status, result = service.cancel_sign_session(
                        wallet_id,
                        rest[1],
                        body.get("cancel_id"),
                        body.get("reason"),
                    )
                    self._send_json(status, result)
                    return

                if (
                    len(rest) == 4
                    and rest[0] == "sign-sessions"
                    and rest[2] == "participants"
                    and rest[3] == "replace"
                ):
                    body = self._read_json_body()
                    # 请求体仅允许 replacement_id/offline_share_id 两键
                    if set(body) != {"replacement_id", "offline_share_id"}:
                        raise ServiceError(
                            400,
                            "body must contain exactly replacement_id and "
                            "offline_share_id",
                        )
                    status, result = service.replace_sign_session_participant(
                        wallet_id,
                        rest[1],
                        body.get("replacement_id"),
                        body.get("offline_share_id"),
                    )
                    self._send_json(status, result)
                    return

                if (
                    len(rest) == 4
                    and rest[0] == "sign-sessions"
                    and rest[2] == "participants"
                    and rest[3] == "takeover"
                ):
                    body = self._read_json_body()
                    # 请求体仅允许 takeover_id/stage/offline_share_id 三键
                    if set(body) != {
                        "takeover_id",
                        "stage",
                        "offline_share_id",
                    }:
                        raise ServiceError(
                            400,
                            "body must contain exactly takeover_id, stage "
                            "and offline_share_id",
                        )
                    status, result = service.takeover_sign_session_participant(
                        wallet_id,
                        rest[1],
                        body.get("takeover_id"),
                        body.get("stage"),
                        body.get("offline_share_id"),
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

                if rest == ["asset-transfers"]:
                    body = self._read_json_body()
                    # 请求体仅允许 transfer_id/from_asset_id/to_asset_id/
                    # amount/expected_from_version/expected_to_version 六键
                    if set(body) != {
                        "transfer_id",
                        "from_asset_id",
                        "to_asset_id",
                        "amount",
                        "expected_from_version",
                        "expected_to_version",
                    }:
                        raise ServiceError(
                            400,
                            "body must contain exactly transfer_id, "
                            "from_asset_id, to_asset_id, amount, "
                            "expected_from_version and expected_to_version",
                        )
                    status, result = service.create_asset_transfer(
                        wallet_id,
                        body.get("transfer_id"),
                        body.get("from_asset_id"),
                        body.get("to_asset_id"),
                        body.get("amount"),
                        body.get("expected_from_version"),
                        body.get("expected_to_version"),
                    )
                    self._send_json(status, result)
                    return

                if rest == ["asset-consistency"]:
                    # 资产一致性校验（纯只读）：钱包 404 优先于一切请求
                    # 校验，故请求体读取/解析错误不在此抛出，而是延迟到
                    # service 判定钱包存在性之后统一重抛；at_seq/
                    # expected_head 为查询参数，与资产清单一样以
                    # keep_blank_values 解析，使空值（?at_seq= 等）落到
                    # service 的 400，而不是被 parse_qs 默认丢弃后误按
                    # 缺省处理。
                    try:
                        body = self._read_json_body()
                        body_error = None
                    except ServiceError as exc:
                        body = None
                        body_error = exc
                    asset_query = parse_qs(
                        parsed.query, keep_blank_values=True
                    )
                    result = service.check_asset_consistency(
                        wallet_id,
                        body,
                        asset_query.get("at_seq"),
                        asset_query.get("expected_head"),
                        body_error,
                    )
                    self._send_json(200, result)
                    return

                if (
                    len(rest) == 3
                    and rest[0] == "asset-operations"
                    and rest[2] == "commit"
                ):
                    # 零字节请求体沿用旧的无条件提交；非空体仅接受恰含
                    # expected_version 的 JSON 对象（乐观版本校验）
                    expected_version = (
                        self._read_optional_expected_version()
                    )
                    status, result = service.commit_asset_operation(
                        wallet_id, rest[1], expected_version
                    )
                    self._send_json(status, result)
                    return

                if (
                    len(rest) == 3
                    and rest[0] == "asset-operations"
                    and rest[2] == "cancel"
                ):
                    body = self._read_json_body()
                    # 请求体仅允许 cancel_id/approval_request_id 两键
                    if set(body) != {
                        "cancel_id",
                        "approval_request_id",
                    }:
                        raise ServiceError(
                            400,
                            "body must contain exactly cancel_id and "
                            "approval_request_id",
                        )
                    status, result = service.cancel_asset_operation(
                        wallet_id,
                        rest[1],
                        body.get("cancel_id"),
                        body.get("approval_request_id"),
                    )
                    self._send_json(status, result)
                    return

                if (
                    len(rest) == 3
                    and rest[0] == "chain"
                    and rest[2] == "report"
                ):
                    body = self._read_json_body()
                    # 请求体仅允许 chain_id/tx_id/block_height/block_hash/
                    # confirmations 五键
                    if set(body) != {
                        "chain_id",
                        "tx_id",
                        "block_height",
                        "block_hash",
                        "confirmations",
                    }:
                        raise ServiceError(
                            400,
                            "body must contain exactly chain_id, tx_id, "
                            "block_height, block_hash and confirmations",
                        )
                    status, result = service.post_chain_report(
                        wallet_id,
                        rest[1],
                        body.get("chain_id"),
                        body.get("tx_id"),
                        body.get("block_height"),
                        body.get("block_hash"),
                        body.get("confirmations"),
                    )
                    self._send_json(status, result)
                    return

                if (
                    len(rest) == 3
                    and rest[0] == "chain"
                    and rest[2] == "observe"
                ):
                    body = self._read_json_body()
                    # 请求体仅允许 source/report 两键（report 为达门槛
                    # chain_report 同形五字段，其键集/值由 service 校验）
                    if set(body) != {"source", "report"}:
                        raise ServiceError(
                            400,
                            "body must contain exactly source and report",
                        )
                    status, result = service.observe(
                        wallet_id,
                        rest[1],
                        body,
                    )
                    self._send_json(status, result)
                    return

                if (
                    len(rest) == 3
                    and rest[0] == "chain"
                    and rest[2] == "result"
                ):
                    # 派发结果回执：成功体与错误体均为 UTF-8 紧凑 JSON
                    # （非 ASCII 不转义、无末换行），同 audit-events。
                    self._compact_response = True
                    body = self._read_json_body()
                    # 请求体仅允许 adapter_id/state/tx_id 三键（值类型/取值
                    # 由 service 校验）
                    if set(body) != {"adapter_id", "state", "tx_id"}:
                        raise ServiceError(
                            400,
                            "body must contain exactly adapter_id, state "
                            "and tx_id",
                        )
                    status, result = service.post_chain_dispatch_result(
                        wallet_id,
                        rest[1],
                        body.get("adapter_id"),
                        body.get("state"),
                        body.get("tx_id"),
                    )
                    self._send_json_compact(status, result)
                    return

                if (
                    len(rest) == 3
                    and rest[0] == "chain"
                    and rest[2] == "confirm"
                ):
                    # 派发确认进展：成功体与错误体均为 UTF-8 紧凑 JSON
                    # （非 ASCII 不转义、无末换行），同 result。
                    self._compact_response = True
                    body = self._read_json_body()
                    # 请求体仅允许 adapter_id/tx_id/block_height/block_hash/
                    # confirmations 五键（值类型/取值由 service 校验）
                    if set(body) != {
                        "adapter_id",
                        "tx_id",
                        "block_height",
                        "block_hash",
                        "confirmations",
                    }:
                        raise ServiceError(
                            400,
                            "body must contain exactly adapter_id, tx_id, "
                            "block_height, block_hash and confirmations",
                        )
                    status, result = service.post_chain_dispatch_confirmation(
                        wallet_id,
                        rest[1],
                        body.get("adapter_id"),
                        body.get("tx_id"),
                        body.get("block_height"),
                        body.get("block_hash"),
                        body.get("confirmations"),
                    )
                    self._send_json_compact(status, result)
                    return

                if (
                    len(rest) == 3
                    and rest[0] == "chain"
                    and rest[2] == "settle"
                ):
                    # 最终性资产结算：空体 POST（请求体零字节，无
                    # Content-Length 或长度 0）；任何非空体（含空 JSON
                    # 对象 {}）一律 400。成功体与错误体均为 UTF-8 紧凑
                    # JSON（沿用 confirm/result 字节规则）。
                    self._compact_response = True
                    self._read_empty_body()
                    status, result = service.settle_chain_dispatch(
                        wallet_id, rest[1]
                    )
                    self._send_json_compact(status, result)
                    return

                if (
                    len(rest) == 3
                    and rest[0] == "chain"
                    and rest[2] == "takeover"
                ):
                    # 失败派发接管：成功体与错误体均为 UTF-8 紧凑 JSON
                    # （非 ASCII 不转义、无末换行），同 result/confirm。
                    self._compact_response = True
                    body = self._read_json_body()
                    # 请求体仅允许 adapter_id/approval_request_id 两键
                    # （值类型/取值由 service 校验）
                    if set(body) != {
                        "adapter_id",
                        "approval_request_id",
                    }:
                        raise ServiceError(
                            400,
                            "body must contain exactly adapter_id and "
                            "approval_request_id",
                        )
                    status, result = service.post_chain_dispatch_takeover(
                        wallet_id,
                        rest[1],
                        body.get("adapter_id"),
                        body.get("approval_request_id"),
                    )
                    self._send_json_compact(status, result)
                    return

                if (
                    len(rest) == 3
                    and rest[0] == "chain"
                    and rest[2] == "isolate"
                ):
                    # 派发隔离：成功体与错误体均为 UTF-8 紧凑 JSON
                    # （非 ASCII 不转义、无末换行），同 takeover/result。
                    # 请求体必须恰为空 JSON 对象 {}（缺键同样不许夹带
                    # 其他键；非对象/非法 JSON 由 _read_json_body 拦）。
                    self._compact_response = True
                    body = self._read_json_body()
                    if set(body) != set():
                        raise ServiceError(
                            400,
                            "body must be exactly the empty JSON object {}",
                        )
                    status, result = service.post_chain_dispatch_isolate(
                        wallet_id,
                        rest[1],
                    )
                    self._send_json_compact(status, result)
                    return

                if (
                    len(rest) == 3
                    and rest[0] == "chain"
                    and rest[2] == "dispatch-auto"
                ):
                    # 健康感知自动派发：响应字节规则同手工 dispatch。
                    body = self._read_json_body()
                    # 请求体仅允许 dispatch_id/approval_request_id 两键
                    # （值类型/取值由 service 校验；适配器由服务端在锁内
                    # 按健康快照选择，不在请求体中）。
                    if set(body) != {
                        "dispatch_id",
                        "approval_request_id",
                    }:
                        raise ServiceError(
                            400,
                            "body must contain exactly dispatch_id and "
                            "approval_request_id",
                        )
                    status, result = service.post_chain_dispatch_auto(
                        wallet_id,
                        rest[1],
                        body.get("dispatch_id"),
                        body.get("approval_request_id"),
                    )
                    self._send_json(status, result)
                    return

                if (
                    len(rest) == 3
                    and rest[0] == "chain"
                    and rest[2] == "dispatch"
                ):
                    body = self._read_json_body()
                    # 请求体仅允许 dispatch_id/adapter_id/approval_request_id
                    # 三键（值类型/取值由 service 校验）
                    if set(body) != {
                        "dispatch_id",
                        "adapter_id",
                        "approval_request_id",
                    }:
                        raise ServiceError(
                            400,
                            "body must contain exactly dispatch_id, "
                            "adapter_id and approval_request_id",
                        )
                    status, result = service.post_chain_dispatch(
                        wallet_id,
                        rest[1],
                        body.get("dispatch_id"),
                        body.get("adapter_id"),
                        body.get("approval_request_id"),
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

                if self._is_share_rotation_cancel_path(rest):
                    body = self._read_json_body()
                    # 请求体仅允许 cancel_id/reason 两键（值类型/取值由
                    # service 校验）；缺键/夹带/非对象/非法 JSON 一律 400
                    if set(body) != {"cancel_id", "reason"}:
                        raise ServiceError(
                            400,
                            "body must contain exactly cancel_id and reason",
                        )
                    status, result = service.cancel_share_rotation(
                        wallet_id,
                        rest[1],
                        body.get("cancel_id"),
                        body.get("reason"),
                    )
                    self._send_json(status, result)
                    return

                if (
                    len(rest) == 3
                    and rest[0] == "sign-requests"
                    and rest[2] in ("approve", "reject", "cancel")
                ):
                    body = self._read_json_body()
                    if rest[2] == "cancel":
                        status, result = service.cancel_sign_request(
                            wallet_id, rest[1], body
                        )
                        self._send_json(status, result)
                    else:
                        decide = (
                            service.approve
                            if rest[2] == "approve"
                            else service.reject
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
            except Exception as exc:
                # fail-closed 边界：业务错误按其状态码；恢复不可对账 /
                # 文件系统 / 持久化 JSON 解析或形状异常 / 任何未预期错误
                # 都转 JSON 503 泛化文案，绝不抛 traceback 或断连，绝不
                # 暴露半完成公钥、余额、version、策略或私钥。
                self._send_failure(exc)

        def do_PUT(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            self._compact_response = False
            try:
                matched = self._split_wallet_path(path)
                if matched is not None:
                    wallet_id, rest = matched
                    if self._is_sign_session_cancel_path(rest):
                        # 会话撤销只接受 POST
                        raise ServiceError(405, "method not allowed")
                    if self._is_share_rotation_cancel_path(rest):
                        # 轮换撤销只接受 POST
                        raise ServiceError(405, "method not allowed")
                    if rest == ["audit-integrity"]:
                        # audit-integrity 只接受 GET
                        raise ServiceError(405, "method not allowed")
                    if rest == ["audit-evidence"]:
                        # audit-evidence 只接受 GET
                        raise ServiceError(405, "method not allowed")
                    if rest == ["asset-consistency"]:
                        # 资产一致性校验只接受 POST
                        raise ServiceError(405, "method not allowed")
                    if rest == ["approval-policy"]:
                        body = self._read_json_body()
                        result = service.put_policy(
                            wallet_id,
                            body.get("required_approvals"),
                            body.get("timeout_seconds"),
                        )
                        self._send_json(200, result)
                        return
                    if rest == ["approval-roster"]:
                        body = self._read_json_body()
                        if set(body) != {"allowed_approvers"}:
                            raise ServiceError(
                                400,
                                "body must contain exactly allowed_approvers",
                            )
                        result = service.put_approval_roster(
                            wallet_id, body.get("allowed_approvers")
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
                    if rest == ["dkg-failover-policy"]:
                        body = self._read_json_body()
                        # PUT 仅收 {"enabled": bool}
                        if set(body) != {"enabled"}:
                            raise ServiceError(
                                400,
                                "body must contain exactly enabled",
                            )
                        result = service.put_dkg_failover_policy(
                            wallet_id, body.get("enabled")
                        )
                        self._send_json(200, result)
                        return
                    if rest == ["nodes"]:
                        body = self._read_json_body()
                        # PUT 仅收 Q={"nodes": ...}；nodes 表形状由 service
                        # 严格校验（非空、安全 ID、key/state 两键）
                        if set(body) != {"nodes"}:
                            raise ServiceError(
                                400,
                                "body must contain exactly nodes",
                            )
                        result = service.put_dkg_nodes(
                            wallet_id, body.get("nodes")
                        )
                        self._send_json(200, result)
                        return
                    if rest == ["chain-adapters"]:
                        # 跨链适配器健康熔断表：成功体与错误体均为 UTF-8
                        # 紧凑 JSON（非 ASCII 不转义、无末换行）。
                        self._compact_response = True
                        body = self._read_json_body()
                        # PUT 仅收 Q={"adapters": ...}；adapters 表形状
                        # （非空、安全 ID、值 up|down）由 service 严格校验
                        if set(body) != {"adapters"}:
                            raise ServiceError(
                                400,
                                "body must contain exactly adapters",
                            )
                        result = service.put_chain_adapters(
                            wallet_id, body.get("adapters")
                        )
                        self._send_json_compact(200, result)
                        return
                    if len(rest) == 2 and rest[0] == "chain":
                        body = self._read_json_body()
                        # PUT 仅收 chain_id/enabled/required_confirmations/
                        # reorg_window 四键
                        if set(body) != {
                            "chain_id",
                            "enabled",
                            "required_confirmations",
                            "reorg_window",
                        }:
                            raise ServiceError(
                                400,
                                "body must contain exactly chain_id, "
                                "enabled, required_confirmations and "
                                "reorg_window",
                            )
                        result = service.put_chain_policy(
                            wallet_id,
                            rest[1],
                            body.get("chain_id"),
                            body.get("enabled"),
                            body.get("required_confirmations"),
                            body.get("reorg_window"),
                        )
                        self._send_json(200, result)
                        return
                    if (
                        len(rest) == 3
                        and rest[0] == "chain"
                        and rest[2] == "arbitration"
                    ):
                        body = self._read_json_body()
                        # PUT 仅收 sources/quorum 两键
                        if set(body) != {"sources", "quorum"}:
                            raise ServiceError(
                                400,
                                "body must contain exactly sources and quorum",
                            )
                        result = service.put_chain_arbitration(
                            wallet_id,
                            rest[1],
                            body.get("sources"),
                            body.get("quorum"),
                        )
                        self._send_json(200, result)
                        return
                self._send_error(404, "not found")
            except Exception as exc:
                # fail-closed 边界：业务错误按其状态码；恢复不可对账 /
                # 文件系统 / 持久化 JSON 解析或形状异常 / 任何未预期错误
                # 都转 JSON 503 泛化文案，绝不抛 traceback 或断连，绝不
                # 暴露半完成公钥、余额、version、策略或私钥。
                self._send_failure(exc)

        def do_DELETE(self) -> None:  # noqa: N802
            self._reject_unsupported_method()

        def do_PATCH(self) -> None:  # noqa: N802
            self._reject_unsupported_method()

        def do_OPTIONS(self) -> None:  # noqa: N802
            self._reject_unsupported_method()

        def do_HEAD(self) -> None:  # noqa: N802
            # HEAD 语义不返回响应体：audit-integrity / audit-evidence、
            # asset-consistency 与会话/轮换 cancel 路径上仅给 405 状态头。
            self._compact_response = False
            path = urlparse(self.path).path
            matched = self._split_wallet_path(path)
            if matched is not None and (
                matched[1]
                in (
                    ["audit-integrity"],
                    ["audit-evidence"],
                    ["asset-consistency"],
                )
                or self._is_cancel_path(matched[1])
            ):
                self.send_response(405)
                self.send_header(
                    "Allow",
                    "GET"
                    if matched[1]
                    in (
                        ["audit-integrity"],
                        ["audit-evidence"],
                    )
                    else "POST",
                )
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self._send_error(404, "not found")

        def _reject_unsupported_method(self) -> None:
            """audit-integrity / audit-evidence 资源、asset-consistency
            与签名会话/份额轮换 cancel 路径上的 DELETE/PATCH/OPTIONS/HEAD
            一律抛 ServiceError(405)；其余路径保持 404。"""
            self._compact_response = False
            try:
                path = urlparse(self.path).path
                matched = self._split_wallet_path(path)
                if matched is not None and (
                    matched[1]
                    in (
                        ["audit-integrity"],
                        ["audit-evidence"],
                        ["asset-consistency"],
                    )
                    or self._is_cancel_path(matched[1])
                ):
                    raise ServiceError(405, "method not allowed")
                self._send_error(404, "not found")
            except Exception as exc:
                self._send_failure(exc)

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

        @staticmethod
        def _is_sign_session_cancel_path(rest) -> bool:
            """rest 是否为 sign-sessions/<sid>/cancel（仅接受 POST）。"""
            return (
                len(rest) == 3
                and rest[0] == "sign-sessions"
                and rest[2] == "cancel"
            )

        @staticmethod
        def _is_share_rotation_cancel_path(rest) -> bool:
            """rest 是否为 share-rotations/<rid>/cancel（仅接受 POST）。"""
            return (
                len(rest) == 3
                and rest[0] == "share-rotations"
                and rest[2] == "cancel"
            )

        @classmethod
        def _is_cancel_path(cls, rest) -> bool:
            """rest 是否为仅接受 POST 的撤销路径（会话/轮换）。"""
            return cls._is_sign_session_cancel_path(
                rest
            ) or cls._is_share_rotation_cancel_path(rest)

        @staticmethod
        def _split_dkg_path(path: str):
            """/v1/dkg/<wallet_id>/<dkg_id> -> (wallet_id, dkg_id)，否则 None。"""
            if not path.startswith(_DKG_PREFIX):
                return None
            parts = path[len(_DKG_PREFIX):].split("/")
            if len(parts) != 2 or not parts[0] or not parts[1]:
                return None
            return parts[0], parts[1]

        @staticmethod
        def _split_dkg_failover_path(path: str):
            """/v1/dkg/<wallet_id>/<dkg_id>/failover -> (wallet_id, dkg_id)，否则 None。"""
            if not path.startswith(_DKG_PREFIX):
                return None
            parts = path[len(_DKG_PREFIX):].split("/")
            if (
                len(parts) != 3
                or not parts[0]
                or not parts[1]
                or parts[2] != "failover"
            ):
                return None
            return parts[0], parts[1]

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
