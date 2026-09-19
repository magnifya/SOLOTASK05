"""门限签名业务逻辑（与 HTTP 框架无关）。

规则：
- 建钱包：shares 必须恰为 2，否则 400；wallet_id 重复返回 409；
  成功生成两个独立份额并返回钱包公钥与两个 share_id（201）。
- 查询：不存在返回 404，成功返回 public_key 与 created_at。
- 签名：服务端不代替任何一方签名，只校验两个份额持有人提交上来的
  Ed25519 份额签名，两份齐备且全部校验通过才聚合返回（201）；
  缺份、份额不对、签名校验失败一律 400；同一 signing_request_id
  重复提交直接返回已有签名（200，幂等）。
"""

from __future__ import annotations

import re
import threading
from datetime import datetime, timedelta, timezone

from . import audit, crypto
from .audit import AuditStore
from .store import DuplicateWalletError, WalletStore

#: 两方门限：份额数固定为 2
REQUIRED_SHARES = 2

#: 服务端为两个份额生成的固定标识（按此顺序聚合公钥与签名）
SHARE_IDS = ("share-1", "share-2")

#: rotation_id 允许字符（与 store._SAFE_ID 一致，同时杜绝路径穿越）
_ROTATION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

#: 轮换状态
ROTATION_PREPARED = "prepared"
ROTATION_ACTIVATING = "activating"
ROTATION_ACTIVE = "active"

#: 审批策略允许的 required_approvals 取值
ALLOWED_REQUIRED_APPROVALS = (1, 2)

#: approve/reject 附言 reason 的最大长度
MAX_REASON_LENGTH = 1024


class ServiceError(Exception):
    """业务错误，携带 HTTP 状态码与错误信息。"""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class WalletService:
    """建钱包、查询钱包、校验并聚合两份额签名。"""

    def __init__(self, store: WalletStore) -> None:
        self._store = store
        self._audit = AuditStore(store.data_dir)
        # 每钱包一把事务锁：串行化同一钱包的"状态变更 + 审计事件"，
        # ThreadingHTTPServer 并发下保证状态与事件原子、懒过期只记一次。
        self._wallet_locks: dict[str, threading.Lock] = {}
        self._wallet_locks_guard = threading.Lock()
        # 启动恢复：回滚上次进程未完成的份额轮换激活
        self.recover_pending_activations()

    def _wallet_lock(self, wallet_id: str) -> threading.Lock:
        with self._wallet_locks_guard:
            lock = self._wallet_locks.get(wallet_id)
            if lock is None:
                lock = threading.Lock()
                self._wallet_locks[wallet_id] = lock
            return lock

    @staticmethod
    def _audit_event(
        event_type: str,
        request_id=None,
        actor_id=None,
        reason=None,
        details=None,
    ) -> dict:
        """构造审计事件（seq 由 AuditStore 分配）。"""
        return {
            "type": event_type,
            "at": _utc_now_iso(),
            "request_id": request_id,
            "actor_id": actor_id,
            "reason": reason,
            "details": details,
        }

    def _emit(self, wallet_id: str, event: dict) -> None:
        self._audit.append_event(wallet_id, event)

    # ---- 建钱包 ---------------------------------------------------------

    def create_wallet(self, wallet_id: object, shares: object) -> dict:
        if not isinstance(wallet_id, str) or not wallet_id:
            raise ServiceError(400, "wallet_id must be a non-empty string")
        # bool 是 int 的子类，必须先排除；2.0 == 2，必须要求真正的 int
        if not isinstance(shares, int) or isinstance(shares, bool):
            raise ServiceError(400, "shares must equal 2")
        if shares != REQUIRED_SHARES:
            raise ServiceError(400, "shares must equal 2")
        try:
            share_keys = [crypto.generate_share_key(sid) for sid in SHARE_IDS]
            self._store.create_wallet(
                wallet_id, share_keys, _utc_now_iso()
            )
        except DuplicateWalletError:
            raise ServiceError(409, f"wallet {wallet_id!r} already exists")
        except ValueError:
            # wallet_id 含非法字符
            raise ServiceError(400, "invalid wallet_id")
        public_key = crypto.combine_public_keys(
            [k.public_bytes for k in share_keys]
        )
        return {
            "wallet_id": wallet_id,
            "public_key": public_key.hex(),
            "share_ids": list(SHARE_IDS),
        }

    # ---- 查询钱包 -------------------------------------------------------

    def get_wallet(self, wallet_id: str) -> dict:
        try:
            record = self._store.get_wallet(wallet_id)
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")
        if record is None:
            raise ServiceError(404, f"wallet {wallet_id!r} not found")
        return {
            "wallet_id": record["wallet_id"],
            "public_key": record["public_key"],
            "created_at": record["created_at"],
        }

    # ---- 审批策略 -------------------------------------------------------

    def _get_wallet_or_404(self, wallet_id: str) -> dict:
        try:
            wallet = self._store.get_wallet(wallet_id)
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")
        if wallet is None:
            raise ServiceError(404, f"wallet {wallet_id!r} not found")
        return wallet

    def put_policy(
        self,
        wallet_id: str,
        required_approvals: object,
        timeout_seconds: object,
    ) -> dict:
        self._get_wallet_or_404(wallet_id)
        # bool 是 int 的子类，必须先排除
        if (
            not isinstance(required_approvals, int)
            or isinstance(required_approvals, bool)
            or required_approvals not in ALLOWED_REQUIRED_APPROVALS
        ):
            raise ServiceError(
                400,
                "required_approvals must be one of "
                + ", ".join(str(v) for v in ALLOWED_REQUIRED_APPROVALS),
            )
        if (
            not isinstance(timeout_seconds, int)
            or isinstance(timeout_seconds, bool)
            or timeout_seconds <= 0
        ):
            raise ServiceError(400, "timeout_seconds must be a positive integer")
        policy = {
            "wallet_id": wallet_id,
            "required_approvals": required_approvals,
            "timeout_seconds": timeout_seconds,
        }
        # 同值更新也成功并记录（operation 区分首设/更新）
        old_policy = self._store.get_policy(wallet_id)
        operation = "created" if old_policy is None else "updated"
        with self._wallet_lock(wallet_id):
            self._store.save_policy(wallet_id, policy)
            event = self._audit_event(
                audit.TYPE_POLICY_UPDATED,
                details={
                    "required_approvals": required_approvals,
                    "timeout_seconds": timeout_seconds,
                    "operation": operation,
                },
            )
            try:
                self._emit(wallet_id, event)
            except BaseException:
                # 状态/事件原子：事件未落盘则回滚策略状态
                if old_policy is None:
                    self._store.delete_policy(wallet_id)
                else:
                    self._store.save_policy(wallet_id, old_policy)
                raise
        return policy

    # ---- 签名请求审批单 ---------------------------------------------------

    @staticmethod
    def _request_view(record: dict) -> dict:
        """审批单对外视图（GET/POST 响应体共用）。"""
        return {
            "id": record["id"],
            "message": record["message"],
            "state": record["state"],
            "approvers": list(record["approvers"]),
            "count": len(record["approvers"]),
            "req": record["req"],
            "t0": record["t0"],
            "t1": record["t1"],
            "reason": record["reason"],
        }

    def _expire_if_needed(self, wallet_id: str, record: dict) -> dict:
        """懒过期：任何操作前把已超时的 pending 单持久化为 expired，
        并原子记录一次 request_expired 事件。调用方须持有该钱包事务锁。
        事件追加失败时回滚为原 pending 状态后向上抛出。"""
        if record["state"] == "pending" and (
            datetime.now(timezone.utc) >= _parse_iso(record["t1"])
        ):
            expired = dict(record)
            expired["state"] = "expired"
            self._store.update_request(wallet_id, record["id"], expired)
            try:
                self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_REQUEST_EXPIRED,
                        request_id=record["id"],
                        details={"state": "expired"},
                    ),
                )
            except BaseException:
                self._store.update_request(wallet_id, record["id"], record)
                raise
            record = expired
        return record

    def _fetch_request_or_404(self, wallet_id: str, request_id: str) -> dict:
        """只读取审批单（404），不做懒过期；调用方自行在钱包事务锁内过期。"""
        try:
            record = self._store.get_request(wallet_id, request_id)
        except ValueError:
            raise ServiceError(400, "invalid signing_request_id")
        if record is None:
            raise ServiceError(
                404, f"signing request {request_id!r} not found"
            )
        return record

    @staticmethod
    def _validate_request_body(request_id: object, message: object) -> None:
        if (
            not isinstance(request_id, str)
            or not request_id
            or not request_id.strip()
        ):
            raise ServiceError(
                400, "signing_request_id must be a non-empty string"
            )
        if not isinstance(message, str) or not message or not message.strip():
            raise ServiceError(400, "message must be a non-empty string")

    def create_sign_request(
        self, wallet_id: str, request_id: object, message: object
    ) -> tuple[int, dict]:
        """返回 (HTTP 状态码, 响应体)。"""
        self._get_wallet_or_404(wallet_id)
        self._validate_request_body(request_id, message)
        try:
            self._store.get_request(wallet_id, request_id)
        except ValueError:
            raise ServiceError(400, "invalid signing_request_id")
        policy = self._store.get_policy(wallet_id)
        if policy is None:
            raise ServiceError(
                409, f"wallet {wallet_id!r} has no approval policy"
            )

        now = datetime.now(timezone.utc)
        record = {
            "id": request_id,
            "message": message,
            "state": "pending",
            "approvers": [],
            "req": policy["required_approvals"],
            "t0": now.isoformat().replace("+00:00", "Z"),
            "t1": (now + timedelta(seconds=policy["timeout_seconds"]))
            .isoformat()
            .replace("+00:00", "Z"),
            "reason": None,
        }
        with self._wallet_lock(wallet_id):
            existing = self._store.create_request(wallet_id, request_id, record)
            if existing is not None:
                # 重放（无论同文幂等还是异文 409）均不记事件、不改状态。
                # POST 不是懒过期触发点：原样返回磁盘中持久化的状态
                # （pending/approved/rejected/expired/signed），绝不在响应里
                # 把磁盘仍是 pending 的单临时呈现成 expired。
                if existing["message"] != message:
                    raise ServiceError(
                        409,
                        f"signing request {request_id!r} already exists "
                        "with a different message",
                    )
                # 同 id 同文：幂等重放
                return 200, self._request_view(existing)
            # 首次创建：状态 + C 事件原子
            event = self._audit_event(
                audit.TYPE_REQUEST_CREATED,
                request_id=request_id,
                details={"message": message},
            )
            try:
                self._emit(wallet_id, event)
            except BaseException:
                self._store.delete_request(wallet_id, request_id)
                raise
        return 201, self._request_view(record)

    def get_sign_request(self, wallet_id: str, request_id: str) -> dict:
        self._get_wallet_or_404(wallet_id)
        with self._wallet_lock(wallet_id):
            record = self._fetch_request_or_404(wallet_id, request_id)
            record = self._expire_if_needed(wallet_id, record)
            return self._request_view(record)

    # ---- 审计事件查询 ---------------------------------------------------

    #: 审计事件查询每页上限与默认条数
    AUDIT_DEFAULT_LIMIT = 1000
    AUDIT_MAX_LIMIT = 1000

    @staticmethod
    def _parse_positive_int(value: object, name: str) -> int:
        """from_seq/limit 必须是正整数（bool/浮点/带符号/缺失均拒绝）。"""
        if isinstance(value, str):
            text = value.strip()
            if not text.isdigit():
                raise ServiceError(400, f"{name} must be a positive integer")
            value = int(text)
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 1
        ):
            raise ServiceError(400, f"{name} must be a positive integer")
        return value

    def get_audit_events(
        self,
        wallet_id: str,
        from_seq: object = None,
        limit: object = None,
    ) -> dict:
        """返回 {wallet_id, events}（seq 升序）。纯只读：不触发懒过期。"""
        self._get_wallet_or_404(wallet_id)
        seq = (
            1
            if from_seq is None
            else self._parse_positive_int(from_seq, "from_seq")
        )
        size = (
            self.AUDIT_DEFAULT_LIMIT
            if limit is None
            else self._parse_positive_int(limit, "limit")
        )
        if size > self.AUDIT_MAX_LIMIT:
            raise ServiceError(
                400, f"limit must be at most {self.AUDIT_MAX_LIMIT}"
            )
        events = self._audit.list_events(wallet_id, from_seq=seq, limit=size)
        return {"wallet_id": wallet_id, "events": events}

    # ---- 批准 / 拒绝 -----------------------------------------------------

    @staticmethod
    def _validate_approver_id(approver_id: object) -> None:
        if (
            not isinstance(approver_id, str)
            or isinstance(approver_id, bool)
            or not approver_id
            or not approver_id.strip()
        ):
            raise ServiceError(
                400, "approver_id must be a non-empty string"
            )

    @staticmethod
    def _validate_reason(reason: object) -> None:
        if reason is None:
            return
        if not isinstance(reason, str) or isinstance(reason, bool):
            raise ServiceError(400, "reason must be a string")
        if not reason.strip():
            raise ServiceError(400, "reason must be non-blank")
        if len(reason) > MAX_REASON_LENGTH:
            raise ServiceError(
                400, f"reason must be at most {MAX_REASON_LENGTH} characters"
            )

    def _decide(
        self,
        wallet_id: str,
        request_id: str,
        approver_id: object,
        reason: object,
        action: str,
    ) -> dict:
        self._get_wallet_or_404(wallet_id)
        self._validate_approver_id(approver_id)
        self._validate_reason(reason)
        with self._wallet_lock(wallet_id):
            record = self._fetch_request_or_404(wallet_id, request_id)
            # 懒过期可能在此原子记一次 E；过期后操作落入终态分支（409、不记 A/R）
            record = self._expire_if_needed(wallet_id, record)
            if record["state"] != "pending":
                raise ServiceError(
                    409,
                    f"signing request {request_id!r} is {record['state']}, "
                    "not pending",
                )

            if action == "approve":
                # 同一 approver 重复批准不计数、不记事件（幂等 200）
                if approver_id in record["approvers"]:
                    return self._request_view(record)
                new_record = dict(record)
                new_record["approvers"] = list(record["approvers"])
                new_record["approvers"].append(approver_id)
                if reason is not None:
                    new_record["reason"] = reason
                reached = len(new_record["approvers"]) >= new_record["req"]
                if reached:
                    new_record["state"] = "approved"
                self._store.update_request(wallet_id, request_id, new_record)
                event = self._audit_event(
                    audit.TYPE_REQUEST_APPROVED,
                    request_id=request_id,
                    actor_id=approver_id,
                    reason=reason,
                    details={
                        "count": len(new_record["approvers"]),
                        "req": new_record["req"],
                        "state": new_record["state"],
                    },
                )
                try:
                    self._emit(wallet_id, event)
                except BaseException:
                    self._store.update_request(wallet_id, request_id, record)
                    raise
                return self._request_view(new_record)

            # reject：任何一名审批人拒绝即终态（首批）
            new_record = dict(record)
            new_record["state"] = "rejected"
            if reason is not None:
                new_record["reason"] = reason
            self._store.update_request(wallet_id, request_id, new_record)
            event = self._audit_event(
                audit.TYPE_REQUEST_REJECTED,
                request_id=request_id,
                actor_id=approver_id,
                reason=reason,
                details={
                    "count": len(new_record["approvers"]),
                    "req": new_record["req"],
                    "state": "rejected",
                },
            )
            try:
                self._emit(wallet_id, event)
            except BaseException:
                self._store.update_request(wallet_id, request_id, record)
                raise
            return self._request_view(new_record)

    def approve(
        self,
        wallet_id: str,
        request_id: str,
        approver_id: object,
        reason: object = None,
    ) -> dict:
        return self._decide(wallet_id, request_id, approver_id, reason, "approve")

    def reject(
        self,
        wallet_id: str,
        request_id: str,
        approver_id: object,
        reason: object = None,
    ) -> dict:
        return self._decide(wallet_id, request_id, approver_id, reason, "reject")

    # ---- 份额签名聚合 ---------------------------------------------------

    def sign(
        self,
        wallet_id: str,
        signing_request_id: object,
        message: object,
        signatures: object,
    ) -> tuple[int, dict]:
        """返回 (HTTP 状态码, 响应体)。"""
        try:
            wallet = self._store.get_wallet(wallet_id)
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")
        if wallet is None:
            raise ServiceError(404, f"wallet {wallet_id!r} not found")

        if (
            not isinstance(signing_request_id, str)
            or not signing_request_id
        ):
            raise ServiceError(
                400, "signing_request_id must be a non-empty string"
            )
        if not isinstance(message, str):
            raise ServiceError(400, "message must be a string")
        if not isinstance(signatures, list) or len(signatures) != REQUIRED_SHARES:
            raise ServiceError(
                400, f"exactly {REQUIRED_SHARES} share signatures are required"
            )

        # 当前生效份额（轮换后为新 share_ids），按元数据顺序聚合
        current_share_ids = tuple(s["share_id"] for s in wallet["shares"])
        share_pub = {s["share_id"]: s["public_key"] for s in wallet["shares"]}

        with self._wallet_lock(wallet_id):
            # 幂等查重的唯一检查点：必须在每钱包事务锁内、且在任何份额校验
            # 之前。重放直接返回磁盘上已提交的签名，不校验签名、不触发懒
            # 过期、不记事件。这把锁同时挡住首签事务尚未提交完成的并发
            # 请求，使重放永远读不到“签名已落盘但审批单/事件未提交”的
            # 半完成数据，保证并发重放只有一个首次结果。
            try:
                existing = self._store.get_signature(
                    wallet_id, signing_request_id
                )
            except ValueError:
                raise ServiceError(400, "invalid signing_request_id")
            if existing is not None:
                return 200, {"signature": existing["signature"]}

            submitted: dict[str, bytes] = {}
            for index, item in enumerate(signatures):
                if not isinstance(item, dict):
                    raise ServiceError(400, f"signatures[{index}] must be an object")
                share_id = item.get("share_id")
                signature_hex = item.get("signature")
                if not isinstance(share_id, str) or share_id not in share_pub:
                    raise ServiceError(400, f"signatures[{index}] has unknown share_id")
                if not isinstance(signature_hex, str):
                    raise ServiceError(400, f"signatures[{index}].signature must be hex")
                try:
                    signature_bytes = bytes.fromhex(signature_hex)
                except ValueError:
                    raise ServiceError(
                        400, f"signatures[{index}].signature must be hex"
                    )
                if share_id in submitted:
                    raise ServiceError(400, "duplicate share_id in signatures")
                submitted[share_id] = signature_bytes

            # 两份必须齐备，且不能夹带未知份额
            if set(submitted) != set(current_share_ids):
                raise ServiceError(400, "signatures from both share_ids are required")

            payload = crypto.build_payload(signing_request_id, message)
            verified: dict[str, bytes] = {}
            for share_id in current_share_ids:
                public_bytes = bytes.fromhex(share_pub[share_id])
                if not crypto.verify_share(
                    public_bytes, payload, submitted[share_id]
                ):
                    raise ServiceError(400, f"signature verification failed for {share_id}")
                verified[share_id] = submitted[share_id]

            aggregate = crypto.combine_signatures(
                [verified[sid] for sid in current_share_ids]
            )
            record = {"message": message, "signature": aggregate.hex()}

            # 启用审批策略时：必须存在同 id、同 message 且已 approved 的审批单。
            # 这一步可能原子地把超时 pending 单记一次 E 并转为 expired。
            approval_record = None
            if self._store.get_policy(wallet_id) is not None:
                approval_record = self._fetch_request_or_404(
                    wallet_id, signing_request_id
                )
                approval_record = self._expire_if_needed(
                    wallet_id, approval_record
                )
                if approval_record["message"] != message:
                    raise ServiceError(
                        409, "message does not match the signing request"
                    )
                if approval_record["state"] != "approved":
                    raise ServiceError(
                        409,
                        f"signing request {signing_request_id!r} is "
                        f"{approval_record['state']}, not approved",
                    )

            # 事务提交：签名记录、审批单 signed 状态与 request_signed 事件
            # 必须在本钱包事务锁内一致落盘。任一写入或事件追加失败，都
            # 删除本次签名并把审批单恢复为原 approved，绝不留下半完成数据。
            committed = False
            try:
                existing = self._store.save_signature(
                    wallet_id, signing_request_id, record
                )
                if existing is not None:
                    # 兜底：锁内查重已保证不会到达；万一到达按重放处理，
                    # 不动审批单、不记事件。
                    return 200, {"signature": existing["signature"]}

                if approval_record is not None:
                    signed_record = dict(approval_record)
                    signed_record["state"] = "signed"
                    self._store.update_request(
                        wallet_id, signing_request_id, signed_record
                    )

                self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_REQUEST_SIGNED,
                        request_id=signing_request_id,
                        details={"message": message, "state": "signed"},
                    ),
                )
                committed = True
            except BaseException:
                if not committed:
                    self._store.delete_signature(
                        wallet_id, signing_request_id
                    )
                    if approval_record is not None:
                        self._store.update_request(
                            wallet_id, signing_request_id, approval_record
                        )
                raise
        return 201, {"signature": aggregate.hex()}

    # ---- 份额轮换 ---------------------------------------------------------

    @staticmethod
    def _rotation_view(record: dict) -> dict:
        return {
            "rotation_id": record["rotation_id"],
            "state": record["state"],
            "share_ids": list(record["share_ids"]),
            "public_key": record["public_key"],
        }

    @staticmethod
    def _validate_rotation_id(rotation_id: object) -> str:
        if not isinstance(rotation_id, str) or not _ROTATION_ID_RE.match(
            rotation_id
        ):
            raise ServiceError(
                400,
                "rotation_id must match [A-Za-z0-9_-]{1,128}",
            )
        return rotation_id

    def prepare_share_rotation(
        self, wallet_id: str, rotation_id: object
    ) -> tuple[int, dict]:
        """POST /share-rotations：暂存两份新份额（201）；同 ID 重放（200）。

        每钱包至多一个 prepared：已有 prepared（不同 id）返回 409，
        且不生成新密钥。同 id 重放原样返回磁盘记录（200），不重生密钥、
        不记事件。
        """
        self._get_wallet_or_404(wallet_id)
        rid = self._validate_rotation_id(rotation_id)
        with self._wallet_lock(wallet_id):
            existing = self._store.get_rotation_state(wallet_id, rid)
            if existing is not None:
                # 同 id 重放：无论 prepared/active 均幂等返回，不重生
                return 200, self._rotation_view(existing)
            # 每钱包限一个 prepared；activating 也拒绝新的 prepare
            for rec in self._store.list_rotations(wallet_id):
                if rec.get("state") in (
                    ROTATION_PREPARED,
                    ROTATION_ACTIVATING,
                ):
                    raise ServiceError(
                        409,
                        f"wallet {wallet_id!r} already has a prepared "
                        "share rotation",
                    )
            share_ids = [f"{rid}-share-1", f"{rid}-share-2"]
            share_keys = [
                crypto.generate_share_key(sid) for sid in share_ids
            ]
            public_key = crypto.combine_public_keys(
                [k.public_bytes for k in share_keys]
            ).hex()
            record = {
                "rotation_id": rid,
                "state": ROTATION_PREPARED,
                "share_ids": share_ids,
                "public_key": public_key,
                "prepared_at": _utc_now_iso(),
            }
            # 先把两份新份额私钥分别落到两个暂存文件（一份一文件，
            # 暂存目录中同样不存在完整私钥），再原子写状态文件。
            staged = False
            try:
                for key in share_keys:
                    self._store.save_staged_share(wallet_id, rid, key)
                self._store.save_rotation_state(wallet_id, record)
                staged = True
            finally:
                if not staged:
                    # 暂存半途失败：清掉可能已写入的暂存文件，不留私钥
                    self._store.delete_rotation_state(wallet_id, rid)
            # prepared 状态与事件原子：事件落盘失败则删除全部暂存
            try:
                self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_SHARE_ROTATION_PREPARED,
                        details={
                            "rotation_id": rid,
                            "share_ids": share_ids,
                            "public_key": public_key,
                        },
                    ),
                )
            except BaseException:
                self._store.delete_rotation_state(wallet_id, rid)
                raise
        return 201, self._rotation_view(record)

    def get_share_rotation(self, wallet_id: str, rotation_id: str) -> dict:
        """GET /share-rotations/{id}：查询轮换状态，未知 404。"""
        self._get_wallet_or_404(wallet_id)
        try:
            rid = self._validate_rotation_id(rotation_id)
            record = self._store.get_rotation_state(wallet_id, rid)
        except ValueError:
            raise ServiceError(400, "invalid rotation_id")
        if record is None:
            raise ServiceError(
                404, f"share rotation {rotation_id!r} not found"
            )
        return self._rotation_view(record)

    def activate_share_rotation(
        self, wallet_id: str, rotation_id: str
    ) -> tuple[int, dict]:
        """POST /share-rotations/{id}/activate：prepared -> active（201）。

        仅 prepared 可激活：active 重放 200（幂等），其余 409。激活在
        钱包事务锁内备份旧材料 -> 替换份额文件/钱包公钥 -> 落 activating
        状态 -> 提交 active 状态与审计事件；任一步失败回滚文件、公钥、
        状态并清理暂存备份。成功后删除暂存私钥与备份。
        """
        self._get_wallet_or_404(wallet_id)
        rid = self._validate_rotation_id(rotation_id)
        with self._wallet_lock(wallet_id):
            # 锁内重读钱包，保证 previous_public_key 与备份内容一致
            wallet = self._store.get_wallet(wallet_id)
            record = self._store.get_rotation_state(wallet_id, rid)
            if record is None:
                raise ServiceError(
                    404, f"share rotation {rid!r} not found"
                )
            if record["state"] == ROTATION_ACTIVE:
                # active 重放：钱包公钥必须确为该轮换公钥，幂等返回
                return 200, self._rotation_view(record)
            if record["state"] != ROTATION_PREPARED:
                raise ServiceError(
                    409,
                    f"share rotation {rid!r} is {record['state']}, "
                    "not prepared",
                )

            share_ids = list(record["share_ids"])
            new_public_key = record["public_key"]
            previous_public_key = wallet["public_key"]

            # 1) 备份旧元数据与旧份额（一份一文件）。备份本身失败时
            #    状态与生效文件均未改变，只需清掉半成品备份后向上抛出。
            try:
                self._store.backup_active_material(wallet_id, rid)
            except BaseException:
                self._store.discard_rotation_backup(wallet_id, rid)
                raise
            # 2) 标记 activating（崩溃恢复的判据：备份已存在）
            activating = dict(record)
            activating["state"] = ROTATION_ACTIVATING
            activating["activated_at"] = _utc_now_iso()
            try:
                self._store.save_rotation_state(wallet_id, activating)
                # 3) 锁内替换份额文件与钱包公钥，删除旧份额文件
                self._store.commit_rotated_shares(
                    wallet_id, rid, share_ids, new_public_key
                )
            except BaseException:
                # 文件/状态回滚并清理：恢复旧公钥、旧份额，删除半装的
                # 新份额，状态退回 prepared，删除备份
                self._rollback_activation(wallet_id, rid, record)
                raise

            # 4) 提交 active 状态并原子追加 activated 事件
            active = dict(activating)
            active["state"] = ROTATION_ACTIVE
            try:
                self._store.save_rotation_state(wallet_id, active)
                self._emit(
                    wallet_id,
                    self._audit_event(
                        audit.TYPE_SHARE_ROTATION_ACTIVATED,
                        details={
                            "rotation_id": rid,
                            "share_ids": share_ids,
                            "public_key": new_public_key,
                            "previous_public_key": previous_public_key,
                        },
                    ),
                )
            except BaseException:
                # active 状态/事件失败：恢复旧文件、旧公钥，状态回 prepared
                self._rollback_activation(wallet_id, rid, record)
                raise

            # 5) 成功提交后清理暂存私钥与备份（私钥只留生效处一份）。
            #    清理失败不影响已提交结果，状态保持 active。
            self._store.discard_staged_shares(wallet_id, rid)
            self._store.discard_rotation_backup(wallet_id, rid)
        return 201, self._rotation_view(active)

    def _rollback_activation(
        self, wallet_id: str, rotation_id: str, prepared_record: dict
    ) -> None:
        """激活失败回滚：恢复旧份额/旧公钥，状态退回 prepared，清理备份。

        幂等且尽量不抛异常（用于异常处理路径）。
        """
        try:
            self._store.restore_active_material(wallet_id, rotation_id)
        except BaseException:
            pass
        try:
            self._store.save_rotation_state(wallet_id, prepared_record)
        except BaseException:
            pass
        self._store.discard_rotation_backup(wallet_id, rotation_id)

    def recover_pending_activations(self) -> None:
        """启动时回滚所有未完成（activating）的轮换激活，状态跨重启。

        判据：状态为 activating，或存在激活备份（wallet.json）但状态
        未到 active——后者覆盖状态文件写入前的崩溃窗口。回滚恢复旧
        份额/公钥、状态退回 prepared（无状态文件则删暂存目录），并
        清理备份。prepared/active 原样保留。
        """
        for wallet_id in self._store.list_rotation_wallets():
            self._recover_wallet(wallet_id)

    def _recover_wallet(self, wallet_id: str) -> None:
        with self._wallet_lock(wallet_id):
            states = {
                rec.get("rotation_id"): rec
                for rec in self._store.list_rotations(wallet_id)
                if isinstance(rec, dict) and rec.get("rotation_id")
            }
            for rid in self._store.list_rotation_dirs(wallet_id):
                record = states.get(rid)
                backup_exists = self._store.rotation_backup_exists(
                    wallet_id, rid
                )
                if record is None:
                    # 状态文件丢失：有备份说明激活已开始，需回滚文件；
                    # 无备份只是暂存残骸，直接清理整个目录
                    if backup_exists:
                        self._store.restore_active_material(wallet_id, rid)
                    self._store.delete_rotation_state(wallet_id, rid)
                    continue
                state = record.get("state")
                if state == ROTATION_ACTIVATING or (
                    state != ROTATION_ACTIVE and backup_exists
                ):
                    # 未完成激活：恢复旧材料，状态退回 prepared
                    self._store.restore_active_material(wallet_id, rid)
                    prepared = dict(record)
                    prepared["state"] = ROTATION_PREPARED
                    prepared.pop("activated_at", None)
                    try:
                        self._store.save_rotation_state(wallet_id, prepared)
                    except BaseException:
                        pass
                    self._store.discard_rotation_backup(wallet_id, rid)
                elif state == ROTATION_ACTIVE:
                    # 激活已提交但清理前崩溃：补删暂存私钥与备份，
                    # 避免旧私钥残留备份、新私钥在暂存重复存在
                    self._store.discard_staged_shares(wallet_id, rid)
                    self._store.discard_rotation_backup(wallet_id, rid)
