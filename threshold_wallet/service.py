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

import threading
from datetime import datetime, timedelta, timezone

from . import audit, crypto
from .audit import AuditStore
from .store import DuplicateWalletError, WalletStore

#: 两方门限：份额数固定为 2
REQUIRED_SHARES = 2

#: 服务端为两个份额生成的固定标识（按此顺序聚合公钥与签名）
SHARE_IDS = ("share-1", "share-2")

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

    @staticmethod
    def _expired_view(record: dict) -> dict:
        """只读视角的过期判定：超时 pending 在返回视图里呈现为 expired，
        但不落盘、不记事件（用于不触发懒过期的操作）。"""
        if record["state"] == "pending" and (
            datetime.now(timezone.utc) >= _parse_iso(record["t1"])
        ):
            record = dict(record)
            record["state"] = "expired"
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
                # 重放（无论同文幂等还是异文 409）均不记事件；
                # POST 重放不是懒过期触发点，只读呈现过期态。
                existing = self._expired_view(existing)
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

        # 幂等：同一 signing_request_id 重放直接返回已有签名，
        # 不校验、不触发过期、不记任何事件
        try:
            existing = self._store.get_signature(wallet_id, signing_request_id)
        except ValueError:
            raise ServiceError(400, "invalid signing_request_id")
        if existing is not None:
            return 200, {"signature": existing["signature"]}

        share_pub = {s["share_id"]: s["public_key"] for s in wallet["shares"]}
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
        if set(submitted) != set(SHARE_IDS):
            raise ServiceError(400, "signatures from both share_ids are required")

        payload = crypto.build_payload(signing_request_id, message)
        verified: dict[str, bytes] = {}
        for share_id in SHARE_IDS:
            public_bytes = bytes.fromhex(share_pub[share_id])
            if not crypto.verify_share(
                public_bytes, payload, submitted[share_id]
            ):
                raise ServiceError(400, f"signature verification failed for {share_id}")
            verified[share_id] = submitted[share_id]

        aggregate = crypto.combine_signatures(
            [verified[sid] for sid in SHARE_IDS]
        )
        record = {"message": message, "signature": aggregate.hex()}

        with self._wallet_lock(wallet_id):
            # 锁内二次查重：并发下可能已有首签提交（重放，无事件）
            existing = self._store.get_signature(wallet_id, signing_request_id)
            if existing is not None:
                return 200, {"signature": existing["signature"]}

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

            existing = self._store.save_signature(
                wallet_id, signing_request_id, record
            )
            if existing is not None:
                # 重复提交：幂等返回已有签名（无事件）
                return 200, {"signature": existing["signature"]}

            if approval_record is not None:
                # 审批单推进到终态 signed
                signed_record = dict(approval_record)
                signed_record["state"] = "signed"
                self._store.update_request(
                    wallet_id, signing_request_id, signed_record
                )

            event = self._audit_event(
                audit.TYPE_REQUEST_SIGNED,
                request_id=signing_request_id,
                details={"message": message, "state": "signed"},
            )
            try:
                self._emit(wallet_id, event)
            except BaseException:
                # 状态/事件原子：撤回签名与审批单终态推进
                self._store.delete_signature(wallet_id, signing_request_id)
                if approval_record is not None:
                    self._store.update_request(
                        wallet_id, signing_request_id, approval_record
                    )
                raise
        return 201, {"signature": aggregate.hex()}
