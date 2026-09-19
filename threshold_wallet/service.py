"""门限签名业务逻辑（与 HTTP 框架无关）。

规则：
- 建钱包：shares 必须恰为 2，否则 400；wallet_id 重复返回 409；
  成功生成两个独立份额并返回钱包公钥与两个 share_id（201）。
- 查询：不存在返回 404，成功返回 public_key 与 created_at。
- 审批策略：PUT approval-policy，required_approvals 为 1|2 的整数、
  timeout_seconds 为 >0 的整数，成功 200，类型非法 400，钱包不存在 404。
- 签名请求：POST sign-requests，id、message 必须为非空字符串；
  未设置审批策略返回 409；同 id 同 message 幂等 200，同 id 异 message 409，
  首次 201。请求持久化为 pending，并带创建时间与超时时刻。
- 每次读取/操作请求前都先把已超时的 pending 请求持久化翻转为 expired。
- approve/reject：approver_id 必填非空字符串，reason 可选且 ≤1024 字符；
  pending 下批准累计不重复的批准人，达到 required_approvals 即 approved；
  重复批准人不计数（200 幂等）；拒绝立即置为 rejected；对非 pending 请求
  再操作返回 409。
- 签名：启用审批策略时，P/sign 要求 id、message 与一条 approved 请求匹配，
  且仍在该请求的审批窗口内，两份份额签名齐备且校验通过才聚合（201）；
  未启用策略时维持首次 201、重放 200 的原有行为。
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from . import crypto
from .store import DuplicateWalletError, WalletStore, validate_request_id

#: 两方门限：份额数固定为 2
REQUIRED_SHARES = 2

#: 服务端为两个份额生成的固定标识（按此顺序聚合公钥与签名）
SHARE_IDS = ("share-1", "share-2")

#: 审批策略允许的门槛取值
_ALLOWED_REQUIRED_APPROVALS = (1, 2)

#: reason 字段最大长度
_MAX_REASON_LEN = 1024


class ServiceError(Exception):
    """业务错误，携带 HTTP 状态码与错误信息。"""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _is_int(value: object) -> bool:
    """真正的 int：排除 bool（True/False）与 2.0 这类 float。"""
    return isinstance(value, int) and not isinstance(value, bool)


def _is_nonempty_str(value: object) -> bool:
    return isinstance(value, str) and len(value.strip()) > 0



class WalletService:
    """建钱包、查询钱包、校验并聚合两份额签名。"""

    def __init__(self, store: WalletStore) -> None:
        self._store = store

    # ---- 通用辅助 -------------------------------------------------------

    def _wallet_or_raise(self, wallet_id: str) -> dict:
        try:
            wallet = self._store.get_wallet(wallet_id)
        except ValueError:
            raise ServiceError(400, "invalid wallet_id")
        if wallet is None:
            raise ServiceError(404, f"wallet {wallet_id!r} not found")
        return wallet

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

    def set_approval_policy(
        self,
        wallet_id: str,
        required_approvals: object,
        timeout_seconds: object,
    ) -> tuple[int, dict]:
        """设置/更新钱包审批策略；成功返回 (200, 策略视图)。"""
        self._wallet_or_raise(wallet_id)
        if (
            not _is_int(required_approvals)
            or required_approvals not in _ALLOWED_REQUIRED_APPROVALS
        ):
            raise ServiceError(
                400, "required_approvals must be an integer of 1 or 2"
            )
        if not _is_int(timeout_seconds) or timeout_seconds <= 0:
            raise ServiceError(
                400, "timeout_seconds must be a positive integer"
            )
        policy = {
            "required_approvals": required_approvals,
            "timeout_seconds": timeout_seconds,
            "updated_at": _utc_now_iso(),
        }
        self._store.save_approval_policy(wallet_id, policy)
        return 200, {
            "required_approvals": required_approvals,
            "timeout_seconds": timeout_seconds,
        }

    # ---- 签名审批请求 ---------------------------------------------------

    @staticmethod
    def _request_view(record: dict) -> dict:
        """把持久化记录投影成对外响应。"""
        return {
            "id": record["id"],
            "message": record["message"],
            "state": record["state"],
            "approvers": list(record["approvers"]),
            "count": len(record["approvers"]),
            "req": record["required_approvals"],
            "t0": record["created_at"],
            "t1": record["decided_at"],
            "reason": record["reason"],
        }

    def _expire_if_due(self, wallet_id: str, request_id: str):
        """若请求仍 pending 且已到超时时刻，持久化翻转为 expired。

        返回（翻转后的）记录；请求不存在返回 None。
        """
        now = time.time()

        def mutate(rec: dict):
            if rec["state"] == "pending" and now >= rec["deadline"]:
                rec["state"] = "expired"
                rec["decided_at"] = now
                rec["reason"] = "approval timed out"
                return rec
            return None

        return self._store.update_sign_request(wallet_id, request_id, mutate)

    def create_sign_request(
        self, wallet_id: str, request_id: object, message: object
    ) -> tuple[int, dict]:
        """创建签名审批请求：首建 201，同 id 同 message 幂等 200。"""
        self._wallet_or_raise(wallet_id)
        self._validate_request_id(request_id)
        if not _is_nonempty_str(message):
            raise ServiceError(400, "message must be a non-empty string")
        policy = self._store.get_approval_policy(wallet_id)
        if policy is None:
            raise ServiceError(
                409, "no approval policy configured for this wallet"
            )

        now = time.time()
        record = {
            "id": request_id,
            "message": message,
            "state": "pending",
            "approvers": [],
            "required_approvals": policy["required_approvals"],
            "timeout_seconds": policy["timeout_seconds"],
            "created_at": now,
            "deadline": now + policy["timeout_seconds"],
            "decided_at": None,
            "reason": None,
            "rejected_by": None,
        }
        outcome = self._store.create_sign_request(wallet_id, record)
        if outcome == "created":
            return 201, self._request_view(record)
        if outcome == "conflict":
            raise ServiceError(
                409,
                "a signing request with the same id but a different "
                "message already exists",
            )
        # 同 id 同 message：幂等返回当前状态（可能已超时）
        current = self._expire_if_due(wallet_id, request_id)
        return 200, self._request_view(current)

    def get_sign_request(self, wallet_id: str, request_id: object) -> dict:
        """返回单个签名审批请求的当前视图；不存在 404。"""
        self._wallet_or_raise(wallet_id)
        self._validate_request_id(request_id)
        record = self._expire_if_due(wallet_id, request_id)
        if record is None:
            raise ServiceError(404, f"signing request {request_id!r} not found")
        return self._request_view(record)

    @staticmethod
    def _validate_approver(approver_id: object) -> str:
        if not _is_nonempty_str(approver_id):
            raise ServiceError(400, "approver_id must be a non-empty string")
        return approver_id

    @staticmethod
    def _validate_request_id(request_id: object) -> str:
        if not isinstance(request_id, str) or not request_id.strip():
            raise ServiceError(400, "id must be a non-empty string")
        try:
            validate_request_id(request_id)
        except ValueError:
            raise ServiceError(400, "id contains invalid characters")
        return request_id

    @staticmethod
    def _validate_reason(reason: object):
        if reason is None:
            return None
        # bool/int/list 等非 str 类型一律 400
        if not isinstance(reason, str):
            raise ServiceError(400, "reason must be a string")
        if len(reason) > _MAX_REASON_LEN:
            raise ServiceError(
                400, f"reason must be at most {_MAX_REASON_LEN} characters"
            )
        return reason

    def approve(
        self,
        wallet_id: str,
        request_id: object,
        approver_id: object,
        reason: object = None,
    ) -> dict:
        """批准：重复批准人不计数，达到门槛即 approved；非 pending 返回 409。"""
        self._wallet_or_raise(wallet_id)
        self._validate_request_id(request_id)
        approver = self._validate_approver(approver_id)
        reason = self._validate_reason(reason)

        record = self._expire_if_due(wallet_id, request_id)
        if record is None:
            raise ServiceError(404, f"signing request {request_id!r} not found")
        if record["state"] != "pending":
            raise ServiceError(
                409, f"signing request is {record['state']}, not pending"
            )

        now = time.time()

        def mutate(rec: dict):
            # 锁内二次确认：可能已被其他线程翻转
            if rec["state"] != "pending":
                return None
            if now >= rec["deadline"]:
                rec["state"] = "expired"
                rec["decided_at"] = now
                rec["reason"] = "approval timed out"
                return rec
            if approver not in rec["approvers"]:
                rec["approvers"].append(approver)
            if len(rec["approvers"]) >= rec["required_approvals"]:
                rec["state"] = "approved"
                rec["decided_at"] = now
                if reason is not None:
                    rec["reason"] = reason
            return rec

        updated = self._store.update_sign_request(wallet_id, request_id, mutate)
        if updated["state"] not in ("pending", "approved"):
            raise ServiceError(
                409, f"signing request is {updated['state']}, not pending"
            )
        return self._request_view(updated)

    def reject(
        self,
        wallet_id: str,
        request_id: object,
        approver_id: object,
        reason: object = None,
    ) -> dict:
        """拒绝：pending 下一次拒绝即置为 rejected；非 pending 返回 409。"""
        self._wallet_or_raise(wallet_id)
        self._validate_request_id(request_id)
        approver = self._validate_approver(approver_id)
        reason = self._validate_reason(reason)

        record = self._expire_if_due(wallet_id, request_id)
        if record is None:
            raise ServiceError(404, f"signing request {request_id!r} not found")
        if record["state"] != "pending":
            raise ServiceError(
                409, f"signing request is {record['state']}, not pending"
            )

        now = time.time()

        def mutate(rec: dict):
            if rec["state"] != "pending":
                return None
            if now >= rec["deadline"]:
                rec["state"] = "expired"
                rec["decided_at"] = now
                rec["reason"] = "approval timed out"
                return rec
            rec["state"] = "rejected"
            rec["decided_at"] = now
            rec["rejected_by"] = approver
            rec["reason"] = reason
            return rec

        updated = self._store.update_sign_request(wallet_id, request_id, mutate)
        if updated["state"] != "rejected":
            raise ServiceError(
                409, f"signing request is {updated['state']}, not pending"
            )
        return self._request_view(updated)

    def _mark_signed(self, wallet_id: str, request_id: str) -> None:
        now = time.time()

        def mutate(rec: dict):
            if rec["state"] == "approved":
                rec["state"] = "signed"
                rec["decided_at"] = now
                return rec
            return None

        self._store.update_sign_request(wallet_id, request_id, mutate)

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

        # 幂等：同一 signing_request_id 重放直接返回已有签名，不再校验
        try:
            existing = self._store.get_signature(wallet_id, signing_request_id)
        except ValueError:
            raise ServiceError(400, "invalid signing_request_id")
        if existing is not None:
            return 200, {"signature": existing["signature"]}

        # 启用审批策略时：必须存在一条 id、message 匹配且已 approved、
        # 仍在审批窗口内的请求，否则拒绝（409）。
        policy = self._store.get_approval_policy(wallet_id)
        if policy is not None:
            # 操作前先把超时的 pending 请求持久化翻转为 expired
            self._expire_if_due(wallet_id, signing_request_id)
            request_doc = self._store.get_request_doc(wallet_id) or {}
            req = request_doc.get(signing_request_id)
            if req is None or req.get("message") != message:
                raise ServiceError(
                    409,
                    "no signing request matching this id and message is approved",
                )
            if req.get("state") != "approved" or time.time() >= req["deadline"]:
                raise ServiceError(
                    409,
                    f"signing request is {req.get('state') or 'missing'}, "
                    "not approved",
                )

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
        existing = self._store.save_signature(
            wallet_id, signing_request_id, record
        )
        if existing is not None:
            # 重复提交：幂等返回已有签名
            return 200, {"signature": existing["signature"]}
        # 启用策略时，把对应审批请求置为终态 signed
        if policy is not None:
            self._mark_signed(wallet_id, signing_request_id)
        return 201, {"signature": aggregate.hex()}
