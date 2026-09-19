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

from datetime import datetime, timedelta, timezone

from . import crypto
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
        self._store.save_policy(wallet_id, policy)
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
        """懒过期：任何操作前把已超时的 pending 单持久化为 expired。"""
        if record["state"] == "pending" and (
            datetime.now(timezone.utc) >= _parse_iso(record["t1"])
        ):
            record = dict(record)
            record["state"] = "expired"
            self._store.update_request(wallet_id, record["id"], record)
        return record

    def _get_request_or_404(self, wallet_id: str, request_id: str) -> dict:
        try:
            record = self._store.get_request(wallet_id, request_id)
        except ValueError:
            raise ServiceError(400, "invalid signing_request_id")
        if record is None:
            raise ServiceError(
                404, f"signing request {request_id!r} not found"
            )
        return self._expire_if_needed(wallet_id, record)

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
        existing = self._store.create_request(wallet_id, request_id, record)
        if existing is not None:
            existing = self._expire_if_needed(wallet_id, existing)
            if existing["message"] != message:
                raise ServiceError(
                    409,
                    f"signing request {request_id!r} already exists "
                    "with a different message",
                )
            # 同 id 同文：幂等重放
            return 200, self._request_view(existing)
        return 201, self._request_view(record)

    def get_sign_request(self, wallet_id: str, request_id: str) -> dict:
        self._get_wallet_or_404(wallet_id)
        record = self._get_request_or_404(wallet_id, request_id)
        return self._request_view(record)

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
        record = self._get_request_or_404(wallet_id, request_id)
        if record["state"] != "pending":
            raise ServiceError(
                409,
                f"signing request {request_id!r} is {record['state']}, "
                "not pending",
            )

        record = dict(record)
        record["approvers"] = list(record["approvers"])
        if action == "approve":
            # 同一 approver 重复批准不计数，但仍返回 200
            if approver_id not in record["approvers"]:
                record["approvers"].append(approver_id)
                if reason is not None:
                    record["reason"] = reason
                if len(record["approvers"]) >= record["req"]:
                    record["state"] = "approved"
                self._store.update_request(wallet_id, request_id, record)
        else:  # reject：任何一名审批人拒绝即终态
            record["state"] = "rejected"
            if reason is not None:
                record["reason"] = reason
            self._store.update_request(wallet_id, request_id, record)
        return self._request_view(record)

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

        # 幂等：同一 signing_request_id 重放直接返回已有签名，不再校验
        try:
            existing = self._store.get_signature(wallet_id, signing_request_id)
        except ValueError:
            raise ServiceError(400, "invalid signing_request_id")
        if existing is not None:
            return 200, {"signature": existing["signature"]}

        # 启用审批策略时：必须存在同 id、同 message 且已 approved 的审批单
        approval_record = None
        if self._store.get_policy(wallet_id) is not None:
            approval_record = self._get_request_or_404(
                wallet_id, signing_request_id
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
        if approval_record is not None:
            # 审批单推进到终态 signed
            approval_record = dict(approval_record)
            approval_record["state"] = "signed"
            self._store.update_request(
                wallet_id, signing_request_id, approval_record
            )
        return 201, {"signature": aggregate.hex()}
