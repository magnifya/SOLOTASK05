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

from datetime import datetime, timezone

from . import crypto
from .store import DuplicateWalletError, WalletStore

#: 两方门限：份额数固定为 2
REQUIRED_SHARES = 2

#: 服务端为两个份额生成的固定标识（按此顺序聚合公钥与签名）
SHARE_IDS = ("share-1", "share-2")


class ServiceError(Exception):
    """业务错误，携带 HTTP 状态码与错误信息。"""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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
        return 201, {"signature": aggregate.hex()}
