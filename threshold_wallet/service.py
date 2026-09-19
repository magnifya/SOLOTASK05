"""门限钱包业务逻辑。

所有方法返回 ``(HTTP 状态码, 可 JSON 序列化的字典)``，与传输层
（HTTP/CLI）解耦。

聚合签名的顺序固定为建钱包时份额的存储顺序，与聚合公钥中两把公钥
的顺序一一对应；客户端提交份额签名时顺序不限，按 share_id 归位。
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone

from . import crypto
from .store import StoredShare, StoredWallet, WalletStore, validate_wallet_id


def _b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64_decode(data: str) -> bytes:
    return base64.b64decode(data, validate=True)


def _error(message: str) -> dict:
    return {"error": message}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class WalletService:
    def __init__(self, store: WalletStore) -> None:
        self._store = store

    def create_wallet(self, wallet_id: str, shares: int) -> tuple[int, dict]:
        """建钱包：shares 必须为 2。

        返回 201（成功）、400（shares 非法或 wallet_id 非法）、409（重复）。
        """
        # bool 是 int 的子类，显式排除 True/False 被当作 1/0。
        if not isinstance(shares, int) or isinstance(shares, bool) or shares != 2:
            return 400, _error("shares 必须等于 2")
        if not isinstance(wallet_id, str):
            return 400, _error("wallet_id 必须为字符串")
        try:
            validate_wallet_id(wallet_id)
        except ValueError as exc:
            return 400, _error(str(exc))

        if self._store.exists(wallet_id):
            return 409, _error("wallet_id 已存在")

        share_keys = crypto.generate_share_keys()
        private_keys = [key.private_bytes for key in share_keys]
        aggregated_public_key = crypto.aggregate_public_key(private_keys)

        wallet = StoredWallet(
            wallet_id=wallet_id,
            public_key_b64=_b64_encode(aggregated_public_key),
            created_at=_utc_now(),
            shares=[
                StoredShare(
                    share_id=key.share_id,
                    private_b64=_b64_encode(priv),
                    public_b64=_b64_encode(crypto.share_public_key(priv)),
                )
                for key, priv in zip(share_keys, private_keys)
            ],
        )
        self._store.save(wallet)
        return 201, {
            "wallet_id": wallet_id,
            "public_key": wallet.public_key_b64,
            "share_ids": [key.share_id for key in share_keys],
        }

    def submit_signature(
        self,
        wallet_id: str,
        signing_request_id: str,
        message_b64: str,
        signatures: list,
    ) -> tuple[int, dict]:
        """提交两份份额签名。

        返回 201（成功，含聚合签名；重复请求幂等返回已有签名）、
        400（缺份额/份额未知/重复份额/签名非法或校验失败）、404（钱包不存在）。
        """
        wallet = self._store.get(wallet_id)
        if wallet is None:
            return 404, _error("钱包不存在")
        if not isinstance(signing_request_id, str) or not signing_request_id:
            return 400, _error("signing_request_id 必须为非空字符串")

        # 幂等：同一 signing_request_id 重复提交，直接返回已有聚合签名。
        existing = wallet.signatures.get(signing_request_id)
        if existing is not None:
            return 201, {"signature": existing["signature_b64"]}

        if not isinstance(message_b64, str):
            return 400, _error("message 必须为 base64 字符串")
        try:
            message = _b64_decode(message_b64)
        except (binascii.Error, ValueError):
            return 400, _error("message 不是合法的 base64")

        # 必须恰好提交两份签名，share_id 互不相同且均属于本钱包。
        if not isinstance(signatures, list) or len(signatures) != crypto.SHARE_COUNT:
            return 400, _error("必须提交恰好两份份额签名")

        shares_by_id = {share.share_id: share for share in wallet.shares}
        submitted: dict[str, bytes] = {}
        for item in signatures:
            if not isinstance(item, dict):
                return 400, _error("signatures 元素必须为对象")
            share_id = item.get("share_id")
            signature_b64 = item.get("signature")
            if not isinstance(share_id, str) or not isinstance(signature_b64, str):
                return 400, _error("每份签名必须含字符串类型的 share_id 与 signature")
            if share_id not in shares_by_id:
                return 400, _error(f"未知的 share_id: {share_id}")
            if share_id in submitted:
                return 400, _error("同一份额提交了多份签名")
            try:
                signature = _b64_decode(signature_b64)
            except (binascii.Error, ValueError):
                return 400, _error("signature 不是合法的 base64")
            if len(signature) != crypto.SIGNATURE_LENGTH:
                return 400, _error("份额签名长度必须为 64 字节")
            submitted[share_id] = signature

        payload = crypto.signing_payload(signing_request_id, message)

        # 按存储顺序聚合并逐份校验。
        ordered_signatures: list[bytes] = []
        for share in wallet.shares:
            signature = submitted[share.share_id]
            if not crypto.verify_share_signature(
                _b64_decode(share.public_b64), payload, signature
            ):
                return 400, _error(f"份额 {share.share_id} 签名校验失败")
            ordered_signatures.append(signature)

        aggregated_signature = b"".join(ordered_signatures)
        signature_b64 = _b64_encode(aggregated_signature)
        wallet.signatures[signing_request_id] = {
            "message_b64": message_b64,
            "signature_b64": signature_b64,
        }
        self._store.save(wallet)
        return 201, {"signature": signature_b64}

    def get_wallet(self, wallet_id: str) -> tuple[int, dict]:
        """查询钱包：200 返回 public_key/created_at，404 不存在。"""
        wallet = self._store.get(wallet_id)
        if wallet is None:
            return 404, _error("钱包不存在")
        return 200, {
            "public_key": wallet.public_key_b64,
            "created_at": wallet.created_at,
        }
