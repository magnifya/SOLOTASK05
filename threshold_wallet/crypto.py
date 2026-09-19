"""Ed25519 门限签名原语。

本模块只产生两份互相独立的份额密钥，系统中任何时刻都不存在
"完整私钥"：两个份额各自是独立的 Ed25519 私钥，聚合公钥是两把
公钥的拼接，聚合签名是两份签名的拼接。校验时逐份额用各自公钥
验证同一段待签名消息。
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# 每份 Ed25519 公钥 32 字节、签名 64 字节；聚合值为两份的顺序拼接。
SHARE_COUNT = 2
PUBLIC_KEY_LENGTH = 32
SIGNATURE_LENGTH = 64
SEED_LENGTH = 32
AGGREGATED_PUBLIC_KEY_LENGTH = PUBLIC_KEY_LENGTH * SHARE_COUNT
AGGREGATED_SIGNATURE_LENGTH = SIGNATURE_LENGTH * SHARE_COUNT

_RAW_ENCODING = serialization.Encoding.Raw
_RAW_PUBLIC_FORMAT = serialization.PublicFormat.Raw


@dataclass(frozen=True)
class ShareKey:
    """一个份额的标识与其 Ed25519 私钥。"""

    share_id: str
    private_bytes: bytes  # Raw 32 字节 Ed25519 种子私钥，仅服务端内存/磁盘可见


def signing_payload(signing_request_id: str, message: bytes) -> bytes:
    """构造各份额统一签名的内容：signing_request_id 与 message 拼接。

    即 ``signing_request_id`` 的 UTF-8 编码后直接拼接 ``message`` 字节。
    """
    return signing_request_id.encode("utf-8") + message


def _load_private_key(private_bytes: bytes) -> Ed25519PrivateKey:
    if len(private_bytes) != SEED_LENGTH:
        raise ValueError("份额私钥必须为 32 字节")
    return Ed25519PrivateKey.from_private_bytes(private_bytes)


def generate_share_keys() -> list[ShareKey]:
    """生成两份独立的份额密钥，返回长度为 2 的列表。

    份额标识用随机十六进制字符串，公开且稳定，不含任何私钥信息。
    """
    return [
        ShareKey(share_id=secrets.token_hex(8), private_bytes=os.urandom(SEED_LENGTH))
        for _ in range(SHARE_COUNT)
    ]


def share_public_key(private_bytes: bytes) -> bytes:
    """由份额私钥导出 32 字节公钥。"""
    return _load_private_key(private_bytes).public_key().public_bytes(
        encoding=_RAW_ENCODING, format=_RAW_PUBLIC_FORMAT
    )


def aggregate_public_key(private_keys: list[bytes]) -> bytes:
    """按份额顺序拼接两把公钥，得到 64 字节聚合公钥。"""
    if len(private_keys) != SHARE_COUNT:
        raise ValueError("聚合公钥需要恰好两份份额私钥")
    return b"".join(share_public_key(priv) for priv in private_keys)


def sign_share(private_bytes: bytes, payload: bytes) -> bytes:
    """用单个份额私钥对 payload 签名，返回 64 字节份额签名。"""
    return _load_private_key(private_bytes).sign(payload)


def verify_share_signature(
    public_key: bytes, payload: bytes, signature: bytes
) -> bool:
    """用单个份额公钥校验份额签名，合法返回 True。"""
    if len(public_key) != PUBLIC_KEY_LENGTH or len(signature) != SIGNATURE_LENGTH:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
        return True
    except InvalidSignature:
        return False


def verify_aggregated_signature(
    aggregated_public_key: bytes, payload: bytes, aggregated_signature: bytes
) -> bool:
    """校验聚合签名：长度正确且两份份额签名分别通过各自公钥验证。"""
    if (
        len(aggregated_public_key) != AGGREGATED_PUBLIC_KEY_LENGTH
        or len(aggregated_signature) != AGGREGATED_SIGNATURE_LENGTH
    ):
        return False
    for index in range(SHARE_COUNT):
        pub = aggregated_public_key[
            index * PUBLIC_KEY_LENGTH : (index + 1) * PUBLIC_KEY_LENGTH
        ]
        sig = aggregated_signature[
            index * SIGNATURE_LENGTH : (index + 1) * SIGNATURE_LENGTH
        ]
        if not verify_share_signature(pub, payload, sig):
            return False
    return True
