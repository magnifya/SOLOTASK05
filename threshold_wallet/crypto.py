"""Ed25519 份额密钥与份额签名原语。

两方各持一把独立的 Ed25519 密钥：系统中任何位置都不存在"完整私钥"，
只有两个份额私钥。钱包公钥为两个份额公钥的有序拼接（64 字节），
门限签名为两个份额签名的有序拼接（128 字节），任何持有公钥的人
都可以把它拆成两把 Ed25519 公钥分别验证。
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)
from cryptography.exceptions import InvalidSignature

#: 单个份额被签名的载荷：signing_request_id 与 message 直接拼接
ENCODING = "utf-8"


@dataclass(frozen=True)
class ShareKey:
    """单个份额的 Ed25519 密钥对（仅服务端内部使用）。"""

    share_id: str
    private_bytes: bytes
    public_bytes: bytes


def generate_share_key(share_id: str) -> ShareKey:
    """为指定份额生成一把新的 Ed25519 密钥。"""
    private_key = Ed25519PrivateKey.generate()
    return ShareKey(
        share_id=share_id,
        private_bytes=private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        ),
        public_bytes=private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        ),
    )


def sign_share(private_bytes: bytes, payload: bytes) -> bytes:
    """用一个份额的私钥对载荷做 Ed25519 签名。"""
    private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
    return private_key.sign(payload)


def public_key_from_private(private_bytes: bytes) -> bytes:
    """从 32 字节份额私钥推导对应的 Ed25519 公钥（启动恢复校验用）。"""
    return Ed25519PrivateKey.from_private_bytes(
        private_bytes
    ).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def verify_share(public_bytes: bytes, payload: bytes, signature: bytes) -> bool:
    """校验一个份额的 Ed25519 签名；任何异常都视为校验失败。"""
    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        public_key.verify(signature, payload)
        return True
    except (InvalidSignature, ValueError):
        return False


def build_payload(signing_request_id: str, message: str) -> bytes:
    """构造份额签名载荷：signing_request_id 与 message 直接拼接。"""
    return signing_request_id.encode(ENCODING) + message.encode(ENCODING)


def combine_public_keys(share_public_keys: list[bytes]) -> bytes:
    """按份额顺序拼接两个份额公钥，形成钱包公钥（64 字节）。"""
    return b"".join(share_public_keys)


def split_public_key(public_key: bytes) -> list[bytes]:
    """把钱包公钥拆回两把份额公钥。"""
    return [public_key[:32], public_key[32:]]


def combine_signatures(share_signatures: list[bytes]) -> bytes:
    """按份额顺序拼接两个份额签名，形成门限签名（128 字节）。"""
    return b"".join(share_signatures)


def split_signature(signature: bytes) -> list[bytes]:
    """把门限签名拆回两个份额签名。"""
    return [signature[:64], signature[64:]]
