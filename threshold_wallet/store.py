"""钱包份额的磁盘持久化。

磁盘上每个钱包一个 JSON 文件，只保存：
- 份额私钥（份额本身，服务端托管的就是份额，不存在完整私钥）
- 聚合公钥、份额标识/公钥、创建时间
- 已完成的签名请求（幂等去重）

写入采用临时文件 + os.replace 原子替换，文件权限 0600。
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# wallet_id 直接用作文件名，只允许保守的字符集，杜绝路径穿越。
_WALLET_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def validate_wallet_id(wallet_id: str) -> None:
    """校验 wallet_id 可安全用作文件名，非法时抛出 ValueError。"""
    if not isinstance(wallet_id, str) or not _WALLET_ID_RE.match(wallet_id):
        raise ValueError(
            "wallet_id 必须为 1-128 个字母/数字/点/下划线/连字符，且以字母或数字开头"
        )


@dataclass
class StoredShare:
    share_id: str
    # 32 字节 Ed25519 种子私钥（份额私钥），base64 落盘
    private_b64: str
    # 32 字节份额公钥，base64 落盘
    public_b64: str


@dataclass
class StoredWallet:
    wallet_id: str
    public_key_b64: str  # 64 字节聚合公钥
    created_at: str  # RFC 3339 UTC 时间
    shares: list[StoredShare] = field(default_factory=list)
    # signing_request_id -> {"message_b64": ..., "signature_b64": ...}
    signatures: dict[str, dict[str, str]] = field(default_factory=dict)


class WalletStore:
    """基于目录的钱包存储，每个钱包对应一个 JSON 文件。"""

    def __init__(self, directory: str | Path) -> None:
        self._directory = Path(directory)
        self._directory.mkdir(parents=True, exist_ok=True)

    def _path(self, wallet_id: str) -> Path:
        validate_wallet_id(wallet_id)
        return self._directory / f"{wallet_id}.json"

    def exists(self, wallet_id: str) -> bool:
        try:
            return self._path(wallet_id).is_file()
        except ValueError:
            return False

    def get(self, wallet_id: str) -> StoredWallet | None:
        try:
            path = self._path(wallet_id)
        except ValueError:
            return None
        if not path.is_file():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return StoredWallet(
            wallet_id=data["wallet_id"],
            public_key_b64=data["public_key"],
            created_at=data["created_at"],
            shares=[
                StoredShare(
                    share_id=share["share_id"],
                    private_b64=share["private_key"],
                    public_b64=share["public_key"],
                )
                for share in data.get("shares", [])
            ],
            signatures={
                request_id: {
                    "message_b64": entry["message"],
                    "signature_b64": entry["signature"],
                }
                for request_id, entry in data.get("signatures", {}).items()
            },
        )

    def save(self, wallet: StoredWallet) -> None:
        """原子写入钱包文件（临时文件 + os.replace）。"""
        path = self._path(wallet.wallet_id)
        payload = {
            "wallet_id": wallet.wallet_id,
            "public_key": wallet.public_key_b64,
            "created_at": wallet.created_at,
            "shares": [
                {
                    "share_id": share.share_id,
                    "private_key": share.private_b64,
                    "public_key": share.public_b64,
                }
                for share in wallet.shares
            ],
            "signatures": {
                request_id: {
                    "message": entry["message_b64"],
                    "signature": entry["signature_b64"],
                }
                for request_id, entry in wallet.signatures.items()
            },
        }
        # NamedTemporaryFile 放在同目录以保证 replace 是原子的同文件系统操作。
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{wallet.wallet_id}.", suffix=".tmp", dir=self._directory
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
                handle.write("\n")
            os.replace(tmp_name, path)
        except BaseException:
            # 出错时清理临时文件，避免残留。
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass
            raise
