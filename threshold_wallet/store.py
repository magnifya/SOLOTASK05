"""钱包持久化：只保存份额，磁盘上不存在完整私钥。

磁盘布局（data_dir 下）::

    wallets/<wallet_id>.json        钱包元数据 + 份额公钥（无私钥）
    shares/<wallet_id>/<share_id>.json
                                    单个份额（份额私钥以 hex 保存），一份一个文件
    signatures/<wallet_id>.json     该钱包已完成的签名请求（幂等去重）
    policies/<wallet_id>.json       审批策略（required_approvals/timeout_seconds）
    requests/<wallet_id>.json       该钱包所有签名审批请求（按 id 索引的字典）

关键安全性质：
- 元数据文件不含任何私钥材料；
- 每个文件至多包含一个 32 字节份额私钥，两个份额分文件存放，
  任何位置都不保存拼接/聚合后的完整私钥；
- 写入采用同目录临时文件 + os.replace 原子替换；
- 进程内用一把锁串行化写操作（ThreadingHTTPServer 下安全）。
"""

from __future__ import annotations

import copy
import json
import os
import re
import tempfile
import threading
from typing import Optional

from .crypto import ShareKey

#: wallet_id / share_id / signing_request_id 允许的字符（同时杜绝路径穿越）
_SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def _check_id(kind: str, value: str) -> None:
    if not isinstance(value, str) or not _SAFE_ID.match(value):
        raise ValueError(f"invalid {kind}: {value!r}")


def validate_request_id(value: str) -> None:
    """供 service 层在边界处校验签名请求 id（同时杜绝路径穿越）。"""
    _check_id("signing_request_id", value)


class DuplicateWalletError(Exception):
    """wallet_id 已存在。"""


class WalletStore:
    """钱包、份额与已完成签名请求的文件存储。"""

    def __init__(self, data_dir: str) -> None:
        self._data_dir = data_dir
        self._wallets_dir = os.path.join(data_dir, "wallets")
        self._shares_dir = os.path.join(data_dir, "shares")
        self._signatures_dir = os.path.join(data_dir, "signatures")
        self._policies_dir = os.path.join(data_dir, "policies")
        self._requests_dir = os.path.join(data_dir, "requests")
        os.makedirs(self._wallets_dir, exist_ok=True)
        os.makedirs(self._shares_dir, exist_ok=True)
        os.makedirs(self._signatures_dir, exist_ok=True)
        os.makedirs(self._policies_dir, exist_ok=True)
        os.makedirs(self._requests_dir, exist_ok=True)
        self._lock = threading.Lock()

    # ---- 内部工具 -------------------------------------------------------

    def _wallet_path(self, wallet_id: str) -> str:
        _check_id("wallet_id", wallet_id)
        return os.path.join(self._wallets_dir, wallet_id + ".json")

    def _share_path(self, wallet_id: str, share_id: str) -> str:
        _check_id("wallet_id", wallet_id)
        _check_id("share_id", share_id)
        return os.path.join(
            self._shares_dir, wallet_id, share_id + ".json"
        )

    def _signatures_path(self, wallet_id: str) -> str:
        _check_id("wallet_id", wallet_id)
        return os.path.join(self._signatures_dir, wallet_id + ".json")

    def _policy_path(self, wallet_id: str) -> str:
        _check_id("wallet_id", wallet_id)
        return os.path.join(self._policies_dir, wallet_id + ".json")

    def _requests_path(self, wallet_id: str) -> str:
        _check_id("wallet_id", wallet_id)
        return os.path.join(self._requests_dir, wallet_id + ".json")

    @staticmethod
    def _atomic_write(path: str, data: dict) -> None:
        directory = os.path.dirname(path)
        os.makedirs(directory, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
                f.write("\n")
            os.replace(tmp_path, path)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
            raise

    @staticmethod
    def _read_json(path: str) -> Optional[dict]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return None

    # ---- 钱包与份额 -----------------------------------------------------

    def create_wallet(
        self, wallet_id: str, shares: list[ShareKey], created_at: str
    ) -> None:
        """原子创建钱包元数据与各份额文件；重复时抛 DuplicateWalletError。"""
        meta_path = self._wallet_path(wallet_id)
        meta = {
            "wallet_id": wallet_id,
            "created_at": created_at,
            "public_key": b"".join(s.public_bytes for s in shares).hex(),
            "shares": [
                {"share_id": s.share_id, "public_key": s.public_bytes.hex()}
                for s in shares
            ],
        }
        share_records = [
            (
                self._share_path(wallet_id, s.share_id),
                {
                    "share_id": s.share_id,
                    "public_key": s.public_bytes.hex(),
                    # 仅该份额自己的私钥；系统中不存在完整私钥
                    "private_key": s.private_bytes.hex(),
                },
            )
            for s in shares
        ]
        with self._lock:
            if os.path.exists(meta_path):
                raise DuplicateWalletError(wallet_id)
            for path, record in share_records:
                self._atomic_write(path, record)
            self._atomic_write(meta_path, meta)

    def get_wallet(self, wallet_id: str) -> Optional[dict]:
        """返回钱包元数据（不含私钥），不存在返回 None。"""
        return self._read_json(self._wallet_path(wallet_id))

    def has_wallet(self, wallet_id: str) -> bool:
        return os.path.exists(self._wallet_path(wallet_id))

    def get_share(self, wallet_id: str, share_id: str) -> Optional[dict]:
        """返回单个份额记录（含该份额私钥 hex），不存在返回 None。"""
        return self._read_json(self._share_path(wallet_id, share_id))

    # ---- 签名请求 -------------------------------------------------------

    def save_signature(
        self, wallet_id: str, signing_request_id: str, record: dict
    ) -> Optional[dict]:
        """原子地保存一条已完成签名。

        在同一把锁内先查重：若该 signing_request_id 已有结果，则不覆盖、
        直接返回已有记录；否则写入并返回 None。
        """
        _check_id("signing_request_id", signing_request_id)
        path = self._signatures_path(wallet_id)
        with self._lock:
            all_records = self._read_json(path) or {}
            existing = all_records.get(signing_request_id)
            if existing is not None:
                return existing
            all_records[signing_request_id] = record
            self._atomic_write(path, all_records)
            return None

    def get_signature(
        self, wallet_id: str, signing_request_id: str
    ) -> Optional[dict]:
        """返回某签名请求的已有结果，不存在返回 None。"""
        _check_id("signing_request_id", signing_request_id)
        all_records = self._read_json(self._signatures_path(wallet_id))
        if not all_records:
            return None
        return all_records.get(signing_request_id)

    # ---- 审批策略 -------------------------------------------------------

    def save_approval_policy(self, wallet_id: str, policy: dict) -> None:
        """原子地（覆盖）写入钱包的审批策略。"""
        path = self._policy_path(wallet_id)
        with self._lock:
            self._atomic_write(path, policy)

    def get_approval_policy(self, wallet_id: str) -> Optional[dict]:
        """返回审批策略，未设置返回 None。"""
        return self._read_json(self._policy_path(wallet_id))

    # ---- 签名审批请求 ---------------------------------------------------

    def get_request_doc(self, wallet_id: str) -> Optional[dict]:
        """返回该钱包全部签名审批请求（id -> record），从未创建返回 None。"""
        return self._read_json(self._requests_path(wallet_id))

    def create_sign_request(self, wallet_id: str, record: dict) -> str:
        """在锁内创建签名审批请求。

        返回：
        - "created"  记录不存在，已写入；
        - "same"     同 id 且 message 相同，不覆盖；
        - "conflict" 同 id 但 message 不同，不覆盖。
        """
        request_id = record["id"]
        _check_id("signing_request_id", request_id)
        path = self._requests_path(wallet_id)
        with self._lock:
            doc = self._read_json(path) or {}
            existing = doc.get(request_id)
            if existing is not None:
                return "same" if existing["message"] == record["message"] else "conflict"
            doc[request_id] = record
            self._atomic_write(path, doc)
            return "created"

    def update_sign_request(
        self, wallet_id: str, request_id: str, mutate
    ) -> Optional[dict]:
        """在锁内读取请求、调用 mutate(record) 并仅在其返回新记录时原子写回。

        mutate 返回 None 表示放弃更新（调用方据此返回 409）；返回 dict 表示
        要持久化的新记录。返回的记录通过深拷贝隔离，避免调用方持有可变别名。
        请求不存在返回 None。
        """
        _check_id("signing_request_id", request_id)
        path = self._requests_path(wallet_id)
        with self._lock:
            doc = self._read_json(path)
            if not doc:
                return None
            record = doc.get(request_id)
            if record is None:
                return None
            updated = mutate(copy.deepcopy(record))
            if updated is None:
                return copy.deepcopy(record)
            doc[request_id] = updated
            self._atomic_write(path, doc)
            return copy.deepcopy(updated)
