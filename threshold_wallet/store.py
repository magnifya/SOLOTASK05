"""钱包持久化：只保存份额，磁盘上不存在完整私钥。

磁盘布局（data_dir 下）::

    wallets/<wallet_id>.json        钱包元数据 + 份额公钥（无私钥）
    shares/<wallet_id>/<share_id>.json
                                    单个份额（份额私钥以 hex 保存），一份一个文件
    signatures/<wallet_id>.json     该钱包已完成的签名请求（幂等去重）
    policies/<wallet_id>.json       该钱包的审批策略（required_approvals 等）
    requests/<wallet_id>.json       该钱包的签名请求审批单（状态机）
    audit/<wallet_id>.json          该钱包的审计事件流（next_seq + events）

关键安全性质：
- 元数据文件不含任何私钥材料；
- 每个文件至多包含一个 32 字节份额私钥，两个份额分文件存放，
  任何位置都不保存拼接/聚合后的完整私钥；
- 写入采用同目录临时文件 + os.replace 原子替换；
- 进程内用一把锁串行化写操作（ThreadingHTTPServer 下安全）。
"""

from __future__ import annotations

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
        self._audit_dir = os.path.join(data_dir, "audit")
        os.makedirs(self._wallets_dir, exist_ok=True)
        os.makedirs(self._shares_dir, exist_ok=True)
        os.makedirs(self._signatures_dir, exist_ok=True)
        os.makedirs(self._policies_dir, exist_ok=True)
        os.makedirs(self._requests_dir, exist_ok=True)
        os.makedirs(self._audit_dir, exist_ok=True)
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

    def _audit_path(self, wallet_id: str) -> str:
        _check_id("wallet_id", wallet_id)
        return os.path.join(self._audit_dir, wallet_id + ".json")

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

    @staticmethod
    def _restore_file(path: str, backup: Optional[dict]) -> None:
        """回滚一个状态文件：backup 为 None 表示事务前文件不存在。"""
        if backup is None:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
        else:
            WalletStore._atomic_write(path, backup)

    # ---- 审计事件 -------------------------------------------------------

    def _read_audit(self, wallet_id: str) -> dict:
        """读取审计流；不存在时返回初始结构（seq 从 1 起）。"""
        data = self._read_json(self._audit_path(wallet_id))
        if not data:
            return {"next_seq": 1, "events": []}
        return data

    def _append_event_unlocked(self, wallet_id: str, event: dict) -> dict:
        """追加一条审计事件并分配 seq（调用方必须已持有 self._lock）。

        seq 单调递增、持久化在审计文件中，进程重启后延续。
        """
        audit = self._read_audit(wallet_id)
        stored = dict(event)
        stored["seq"] = audit["next_seq"]
        audit["events"].append(stored)
        audit["next_seq"] += 1
        self._atomic_write(self._audit_path(wallet_id), audit)
        return stored

    def get_audit_events(self, wallet_id: str) -> list[dict]:
        """返回该钱包按 seq 升序的全部审计事件。"""
        with self._lock:
            return list(self._read_audit(wallet_id)["events"])

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
        self,
        wallet_id: str,
        signing_request_id: str,
        record: dict,
        event: Optional[dict] = None,
        request_record: Optional[dict] = None,
    ) -> Optional[dict]:
        """原子地保存一条已完成签名。

        在同一把锁内先查重：若该 signing_request_id 已有结果，则不覆盖、
        直接返回已有记录（也不写事件）；否则写入并返回 None。

        event 不为 None 时，审计事件与签名记录（以及可选的审批单推进
        request_record）在同一事务内写入；任一步失败则回滚状态文件，
        不留半成品。
        """
        _check_id("signing_request_id", signing_request_id)
        path = self._signatures_path(wallet_id)
        req_path = (
            self._requests_path(wallet_id)
            if request_record is not None
            else None
        )
        with self._lock:
            backup = self._read_json(path)
            all_records = dict(backup) if backup else {}
            existing = all_records.get(signing_request_id)
            if existing is not None:
                return existing
            req_backup = self._read_json(req_path) if req_path else None
            try:
                all_records[signing_request_id] = record
                self._atomic_write(path, all_records)
                if req_path is not None:
                    requests = dict(req_backup) if req_backup else {}
                    requests[signing_request_id] = request_record
                    self._atomic_write(req_path, requests)
                if event is not None:
                    self._append_event_unlocked(wallet_id, event)
            except BaseException:
                self._restore_file(path, backup)
                if req_path is not None:
                    self._restore_file(req_path, req_backup)
                raise
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

    def save_policy(
        self, wallet_id: str, policy: dict, event: Optional[dict] = None
    ) -> None:
        """原子地写入（或覆盖）钱包的审批策略。

        event 不为 None 时，审计事件与策略在同一事务内写入，
        失败时回滚策略文件。
        """
        path = self._policy_path(wallet_id)
        with self._lock:
            backup = self._read_json(path)
            try:
                self._atomic_write(path, policy)
                if event is not None:
                    self._append_event_unlocked(wallet_id, event)
            except BaseException:
                self._restore_file(path, backup)
                raise

    def get_policy(self, wallet_id: str) -> Optional[dict]:
        """返回钱包的审批策略，未设置返回 None。"""
        return self._read_json(self._policy_path(wallet_id))

    # ---- 签名请求审批单 ---------------------------------------------------

    def create_request(
        self,
        wallet_id: str,
        signing_request_id: str,
        record: dict,
        event: Optional[dict] = None,
    ) -> Optional[dict]:
        """原子地创建一条签名请求审批单。

        在同一把锁内先查重：若该 signing_request_id 已存在，则不覆盖、
        直接返回已有记录（也不写事件）；否则写入并返回 None。

        event 不为 None 时，审计事件与审批单在同一事务内写入，
        失败时回滚审批单文件。
        """
        _check_id("signing_request_id", signing_request_id)
        path = self._requests_path(wallet_id)
        with self._lock:
            backup = self._read_json(path)
            all_records = dict(backup) if backup else {}
            existing = all_records.get(signing_request_id)
            if existing is not None:
                return existing
            try:
                all_records[signing_request_id] = record
                self._atomic_write(path, all_records)
                if event is not None:
                    self._append_event_unlocked(wallet_id, event)
            except BaseException:
                self._restore_file(path, backup)
                raise
            return None

    def get_request(
        self, wallet_id: str, signing_request_id: str
    ) -> Optional[dict]:
        """返回某条签名请求审批单，不存在返回 None。"""
        _check_id("signing_request_id", signing_request_id)
        all_records = self._read_json(self._requests_path(wallet_id))
        if not all_records:
            return None
        return all_records.get(signing_request_id)

    def update_request(
        self,
        wallet_id: str,
        signing_request_id: str,
        record: dict,
        event: Optional[dict] = None,
    ) -> None:
        """原子地覆盖一条已存在的签名请求审批单（状态机推进用）。

        event 不为 None 时，审计事件与状态推进在同一事务内写入，
        失败时回滚审批单文件（状态与事件不会只落一半）。
        """
        _check_id("signing_request_id", signing_request_id)
        path = self._requests_path(wallet_id)
        with self._lock:
            backup = self._read_json(path)
            all_records = dict(backup) if backup else {}
            try:
                all_records[signing_request_id] = record
                self._atomic_write(path, all_records)
                if event is not None:
                    self._append_event_unlocked(wallet_id, event)
            except BaseException:
                self._restore_file(path, backup)
                raise
