"""钱包持久化：只保存份额，磁盘上不存在完整私钥。

磁盘布局（data_dir 下）::

    wallets/<wallet_id>.json        钱包元数据 + 份额公钥（无私钥）
    shares/<wallet_id>/<share_id>.json
                                    单个份额（份额私钥以 hex 保存），一份一个文件
    signatures/<wallet_id>.json     该钱包已完成的签名请求（幂等去重）
    policies/<wallet_id>.json       该钱包的审批策略（required_approvals 等）
    requests/<wallet_id>.json       该钱包的签名请求审批单（状态机）
    rotations/<wallet_id>.json      该钱包的份额轮换记录（prepared/activating/active）
    rotation-staging/<wallet_id>/<rotation_id>/
                                    轮换暂存目录：新份额私钥文件（<share_id>.json），
                                    激活期间的旧份额/钱包元数据备份（*.bak.json），
                                    激活成功后整目录删除
    audit/<wallet_id>.json          该钱包的审计事件日志（seq 从 1 起仅追加，
                                    由 audit.AuditStore 维护）
    locks/<sha256(wallet_id)>.lock  每钱包跨进程事务锁文件（flock，进程退出
                                    自动释放，由 locks.WalletLockManager 维护）

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
import shutil
import tempfile
import threading
from contextlib import AbstractContextManager
from typing import Optional

from .crypto import ShareKey, public_key_from_private
from .locks import WalletLockManager

#: wallet_id / rotation_id / signing_request_id 允许的字符（同时杜绝路径穿越）
_SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

#: share_id 允许的字符：轮换份额 id 为 <rotation_id>-share-N，最长 128+8
_SAFE_SHARE_ID = re.compile(r"^[A-Za-z0-9_-]{1,136}$")


def _check_id(kind: str, value: str) -> None:
    if not isinstance(value, str) or not _SAFE_ID.match(value):
        raise ValueError(f"invalid {kind}: {value!r}")


def _check_share_id(value: str) -> None:
    if not isinstance(value, str) or not _SAFE_SHARE_ID.match(value):
        raise ValueError(f"invalid share_id: {value!r}")


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
        self._rotations_dir = os.path.join(data_dir, "rotations")
        self._rotation_staging_dir = os.path.join(data_dir, "rotation-staging")
        self._locks_dir = os.path.join(data_dir, "locks")
        os.makedirs(self._wallets_dir, exist_ok=True)
        os.makedirs(self._shares_dir, exist_ok=True)
        os.makedirs(self._signatures_dir, exist_ok=True)
        os.makedirs(self._policies_dir, exist_ok=True)
        os.makedirs(self._requests_dir, exist_ok=True)
        os.makedirs(self._rotations_dir, exist_ok=True)
        os.makedirs(self._rotation_staging_dir, exist_ok=True)
        self._lock = threading.Lock()
        self._lock_manager = WalletLockManager(self._locks_dir)

    @property
    def data_dir(self) -> str:
        return self._data_dir

    def wallet_lock(self, wallet_id: str) -> AbstractContextManager[None]:
        """该钱包的跨进程排他事务锁（flock；进程死亡自动释放，无陈旧锁）。

        多个服务进程共用同一 data-dir 时，同一钱包的"状态变更 + 审计
        事件追加"必须在此锁内完成。wallet_id 先经安全校验，与存储路径
        使用同一规则，拒绝非法 id。
        """
        _check_id("wallet_id", wallet_id)
        return self._lock_manager.hold(wallet_id)

    # ---- 内部工具 -------------------------------------------------------

    def _wallet_path(self, wallet_id: str) -> str:
        _check_id("wallet_id", wallet_id)
        return os.path.join(self._wallets_dir, wallet_id + ".json")

    def _share_path(self, wallet_id: str, share_id: str) -> str:
        _check_id("wallet_id", wallet_id)
        _check_share_id(share_id)
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

    def save_policy(self, wallet_id: str, policy: dict) -> None:
        """原子地写入（或覆盖）钱包的审批策略。"""
        path = self._policy_path(wallet_id)
        with self._lock:
            self._atomic_write(path, policy)

    def get_policy(self, wallet_id: str) -> Optional[dict]:
        """返回钱包的审批策略，未设置返回 None。"""
        return self._read_json(self._policy_path(wallet_id))

    # ---- 签名请求审批单 ---------------------------------------------------

    def create_request(
        self, wallet_id: str, signing_request_id: str, record: dict
    ) -> Optional[dict]:
        """原子地创建一条签名请求审批单。

        在同一把锁内先查重：若该 signing_request_id 已存在，则不覆盖、
        直接返回已有记录；否则写入并返回 None。
        """
        _check_id("signing_request_id", signing_request_id)
        path = self._requests_path(wallet_id)
        with self._lock:
            all_records = self._read_json(path) or {}
            existing = all_records.get(signing_request_id)
            if existing is not None:
                return existing
            all_records[signing_request_id] = record
            self._atomic_write(path, all_records)
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
        self, wallet_id: str, signing_request_id: str, record: dict
    ) -> None:
        """原子地覆盖一条已存在的签名请求审批单（状态机推进用）。"""
        _check_id("signing_request_id", signing_request_id)
        path = self._requests_path(wallet_id)
        with self._lock:
            all_records = self._read_json(path) or {}
            all_records[signing_request_id] = record
            self._atomic_write(path, all_records)

    # ---- 回滚（状态/事件原子性用）----------------------------------------

    def delete_policy(self, wallet_id: str) -> None:
        """删除钱包的审批策略文件（策略事件追加失败时回滚用）。"""
        path = self._policy_path(wallet_id)
        with self._lock:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def delete_request(self, wallet_id: str, signing_request_id: str) -> None:
        """删除一条签名请求审批单（创建事件追加失败时回滚用）。"""
        _check_id("signing_request_id", signing_request_id)
        path = self._requests_path(wallet_id)
        with self._lock:
            all_records = self._read_json(path)
            if not all_records or signing_request_id not in all_records:
                return
            del all_records[signing_request_id]
            if all_records:
                self._atomic_write(path, all_records)
            else:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass

    def delete_signature(self, wallet_id: str, signing_request_id: str) -> None:
        """删除一条已完成签名记录（签名事件追加失败时回滚用）。"""
        _check_id("signing_request_id", signing_request_id)
        path = self._signatures_path(wallet_id)
        with self._lock:
            all_records = self._read_json(path)
            if not all_records or signing_request_id not in all_records:
                return
            del all_records[signing_request_id]
            if all_records:
                self._atomic_write(path, all_records)
            else:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass

    # ---- 份额文件与钱包元数据（轮换激活用）--------------------------------

    def save_share(self, wallet_id: str, record: dict) -> None:
        """原子地写入（或覆盖）一个份额文件（含该份额私钥 hex）。"""
        path = self._share_path(wallet_id, record["share_id"])
        with self._lock:
            self._atomic_write(path, record)

    def delete_share(self, wallet_id: str, share_id: str) -> None:
        """删除一个份额文件（轮换激活换下旧份额 / 回滚清理新份额用）。"""
        path = self._share_path(wallet_id, share_id)
        with self._lock:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def save_wallet_meta(self, wallet_id: str, meta: dict) -> None:
        """原子地覆盖钱包元数据文件（无私钥；轮换激活/回滚用）。"""
        path = self._wallet_path(wallet_id)
        with self._lock:
            self._atomic_write(path, meta)

    # ---- 份额轮换记录 -----------------------------------------------------

    def _rotations_path(self, wallet_id: str) -> str:
        _check_id("wallet_id", wallet_id)
        return os.path.join(self._rotations_dir, wallet_id + ".json")

    def create_rotation(
        self, wallet_id: str, rotation_id: str, record: dict
    ) -> Optional[dict]:
        """原子地创建一条份额轮换记录。

        在同一把锁内先查重：若该 rotation_id 已存在，则不覆盖、
        直接返回已有记录；否则写入并返回 None。
        """
        _check_id("rotation_id", rotation_id)
        path = self._rotations_path(wallet_id)
        with self._lock:
            all_records = self._read_json(path) or {}
            existing = all_records.get(rotation_id)
            if existing is not None:
                return existing
            all_records[rotation_id] = record
            self._atomic_write(path, all_records)
            return None

    def get_rotation(
        self, wallet_id: str, rotation_id: str
    ) -> Optional[dict]:
        """返回某条份额轮换记录，不存在返回 None。"""
        _check_id("rotation_id", rotation_id)
        all_records = self._read_json(self._rotations_path(wallet_id))
        if not all_records:
            return None
        return all_records.get(rotation_id)

    def list_rotations(self, wallet_id: str) -> list[dict]:
        """返回该钱包的全部份额轮换记录（无文件时返回 []）。"""
        _check_id("wallet_id", wallet_id)
        all_records = self._read_json(self._rotations_path(wallet_id))
        if not all_records:
            return []
        return [
            dict(record)
            for record in all_records.values()
            if isinstance(record, dict)
        ]

    def update_rotation(
        self, wallet_id: str, rotation_id: str, record: dict
    ) -> None:
        """原子地覆盖一条已存在的份额轮换记录（状态机推进用）。"""
        _check_id("rotation_id", rotation_id)
        path = self._rotations_path(wallet_id)
        with self._lock:
            all_records = self._read_json(path) or {}
            all_records[rotation_id] = record
            self._atomic_write(path, all_records)

    def delete_rotation(self, wallet_id: str, rotation_id: str) -> None:
        """删除一条份额轮换记录（准备事件追加失败时回滚用）。"""
        _check_id("rotation_id", rotation_id)
        path = self._rotations_path(wallet_id)
        with self._lock:
            all_records = self._read_json(path)
            if not all_records or rotation_id not in all_records:
                return
            del all_records[rotation_id]
            if all_records:
                self._atomic_write(path, all_records)
            else:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass

    # ---- 轮换暂存目录（新份额私钥 + 激活备份）------------------------------

    def _staging_dir(self, wallet_id: str, rotation_id: str) -> str:
        _check_id("wallet_id", wallet_id)
        _check_id("rotation_id", rotation_id)
        return os.path.join(
            self._rotation_staging_dir, wallet_id, rotation_id
        )

    def _staging_share_path(
        self, wallet_id: str, rotation_id: str, share_id: str
    ) -> str:
        _check_share_id(share_id)
        return os.path.join(
            self._staging_dir(wallet_id, rotation_id), share_id + ".json"
        )

    def _staging_backup_path(
        self, wallet_id: str, rotation_id: str, share_id: str
    ) -> str:
        _check_share_id(share_id)
        return os.path.join(
            self._staging_dir(wallet_id, rotation_id),
            share_id + ".bak.json",
        )

    def _staging_wallet_backup_path(
        self, wallet_id: str, rotation_id: str
    ) -> str:
        return os.path.join(
            self._staging_dir(wallet_id, rotation_id), "wallet.bak.json"
        )

    def save_staging_share(
        self, wallet_id: str, rotation_id: str, record: dict
    ) -> None:
        """把一个新份额（含私钥）写入轮换暂存目录，一份一个文件。"""
        path = self._staging_share_path(
            wallet_id, rotation_id, record["share_id"]
        )
        with self._lock:
            self._atomic_write(path, record)

    def get_staging_share(
        self, wallet_id: str, rotation_id: str, share_id: str
    ) -> Optional[dict]:
        """返回暂存的新份额记录，不存在返回 None。"""
        return self._read_json(
            self._staging_share_path(wallet_id, rotation_id, share_id)
        )

    def save_activation_backups(
        self,
        wallet_id: str,
        rotation_id: str,
        old_shares: list[dict],
        wallet_meta: dict,
    ) -> None:
        """激活前把旧份额文件与钱包元数据备份进暂存目录（回滚依据）。"""
        with self._lock:
            for record in old_shares:
                self._atomic_write(
                    self._staging_backup_path(
                        wallet_id, rotation_id, record["share_id"]
                    ),
                    record,
                )
            self._atomic_write(
                self._staging_wallet_backup_path(wallet_id, rotation_id),
                wallet_meta,
            )

    def delete_activation_backups(
        self, wallet_id: str, rotation_id: str
    ) -> None:
        """删除激活备份（*.bak.json），保留暂存的新份额文件。"""
        staging = self._staging_dir(wallet_id, rotation_id)
        with self._lock:
            try:
                names = os.listdir(staging)
            except FileNotFoundError:
                return
            for name in names:
                if name.endswith(".bak.json"):
                    try:
                        os.unlink(os.path.join(staging, name))
                    except FileNotFoundError:
                        pass

    def delete_staging(self, wallet_id: str, rotation_id: str) -> None:
        """删除整个轮换暂存目录（激活成功后清理暂存与备份）。"""
        staging = self._staging_dir(wallet_id, rotation_id)
        with self._lock:
            shutil.rmtree(staging, ignore_errors=True)

    # ---- 启动恢复：未完成的激活先回滚 --------------------------------------

    def list_rotation_wallet_ids(self) -> list[str]:
        """返回拥有轮换记录文件的全部 wallet_id。"""
        try:
            names = os.listdir(self._rotations_dir)
        except FileNotFoundError:
            return []
        return sorted(
            name[: -len(".json")] for name in names if name.endswith(".json")
        )

    def rollback_activation_files(
        self, wallet_id: str, rotation_record: dict
    ) -> None:
        """用暂存目录中的备份恢复钱包元数据与旧份额文件，并删除已换入的
        新份额文件。备份缺失（崩溃发生在备份写入前）时各步自动跳过。"""
        rotation_id = rotation_record["rotation_id"]
        wallet_backup = self._read_json(
            self._staging_wallet_backup_path(wallet_id, rotation_id)
        )
        if wallet_backup is not None:
            self.save_wallet_meta(wallet_id, wallet_backup)
        staging = self._staging_dir(wallet_id, rotation_id)
        try:
            names = os.listdir(staging)
        except FileNotFoundError:
            names = []
        for name in names:
            if name.endswith(".bak.json") and name != "wallet.bak.json":
                share_record = self._read_json(os.path.join(staging, name))
                if isinstance(share_record, dict) and isinstance(
                    share_record.get("share_id"), str
                ):
                    self.save_share(wallet_id, share_record)
        for share_id in rotation_record.get("share_ids", []):
            if isinstance(share_id, str):
                self.delete_share(wallet_id, share_id)

    def recover_incomplete_activations(self) -> None:
        """启动恢复（幂等、不产生任何审计事件）。逐个钱包尽力而为：

        1. ``activating``：用备份恢复原钱包元数据与旧份额、删除已换入的
           新份额，记录回滚为 ``prepared``，再按 prepared 规则校验；
        2. ``active``：激活已提交，清理残留的暂存目录与备份；
        3. ``prepared``：仅当目录名与 rotation_id 一致、目录内恰有记录中
           两个 share_ids 的文件、JSON 可解析且 share_id、public_key、
           32 字节私钥均匹配时保留；否则记录与暂存目录一并安全删除；
        4. 未知状态的记录、没有有效 prepared 记录对应的暂存目录（孤儿）
           一律安全删除。

        绝不改动在用钱包与其份额（除第 1 步按备份恢复），清理后不留
        任何私钥副本。每钱包的恢复在该钱包的跨进程事务锁内进行，
        与并行进程的轮换/签名操作互斥。
        """
        handled: set[str] = set()
        for wallet_id in self.list_rotation_wallet_ids():
            handled.add(wallet_id)
            try:
                with self.wallet_lock(wallet_id):
                    self._recover_wallet_rotations(wallet_id)
            except (ValueError, OSError):
                continue
        # 没有轮换记录文件的钱包：其暂存目录整体为孤儿，安全删除
        for wallet_id in self._list_staging_wallet_ids():
            if wallet_id in handled:
                continue
            try:
                with self.wallet_lock(wallet_id):
                    shutil.rmtree(
                        os.path.join(self._rotation_staging_dir, wallet_id),
                        ignore_errors=True,
                    )
            except (ValueError, OSError):
                continue

    def _list_staging_wallet_ids(self) -> list[str]:
        """返回 rotation-staging 下全部安全的 wallet_id 目录名。"""
        try:
            names = os.listdir(self._rotation_staging_dir)
        except FileNotFoundError:
            return []
        result = []
        for name in sorted(names):
            if not _SAFE_ID.match(name):
                continue
            if os.path.isdir(os.path.join(self._rotation_staging_dir, name)):
                result.append(name)
        return result

    def _recover_wallet_rotations(self, wallet_id: str) -> None:
        """单个钱包的轮换恢复（调用方须持有该钱包跨进程事务锁）。"""
        keep_staging: set[str] = set()
        for record in self.list_rotations(wallet_id):
            rotation_id = record.get("rotation_id")
            state = record.get("state")
            if not isinstance(rotation_id, str) or not _SAFE_ID.match(
                rotation_id
            ):
                # 无法安全定位暂存目录的损坏记录：保持原样（不可激活、
                # 不可查询，inert），绝不做任何猜测性删除
                continue
            try:
                if state == "activating":
                    # 崩溃发生在激活中途：恢复原钱包、旧份额与 prepared
                    self.rollback_activation_files(wallet_id, record)
                    restored = {
                        key: value
                        for key, value in record.items()
                        if key != "previous_public_key"
                    }
                    restored["state"] = "prepared"
                    self.update_rotation(wallet_id, rotation_id, restored)
                    self.delete_activation_backups(wallet_id, rotation_id)
                    record = restored
                    state = "prepared"
                if state == "prepared":
                    if self._is_valid_prepared_staging(wallet_id, record):
                        keep_staging.add(rotation_id)
                    else:
                        # 无效 prepared：记录与暂存一并安全删除，
                        # 在用钱包与份额不受影响
                        self.delete_rotation(wallet_id, rotation_id)
                        self.delete_staging(wallet_id, rotation_id)
                elif state == "active":
                    # 崩溃发生在激活提交之后、暂存清理之前
                    self.delete_staging(wallet_id, rotation_id)
                elif state != "activating":
                    # 未知状态：记录不可信，安全删除（不触碰在用钱包）
                    self.delete_rotation(wallet_id, rotation_id)
                    self.delete_staging(wallet_id, rotation_id)
            except (ValueError, OSError):
                continue
        # 孤儿暂存目录：没有有效 prepared 记录对应的目录一律删除
        staging_root = os.path.join(self._rotation_staging_dir, wallet_id)
        try:
            names = os.listdir(staging_root)
        except FileNotFoundError:
            names = []
        for name in names:
            if not _SAFE_ID.match(name) or name in keep_staging:
                continue
            shutil.rmtree(
                os.path.join(staging_root, name), ignore_errors=True
            )
        # 清理后空的钱包暂存根目录一并移除
        try:
            if not os.listdir(staging_root):
                os.rmdir(staging_root)
        except (FileNotFoundError, OSError):
            pass

    def _is_valid_prepared_staging(
        self, wallet_id: str, record: dict
    ) -> bool:
        """prepared 记录 + 暂存目录的严格有效性判定。

        全部满足才保留：目录名与 rotation_id 一致；目录内**恰好**有
        记录中两个 share_ids 的 ``<share_id>.json`` 文件（无多无少）；
        每个文件 JSON 可解析，share_id 与记录一致，private_key 为
        32 字节且能推导出与文件 public_key 一致的公钥；两个份额公钥
        按序拼接与记录的 public_key 一致。
        """
        rotation_id = record.get("rotation_id")
        share_ids = record.get("share_ids")
        public_key = record.get("public_key")
        if not isinstance(rotation_id, str) or not _SAFE_ID.match(rotation_id):
            return False
        if (
            not isinstance(share_ids, list)
            or len(share_ids) != 2
            or len(set(share_ids)) != 2
            or any(
                not isinstance(sid, str) or not _SAFE_SHARE_ID.match(sid)
                for sid in share_ids
            )
        ):
            return False
        if not isinstance(public_key, str):
            return False
        try:
            combined = bytes.fromhex(public_key)
        except ValueError:
            return False
        if len(combined) != 64:
            return False
        staging = self._staging_dir(wallet_id, rotation_id)
        if not os.path.isdir(staging):
            return False
        try:
            names = os.listdir(staging)
        except OSError:
            return False
        if set(names) != {sid + ".json" for sid in share_ids}:
            return False
        public_parts = []
        for share_id in share_ids:
            try:
                staged = self._read_json(
                    os.path.join(staging, share_id + ".json")
                )
            except (ValueError, OSError):
                # JSON 不可解析 / 读取失败：一律判定无效
                return False
            if not isinstance(staged, dict):
                return False
            if staged.get("share_id") != share_id:
                return False
            pub_hex = staged.get("public_key")
            priv_hex = staged.get("private_key")
            if not isinstance(pub_hex, str) or not isinstance(priv_hex, str):
                return False
            try:
                public_bytes = bytes.fromhex(pub_hex)
                private_bytes = bytes.fromhex(priv_hex)
            except ValueError:
                return False
            if len(public_bytes) != 32 or len(private_bytes) != 32:
                return False
            try:
                if public_key_from_private(private_bytes) != public_bytes:
                    return False
            except ValueError:
                return False
            public_parts.append(public_bytes)
        return b"".join(public_parts) == combined
