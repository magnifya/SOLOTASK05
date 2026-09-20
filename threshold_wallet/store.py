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
    assets/<wallet_id>.json         该钱包的资产账本：asset-operations（操作
                                    状态机 pending/committed）与 assets（每个
                                    资产的 balance/version），同一文件原子写入

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
from typing import Optional

from .crypto import ShareKey, combine_public_keys, public_key_from_private

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
        self._assets_dir = os.path.join(data_dir, "assets")
        os.makedirs(self._wallets_dir, exist_ok=True)
        os.makedirs(self._shares_dir, exist_ok=True)
        os.makedirs(self._signatures_dir, exist_ok=True)
        os.makedirs(self._policies_dir, exist_ok=True)
        os.makedirs(self._requests_dir, exist_ok=True)
        os.makedirs(self._rotations_dir, exist_ok=True)
        os.makedirs(self._rotation_staging_dir, exist_ok=True)
        os.makedirs(self._assets_dir, exist_ok=True)
        self._lock = threading.Lock()

    @property
    def data_dir(self) -> str:
        return self._data_dir

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

    # ---- 资产账本（asset-operations 与 assets）-----------------------------

    def _assets_path(self, wallet_id: str) -> str:
        _check_id("wallet_id", wallet_id)
        return os.path.join(self._assets_dir, wallet_id + ".json")

    def _read_asset_ledger(self, wallet_id: str) -> dict:
        """读取资产账本（无文件时返回空结构）。"""
        ledger = self._read_json(self._assets_path(wallet_id))
        if not isinstance(ledger, dict):
            ledger = {}
        operations = ledger.get("operations")
        if not isinstance(operations, dict):
            operations = {}
        assets = ledger.get("assets")
        if not isinstance(assets, dict):
            assets = {}
        return {"operations": operations, "assets": assets}

    def create_asset_operation(
        self, wallet_id: str, operation_id: str, record: dict
    ) -> Optional[dict]:
        """原子地创建一条资产操作记录。

        在同一把锁内先查重：若该 operation_id 已存在，则不覆盖、
        直接返回已有记录；否则写入并返回 None。
        """
        _check_id("operation_id", operation_id)
        path = self._assets_path(wallet_id)
        with self._lock:
            ledger = self._read_asset_ledger(wallet_id)
            existing = ledger["operations"].get(operation_id)
            if isinstance(existing, dict):
                return existing
            ledger["operations"][operation_id] = record
            self._atomic_write(path, ledger)
            return None

    def get_asset_operation(
        self, wallet_id: str, operation_id: str
    ) -> Optional[dict]:
        """返回某条资产操作记录，不存在返回 None。"""
        _check_id("operation_id", operation_id)
        record = self._read_asset_ledger(wallet_id)["operations"].get(
            operation_id
        )
        return dict(record) if isinstance(record, dict) else None

    def get_asset(self, wallet_id: str, asset_id: str) -> Optional[dict]:
        """返回某资产的账本记录（balance/version），不存在返回 None。"""
        _check_id("asset_id", asset_id)
        record = self._read_asset_ledger(wallet_id)["assets"].get(asset_id)
        return dict(record) if isinstance(record, dict) else None

    def commit_asset_operation(
        self,
        wallet_id: str,
        operation_id: str,
        operation_record: dict,
        asset_id: str,
        asset_record: dict,
    ) -> None:
        """原子地提交一条资产操作：操作记录与资产 balance/version 同文件
        一次写入（调用方须持有该钱包事务锁）。"""
        _check_id("operation_id", operation_id)
        _check_id("asset_id", asset_id)
        path = self._assets_path(wallet_id)
        with self._lock:
            ledger = self._read_asset_ledger(wallet_id)
            ledger["operations"][operation_id] = operation_record
            ledger["assets"][asset_id] = asset_record
            self._atomic_write(path, ledger)

    def restore_asset_operation(
        self,
        wallet_id: str,
        operation_id: str,
        operation_record: dict,
        asset_id: str,
        asset_record: Optional[dict],
    ) -> None:
        """提交事件追加失败时回滚：恢复操作记录与资产记录
        （asset_record 为 None 表示提交前该资产无账本记录，直接删除）。"""
        _check_id("operation_id", operation_id)
        _check_id("asset_id", asset_id)
        path = self._assets_path(wallet_id)
        with self._lock:
            ledger = self._read_asset_ledger(wallet_id)
            ledger["operations"][operation_id] = operation_record
            if asset_record is None:
                ledger["assets"].pop(asset_id, None)
            else:
                ledger["assets"][asset_id] = asset_record
            self._atomic_write(path, ledger)

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

    # ---- 启动恢复：未完成的激活先回滚，轮换残留按有效性判定 --------------

    def list_rotation_wallet_ids(self) -> list[str]:
        """返回拥有轮换记录文件的全部 wallet_id。"""
        try:
            names = os.listdir(self._rotations_dir)
        except FileNotFoundError:
            return []
        return sorted(
            name[: -len(".json")] for name in names if name.endswith(".json")
        )

    def list_staging_wallet_ids(self) -> list[str]:
        """返回轮换暂存根目录下出现过的全部 wallet_id（含无记录文件的）。"""
        try:
            names = os.listdir(self._rotation_staging_dir)
        except FileNotFoundError:
            return []
        return sorted(
            name
            for name in names
            if os.path.isdir(os.path.join(self._rotation_staging_dir, name))
        )

    def list_staging_rotation_ids(self, wallet_id: str) -> list[str]:
        """返回某钱包暂存目录下的全部 rotation_id 目录名。"""
        _check_id("wallet_id", wallet_id)
        base = os.path.join(self._rotation_staging_dir, wallet_id)
        try:
            names = os.listdir(base)
        except (FileNotFoundError, NotADirectoryError):
            return []
        return sorted(
            name for name in names if os.path.isdir(os.path.join(base, name))
        )

    def list_rotation_entries(self, wallet_id: str) -> list[tuple[str, dict]]:
        """返回 (记录键, 记录) 对；记录键即删除时使用的 rotation_id。"""
        _check_id("wallet_id", wallet_id)
        all_records = self._read_json(self._rotations_path(wallet_id))
        if not isinstance(all_records, dict):
            return []
        return [
            (key, record)
            for key, record in all_records.items()
            if isinstance(key, str) and isinstance(record, dict)
        ]

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

    @staticmethod
    def _rotation_record_shape_ok(record: dict) -> bool:
        """轮换记录的基本形状校验（启动恢复判定"无效记录"用）。"""
        rotation_id = record.get("rotation_id")
        if not isinstance(rotation_id, str) or not _SAFE_ID.match(rotation_id):
            return False
        if record.get("state") not in ("prepared", "activating", "active"):
            return False
        share_ids = record.get("share_ids")
        if (
            not isinstance(share_ids, list)
            or len(share_ids) != 2
            or any(
                not isinstance(sid, str) or not _SAFE_SHARE_ID.match(sid)
                for sid in share_ids
            )
        ):
            return False
        public_key = record.get("public_key")
        if not isinstance(public_key, str):
            return False
        try:
            if len(bytes.fromhex(public_key)) != 64:
                return False
        except ValueError:
            return False
        return True

    def _prepared_staging_valid(self, wallet_id: str, record: dict) -> bool:
        """判定 prepared 轮换的暂存目录是否完整有效。

        仅当全部满足时保留：目录名与 rotation_id 一致（由路径构造保证）、
        目录内恰有记录中两个 share_ids 对应的份额文件（无多无缺）、每个
        文件 JSON 可解析、share_id 与记录一致、public_key 恰为 32 字节、
        私钥恰为 32 字节且能推导出该 public_key、两个份额公钥按序拼接
        等于记录中的钱包 public_key。
        """
        rotation_id = record["rotation_id"]
        share_ids = list(record["share_ids"])
        staging = self._staging_dir(wallet_id, rotation_id)
        try:
            names = set(os.listdir(staging))
        except (FileNotFoundError, NotADirectoryError):
            return False
        if names != {sid + ".json" for sid in share_ids}:
            return False
        share_public_keys: list[bytes] = []
        for share_id in share_ids:
            try:
                data = self._read_json(
                    os.path.join(staging, share_id + ".json")
                )
            except (ValueError, OSError):
                # JSON 不可解析 / 读取失败
                return False
            if not isinstance(data, dict) or data.get("share_id") != share_id:
                return False
            public_hex = data.get("public_key")
            private_hex = data.get("private_key")
            if not isinstance(public_hex, str) or not isinstance(
                private_hex, str
            ):
                return False
            try:
                public_bytes = bytes.fromhex(public_hex)
                private_bytes = bytes.fromhex(private_hex)
            except ValueError:
                return False
            if len(public_bytes) != 32 or len(private_bytes) != 32:
                return False
            try:
                if public_key_from_private(private_bytes) != public_bytes:
                    return False
            except ValueError:
                return False
            share_public_keys.append(public_bytes)
        return (
            combine_public_keys(share_public_keys).hex()
            == record["public_key"]
        )

    def recover_wallet_rotation(self, wallet_id: str) -> None:
        """按钱包恢复轮换现场（调用方须持有该钱包的跨进程事务锁）。

        - activating：用备份回滚钱包元数据与旧份额、删除已换入的新份额，
          状态恢复为 prepared，再按 prepared 规则校验暂存；
        - active：激活已提交，删除残留的暂存与备份；
        - prepared：暂存校验通过才保留，否则安全删除记录与暂存目录；
        - 无效记录：安全删除记录及其暂存目录；
        - 孤儿暂存目录（无对应有效 prepared 记录）：安全删除。
        全程不触碰在用钱包的份额文件与元数据（activating 回滚除外），
        被删除的暂存私钥不留任何副本，也不产生审计事件。
        """
        _check_id("wallet_id", wallet_id)
        kept_prepared: set[str] = set()
        for key, record in self.list_rotation_entries(wallet_id):
            rotation_id = record.get("rotation_id")
            try:
                if not self._rotation_record_shape_ok(record):
                    # 无效记录：连记录带暂存一起安全删除
                    self.delete_rotation(wallet_id, key)
                    if isinstance(rotation_id, str) and _SAFE_ID.match(
                        rotation_id
                    ):
                        self.delete_staging(wallet_id, rotation_id)
                    continue
                state = record["state"]
                if state == "activating":
                    self.rollback_activation_files(wallet_id, record)
                    restored = {
                        k: v
                        for k, v in record.items()
                        if k != "previous_public_key"
                    }
                    restored["state"] = "prepared"
                    self.update_rotation(wallet_id, rotation_id, restored)
                    self.delete_activation_backups(wallet_id, rotation_id)
                    record = restored
                    state = "prepared"
                if state == "active":
                    # 崩溃发生在激活提交之后、暂存清理之前
                    self.delete_staging(wallet_id, rotation_id)
                elif state == "prepared":
                    if self._prepared_staging_valid(wallet_id, record):
                        kept_prepared.add(rotation_id)
                    else:
                        # 暂存缺失/损坏/不匹配：记录与残留一起安全删除，
                        # 绝不留下来路不明的私钥副本
                        self.delete_rotation(wallet_id, rotation_id)
                        self.delete_staging(wallet_id, rotation_id)
            except (ValueError, OSError):
                continue
        # 孤儿暂存目录：没有对应有效 prepared 记录的一律安全删除
        for rotation_id in self.list_staging_rotation_ids(wallet_id):
            if rotation_id not in kept_prepared:
                self.delete_staging(wallet_id, rotation_id)

    def recover_incomplete_activations(self) -> None:
        """启动恢复：逐个钱包回滚未完成激活、清理轮换残留，尽力而为。

        注意：本方法不持跨进程锁；多进程共用 data-dir 时应使用
        service 层的加锁编排（见 WalletService 启动恢复）。
        """
        wallet_ids = sorted(
            set(self.list_rotation_wallet_ids())
            | set(self.list_staging_wallet_ids())
        )
        for wallet_id in wallet_ids:
            try:
                self.recover_wallet_rotation(wallet_id)
            except (ValueError, OSError):
                continue
