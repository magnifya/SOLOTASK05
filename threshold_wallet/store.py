"""钱包持久化：只保存份额，磁盘上不存在完整私钥。

磁盘布局（data_dir 下）::

    wallets/<wallet_id>.json        钱包元数据 + 份额公钥（无私钥）
    shares/<wallet_id>/<share_id>.json
                                    单个份额（份额私钥以 hex 保存），一份一个文件
    signatures/<wallet_id>.json     该钱包已完成的签名请求（幂等去重）
    policies/<wallet_id>.json       该钱包的审批策略（required_approvals 等）
    requests/<wallet_id>.json       该钱包的签名请求审批单（状态机）
    rotations/<wallet_id>/<rotation_id>/state.json
                                    份额轮换状态（prepared/activating/active）
    rotations/<wallet_id>/<rotation_id>/<share_id>.json
                                    轮换暂存的新份额（prepared 阶段，一份一文件）
    rotations/<wallet_id>/<rotation_id>/backup/
                                    激活期间旧钱包元数据与旧份额备份（回滚用，
                                    激活成功或回滚完成后删除）
    audit/<wallet_id>.json          该钱包的审计事件日志（seq 从 1 起仅追加，
                                    由 audit.AuditStore 维护）

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

from .crypto import ShareKey

#: wallet_id / signing_request_id / rotation_id 允许的字符（同时杜绝路径穿越）
_SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

#: share_id：除固定的 share-1/share-2 外，轮换产生
#: "<rotation_id>-share-<n>"（rotation_id 最长 128 + 8），放宽到 136
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
        os.makedirs(self._wallets_dir, exist_ok=True)
        os.makedirs(self._shares_dir, exist_ok=True)
        os.makedirs(self._signatures_dir, exist_ok=True)
        os.makedirs(self._policies_dir, exist_ok=True)
        os.makedirs(self._requests_dir, exist_ok=True)
        os.makedirs(self._rotations_dir, exist_ok=True)
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

    # ---- 份额轮换暂存 -----------------------------------------------------

    def _rotation_dir(self, wallet_id: str, rotation_id: str) -> str:
        _check_id("wallet_id", wallet_id)
        _check_id("rotation_id", rotation_id)
        return os.path.join(self._rotations_dir, wallet_id, rotation_id)

    def _rotation_state_path(self, wallet_id: str, rotation_id: str) -> str:
        return os.path.join(
            self._rotation_dir(wallet_id, rotation_id), "state.json"
        )

    def _staged_share_path(
        self, wallet_id: str, rotation_id: str, share_id: str
    ) -> str:
        _check_share_id(share_id)
        return os.path.join(
            self._rotation_dir(wallet_id, rotation_id),
            share_id + ".json",
        )

    def _rotation_backup_dir(self, wallet_id: str, rotation_id: str) -> str:
        return os.path.join(
            self._rotation_dir(wallet_id, rotation_id), "backup"
        )

    def list_rotations(self, wallet_id: str) -> list[dict]:
        """列出钱包磁盘上所有轮换状态记录（启动恢复用）。

        扫描 rotations/<wallet_id>/*/state.json；损坏/缺状态文件的目录
        跳过。返回记录列表（顺序不保证）。
        """
        _check_id("wallet_id", wallet_id)
        base = os.path.join(self._rotations_dir, wallet_id)
        records: list[dict] = []
        try:
            names = os.listdir(base)
        except FileNotFoundError:
            return records
        for name in names:
            path = os.path.join(base, name, "state.json")
            record = self._read_json(path)
            if isinstance(record, dict):
                records.append(record)
        return records

    def list_rotation_wallets(self) -> list[str]:
        """列出磁盘上存在轮换暂存目录的所有 wallet_id（启动恢复用）。"""
        try:
            names = os.listdir(self._rotations_dir)
        except FileNotFoundError:
            return []
        return [
            name
            for name in names
            if not name.startswith(".")
            and os.path.isdir(os.path.join(self._rotations_dir, name))
            and _SAFE_ID.match(name)
        ]

    def list_rotation_dirs(self, wallet_id: str) -> list[str]:
        """列出钱包下所有轮换目录名（含缺失 state.json 的孤儿目录）。"""
        _check_id("wallet_id", wallet_id)
        base = os.path.join(self._rotations_dir, wallet_id)
        try:
            names = os.listdir(base)
        except FileNotFoundError:
            return []
        return [
            name
            for name in names
            if os.path.isdir(os.path.join(base, name))
            and _SAFE_ID.match(name)
        ]

    def rotation_backup_exists(
        self, wallet_id: str, rotation_id: str
    ) -> bool:
        """备份目录中是否有已持久化的 wallet.json（激活已开始的判据）。"""
        return os.path.exists(
            os.path.join(
                self._rotation_backup_dir(wallet_id, rotation_id),
                "wallet.json",
            )
        )

    def save_rotation_state(self, wallet_id: str, record: dict) -> None:
        """原子写入轮换状态文件（prepared/activating/active）。"""
        rotation_id = record["rotation_id"]
        path = self._rotation_state_path(wallet_id, rotation_id)
        with self._lock:
            self._atomic_write(path, record)

    def get_rotation_state(
        self, wallet_id: str, rotation_id: str
    ) -> Optional[dict]:
        """读取一条轮换状态，不存在返回 None。"""
        return self._read_json(
            self._rotation_state_path(wallet_id, rotation_id)
        )

    def delete_rotation_state(self, wallet_id: str, rotation_id: str) -> None:
        """删除整条轮换暂存目录（状态文件 + 暂存份额 + 备份）。"""
        path = self._rotation_dir(wallet_id, rotation_id)
        with self._lock:
            shutil.rmtree(path, ignore_errors=True)

    def save_staged_share(
        self, wallet_id: str, rotation_id: str, share: ShareKey
    ) -> None:
        """把一个新份额（含私钥）写入轮换暂存文件（一份一文件）。"""
        path = self._staged_share_path(wallet_id, rotation_id, share.share_id)
        record = {
            "share_id": share.share_id,
            "public_key": share.public_bytes.hex(),
            # 仅该新份额自己的私钥；暂存目录中同样不存在完整私钥
            "private_key": share.private_bytes.hex(),
        }
        with self._lock:
            self._atomic_write(path, record)

    def get_staged_share(
        self, wallet_id: str, rotation_id: str, share_id: str
    ) -> Optional[dict]:
        """读取暂存的新份额记录（含私钥 hex），不存在返回 None。"""
        return self._read_json(
            self._staged_share_path(wallet_id, rotation_id, share_id)
        )

    # ---- 轮换激活：备份 / 替换 / 回滚 -------------------------------------

    def backup_active_material(
        self, wallet_id: str, rotation_id: str
    ) -> dict:
        """把当前生效的钱包元数据与全部旧份额复制进轮换备份目录。

        每个旧份额仍是一个独立文件（一份一文件，不破坏私钥边界）。
        返回备份前的钱包元数据（含旧 public_key）。调用方须在事务锁内。
        """
        meta_path = self._wallet_path(wallet_id)
        with self._lock:
            meta = self._read_json(meta_path)
            if meta is None:
                raise FileNotFoundError(meta_path)
            backup_dir = self._rotation_backup_dir(wallet_id, rotation_id)
            shares_backup = os.path.join(backup_dir, "shares")
            os.makedirs(shares_backup, exist_ok=True)
            for old in meta["shares"]:
                old_record = self._read_json(
                    self._share_path(wallet_id, old["share_id"])
                )
                self._atomic_write(
                    os.path.join(
                        shares_backup, old["share_id"] + ".json"
                    ),
                    old_record,
                )
            self._atomic_write(
                os.path.join(backup_dir, "wallet.json"), meta
            )
            return meta

    def commit_rotated_shares(
        self,
        wallet_id: str,
        rotation_id: str,
        staged_share_ids: list[str],
        new_public_key: str,
    ) -> list[str]:
        """锁内把暂存的新份额安装为生效份额并替换钱包公钥。

        顺序：先写两份新份额文件 -> 原子替换钱包元数据 -> 删除旧份额
        文件。崩溃后由 backup/ 目录在启动时回滚。返回被删除的旧
        share_id 列表。调用方须在每钱包事务锁内。
        """
        meta_path = self._wallet_path(wallet_id)
        with self._lock:
            old_meta = self._read_json(meta_path)
            if old_meta is None:
                raise FileNotFoundError(meta_path)
            old_share_ids = [s["share_id"] for s in old_meta["shares"]]
            new_shares = []
            for sid in staged_share_ids:
                staged = self._read_json(
                    self._staged_share_path(wallet_id, rotation_id, sid)
                )
                if staged is None:
                    raise FileNotFoundError(
                        self._staged_share_path(wallet_id, rotation_id, sid)
                    )
                target = self._share_path(wallet_id, sid)
                self._atomic_write(target, staged)
                new_shares.append(
                    {"share_id": sid, "public_key": staged["public_key"]}
                )
            new_meta = dict(old_meta)
            new_meta["public_key"] = new_public_key
            new_meta["shares"] = new_shares
            self._atomic_write(meta_path, new_meta)
            for sid in old_share_ids:
                try:
                    os.unlink(self._share_path(wallet_id, sid))
                except FileNotFoundError:
                    pass
            return old_share_ids

    def restore_active_material(
        self, wallet_id: str, rotation_id: str
    ) -> bool:
        """从备份恢复旧钱包元数据与旧份额文件（激活失败/启动回滚用）。

        还会删除安装到一半的新份额文件（以暂存目录中的份额 id 为准，
        无论钱包元数据是否已替换），使磁盘上每个私钥只出现一次。
        无备份目录时不动任何文件并返回 False；恢复完成返回 True。
        """
        rotation_dir = self._rotation_dir(wallet_id, rotation_id)
        backup_dir = self._rotation_backup_dir(wallet_id, rotation_id)
        with self._lock:
            backup_meta = self._read_json(
                os.path.join(backup_dir, "wallet.json")
            )
            if backup_meta is None:
                return False
            # 暂存目录中的份额即本次试图安装的新份额
            staged_ids = set()
            try:
                names = os.listdir(rotation_dir)
            except FileNotFoundError:
                names = []
            for name in names:
                if name.endswith(".json") and name != "state.json":
                    staged_ids.add(name[: -len(".json")])
            shares_backup = os.path.join(backup_dir, "shares")
            try:
                backup_names = os.listdir(shares_backup)
            except FileNotFoundError:
                backup_names = []
            for name in backup_names:
                record = self._read_json(os.path.join(shares_backup, name))
                if not isinstance(record, dict):
                    continue
                self._atomic_write(
                    self._share_path(wallet_id, record["share_id"]), record
                )
            # 删除安装到一半的新份额文件（旧 id 已由备份覆盖恢复）
            for sid in staged_ids:
                if sid not in {
                    s["share_id"] for s in backup_meta.get("shares", [])
                }:
                    try:
                        os.unlink(self._share_path(wallet_id, sid))
                    except FileNotFoundError:
                        pass
            self._atomic_write(
                self._wallet_path(wallet_id), backup_meta
            )
            return True

    def discard_rotation_backup(self, wallet_id: str, rotation_id: str) -> None:
        """删除激活备份目录（激活成功或回滚后清理用）。"""
        backup_dir = self._rotation_backup_dir(wallet_id, rotation_id)
        with self._lock:
            shutil.rmtree(backup_dir, ignore_errors=True)

    def discard_staged_shares(
        self, wallet_id: str, rotation_id: str
    ) -> None:
        """删除暂存的新份额私钥文件（激活成功后：私钥只留生效处一份）。"""
        rotation_dir = self._rotation_dir(wallet_id, rotation_id)
        with self._lock:
            try:
                names = os.listdir(rotation_dir)
            except FileNotFoundError:
                return
            for name in names:
                if name.endswith(".json") and name != "state.json":
                    try:
                        os.unlink(os.path.join(rotation_dir, name))
                    except FileNotFoundError:
                        pass
