"""兼容灾备：单钱包快照备份与恢复（CLI 本地命令，不经 HTTP）。

- ``backup``：持有钱包事务锁，先把轮换现场、资产提交意图、签名会话全部
  恢复对账到一致静止状态，再只打包该钱包白名单内的文件；生成 v1
  manifest（wallet_id、snapshot_id 及每项 path/bytes/sha256）。
- ``restore``：锁内严格校验备份身份、白名单、哈希、形状、公私钥对应、
  审计 seq、账本/会话/轮换一致性，全部通过才以事务方式换入；失败不写
  业务文件。同快照同内容幂等，不同内容冲突。

备份与恢复都不新增审计事件；任何响应、日志、清单都不泄露份额私钥或
签名载荷（清单只记录路径、字节数与 SHA-256）。

备份文件为（非压缩）tar：首个成员是 ``manifest.json``，其余成员路径
与 manifest.files[].path 一一对应，全部是相对 POSIX 路径。
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import stat
import tarfile
import tempfile
from typing import Optional

from .store import (
    CorruptDataError,
    RecoveryError,
    WalletStore,
    _SAFE_ID,
    _SAFE_SHARE_ID,
    parse_utc_iso,
)

#: manifest 格式版本
MANIFEST_VERSION = 1

#: snapshot_id 允许的字符（与 wallet_id 等安全标识一致，杜绝路径穿越）
SNAPSHOT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

#: tar 内 manifest 成员名
MANIFEST_NAME = "manifest.json"

#: 单个打包文件的大小上限（业务文件均很小；审计日志也远小于此），
#: 超出视为数据目录被篡改/损坏，拒绝打包，避免内存被异常文件拖垮。
MAX_FILE_BYTES = 64 * 1024 * 1024

#: 白名单根（成员目录名, 是否递归整棵 W 子树）。顺序即 manifest 排序。
#: 仅这些 README 磁盘布局中属于单个钱包的文件会进入备份；locks/ 等
#: 运行期文件与其他钱包的数据一律不打包。
_WHITELIST_ROOTS: tuple[tuple[str, bool], ...] = (
    ("wallets", False),
    ("shares", True),
    ("signatures", False),
    ("policies", False),
    ("requests", False),
    ("rotations", False),
    ("rotation-staging", True),
    ("audit", False),
    ("assets", False),
    ("asset-intents", True),
    ("transaction-policies", False),
    ("sign-sessions", False),
)


class BackupError(Exception):
    """灾备错误，携带对外状态码与不含敏感信息的错误文案。"""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def validate_snapshot_id(value: object) -> str:
    """校验 snapshot_id 匹配 [A-Za-z0-9_-]{1,128}；非法抛 BackupError(400)。"""
    if not isinstance(value, str) or not SNAPSHOT_ID_RE.match(value):
        raise BackupError(400, "invalid snapshot_id")
    return value


def _safe_rel_name(parts: list[str]) -> bool:
    """归档内相对路径的每个分量都必须是安全标识；文件名恰为
    ``<安全标识>.json``（share_id 允许最长 136），目录名为安全标识。
    由此天然拒绝绝对路径、``..``、隐藏/临时/锁/备份文件与任何额外文件。"""
    if not parts:
        return False
    for index, part in enumerate(parts):
        if part in ("", ".", "..") or "/" in part or "\\" in part or "\x00" in part:
            return False
        if index < len(parts) - 1:
            if not _SAFE_ID.match(part):
                return False
        else:
            stem, dot, suffix = part.rpartition(".")
            if not dot or suffix != "json" or not _SAFE_SHARE_ID.match(stem):
                return False
    return True


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(obj: object) -> bytes:
    """规范化 JSON 字节：manifest 内容哈希与幂等判定的唯一序列化方式。"""
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _whitelist_files(data_dir: str, wallet_id: str) -> list[tuple[str, str]]:
    """枚举白名单内属于该钱包的全部常规文件，返回 (绝对路径, 归档相对
    路径) 列表，按归档路径排序。

    拒绝任何符号链接（含指向目录的链接）、非常规文件、非白名单命名的
    额外文件、重复归档路径。持钱包事务锁调用：现场已恢复静止，白名单
    树内出现任何意料之外的条目都说明数据目录被外部篡改，fail-closed。
    """
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    for root_name, recursive in _WHITELIST_ROOTS:
        if recursive:
            base = os.path.join(data_dir, root_name, wallet_id)
            if not os.path.exists(base) and not os.path.islink(base):
                continue
            if os.path.islink(base):
                raise BackupError(503, "refusing to back up a symlinked path")
            for current, dirnames, filenames in os.walk(base):
                # followlinks=False 仍会把目录符号链接列进 dirnames：
                # 显式拒绝，绝不跟随。
                for d in list(dirnames):
                    if os.path.islink(os.path.join(current, d)):
                        raise BackupError(
                            503, "refusing to back up a symlinked path"
                        )
                for name in filenames:
                    abs_path = os.path.join(current, name)
                    rel = os.path.relpath(abs_path, data_dir)
                    parts = rel.split(os.sep)
                    if os.path.islink(abs_path) or not _safe_rel_name(parts):
                        raise BackupError(
                            503, "unexpected file in wallet data directory"
                        )
                    if rel in seen:
                        raise BackupError(503, "duplicate backup entry")
                    seen.add(rel)
                    found.append((abs_path, rel))
        else:
            abs_path = os.path.join(
                data_dir, root_name, wallet_id + ".json"
            )
            if os.path.exists(abs_path) or os.path.islink(abs_path):
                if os.path.islink(abs_path):
                    raise BackupError(
                        503, "refusing to back up a symlinked path"
                    )
                rel = f"{root_name}/{wallet_id}.json"
                if rel in seen:
                    raise BackupError(503, "duplicate backup entry")
                seen.add(rel)
                found.append((abs_path, rel))
    found.sort(key=lambda item: item[1])
    return found


def _read_regular_file(path: str) -> bytes:
    """读取白名单常规文件；符号链接、非常规文件或超过上限一律拒绝。"""
    st = os.lstat(path)

    if not stat.S_ISREG(st.st_mode):
        raise BackupError(503, "unexpected file in wallet data directory")
    if st.st_size > MAX_FILE_BYTES:
        raise BackupError(503, "wallet data file is too large to back up")
    with open(path, "rb") as f:
        data = f.read()
    if len(data) != st.st_size or len(data) > MAX_FILE_BYTES:
        raise BackupError(503, "wallet data file changed during backup")
    return data


def build_manifest(
    wallet_id: str, snapshot_id: str, entries: list[tuple[str, bytes]]
) -> dict:
    """根据 (归档相对路径, 文件内容) 列表构造 v1 manifest。

    snapshot_id 直接进入 manifest 并参与 manifest 自身哈希，使快照标识
    与清单内容绑定：任何对 S 或条目内容的篡改都会改变 manifest 哈希。
    """
    files = []
    for rel, data in entries:
        files.append(
            {
                "path": rel,
                "bytes": len(data),
                "sha256": _sha256_hex(data),
            }
        )
    return {
        "version": MANIFEST_VERSION,
        "wallet_id": wallet_id,
        "snapshot_id": snapshot_id,
        "files": files,
    }


def manifest_hash(manifest: dict) -> str:
    """manifest 的规范化 SHA-256（restore-records 记录与幂等判定用）。"""
    return _sha256_hex(_canonical_json(manifest))


def _write_backup_file(
    output_path: str, manifest: dict, entries: list[tuple[str, bytes]]
) -> None:
    """原子地写出 tar 备份：manifest.json 为首成员，随后按清单写各文件。

    写到输出文件同目录的临时文件再 os.replace：失败不留半截备份。
    """
    directory = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        dir=directory, prefix=".tmp-backup-", suffix=".tar"
    )
    try:
        with os.fdopen(fd, "wb") as raw:
            with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
                manifest_bytes = _canonical_json(manifest) + b"\n"
                info = tarfile.TarInfo(MANIFEST_NAME)
                info.size = len(manifest_bytes)
                info.mode = 0o600
                tar.addfile(info, io.BytesIO(manifest_bytes))
                for rel, data in entries:
                    info = tarfile.TarInfo(rel)
                    info.size = len(data)
                    info.mode = 0o600
                    tar.addfile(info, io.BytesIO(data))
        os.replace(tmp_path, output_path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise


def _assert_static_layout(
    store: WalletStore, wallet_id: str, wallet: dict
) -> None:
    """恢复静止后，白名单树内各目录的"额外文件"不变量校验。

    服务正常写出且恢复对账完成后：

    - ``shares/W/`` 恰有钱包元数据中当前在用两份份额，无任何第三份；
    - ``rotation-staging/W/<rid>/`` 与每条 prepared 轮换一一对应，目录内
      恰有该记录两个 share_ids 的新份额文件（备份在恢复后已不存在）；
    - ``asset-intents/W/`` 不存在或为空（提交意图只在事务窗口内存活）。

    任何多余条目都属于白名单形状之外的"额外文件"，拒绝打包（503）。
    """
    expected_share_ids = [
        entry.get("share_id")
        for entry in wallet.get("shares", [])
        if isinstance(entry, dict)
    ]
    if (
        len(expected_share_ids) != 2
        or len(set(expected_share_ids)) != 2
        or not all(isinstance(sid, str) for sid in expected_share_ids)
    ):
        raise BackupError(503, "wallet metadata shares are malformed")
    actual_share_ids = set(store.list_share_files(wallet_id))
    if actual_share_ids != set(expected_share_ids):
        raise BackupError(503, "unexpected share files in wallet directory")

    # prepared 轮换记录与暂存目录必须一一对应、内容恰为两份新份额；
    # active 记录（恢复已保证其激活事件在）必须已清空暂存；activating
    # 在恢复后不应存在（未提交激活会被回滚为 prepared）。
    staging_root = os.path.join(store.data_dir, "rotation-staging", wallet_id)
    staging_on_disk = set(store.list_staging_rotation_ids(wallet_id))
    prepared: dict[str, dict] = {}
    for record in store.list_rotations(wallet_id):
        rid = record.get("rotation_id")
        state = record.get("state")
        if state == "prepared":
            if not isinstance(rid, str):
                raise BackupError(503, "malformed rotation record")
            if rid in staging_on_disk:
                prepared[rid] = record
            else:
                raise BackupError(503, "rotation scene is not quiescent")
        elif state == "active":
            if isinstance(rid, str) and rid in staging_on_disk:
                raise BackupError(503, "rotation scene is not quiescent")
        else:
            raise BackupError(503, "rotation scene is not quiescent")
    if staging_on_disk != set(prepared):
        raise BackupError(503, "unexpected rotation staging directory")
    for rid, record in prepared.items():
        staging_dir = os.path.join(staging_root, rid)
        try:
            names = set(os.listdir(staging_dir))
        except OSError:
            raise BackupError(503, "cannot read rotation staging directory")
        expected_names = {
            sid + ".json"
            for sid in record.get("share_ids", [])
            if isinstance(sid, str)
        }
        if names != expected_names:
            raise BackupError(503, "unexpected files in rotation staging directory")

    # 提交意图在恢复后必须清零；目录下不得残留任何文件。
    for _op_id, intent in store.list_asset_intents(wallet_id):
        # list_asset_intents 只返回 *.json；恢复后出现任何条目都说明
        # 存在未完成提交现场（损坏意图恢复会直接抛错，不会静默列出）。
        raise BackupError(503, "asset commit scene is not quiescent")


def create_backup(
    data_dir: str, wallet_id: str, snapshot_id: str, output_path: str
) -> dict:
    """创建单钱包快照备份，返回成功响应体（不含 status 字段）。

    流程：参数校验 → 持该钱包跨进程事务锁 → 构造服务并做全量恢复对账
    （轮换、资产意图、会话；不能对账即失败）→ 确认钱包存在 → 枚举并
    读取白名单文件（拒绝链接/额外/锁/临时文件）→ 构造 v1 manifest 并
    原子写出 tar。任何失败都不产生半截备份。
    """
    if not isinstance(wallet_id, str) or not _SAFE_ID.match(wallet_id):
        raise BackupError(400, "invalid wallet_id")
    validate_snapshot_id(snapshot_id)
    if not isinstance(output_path, str) or not output_path:
        raise BackupError(400, "invalid output path")
    # 备份文件不得写入 data-dir 内部：避免覆盖白名单业务文件或把备份
    # 当成数据目录的一部分再次打包/恢复。
    try:
        data_root = os.path.abspath(data_dir)
        out_abs = os.path.abspath(output_path)
        if os.path.commonpath([data_root, out_abs]) == data_root:
            raise BackupError(400, "backup output must not be inside the data dir")
    except ValueError:
        # Windows 跨盘符等情况下 commonpath 抛 ValueError：路径不在同一根，
        # 不可能落在 data-dir 内，放行。
        pass

    store = WalletStore(data_dir)
    # 延迟导入避免 service <-> backup 循环依赖。
    from .service import WalletService

    # WalletService 构造即完成全部钱包的启动恢复；目标钱包的锁内对账在
    # 下方显式进行，保证打包看到的是静止一致现场。
    try:
        service = WalletService(store)
    except RecoveryError:
        raise BackupError(503, "recovery failed, refusing to back up")
    except OSError:
        raise BackupError(503, "cannot open data dir, refusing to back up")
    except (CorruptDataError, ValueError):
        raise BackupError(503, "data directory is corrupt, refusing to back up")

    with service._wallet_lock(wallet_id):
        try:
            # 与常驻请求完全相同的持锁自愈/对账：轮换 → 资产意图 → 账本 ↔
            # 事件 → 签名会话。不能对账即 fail-closed，绝不打包半状态。
            service._recover_wallet(wallet_id)
            wallet = store.get_wallet(wallet_id)
        except RecoveryError:
            raise BackupError(
                503, "wallet cannot be reconciled, refusing to back up"
            )
        except (CorruptDataError, ValueError):
            raise BackupError(
                503, "wallet data is corrupt, refusing to back up"
            )
        except OSError:
            raise BackupError(503, "cannot read wallet data, refusing to back up")
        if not isinstance(wallet, dict):
            raise BackupError(404, f"wallet {wallet_id!r} not found")

        # 静止现场的额外文件不变量（shares/W/ 恰两份、staging 与 prepared
        # 一一对应且恰两份新份额、意图清零）。
        _assert_static_layout(store, wallet_id, wallet)

        paths = _whitelist_files(data_dir, wallet_id)
        entries: list[tuple[str, bytes]] = []
        for abs_path, rel in paths:
            try:
                entries.append((rel, _read_regular_file(abs_path)))
            except OSError:
                raise BackupError(503, "cannot read wallet data, refusing to back up")

        manifest = build_manifest(wallet_id, snapshot_id, entries)
        try:
            _write_backup_file(output_path, manifest, entries)
        except OSError:
            raise BackupError(503, "cannot write backup file")

    # 响应只含标识与清单（路径/字节数/哈希），绝不含私钥或签名载荷。
    return {
        "wallet_id": wallet_id,
        "snapshot_id": snapshot_id,
        "manifest": manifest,
        "manifest_sha256": manifest_hash(manifest),
    }


#: 恢复事务工作区根（data_dir 下，不在备份白名单内）
RESTORE_TXN_DIRNAME = "restore-txn"

#: 已完成恢复记录根：restore-records/<wallet_id>.json
RESTORE_RECORDS_DIRNAME = "restore-records"

#: 恢复事务提交标记文件名（位于 restore-txn/W/S/ 下）
COMMIT_MARKER_NAME = "commit.json"

_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_NON_RECURSIVE_ROOTS = {name for name, recursive in _WHITELIST_ROOTS if not recursive}
_RECURSIVE_ROOTS = {name for name, recursive in _WHITELIST_ROOTS if recursive}


def _restore_records_path(data_dir: str, wallet_id: str) -> str:
    return os.path.join(
        data_dir, RESTORE_RECORDS_DIRNAME, wallet_id + ".json"
    )


def load_restore_records(data_dir: str, wallet_id: str) -> dict:
    """读取并严格校验 restore-records/W.json；不存在返回空记录。

    记录形如 ``{"wallet_id": W, "snapshots": {S: {snapshot_id,
    manifest_sha256, restored_at}}}``：只记录快照标识与 manifest 哈希，
    不复制清单全文。文件存在但 JSON 损坏、形状非法、wallet_id 不匹配、
    条目字段非法时抛 BackupError(503)：绝不忽略或重置恢复历史（否则
    幂等/冲突判定将失效）。
    """
    path = _restore_records_path(data_dir, wallet_id)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {"wallet_id": wallet_id, "snapshots": {}}
    except (ValueError, OSError) as exc:
        raise BackupError(503, "restore records are unreadable") from exc
    if not isinstance(data, dict) or data.get("wallet_id") != wallet_id:
        raise BackupError(503, "restore records are malformed")
    snapshots = data.get("snapshots")
    if not isinstance(snapshots, dict):
        raise BackupError(503, "restore records are malformed")
    for key, entry in snapshots.items():
        if not SNAPSHOT_ID_RE.match(key) or not isinstance(entry, dict):
            raise BackupError(503, "restore records are malformed")
        if set(entry) != {"snapshot_id", "manifest_sha256", "restored_at"}:
            raise BackupError(503, "restore records are malformed")
        if entry.get("snapshot_id") != key:
            raise BackupError(503, "restore records are malformed")
        manifest_hash_hex = entry.get("manifest_sha256")
        if not isinstance(manifest_hash_hex, str) or not _SHA256_HEX_RE.match(
            manifest_hash_hex
        ):
            raise BackupError(503, "restore records are malformed")
        if not isinstance(entry.get("restored_at"), str):
            raise BackupError(503, "restore records are malformed")
    return data


def save_restore_records(data_dir: str, wallet_id: str, records: dict) -> None:
    """原子覆盖 restore-records/W.json（临时文件 + os.replace）。"""
    WalletStore._atomic_write(
        _restore_records_path(data_dir, wallet_id), records
    )


def _whitelist_path_shape(parts: list[str], wallet_id: str) -> bool:
    """归档成员路径是否恰为该钱包白名单布局：

    - 非递归根：``<root>/<wallet_id>.json``；
    - 递归根 shares/asset-intents：``<root>/<wallet_id>/<id>.json``；
    - rotation-staging：``rotation-staging/<wallet_id>/<rid>/<id>.json``。

    各分量的安全标识检查由 _safe_rel_name 完成；这里额外限定根、层级
    深度与钱包分量必须等于目标 wallet_id。
    """
    if not _safe_rel_name(parts):
        return False
    root = parts[0]
    if root in _NON_RECURSIVE_ROOTS and len(parts) == 2:
        stem = parts[1][: -len(".json")]
        return stem == wallet_id
    if root in _RECURSIVE_ROOTS and len(parts) >= 3:
        if parts[1] != wallet_id:
            return False
        if root == "rotation-staging":
            return len(parts) == 4
        return len(parts) == 3
    return False


def _validate_manifest_shape(
    manifest: object, wallet_id: str
) -> tuple[str, list[dict]]:
    """严格校验 manifest 形状与身份；返回 (snapshot_id, files)。"""
    if not isinstance(manifest, dict):
        raise BackupError(503, "backup manifest is malformed")
    if manifest.get("version") != MANIFEST_VERSION:
        raise BackupError(503, "unsupported backup manifest version")
    if manifest.get("wallet_id") != wallet_id:
        raise BackupError(503, "backup wallet identity mismatch")
    snapshot_id = manifest.get("snapshot_id")
    if not isinstance(snapshot_id, str) or not SNAPSHOT_ID_RE.match(
        snapshot_id
    ):
        raise BackupError(503, "backup manifest is malformed")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise BackupError(503, "backup manifest is malformed")
    seen: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict):
            raise BackupError(503, "backup manifest is malformed")
        rel = entry.get("path")
        if not isinstance(rel, str) or rel in seen:
            raise BackupError(503, "backup manifest is malformed")
        seen.add(rel)
        parts = rel.split("/")
        if not _whitelist_path_shape(parts, wallet_id):
            raise BackupError(503, "backup contains a non-whitelisted path")
        size = entry.get("bytes")
        digest = entry.get("sha256")
        if not isinstance(size, int) or isinstance(size, bool) or not (
            0 <= size <= MAX_FILE_BYTES
        ):
            raise BackupError(503, "backup manifest is malformed")
        if not isinstance(digest, str) or not _SHA256_HEX_RE.match(digest):
            raise BackupError(503, "backup manifest is malformed")
    if f"wallets/{wallet_id}.json" not in seen:
        # 钱包元数据是恢复身份与公钥链的锚点，缺失即不可恢复
        raise BackupError(503, "backup is missing the wallet metadata file")
    return snapshot_id, files


def read_backup_archive(
    input_path: str, wallet_id: str
) -> tuple[dict, dict[str, bytes]]:
    """严格读取并校验备份 tar（锁外只读，绝不向 data_dir 写任何内容）。

    校验：输入为常规非链接文件；tar 为非压缩 USTAR；首个成员恰为
    manifest.json；其余成员全部是白名单内该钱包的常规文件，无绝对/
    ``..``/重复/额外成员、无目录/链接/设备；成员集合、字节数、SHA-256
    与 manifest 完全一致。任何损坏或不一致抛 BackupError(503)。

    返回 (manifest, {归档相对路径: 文件字节})。
    """
    if not isinstance(input_path, str) or not input_path:
        raise BackupError(400, "invalid input path")

    try:
        st = os.lstat(input_path)
    except OSError as exc:
        raise BackupError(503, "cannot read backup file")
    if not stat.S_ISREG(st.st_mode):
        raise BackupError(503, "backup input is not a regular file")
    if st.st_size > MAX_FILE_BYTES * 128:
        raise BackupError(503, "backup is too large")
    try:
        with open(input_path, "rb") as f:
            raw = f.read()
    except OSError as exc:
        raise BackupError(503, "cannot read backup file")

    manifest: Optional[dict] = None
    members: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
            first = True
            for info in tar:
                if first:
                    if info.name != MANIFEST_NAME or not info.isfile():
                        raise BackupError(
                            503, "backup must begin with a regular manifest.json"
                        )
                    handle = tar.extractfile(info)
                    if handle is None:
                        raise BackupError(503, "backup manifest is unreadable")
                    with handle:
                        manifest_bytes = handle.read(MAX_FILE_BYTES + 1)
                    try:
                        manifest = json.loads(manifest_bytes.decode("utf-8"))
                    except (ValueError, UnicodeDecodeError) as exc:
                        raise BackupError(503, "backup manifest is malformed") from exc
                    first = False
                    continue
                if not info.isfile():
                    raise BackupError(503, "backup contains a non-regular member")
                rel = info.name
                if os.path.isabs(rel) or rel in members:
                    raise BackupError(503, "backup contains an invalid member")
                parts = rel.split("/")
                if not _whitelist_path_shape(parts, wallet_id):
                    raise BackupError(
                        503, "backup contains a non-whitelisted path"
                    )
                if info.size < 0 or info.size > MAX_FILE_BYTES:
                    raise BackupError(503, "backup member is too large")
                handle = tar.extractfile(info)
                if handle is None:
                    raise BackupError(503, "backup member is unreadable")
                with handle:
                    data = handle.read(MAX_FILE_BYTES + 1)
                if len(data) > MAX_FILE_BYTES:
                    raise BackupError(503, "backup member is too large")
                members[rel] = data
    except tarfile.TarError as exc:
        raise BackupError(503, "backup archive is corrupt") from exc
    if manifest is None:
        raise BackupError(503, "backup is missing manifest.json")

    snapshot_id, files = _validate_manifest_shape(manifest, wallet_id)
    if set(members) != {entry["path"] for entry in files}:
        raise BackupError(503, "backup members do not match its manifest")
    for entry in files:
        data = members[entry["path"]]
        if len(data) != entry["bytes"] or _sha256_hex(data) != entry["sha256"]:
            raise BackupError(503, "backup content does not match its manifest")
    return manifest, members


def list_restore_txn_wallet_ids(data_dir: str) -> list[str]:
    """列出存在未结清恢复事务工作区的全部 wallet_id（启动恢复扫描用）。"""
    base = os.path.join(data_dir, RESTORE_TXN_DIRNAME)
    try:
        names = os.listdir(base)
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise RecoveryError("restore workspace root is unreadable") from exc
    return sorted(
        name
        for name in names
        if _SAFE_ID.match(name)
        and os.path.isdir(os.path.join(base, name))
        and not os.path.islink(os.path.join(base, name))
    )


def _txn_dir(data_dir: str, wallet_id: str, snapshot_id: str) -> str:
    return os.path.join(
        data_dir, RESTORE_TXN_DIRNAME, wallet_id, snapshot_id
    )


def _atomic_write_bytes(path: str, data: bytes) -> None:
    """同目录临时文件 + os.replace 原子写出二进制内容（0o600）。"""

    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        dir=directory, prefix=".tmp-", suffix=".bin"
    )
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise


def _materialize_staging(
    staging_dir: str, members: dict[str, bytes]
) -> None:
    """把备份成员按 data-dir 相对布局写入暂存区（每文件原子替换）。"""
    for rel, data in members.items():
        path = os.path.join(staging_dir, *rel.split("/"))
        _atomic_write_bytes(path, data)


def _walk_wallet_files(
    root_dir: str, wallet_id: str
) -> list[tuple[str, bytes]]:
    """枚举某根目录下该钱包白名单布局的全部常规文件，返回 (rel, data)。

    与备份打包同样严格：拒绝符号链接、非常规文件与非白名单命名。
    """
    found: list[tuple[str, bytes]] = []
    for root_name, recursive in _WHITELIST_ROOTS:
        if recursive:
            base = os.path.join(root_dir, root_name, wallet_id)
            if not os.path.exists(base) and not os.path.islink(base):
                continue
            if os.path.islink(base):
                raise BackupError(503, "refusing a symlinked path")
            for current, dirnames, filenames in os.walk(base):
                for d in list(dirnames):
                    if os.path.islink(os.path.join(current, d)):
                        raise BackupError(503, "refusing a symlinked path")
                for name in filenames:
                    abs_path = os.path.join(current, name)
                    rel = os.path.relpath(abs_path, root_dir)
                    parts = rel.split(os.sep)
                    if os.path.islink(abs_path) or not _safe_rel_name(parts):
                        raise BackupError(
                            503, "unexpected file in wallet data directory"
                        )
                    found.append((rel, _read_regular_file(abs_path)))
        else:
            abs_path = os.path.join(root_dir, root_name, wallet_id + ".json")
            if os.path.exists(abs_path) or os.path.islink(abs_path):
                if os.path.islink(abs_path):
                    raise BackupError(503, "refusing a symlinked path")
                rel = f"{root_name}/{wallet_id}.json"
                found.append((rel, _read_regular_file(abs_path)))
    found.sort(key=lambda item: item[0])
    return found


def _parse_json_member(name: str, data: bytes) -> object:
    try:
        return json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise BackupError(503, f"backup member {name!r} is not valid JSON") from exc


def _validate_requests_ledger(wallet_id: str, data: bytes) -> None:
    """审批单文件形状校验（恢复对账不读它，备份恢复需独立 fail-closed）。"""
    ledger = _parse_json_member("requests", data)
    if not isinstance(ledger, dict):
        raise BackupError(503, "requests backup is malformed")
    for key, record in ledger.items():
        if not _SAFE_ID.match(key) or not isinstance(record, dict):
            raise BackupError(503, "requests backup is malformed")
        if set(record) != {
            "id", "message", "state", "approvers", "req", "t0", "t1", "reason"
        }:
            raise BackupError(503, "requests backup is malformed")
        if record.get("id") != key:
            raise BackupError(503, "requests backup is malformed")
        if not isinstance(record.get("message"), str):
            raise BackupError(503, "requests backup is malformed")
        if record.get("state") not in (
            "pending", "approved", "rejected", "expired", "signed"
        ):
            raise BackupError(503, "requests backup is malformed")
        approvers = record.get("approvers")
        if not isinstance(approvers, list) or not all(
            isinstance(a, str) and a for a in approvers
        ):
            raise BackupError(503, "requests backup is malformed")
        req = record.get("req")
        if not isinstance(req, int) or isinstance(req, bool) or req not in (1, 2):
            raise BackupError(503, "requests backup is malformed")
        # count 是查询视图动态计算的（len(approvers)），不落盘
        for field in ("t0", "t1"):
            if parse_utc_iso(record.get(field)) is None:
                raise BackupError(503, "requests backup is malformed")
        reason = record.get("reason")
        if reason is not None and not isinstance(reason, str):
            raise BackupError(503, "requests backup is malformed")


def _validate_wallet_and_shares(
    wallet_id: str, members: dict[str, bytes]
) -> dict:
    """钱包元数据与全部份额的密码学一致性校验。

    - wallets/W.json 形状、身份与 64 字节公钥；
    - 每份在用份额（含暂存新份额）私钥恰 32 字节且推导出记录公钥；
    - 钱包 shares 恰两份、公钥按序拼接等于钱包公钥；shares/W/ 下恰有
      这两份文件（无第三份）。
    返回钱包元数据。
    """
    from .crypto import combine_public_keys, public_key_from_private

    meta = _parse_json_member(
        f"wallets/{wallet_id}.json", members[f"wallets/{wallet_id}.json"]
    )
    if not isinstance(meta, dict):
        raise BackupError(503, "wallet metadata backup is malformed")
    if meta.get("wallet_id") != wallet_id:
        raise BackupError(503, "backup wallet identity mismatch")
    if parse_utc_iso(meta.get("created_at")) is None:
        raise BackupError(503, "wallet metadata backup is malformed")
    shares = meta.get("shares")
    if not isinstance(shares, list) or len(shares) != 2:
        raise BackupError(503, "wallet metadata backup is malformed")
    tail_ids: list[str] = []
    tail_pubs: list[bytes] = []
    for entry in shares:
        if not isinstance(entry, dict):
            raise BackupError(503, "wallet metadata backup is malformed")
        sid = entry.get("share_id")
        if not isinstance(sid, str) or not _SAFE_SHARE_ID.match(sid):
            raise BackupError(503, "wallet metadata backup is malformed")
        try:
            pub = bytes.fromhex(entry.get("public_key", ""))
        except ValueError:
            raise BackupError(503, "wallet metadata backup is malformed")
        if len(pub) != 32:
            raise BackupError(503, "wallet metadata backup is malformed")
        tail_ids.append(sid)
        tail_pubs.append(pub)
    if len(set(tail_ids)) != 2:
        raise BackupError(503, "wallet metadata backup is malformed")
    try:
        wallet_pub = bytes.fromhex(meta.get("public_key", ""))
    except ValueError:
        raise BackupError(503, "wallet metadata backup is malformed")
    if len(wallet_pub) != 64 or combine_public_keys(tail_pubs) != wallet_pub:
        raise BackupError(503, "wallet public key does not match its shares")

    share_files = {
        rel: data
        for rel, data in members.items()
        if rel.startswith(f"shares/{wallet_id}/")
    }
    if set(share_files) != {f"shares/{wallet_id}/{sid}.json" for sid in tail_ids}:
        raise BackupError(503, "share files do not match the wallet metadata")
    for rel, data in share_files.items():
        record = _parse_json_member(rel, data)
        if not isinstance(record, dict):
            raise BackupError(503, "share backup is malformed")
        sid = record.get("share_id")
        if sid not in tail_ids:
            raise BackupError(503, "share backup has an unexpected share_id")
        try:
            pub = bytes.fromhex(record.get("public_key", ""))
            priv = bytes.fromhex(record.get("private_key", ""))
        except ValueError:
            raise BackupError(503, "share backup is malformed")
        if len(pub) != 32 or len(priv) != 32:
            raise BackupError(503, "share backup is malformed")
        try:
            if public_key_from_private(priv) != pub:
                raise BackupError(503, "share private key does not match its public key")
        except ValueError:
            raise BackupError(503, "share private key is invalid")
        if pub != tail_pubs[tail_ids.index(sid)]:
            raise BackupError(503, "share public key is not the wallet's in-use key")

    # rotation-staging 内的暂存新份额同样逐份密码学校验。
    for rel, data in members.items():
        if not rel.startswith("rotation-staging/"):
            continue
        record = _parse_json_member(rel, data)
        if not isinstance(record, dict):
            raise BackupError(503, "staged share backup is malformed")
        try:
            pub = bytes.fromhex(record.get("public_key", ""))
            priv = bytes.fromhex(record.get("private_key", ""))
        except ValueError:
            raise BackupError(503, "staged share backup is malformed")
        if len(pub) != 32 or len(priv) != 32:
            raise BackupError(503, "staged share backup is malformed")
        try:
            if public_key_from_private(priv) != pub:
                raise BackupError(503, "staged share key mismatch")
        except ValueError:
            raise BackupError(503, "staged share private key is invalid")
    return meta


def _validate_historical_signatures(
    staging_dir: str, wallet_id: str, members: dict[str, bytes]
) -> None:
    """历史签名连续性：每条已保存签名必须能用其提交时刻的钱包公钥独立验签。

    对 signatures/W.json 中每条 (rid -> {message, signature})：审计中必须
    恰有一条 request_signed 事件（签名记录与事件同一事务提交）；按事件
    seq 时刻的轮换激活时间线取当时在用公钥，把 128 字节聚合签名拆成两个
    64 字节，分别对 payload(rid, message) 验签。任一失败 fail-closed。
    """
    from . import crypto
    from .audit import AuditStore

    rel = f"signatures/{wallet_id}.json"
    if rel not in members:
        return
    ledger = _parse_json_member(rel, members[rel])
    if not isinstance(ledger, dict):
        raise BackupError(503, "signatures backup is malformed")
    audit_store = AuditStore(staging_dir)
    events = audit_store.events_by_type(wallet_id, "request_signed")
    signed_by_rid: dict[str, dict] = {}
    for event in events:
        rid = event.get("request_id")
        if not isinstance(rid, str) or rid in signed_by_rid:
            raise BackupError(503, "duplicate request_signed commit point")
        signed_by_rid[rid] = event

    timeline = []
    for rid_key, event in audit_store.activated_rotation_events(wallet_id).items():
        details = event.get("details")
        seq = event.get("seq")
        if not isinstance(details, dict) or not isinstance(seq, int):
            raise BackupError(503, "rotation event is malformed in backup")
        try:
            pub = bytes.fromhex(details.get("public_key", ""))
        except ValueError:
            raise BackupError(503, "rotation event is malformed in backup")
        if len(pub) != 64:
            raise BackupError(503, "rotation event is malformed in backup")
        timeline.append((seq, pub))
    timeline.sort(key=lambda item: item[0])

    for key, record in ledger.items():
        if not _SAFE_ID.match(key) or not isinstance(record, dict):
            raise BackupError(503, "signatures backup is malformed")
        message = record.get("message")
        signature_hex = record.get("signature")
        if not isinstance(message, str) or not isinstance(signature_hex, str):
            raise BackupError(503, "signatures backup is malformed")
        try:
            signature = bytes.fromhex(signature_hex)
        except ValueError:
            raise BackupError(503, "signatures backup is malformed")
        if len(signature) != 128:
            raise BackupError(503, "signatures backup is malformed")
        event = signed_by_rid.get(key)
        if event is None:
            raise BackupError(503, "saved signature has no request_signed event")
        details = event.get("details")
        if not isinstance(details, dict) or details.get("message") != message:
            raise BackupError(503, "signed event does not match the saved signature")
        # 事件 seq 时刻的在用公钥：取最后一个 seq <= event.seq 的激活公钥；
        # 首次激活之前的公钥取首项激活事件的 previous_public_key。
        seq = event["seq"]
        pubs_before = [pub for act_seq, pub in timeline if act_seq <= seq]
        if pubs_before:
            public = pubs_before[-1]
        elif not timeline:
            # 从未发生过轮换：当前钱包公钥即创世公钥
            wallet_meta = _parse_json_member(
                f"wallets/{wallet_id}.json",
                members[f"wallets/{wallet_id}.json"],
            )
            try:
                public = bytes.fromhex(wallet_meta["public_key"])
            except (KeyError, TypeError, ValueError):
                raise BackupError(503, "cannot resolve historical public key")
        else:
            # 签名发生在首次激活之前：公钥取首项激活事件的 previous
            first_event = min(
                audit_store.activated_rotation_events(wallet_id).values(),
                key=lambda e: e.get("seq", 0),
            )
            try:
                public = bytes.fromhex(
                    first_event["details"]["previous_public_key"]
                )
            except (KeyError, TypeError, ValueError):
                raise BackupError(503, "cannot resolve historical public key")
        payload = crypto.build_payload(key, message)
        halves = [signature[:64], signature[64:]]
        for index, half in enumerate(halves):
            if not crypto.verify_share(public[index * 32:index * 32 + 32], payload, half):
                raise BackupError(503, "historical signature does not verify")


def _load_json_file(path: str) -> Optional[object]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except (ValueError, OSError) as exc:
        raise RecoveryError(f"cannot parse {path!r}: {exc}") from exc


def _capture_live(backup_dir: str, data_dir: str, wallet_id: str) -> list[str]:
    """把当前 live 白名单文件快照进事务 backup/ 区，返回捕获到的 rel 集合。

    同时写 backup/manifest.json：每项含 path/bytes/sha256（回滚前据此
    校验捕获镜像未被损坏/篡改），使崩溃回滚能精确恢复到事务前（包括
    "钱包原本不存在"）。
    """
    live = _walk_wallet_files(data_dir, wallet_id)
    rels = [rel for rel, _data in live]
    for rel, data in live:
        _atomic_write_bytes(os.path.join(backup_dir, *rel.split("/")), data)
    capture_manifest = {
        "files": [
            {"path": rel, "bytes": len(data), "sha256": _sha256_hex(data)}
            for rel, data in live
        ]
    }
    _atomic_write_bytes(
        os.path.join(backup_dir, "manifest.json"),
        _canonical_json(capture_manifest),
    )
    return rels


def _verify_image_against_manifest(
    image_dir: str,
    wallet_id: str,
    expected_files: list[dict],
) -> dict[str, bytes]:
    """校验事务镜像（staging 或 backup）与清单逐项一致。

    镜像实际文件集合必须恰为清单中的 path 集合，且每项字节数与 SHA-256
    完全匹配；任何缺项、多项或哈希不符都抛 RecoveryError：绝不基于损坏
    的暂存/捕获镜像前滚或回滚（fail-closed，不猜写）。返回 {rel: data}。
    """
    entries = dict(_walk_wallet_files(image_dir, wallet_id))
    expected = {entry["path"]: entry for entry in expected_files}
    if set(entries) != set(expected):
        raise RecoveryError(
            f"wallet {wallet_id!r} restore image does not match its manifest"
        )
    for rel, data in entries.items():
        spec = expected[rel]
        if (
            not isinstance(spec.get("bytes"), int)
            or spec["bytes"] != len(data)
            or not isinstance(spec.get("sha256"), str)
            or spec["sha256"] != _sha256_hex(data)
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} restore image file {rel!r} failed its "
                "hash check"
            )
    return entries


def _prune_wallet_dirs(data_dir: str, wallet_id: str, keep: set[str]) -> None:
    """删除 live 中不属于 keep 的白名单文件，并清理空掉的 W 专属目录。

    绝不触碰其他钱包的目录与文件；绝不跟随符号链接（白名单走查已先行
    拒绝链接，此处只处理常规文件与空目录）。
    """
    current = dict(_walk_wallet_files(data_dir, wallet_id))
    for rel in list(current):
        if rel not in keep:
            try:
                os.unlink(os.path.join(data_dir, *rel.split("/")))
            except FileNotFoundError:
                pass
    # 自底向上删除空的 W 子树（shares/W、asset-intents/W、
    # rotation-staging/W/<rid>、rotation-staging/W）。
    for root_name, recursive in _WHITELIST_ROOTS:
        if not recursive:
            continue
        base = os.path.join(data_dir, root_name, wallet_id)
        if not os.path.isdir(base) or os.path.islink(base):
            continue
        for current_dir, dirnames, filenames in os.walk(base, topdown=False):
            for d in list(dirnames):
                path = os.path.join(current_dir, d)
                try:
                    if not os.listdir(path):
                        os.rmdir(path)
                except OSError:
                    pass
        try:
            if not os.listdir(base):
                os.rmdir(base)
        except (FileNotFoundError, OSError):
            pass


def _apply_snapshot(
    data_dir: str, wallet_id: str, members: dict[str, bytes]
) -> None:
    """把暂存快照换入 live：原子写入全部成员，再删除多余 live 文件。"""
    for rel, data in members.items():
        _atomic_write_bytes(os.path.join(data_dir, *rel.split("/")), data)
    _prune_wallet_dirs(data_dir, wallet_id, set(members))


def _resolve_pending_txn(
    data_dir: str, wallet_id: str, snapshot_id: str
) -> None:
    """按 commit 标记前滚/回滚一次中断的恢复事务（调用方持 live 钱包锁）。"""
    txn = _txn_dir(data_dir, wallet_id, snapshot_id)
    staging = os.path.join(txn, "staging")
    backup_dir = os.path.join(txn, "backup")
    marker = os.path.join(txn, COMMIT_MARKER_NAME)
    committed = os.path.exists(marker) and not os.path.islink(marker)

    if committed:
        # 提交点已落盘：前滚补齐 live 为快照唯一结果，补记 restore-records
        # （崩溃可能发生在标记之后、记录之前），最后清理事务区。
        txn_manifest = _load_json_file(os.path.join(txn, "manifest.json"))
        marker_data = _load_json_file(marker)
        if not isinstance(txn_manifest, dict) or not isinstance(
            txn_manifest.get("files"), list
        ) or not isinstance(marker_data, dict):
            raise RecoveryError(
                f"wallet {wallet_id!r} committed restore {snapshot_id!r} "
                "is missing its manifest"
            )
        # commit 标记记录的 manifest 哈希必须与工作区 manifest 一致
        marker_digest = marker_data.get("manifest_sha256")
        if marker_digest != manifest_hash(txn_manifest):
            raise RecoveryError(
                f"wallet {wallet_id!r} committed restore {snapshot_id!r} "
                "marker does not match its manifest"
            )
        # 换入前重算暂存镜像全部哈希：绝不基于被损坏/篡改的暂存私钥前滚。
        entries = _verify_image_against_manifest(
            staging, wallet_id, txn_manifest["files"]
        )
        _apply_snapshot(data_dir, wallet_id, entries)
        records = load_restore_records(data_dir, wallet_id)
        if snapshot_id not in records["snapshots"]:
            restored_at = marker_data.get("committed_at")
            if not isinstance(restored_at, str):
                restored_at = ""
            records["snapshots"][snapshot_id] = {
                "snapshot_id": snapshot_id,
                "manifest_sha256": marker_digest,
                "restored_at": restored_at,
            }
            save_restore_records(data_dir, wallet_id, records)
    else:
        # 标记未落盘：换入未生效。
        captured_manifest_path = os.path.join(backup_dir, "manifest.json")
        if not os.path.exists(captured_manifest_path):
            # live 捕获尚未开始（崩溃发生在物化/校验阶段）：live 从未被
            # 触碰，直接丢弃事务工作区即可，无需回滚、也不阻塞服务。
            shutil.rmtree(txn, ignore_errors=True)
            return
        captured_manifest = _load_json_file(captured_manifest_path)
        if not isinstance(captured_manifest, dict) or not isinstance(
            captured_manifest.get("files"), list
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} uncommitted restore {snapshot_id!r} "
                "cannot be rolled back safely"
            )
        # 回滚前重算捕获镜像全部哈希：镜像损坏则无法精确还原事务前 live，
        # fail-closed，绝不猜测写回。
        captured_entries = _verify_image_against_manifest(
            backup_dir, wallet_id, captured_manifest["files"]
        )
        _apply_snapshot(data_dir, wallet_id, captured_entries)

    shutil.rmtree(txn, ignore_errors=True)
    # 清掉空下来的 S 与 W 事务父目录
    parent = os.path.dirname(txn)
    try:
        if os.path.isdir(parent) and not os.listdir(parent):
            os.rmdir(parent)
    except OSError:
        pass


def recover_interrupted_restores(data_dir: str, wallet_id: str) -> None:
    """解析该钱包全部中断的恢复事务（供 restore 命令与常驻服务自愈共用）。

    扫描 restore-txn/W/ 下的 S 目录：有 commit 标记前滚、无标记回滚，
    完成后删除事务区。非安全标识目录、缺捕获清单等无法安全对账的现场
    抛 RecoveryError（fail-closed），绝不静默跳过。调用方必须持有该钱包
    的 live 事务锁。
    """
    base = os.path.join(data_dir, RESTORE_TXN_DIRNAME, wallet_id)
    try:
        names = os.listdir(base)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RecoveryError(
            f"wallet {wallet_id!r} restore workspace is unreadable"
        ) from exc
    for name in sorted(names):
        if not SNAPSHOT_ID_RE.match(name):
            raise RecoveryError(
                f"wallet {wallet_id!r} restore workspace has an unknown entry"
            )
        if not os.path.isdir(os.path.join(base, name)) or os.path.islink(
            os.path.join(base, name)
        ):
            raise RecoveryError(
                f"wallet {wallet_id!r} restore workspace is malformed"
            )
        try:
            _resolve_pending_txn(data_dir, wallet_id, name)
        except RecoveryError:
            raise
        except BackupError as exc:
            # restore-records 形状损坏等：统一为不可对账，交给调用方
            # fail-closed，绝不把 BackupError(面向 CLI) 漏给服务自愈。
            raise RecoveryError(
                f"wallet {wallet_id!r} restore {name!r} cannot be resolved: "
                f"{exc.message}"
            ) from exc


def _validate_member_shapes(
    wallet_id: str, members: dict[str, bytes]
) -> None:
    """对不被服务恢复对账覆盖的成员做独立形状校验（fail-closed）。"""
    from .store import (
        approval_policy_shape_ok,
        transaction_policy_shape_ok,
    )

    rel = f"policies/{wallet_id}.json"
    if rel in members:
        policy = _parse_json_member(rel, members[rel])
        if not approval_policy_shape_ok(policy):
            raise BackupError(503, "approval policy backup is malformed")

    rel = f"transaction-policies/{wallet_id}.json"
    if rel in members:
        policy = _parse_json_member(rel, members[rel])
        if not transaction_policy_shape_ok(policy):
            raise BackupError(503, "transaction policy backup is malformed")

    rel = f"requests/{wallet_id}.json"
    if rel in members:
        _validate_requests_ledger(wallet_id, members[rel])

    rel = f"signatures/{wallet_id}.json"
    if rel in members:
        ledger = _parse_json_member(rel, members[rel])
        if not isinstance(ledger, dict):
            raise BackupError(503, "signatures backup is malformed")
        for key, record in ledger.items():
            if not _SAFE_ID.match(key) or not isinstance(record, dict):
                raise BackupError(503, "signatures backup is malformed")
            if not isinstance(record.get("message"), str):
                raise BackupError(503, "signatures backup is malformed")
            signature_hex = record.get("signature")
            if not isinstance(signature_hex, str):
                raise BackupError(503, "signatures backup is malformed")
            try:
                if len(bytes.fromhex(signature_hex)) != 128:
                    raise ValueError
            except ValueError:
                raise BackupError(503, "signatures backup is malformed")

    # 提交意图只存在于提交事务窗口；静止备份绝不包含意图文件。
    if any(rel.startswith("asset-intents/") for rel in members):
        raise BackupError(503, "backup must not contain asset commit intents")


def restore_backup(
    data_dir: str, wallet_id: str, input_path: str
) -> tuple[int, dict]:
    """从快照恢复单钱包，返回 (200|201, 响应体)；失败抛 BackupError。

    在该钱包 live 事务锁内完成：先解析他进程/上次崩溃遗留的恢复事务
    （按 commit 标记前滚/回滚），再做幂等/冲突判定，随后把快照物化到
    私有 restore-txn 工作区并做全部校验（身份、白名单哈希、形状、公私钥
    对应、审计 seq、账本/会话/轮换一致性、历史签名连续），全部通过后才
    捕获 live、换入、落 commit 标记、记录 restore-records。任何校验失败
    都不触碰 live 业务文件。
    """
    if not isinstance(wallet_id, str) or not _SAFE_ID.match(wallet_id):
        raise BackupError(400, "invalid wallet_id")

    # 锁外只读：tar/manifest/成员/哈希严格校验，绝不写 data_dir。
    manifest, members = read_backup_archive(input_path, wallet_id)
    snapshot_id = manifest["snapshot_id"]
    digest = manifest_hash(manifest)

    store = WalletStore(data_dir)
    from .service import WalletService

    try:
        # 构造服务：先恢复 live data-dir 中所有钱包（与 share-sign 同一边界）。
        service = WalletService(store)
    except RecoveryError:
        raise BackupError(503, "recovery failed, refusing to restore")
    except OSError:
        raise BackupError(503, "cannot open data dir, refusing to restore")
    except (CorruptDataError, ValueError):
        raise BackupError(503, "data directory is corrupt, refusing to restore")

    with service._wallet_lock(wallet_id):
        # 任何上次崩溃的半事务必须先按标记结清，请求期间也不可见半状态。
        try:
            recover_interrupted_restores(data_dir, wallet_id)
        except RecoveryError:
            raise BackupError(503, "a pending restore cannot be resolved, refusing to restore")
        except OSError:
            raise BackupError(503, "cannot resolve a pending restore, refusing to restore")

        records = load_restore_records(data_dir, wallet_id)
        existing = records["snapshots"].get(snapshot_id)
        if existing is not None:
            if existing["manifest_sha256"] != digest:
                # 同一 snapshot_id 已以不同内容恢复过：冲突，拒绝覆盖
                raise BackupError(
                    409,
                    f"snapshot {snapshot_id!r} already restored with different content",
                )
            # 幂等：同 S 同哈希。哈希（规范化 JSON）相同即清单内容相同，
            # 直接返回本次输入的清单，响应体与首次恢复一致（200）。
            return 200, {
                "wallet_id": wallet_id,
                "snapshot_id": snapshot_id,
                "manifest": manifest,
                "manifest_sha256": existing["manifest_sha256"],
            }

        # 私有工作区（白名单之外，对常驻请求不可见）。
        txn = _txn_dir(data_dir, wallet_id, snapshot_id)
        staging = os.path.join(txn, "staging")
        backup_dir = os.path.join(txn, "backup")
        if os.path.exists(txn):
            # 上面已结清全部 S 事务；同 S 目录残留说明无法识别，fail-closed
            raise BackupError(503, "restore workspace for this snapshot already exists")
        # 标记 live 是否已开始被换入：换入开始后的任何失败都必须先按
        # 捕获镜像回滚 live，绝不能删除事务区丢失回滚依据。
        live_touched = False
        try:
            # 1) 物化快照到工作区。
            _materialize_staging(staging, members)
            _atomic_write_bytes(
                os.path.join(txn, "manifest.json"),
                _canonical_json(manifest),
            )

            # 2) 独立形状与密码学校验。
            _validate_member_shapes(wallet_id, members)
            _validate_wallet_and_shares(wallet_id, members)

            # 3) 在工作区上做与常驻完全相同的恢复对账：审计 seq 连续、
            #    账本语义/事件双向一致、轮换链、签名会话严格恢复。任一
            #    不可对账即 fail-closed。
            staging_store = WalletStore(staging)
            try:
                WalletService(staging_store)
            except (RecoveryError, CorruptDataError, ValueError, OSError):
                # 恢复无法对账到一致状态：不回显内部细节（可能含路径/
                # 公钥/seq 等现场信息），统一泛化 503。
                raise BackupError(
                    503, "backup cannot be reconciled, refusing to restore"
                )

            # 恢复不得改动快照内容（例如安全删除无效 prepared）：任何
            # 漂移都意味着备份不是静止一致现场，拒绝恢复。
            recovered = dict(_walk_wallet_files(staging, wallet_id))
            if set(recovered) != set(members):
                raise BackupError(
                    503, "backup content is not a quiescent wallet state"
                )
            for rel, data in members.items():
                if recovered[rel] != data:
                    raise BackupError(
                        503, "backup content is not a quiescent wallet state"
                    )

            # 4) 历史签名必须沿轮换公钥链连续可验。
            _validate_historical_signatures(staging, wallet_id, members)

            # 5) 捕获 live（事务前镜像），随后换入快照。从这里开始 live
            #    被触碰：之后任何失败都按 commit 标记立即结清（前滚/回滚），
            #    绝不删除事务区丢失回滚依据。
            _capture_live(backup_dir, data_dir, wallet_id)
            live_touched = True
            _apply_snapshot(data_dir, wallet_id, members)

            # 6) commit 标记是唯一提交点：标记在则前滚，不在则回滚。
            marker = {
                "wallet_id": wallet_id,
                "snapshot_id": snapshot_id,
                "manifest_sha256": digest,
                "committed_at": _utc_now_iso(),
            }
            _atomic_write_bytes(
                os.path.join(txn, COMMIT_MARKER_NAME),
                _canonical_json(marker),
            )

            # 7) 提交后补记 restore-records（崩溃也可由前滚补齐），再清理。
            records["snapshots"][snapshot_id] = {
                "snapshot_id": snapshot_id,
                "manifest_sha256": digest,
                "restored_at": marker["committed_at"],
            }
            save_restore_records(data_dir, wallet_id, records)
            shutil.rmtree(txn, ignore_errors=True)
            parent = os.path.dirname(txn)
            try:
                if os.path.isdir(parent) and not os.listdir(parent):
                    os.rmdir(parent)
            except OSError:
                pass
        except BackupError:
            if not live_touched:
                # 捕获/换入之前的校验失败：live 从未被触碰，清掉仅含快照
                # 的私有工作区（不留私钥副本）即可。
                shutil.rmtree(txn, ignore_errors=True)
                raise
            # live 已开始换入却未走到返回（理论上只能是捕获/换入阶段的
            # 文件系统或竞态异常）：commit 标记尚不在，按捕获镜像立即
            # 回滚 live 并清理，使本次失败对外仍表现为"未恢复、无半状态"。
            try:
                _resolve_pending_txn(data_dir, wallet_id, snapshot_id)
            except RecoveryError:
                # 无法安全回滚：保留现场 fail-closed（下次持锁访问继续
                # 对账），绝不静默丢弃回滚依据。
                raise BackupError(
                    503, "a pending restore cannot be resolved, refusing to restore"
                )
            raise
        except OSError:
            if live_touched:
                # 换入/标记阶段的文件系统故障：按 commit 标记前滚/回滚
                # 结清现场，使请求不可见半状态；无法对账时 fail-closed。
                try:
                    _resolve_pending_txn(data_dir, wallet_id, snapshot_id)
                except RecoveryError:
                    raise BackupError(
                        503,
                        "a pending restore cannot be resolved, refusing to restore",
                    )
            else:
                shutil.rmtree(txn, ignore_errors=True)
            raise BackupError(503, "restore interrupted by a filesystem error")

    return 201, {
        "wallet_id": wallet_id,
        "snapshot_id": snapshot_id,
        "manifest": manifest,
        "manifest_sha256": digest,
    }


def _utc_now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
