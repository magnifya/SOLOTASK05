"""兼容灾备 CLI：``backup`` / ``restore``（离线快照与对账恢复）。

本模块只处理**单个钱包**（--wallet-id W）的灾备，绝不触碰 data-dir 内
其他钱包的任何文件：

``backup --data-dir D --wallet-id W --snapshot-id S --output B``
    在该钱包的跨进程事务锁内先自愈轮换/资产提交/签名会话的崩溃现场，
    再按**白名单**逐文件读取、逐字节计算 sha256，打包成确定性 tar
    （内含 manifest v1：W、S 与每项 path/bytes/sha256，manifest 主体
    sha256 绑定含 S 在内的内容）。白名单之外（绝对路径/``..``/重复/符号
    链接/额外文件/锁文件/临时文件）一律拒绝。无法对账（恢复失败/数据
    损坏）即失败，绝不出包。

``restore --data-dir D --wallet-id W --input B``
    在钱包事务锁内先校验快照身份、白名单哈希、文件形状、公私钥对应、
    审计 seq 连续、账本/会话/轮换一致性（失败不写盘），再以
    ``restore-txn/<W>/<S>/`` 下的 prepared/committed 标记完成崩溃安全的
    前滚/回滚替换；``restore-records/<W>.json`` 记录 S 与 manifest 哈希，
    首次 201、同 S 同 manifest 200 同体、不同内容 409、损坏/不可对账 503。

安全边界：恢复不新增审计事件，余额/version 不跳变，幂等保持，历史签名
连续可验；响应与 manifest 只含公钥/标识/哈希/整数/业务原文，绝不含任何
份额私钥。
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import tarfile
import tempfile
from typing import Optional

from .service import WalletService
from .store import CorruptDataError, RecoveryError, WalletStore

#: snapshot_id / wallet_id 允许的字符（与存储层安全 id 一致）
_SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

#: share_id 允许的字符（<rotation_id>-share-N 最长 136）
_SAFE_SHARE_ID = re.compile(r"^[A-Za-z0-9_-]{1,136}$")

#: manifest 版本
MANIFEST_VERSION = 1

#: 快照内 manifest 成员的固定路径（必须且唯一）
MANIFEST_MEMBER = "manifest.json"

#: data-dir 下的灾备事务与记录目录
RESTORE_TXN_DIRNAME = "restore-txn"
RESTORE_RECORDS_DIRNAME = "restore-records"

#: restore-txn 标记文件名
MARKER_PREPARED = "prepared.json"
MARKER_COMMITTED = "committed.json"

#: 业务目录下的单文件成员（<dir>/<wallet_id>.json）
_BUSINESS_FILE_DIRS = (
    "audit",
    "signatures",
    "policies",
    "requests",
    "rotations",
    "assets",
    "transaction-policies",
    "sign-sessions",
)


class BackupError(Exception):
    """备份/恢复失败。``status`` 为对外语义状态码（400/404/409/503）。"""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def is_safe_id(value: object) -> bool:
    """wallet_id / snapshot_id 是否匹配 [A-Za-z0-9_-]{1,128}。"""
    return isinstance(value, str) and bool(_SAFE_ID.match(value))


def sha256_hex(data: bytes) -> str:
    """返回字节串的 sha256 hex。"""
    return hashlib.sha256(data).hexdigest()


def _is_sha256_hex(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


def _is_inside(child: str, parent: str) -> bool:
    """词法判定 ``child`` 是否等于 ``parent`` 或位于其目录树内。"""
    return child == parent or child.startswith(parent + os.sep)


def _assert_output_outside_data_dir(output: str, data_dir: str) -> None:
    """拒绝任何解析后落在 data-dir 内（含边界）的备份输出路径。

    成功写包会以快照内容原子替换 ``--output`` 目标：若目标位于 data-dir
    内（业务文件、份额文件、灾备事务/记录文件、锁文件、根目录本身），出包
    即覆盖在线状态。故在**取得钱包锁之后、开始读取任何钱包文件之前**调用：

    - 词法绝对路径位于 data-dir 内：拒绝（含尚不存在的目标，覆盖
      ``data/audit/<W>.json``、``data/shares/<W>/...``、
      ``data/restore-txn/...`` 等情形）；
    - 路径或其任一已存在父级是符号链接、最终 realpath 落入 data-dir：
      拒绝（防 data-dir 内符号链接指向外部、或外部链接回指 data-dir）；
    - 输出同目录临时文件（``.snapshot-*.tmp``）的父目录位于 data-dir 内：
      拒绝（连半包临时文件也不得落进 data-dir）。

    命中抛 BackupError(400)——这是确定性的调用方参数错误，且绝不进行任何
    读盘/自愈/写盘，钱包现场与既有快照都不受影响。
    """
    abs_data = os.path.abspath(data_dir)
    real_data = os.path.realpath(abs_data)
    abs_out = os.path.abspath(output)
    real_out = os.path.realpath(abs_out)
    # 词法判定先行：即使目标尚不存在（realpath 无法解析叶子），只要路径
    # 串落在 data-dir 命名空间内即拒绝。
    if _is_inside(abs_out, abs_data) or _is_inside(abs_out, real_data):
        raise BackupError(
            400, "--output must not point inside the data directory"
        )
    # 跟随符号链接后的真实落点（含外部链接回指 data-dir 的情形）。
    if _is_inside(real_out, real_data) or _is_inside(real_out, abs_data):
        raise BackupError(
            400, "--output resolves inside the data directory via a link"
        )
    # 原子写出的临时文件与输出同目录：该目录在 data-dir 内同样拒绝。
    parent = os.path.dirname(abs_out) or os.sep
    real_parent = os.path.realpath(parent)
    if (
        _is_inside(parent, abs_data)
        or _is_inside(real_parent, real_data)
        or _is_inside(real_parent, abs_data)
    ):
        raise BackupError(
            400, "--output temporary file would land inside the data directory"
        )


def _read_regular_file(path: str) -> bytes:
    """读取普通文件字节；符号链接/非常规文件一律拒绝（绝不跟随链接）。"""
    if os.path.islink(path):
        raise BackupError(503, f"refusing to read symbolic link: {path}")
    if not os.path.isfile(path):
        raise BackupError(503, f"not a regular file: {path}")
    with open(path, "rb") as f:
        return f.read()


# ---- 白名单 ---------------------------------------------------------------

def _wallet_members(wallet_id: str) -> list[str]:
    """该钱包在快照中允许出现的非目录成员路径（文件须现存才打包）。"""
    members = [f"wallets/{wallet_id}.json"]
    members.extend(f"{d}/{wallet_id}.json" for d in _BUSINESS_FILE_DIRS)
    return members


def _scan_share_dir(data_dir: str, wallet_id: str) -> list[str]:
    """枚举 shares/<W>/ 下的全部成员并严格校验，返回成员相对路径。

    只允许名为 ``<合法 share_id>.json`` 的普通文件；符号链接、子目录、
    非 .json、临时文件（.tmp-*）等任何额外条目一律拒绝。
    """
    base = os.path.join(data_dir, "shares", wallet_id)
    return _scan_flat_dir(
        base,
        f"shares/{wallet_id}",
        lambda name: (
            name.endswith(".json")
            and bool(_SAFE_SHARE_ID.match(name[: -len(".json")]))
        ),
    )


def _scan_staging_dir(data_dir: str, wallet_id: str) -> list[str]:
    """递归枚举 rotation-staging/<W>/ 下的全部成员并严格校验。

    结构只能是 ``<rotation_id>/<share_id>.json`` 两层：rotation_id 为安全
    标识；文件名只能是 ``<share_id>.json``。符号链接、更深层级、原子写
    临时文件、``*.bak.json`` 激活备份（持锁自愈后必已清理）或任何额外
    条目一律拒绝。
    """
    fs_root = os.path.join(data_dir, "rotation-staging", wallet_id)
    members: list[str] = []
    if not os.path.exists(fs_root) and not os.path.islink(fs_root):
        return members
    if os.path.islink(fs_root) or not os.path.isdir(fs_root):
        raise BackupError(503, "rotation-staging wallet entry is not a directory")
    with os.scandir(fs_root) as it:
        rotations = list(it)
    for rid_entry in sorted(rotations, key=lambda e: e.name):
        if rid_entry.is_symlink():
            raise BackupError(503, "refusing symbolic link in rotation-staging")
        if not rid_entry.name or not _SAFE_ID.match(rid_entry.name):
            raise BackupError(503, "unexpected entry in rotation-staging")
        if not rid_entry.is_dir(follow_symlinks=False):
            raise BackupError(503, "unexpected file in rotation-staging")
        rid_fs = os.path.join(fs_root, rid_entry.name)
        with os.scandir(rid_fs) as it2:
            files = list(it2)
        for f_entry in sorted(files, key=lambda e: e.name):
            if f_entry.is_symlink():
                raise BackupError(503, "refusing symbolic link in rotation-staging")
            if not f_entry.is_file(follow_symlinks=False):
                raise BackupError(503, "unexpected non-file in rotation-staging")
            name = f_entry.name
            # 激活备份 *.bak.json（含 wallet.bak.json）只可能存在于激活
            # 事务窗口；持锁自愈后仍在等于现场半完成，绝不出包。
            if name.endswith(".bak.json") or not (
                name.endswith(".json")
                and _SAFE_SHARE_ID.match(name[: -len(".json")])
            ):
                raise BackupError(503, "unexpected file in rotation-staging")
            members.append(
                f"rotation-staging/{wallet_id}/{rid_entry.name}/{name}"
            )
    return members


def _scan_shared_root(data_dir: str, dirname: str, wallet_id: str) -> None:
    """严格扫描一个多钱包共享根目录（wallets/ 与各业务目录）。

    这些目录里允许存在**其他钱包**的 ``<other_id>.json`` 正式文件；但凡
    属于目标钱包 W 命名空间的额外条目、原子写临时文件（``.tmp-*.json``）、
    ``*.bak.json`` 备份、符号链接或子目录都意味着未对账现场，一律 503。
    """
    fs_root = os.path.join(data_dir, dirname)
    if not os.path.exists(fs_root) and not os.path.islink(fs_root):
        return
    if os.path.islink(fs_root) or not os.path.isdir(fs_root):
        raise BackupError(503, f"{dirname} is not a directory")
    with os.scandir(fs_root) as it:
        entries = list(it)
    for entry in entries:
        name = entry.name
        if entry.is_symlink():
            raise BackupError(503, f"refusing symbolic link under {dirname}")
        if not entry.is_file(follow_symlinks=False):
            raise BackupError(503, f"unexpected non-file under {dirname}")
        if name.startswith(".tmp-") and name.endswith(".json"):
            raise BackupError(503, f"atomic-write temp file under {dirname}")
        if name.endswith(".bak.json"):
            raise BackupError(503, f"activation backup file under {dirname}")
        # 共享根目录只允许正式的 <safe-id>.json 文件（其他钱包的正式文件
        # 自然允许）；任何其他命名都是白名单外的非法条目。
        if not (
            name.endswith(".json")
            and bool(_SAFE_ID.match(name[: -len(".json")]))
        ):
            raise BackupError(503, f"unexpected file name under {dirname}")


def _scan_flat_dir(
    fs_root: str, rel_root: str, name_ok
) -> list[str]:
    """枚举一个扁平目录：只接受通过 name_ok 的普通文件，其余一律拒绝。"""
    if not os.path.exists(fs_root) and not os.path.islink(fs_root):
        return []
    if os.path.islink(fs_root) or not os.path.isdir(fs_root):
        raise BackupError(503, f"{rel_root} is not a directory")
    members: list[str] = []
    with os.scandir(fs_root) as it:
        entries = list(it)
    for entry in sorted(entries, key=lambda e: e.name):
        if entry.is_symlink():
            raise BackupError(503, f"refusing symbolic link under {rel_root}")
        if not entry.is_file(follow_symlinks=False):
            raise BackupError(503, f"unexpected non-file under {rel_root}")
        if not name_ok(entry.name):
            raise BackupError(503, f"unexpected file under {rel_root}")
        members.append(f"{rel_root}/{entry.name}")
    return members


def _iter_whitelist_files(data_dir: str, wallet_id: str) -> list[str]:
    """枚举该钱包白名单内的现存相对路径（POSIX 风格，已排序、去重）。

    覆盖：wallets/W.json、shares/W/*、业务目录 W（审计/审批/签名/策略/
    交易策略/资产/会话/轮换）、rotation-staging/W/*（递归）。锁文件
    （locks/）、资产提交意图（asset-intents/，恢复后必为空）、灾备事务
    目录与原子写临时文件均不在白名单。
    """
    members: list[str] = []
    # wallets/ 与每个业务共享根目录都要严格扫描：任何原子写临时文件、
    # *.bak.json、符号链接、子目录或非法命名都拒绝出包（fail-closed）。
    _scan_shared_root(data_dir, "wallets", wallet_id)
    for dirname in _BUSINESS_FILE_DIRS:
        _scan_shared_root(data_dir, dirname, wallet_id)
    for rel in _wallet_members(wallet_id):
        path = os.path.join(data_dir, *rel.split("/"))
        if os.path.exists(path) or os.path.islink(path):
            if os.path.islink(path):
                raise BackupError(503, "refusing symbolic link to a wallet file")
            if not os.path.isfile(path):
                raise BackupError(503, "wallet file is not a regular file")
            members.append(rel)
    members.extend(_scan_share_dir(data_dir, wallet_id))
    members.extend(_scan_staging_dir(data_dir, wallet_id))
    if len(members) != len(set(members)):
        raise BackupError(503, "duplicate snapshot member detected")
    return sorted(members)


# ---- manifest -------------------------------------------------------------

def _canonical_manifest_body(manifest: dict) -> bytes:
    """manifest 参与哈希绑定的主体（不含自引用 manifest_sha256）。"""
    body = {
        "version": manifest["version"],
        "wallet_id": manifest["wallet_id"],
        "snapshot_id": manifest["snapshot_id"],
        "files": manifest["files"],
    }
    return json.dumps(body, ensure_ascii=False, sort_keys=True).encode("utf-8")


def _build_manifest(
    data_dir: str, wallet_id: str, snapshot_id: str
) -> tuple[dict, list[tuple[str, bytes]]]:
    """锁内、恢复完成后读取白名单文件，构造 manifest v1 与 (relpath, data)。

    manifest 含 version/wallet_id/snapshot_id/files，每项 path/bytes/sha256；
    manifest_sha256 绑定（含 S 在内的）主体哈希。任何符号链接/非常规文件/
    路径异常都抛 BackupError。
    """
    relpaths = _iter_whitelist_files(data_dir, wallet_id)
    files: list[dict] = []
    payloads: list[tuple[str, bytes]] = []
    for rel in relpaths:
        path = os.path.join(data_dir, *rel.split("/"))
        data = _read_regular_file(path)
        files.append(
            {
                "path": rel,
                "bytes": len(data),
                "sha256": sha256_hex(data),
            }
        )
        payloads.append((rel, data))
    manifest = {
        "version": MANIFEST_VERSION,
        "wallet_id": wallet_id,
        "snapshot_id": snapshot_id,
        "files": files,
    }
    manifest["manifest_sha256"] = sha256_hex(_canonical_manifest_body(manifest))
    return manifest, payloads


def _write_snapshot(
    out_path: str, manifest: dict, payloads: list[tuple[str, bytes]]
) -> None:
    """把 manifest 与白名单文件按确定性顺序写入 tar（pax），原子替换。

    全部成员为固定 mtime/属主/权限的普通文件：无绝对路径、无 ``..``、
    无符号/硬链接/设备、无目录项之外的元数据。先写同目录临时文件再
    os.replace，绝不留下半截快照。
    """
    out_dir = os.path.dirname(os.path.abspath(out_path)) or "."
    os.makedirs(out_dir, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        dir=out_dir, prefix=".snapshot-", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "wb") as raw:
            with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
                manifest_bytes = json.dumps(
                    manifest, ensure_ascii=False, sort_keys=True, indent=2
                ).encode("utf-8") + b"\n"
                _add_bytes(tar, MANIFEST_MEMBER, manifest_bytes)
                for rel, data in payloads:
                    _add_bytes(tar, rel, data)
        os.replace(tmp_path, out_path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mtime = 0
    info.mode = 0o600
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.type = tarfile.REGTYPE
    tar.addfile(info, io.BytesIO(data))


def backup(
    data_dir: str, wallet_id: str, snapshot_id: str, output: str
) -> dict:
    """执行一次备份，返回成功响应体（含 status/snapshot_id/manifest）。

    在该钱包的跨进程事务锁内先自愈崩溃现场（轮换/资产提交/签名会话），
    再读盘打包；恢复无法对账或数据损坏一律失败（503），绝不出包。
    """
    if not isinstance(output, str) or not output:
        raise BackupError(400, "--output must be a non-empty path")
    if not is_safe_id(wallet_id):
        raise BackupError(400, "invalid wallet_id")
    if not is_safe_id(snapshot_id):
        raise BackupError(400, "invalid snapshot_id")
    try:
        service = WalletService(WalletStore(data_dir), recover=False)
        with service._wallet_lock(wallet_id):
            # 取得钱包锁后、开始任何读取/自愈前先封闭输出路径：--output 落入
            # data-dir（业务/份额/事务/记录/锁文件、已存在文件、符号链接或
            # 同目录临时路径）一律 400 拒绝，绝不触发自愈或写盘，因而失败不会
            # 改动任何钱包现场或既有快照。
            _assert_output_outside_data_dir(output, data_dir)
            # 持锁自愈：先把他进程崩溃遗留的半完成轮换/提交/会话对账干净，
            # 绝不打包半状态；恢复失败直接向上抛（fail-closed）。
            service._heal_wallet(wallet_id)
            if service._store.get_wallet(wallet_id) is None:
                raise BackupError(404, f"wallet {wallet_id!r} not found")
            manifest, payloads = _build_manifest(
                data_dir, wallet_id, snapshot_id
            )
            # 出包前用与 restore 完全相同的全量对账（临时目录跑线上恢复器 +
            # 在用份额公私钥 + 审计/账本/会话/轮换/历史签名对账）校验即将
            # 打包的**确切字节**：不能对账绝不出包，也绝不生成无法恢复的快照。
            _verify_snapshot(service, wallet_id, manifest, dict(payloads))
            _write_snapshot(output, manifest, payloads)
    except BackupError:
        raise
    except (RecoveryError, CorruptDataError) as exc:
        # 不回显内部对账细节，避免泄露任何密钥/载荷线索
        raise BackupError(503, "wallet cannot be reconciled, backup refused") from exc
    except OSError as exc:
        raise BackupError(503, f"backup failed: {exc.__class__.__name__}") from exc
    return {
        "status": 201,
        "snapshot_id": snapshot_id,
        "manifest": manifest,
    }


# ---- 还原（读取快照）------------------------------------------------------

def _is_whitelisted(wallet_id: str, rel: str) -> bool:
    """成员相对路径是否属于该钱包白名单（不判断现存，只判形状/归属）。"""
    parts = rel.split("/")
    if rel == f"wallets/{wallet_id}.json":
        return True
    if (
        len(parts) == 2
        and parts[0] in _BUSINESS_FILE_DIRS
        and parts[1] == f"{wallet_id}.json"
    ):
        return True
    if (
        len(parts) == 3
        and parts[0] == "shares"
        and parts[1] == wallet_id
        and parts[2].endswith(".json")
        and bool(_SAFE_SHARE_ID.match(parts[2][: -len(".json")]))
    ):
        return True
    if (
        len(parts) == 4
        and parts[0] == "rotation-staging"
        and parts[1] == wallet_id
        and bool(_SAFE_ID.match(parts[2]))
        and _staging_filename_ok(parts[3])
    ):
        return True
    return False


def _staging_filename_ok(name: str) -> bool:
    """合法快照的暂存目录只允许 <share_id>.json 正式新份额文件。

    ``*.bak.json``（含 wallet.bak.json）是激活事务窗口内的瞬态备份，持锁
    自愈后必已清理，任何快照都不得携带（manifest 校验另有显式拒绝）。
    """
    if name.endswith(".bak.json"):
        return False
    return name.endswith(".json") and bool(
        _SAFE_SHARE_ID.match(name[: -len(".json")])
    )


def _validate_member_name(name: str) -> None:
    """拒绝绝对路径、Windows 盘符/反斜杠、``..``/`.`/空段。"""
    if not name or name.startswith("/") or "\\" in name or ":" in name:
        raise BackupError(503, "illegal member path in snapshot")
    parts = name.split("/")
    for part in parts:
        if part in ("", ".", ".."):
            raise BackupError(503, "illegal member path in snapshot")


def _read_snapshot(input_path: str) -> tuple[dict, dict[str, bytes]]:
    """严格读取 tar：返回 (manifest, {relpath: bytes})。

    拒绝：无法打开/非 tar、绝对/``..``/重复成员、符号链接/设备/硬链接等
    非常规文件、白名单外成员、缺/多 manifest、manifest JSON/形状/哈希
    绑定错误。调用方再做钱包身份与业务对账。
    """
    try:
        tar = tarfile.open(input_path, mode="r:*")
    except (tarfile.TarError, OSError) as exc:
        raise BackupError(503, "snapshot is unreadable or not a tar archive") from exc
    files: dict[str, bytes] = {}
    manifest: Optional[dict] = None
    try:
        for member in tar.getmembers():
            # PAX/GNU 的扩展头记录不会出现在 getmembers；任何残留的非常规
            # 类型（目录/符号/硬链接/设备/PAX 头）一律拒绝。
            if not member.isfile() or member.issym() or member.islnk():
                raise BackupError(503, "snapshot contains a non-regular member")
            name = member.name
            _validate_member_name(name)
            if name == MANIFEST_MEMBER:
                if manifest is not None:
                    raise BackupError(503, "duplicate manifest in snapshot")
            elif not _is_whitelisted_path_any(name):
                # 读取期还没有 wallet_id 上下文，用结构谓词初筛
                raise BackupError(503, "snapshot contains a non-whitelisted member")
            if name in files:
                raise BackupError(503, "duplicate member in snapshot")
            extracted = tar.extractfile(member)
            if extracted is None:
                raise BackupError(503, "snapshot member is not readable")
            with extracted:
                data = extracted.read()
            if len(data) != member.size:
                raise BackupError(503, "snapshot member size mismatch")
            if name == MANIFEST_MEMBER:
                try:
                    manifest = json.loads(data.decode("utf-8"))
                except (ValueError, UnicodeDecodeError) as exc:
                    raise BackupError(503, "manifest is not valid JSON") from exc
            else:
                files[name] = data
    except tarfile.TarError as exc:
        raise BackupError(503, "snapshot archive is corrupt") from exc
    finally:
        tar.close()
    if manifest is None:
        raise BackupError(503, "snapshot has no manifest")
    manifest = _validate_manifest_shape(manifest, files)
    return manifest, files


def _is_whitelisted_path_any(rel: str) -> bool:
    """读取期（尚无 wallet_id）的结构初筛：路径段必须是安全标识/文件名。"""
    parts = rel.split("/")
    if len(parts) == 2 and parts[0] == "wallets":
        stem = parts[1][: -len(".json")] if parts[1].endswith(".json") else ""
        return bool(_SAFE_ID.match(stem))
    if len(parts) == 2 and parts[0] in _BUSINESS_FILE_DIRS:
        stem = parts[1][: -len(".json")] if parts[1].endswith(".json") else ""
        return bool(_SAFE_ID.match(stem))
    if len(parts) == 3 and parts[0] == "shares":
        return bool(_SAFE_ID.match(parts[1])) and parts[2].endswith(".json") and (
            bool(_SAFE_SHARE_ID.match(parts[2][: -len(".json")]))
        )
    if len(parts) == 4 and parts[0] == "rotation-staging":
        return bool(_SAFE_ID.match(parts[1])) and bool(
            _SAFE_ID.match(parts[2])
        ) and _staging_filename_ok(parts[3])
    return False


#: manifest v1 顶层允许的契约键
_MANIFEST_TOP_KEYS = frozenset(
    ("version", "wallet_id", "snapshot_id", "files", "manifest_sha256")
)

#: manifest 每个 files 项允许的契约键
_MANIFEST_ENTRY_KEYS = frozenset(("path", "bytes", "sha256"))

#: 钱包元数据文件与其 shares 条目允许的契约键（绝不包含私钥材料）
_WALLET_META_KEYS = frozenset(
    ("wallet_id", "created_at", "public_key", "shares")
)
_WALLET_SHARE_ENTRY_KEYS = frozenset(("share_id", "public_key"))

#: 单个份额文件允许的契约键（全系统唯一允许含 private_key 的文件形状）
_SHARE_RECORD_KEYS = frozenset(("share_id", "public_key", "private_key"))

#: 轮换记录允许的契约键（previous_public_key 仅 activating/active 携带）
_ROTATION_RECORD_KEYS = frozenset(
    ("rotation_id", "state", "share_ids", "public_key", "created_at",
     "previous_public_key")
)

#: 审批单记录允许的契约键
_REQUEST_RECORD_KEYS = frozenset(
    ("id", "message", "state", "approvers", "req", "t0", "t1", "reason")
)

#: 已完成签名记录允许的契约键（绝不含份额私钥）
_SIGNATURE_RECORD_KEYS = frozenset(("message", "signature"))

#: 审批策略 / 交易策略文件允许的契约键
_APPROVAL_POLICY_KEYS = frozenset(
    ("wallet_id", "required_approvals", "timeout_seconds")
)
_TRANSACTION_POLICY_KEYS = frozenset(("mode", "max_delta", "allowed_assets"))

#: 非份额文件中绝不得出现的私钥字段名
_PRIVATE_KEY_FIELD = "private_key"

#: 审计事件恰允许的七个字段
_AUDIT_EVENT_KEYS = frozenset(
    ("seq", "type", "at", "request_id", "actor_id", "reason", "details")
)

#: 审计日志顶层允许的契约键
_AUDIT_LOG_KEYS = frozenset(("wallet_id", "next_seq", "events"))

#: manifest v1 契约内全部已知审计事件类型（封闭集合，未知类型拒绝）
_KNOWN_AUDIT_TYPES = frozenset(
    (
        "policy_updated",
        "request_created",
        "request_approved",
        "request_rejected",
        "request_expired",
        "request_signed",
        "share_rotation_prepared",
        "share_rotation_activated",
        "asset_operation_committed",
        "transaction_policy_updated",
        "session_event",
        "session_participant_replaced",
        "session_takeover",
        "dkg_stage",
        "dkg_failover",
        "dkg_failover_policy_updated",
        "node_state",
        "node_rejoined",
        "chain_policy",
        "chain_report",
        "chain_arbitration",
        "chain_vote",
    )
)


def _verify_audit_contract(wallet_id: str, files: dict[str, bytes]) -> None:
    """审计日志契约校验：顶层契约键、事件恰七字段、类型为封闭已知集合。

    seq 连续性与各类型的语义对账由线上恢复器（check_log/轮换链/账本/会话/
    审批单对账）负责；这里拦住夹带额外字段或未知事件类型的日志——审计是
    恢复提交点的唯一依据，未识别类型不得静默带入恢复后的系统。
    """
    rel = f"audit/{wallet_id}.json"
    if rel not in files:
        return
    log = _load_json_object(files[rel], "audit file")
    if not set(log) <= _AUDIT_LOG_KEYS:
        raise BackupError(503, "audit file has an unexpected top-level key")
    recorded_wallet = log.get("wallet_id")
    if recorded_wallet is not None and recorded_wallet != wallet_id:
        raise BackupError(503, "audit file wallet_id does not match")
    events = log.get("events")
    if not isinstance(events, list):
        raise BackupError(503, "audit file events must be a list")
    for event in events:
        if not isinstance(event, dict) or set(event) != _AUDIT_EVENT_KEYS:
            raise BackupError(503, "audit event has an unexpected shape")
        if event.get("type") not in _KNOWN_AUDIT_TYPES:
            raise BackupError(503, "audit file has an unknown event type")


def _validate_manifest_shape(
    manifest: object, files: dict[str, bytes]
) -> dict:
    """校验 manifest v1 形状、成员清单与每项字节/sha256，以及 S 绑定哈希。

    manifest 顶层与每个 files 项都只允许契约键：任何额外键（夹带的标识、
    私钥材料或未知扩展）一律 503，绝不静默忽略后继续。"""
    if not isinstance(manifest, dict):
        raise BackupError(503, "manifest is not a JSON object")
    if not set(manifest) <= _MANIFEST_TOP_KEYS:
        raise BackupError(503, "manifest has an unexpected top-level key")
    if manifest.get("version") != MANIFEST_VERSION:
        raise BackupError(503, "unsupported manifest version")
    wallet_id = manifest.get("wallet_id")
    snapshot_id = manifest.get("snapshot_id")
    if not is_safe_id(wallet_id) or not is_safe_id(snapshot_id):
        raise BackupError(503, "manifest has invalid wallet or snapshot id")
    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise BackupError(503, "manifest files must be a list")
    bound = manifest.get("manifest_sha256")
    if not isinstance(bound, str) or not _is_sha256_hex(bound):
        raise BackupError(503, "manifest is missing its binding hash")
    if sha256_hex(_canonical_manifest_body(manifest)) != bound:
        raise BackupError(503, "manifest binding hash mismatch")
    # 归一为"规范主体 + 绑定哈希"：保证同 S 同哈希的重放返回与首次逐字节
    # 一致的 manifest（同体），忽略包内任何额外键/排版差异。
    normalized = json.loads(_canonical_manifest_body(manifest))
    normalized["manifest_sha256"] = bound
    seen: set[str] = set()
    prev_path: Optional[str] = None
    for entry in entries:
        if not isinstance(entry, dict):
            raise BackupError(503, "manifest entry is not an object")
        if not set(entry) <= _MANIFEST_ENTRY_KEYS:
            raise BackupError(503, "manifest entry has an unexpected key")
        path = entry.get("path")
        nbytes = entry.get("bytes")
        digest = entry.get("sha256")
        if not isinstance(path, str) or path in seen:
            raise BackupError(503, "manifest has a missing or duplicate path")
        # 契约要求 files 项严格按 path 升序：即使绑定哈希自洽（包可被整体
        # 重造），乱序清单也不是合法快照形状，绝不据其恢复或落 committed。
        if prev_path is not None and path <= prev_path:
            raise BackupError(503, "manifest files are not sorted by path")
        prev_path = path
        seen.add(path)
        if not _is_whitelisted(wallet_id, path):
            raise BackupError(503, "manifest lists a non-whitelisted path")
        if not isinstance(nbytes, int) or isinstance(nbytes, bool) or nbytes < 0:
            raise BackupError(503, "manifest entry has a bad byte count")
        if not isinstance(digest, str) or not _is_sha256_hex(digest):
            raise BackupError(503, "manifest entry has a bad sha256")
        data = files.get(path)
        if data is None or len(data) != nbytes or sha256_hex(data) != digest:
            raise BackupError(503, "snapshot file fails its manifest hash")
    extra = set(files) - seen
    if extra:
        raise BackupError(503, "snapshot contains files absent from the manifest")
    if not any(p == f"wallets/{wallet_id}.json" for p in seen):
        raise BackupError(503, "snapshot is missing the wallet metadata file")
    # 激活备份（*.bak.json）只是激活事务窗口内的瞬态文件，持锁备份前的
    # 自愈必然已回滚/清理：合法快照里出现它们等于打包了半状态，拒绝。
    if any(
        p.startswith(f"rotation-staging/{wallet_id}/")
        and p.endswith(".bak.json")
        for p in seen
    ):
        raise BackupError(503, "snapshot must not carry transient rotation backups")
    return normalized


def _load_json_object(data: bytes, what: str) -> dict:
    try:
        value = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise BackupError(503, f"{what} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise BackupError(503, f"{what} must be a JSON object")
    return value


# ---- 业务对账（形状/公私钥/审计/账本/会话/轮换/签名）--------------------

def _request_shape_ok(key: str, record: object) -> bool:
    """审批单记录的最小形状（state 机/审批人/时间窗）。"""
    from .store import parse_utc_iso

    if not isinstance(record, dict):
        return False
    if set(record) != _REQUEST_RECORD_KEYS:
        return False
    if record.get("id") != key:
        return False
    if not isinstance(record.get("message"), str):
        return False
    if record.get("state") not in (
        "pending", "approved", "rejected", "expired", "signed",
    ):
        return False
    approvers = record.get("approvers")
    if not isinstance(approvers, list) or not all(
        isinstance(a, str) for a in approvers
    ) or len(set(approvers)) != len(approvers):
        return False
    if record.get("req") not in (1, 2):
        return False
    if parse_utc_iso(record.get("t0")) is None:
        return False
    t1 = parse_utc_iso(record.get("t1"))
    if t1 is None or t1 <= parse_utc_iso(record.get("t0")):
        return False
    reason = record.get("reason")
    if reason is not None and not isinstance(reason, str):
        return False
    # pending 不得已有批准；达到门槛必须是 approved
    approvers_n = len(approvers)
    if approvers_n > record.get("req"):
        return False
    if record.get("state") == "approved" and approvers_n < record.get("req"):
        return False
    return True


def _verify_inuse_shares(wallet: dict, files: dict[str, bytes], wallet_id: str) -> None:
    """逐份校验当前在用份额：私钥 32 字节、推导公钥匹配、两份拼成钱包公钥。"""
    from . import crypto

    shares = wallet.get("shares")
    public_hex = wallet.get("public_key")
    if (
        not isinstance(shares, list)
        or len(shares) != 2
        or len({s.get("share_id") for s in shares if isinstance(s, dict)}) != 2
        or not isinstance(public_hex, str)
    ):
        raise BackupError(503, "wallet metadata shares are malformed")
    # 钱包元数据文件只允许公开契约键（wallet_id/created_at/public_key/
    # shares），份额条目只允许 share_id/public_key：任何私钥材料或夹带的
    # 额外字段都不得出现在非份额文件中。
    if not set(wallet) <= _WALLET_META_KEYS:
        raise BackupError(503, "wallet metadata has an unexpected key")
    from .store import parse_utc_iso

    if parse_utc_iso(wallet.get("created_at")) is None:
        raise BackupError(503, "wallet metadata has a bad created_at")
    for entry in shares:
        if not isinstance(entry, dict) or set(entry) != _WALLET_SHARE_ENTRY_KEYS:
            raise BackupError(503, "wallet metadata shares are malformed")
    try:
        wallet_pub = bytes.fromhex(public_hex)
    except ValueError:
        raise BackupError(503, "wallet public_key is not hex")
    if len(wallet_pub) != 64:
        raise BackupError(503, "wallet public_key has a bad length")
    pubs: list[bytes] = []
    share_dir_prefix = f"shares/{wallet_id}/"
    share_files = {p for p in files if p.startswith(share_dir_prefix)}
    expected_share_files = set()
    for index, entry in enumerate(shares):
        share_id = entry.get("share_id")
        meta_pub_hex = entry.get("public_key")
        if not isinstance(share_id, str) or not isinstance(meta_pub_hex, str):
            raise BackupError(503, "wallet metadata shares are malformed")
        rel = f"{share_dir_prefix}{share_id}.json"
        expected_share_files.add(rel)
        if rel not in files:
            raise BackupError(503, "snapshot is missing an in-use share file")
        record = _load_json_object(files[rel], "share file")
        priv_hex = record.get("private_key")
        rec_pub_hex = record.get("public_key")
        if set(record) != _SHARE_RECORD_KEYS or (
            record.get("share_id") != share_id
            or not isinstance(priv_hex, str)
            or rec_pub_hex != meta_pub_hex
        ):
            raise BackupError(503, "share record does not match wallet metadata")
        try:
            priv = bytes.fromhex(priv_hex)
            pub = bytes.fromhex(rec_pub_hex)
        except ValueError:
            raise BackupError(503, "share key is not hex")
        if len(priv) != 32 or len(pub) != 32:
            raise BackupError(503, "share key has a bad length")
        try:
            if crypto.public_key_from_private(priv) != pub:
                raise BackupError(503, "share private/public key mismatch")
        except (ValueError, TypeError):
            raise BackupError(503, "share private key is invalid")
        if pub != wallet_pub[32 * index: 32 * (index + 1)]:
            raise BackupError(503, "share public keys do not form wallet public_key")
        pubs.append(pub)
    if share_files != expected_share_files:
        # 会话参与者替换/接管份额（<replacement_id>-share 与
        # <takeover_id>-<stage>-share）：必须被包内审计中已提交的
        # session_participant_replaced / session_takeover 事件引用，且
        # 逐份密码学自洽；每个已提交换槽的新份额也必须在包内。否则 503。
        replacement_ids = _committed_participant_share_ids(files, wallet_id)
        for rel in sorted(share_files - expected_share_files):
            share_id = rel[len(share_dir_prefix):-len(".json")]
            if share_id not in replacement_ids:
                raise BackupError(
                    503, "share directory does not match the in-use share set"
                )
            record = _load_json_object(files[rel], "share file")
            priv_hex = record.get("private_key")
            rec_pub_hex = record.get("public_key")
            if set(record) != _SHARE_RECORD_KEYS or (
                record.get("share_id") != share_id
                or not isinstance(priv_hex, str)
                or not isinstance(rec_pub_hex, str)
            ):
                raise BackupError(503, "replacement share record is malformed")
            try:
                priv = bytes.fromhex(priv_hex)
                pub = bytes.fromhex(rec_pub_hex)
            except ValueError:
                raise BackupError(503, "replacement share key is not hex")
            if len(priv) != 32 or len(pub) != 32:
                raise BackupError(503, "replacement share key has a bad length")
            try:
                if crypto.public_key_from_private(priv) != pub:
                    raise BackupError(
                        503, "replacement share private/public key mismatch"
                    )
            except (ValueError, TypeError):
                raise BackupError(503, "replacement share private key is invalid")
        for share_id in replacement_ids:
            if f"{share_dir_prefix}{share_id}.json" not in share_files:
                raise BackupError(
                    503, "snapshot is missing a committed replacement share"
                )
    if b"".join(pubs) != wallet_pub:
        raise BackupError(503, "wallet public_key does not match its shares")


def _committed_participant_share_ids(
    files: dict[str, bytes], wallet_id: str
) -> set:
    """从包内审计日志收集已提交 session_participant_replaced 与
    session_takeover 事件的 new_share_id 集合（无审计文件/无事件为空集）。

    事件形状本身由 _verify_audit_contract 与线上恢复器严格校验；这里
    只做份额文件 ↔ 提交事件的集合对账。"""
    rel = f"audit/{wallet_id}.json"
    if rel not in files:
        return set()
    log = _load_json_object(files[rel], "audit file")
    events = log.get("events")
    if not isinstance(events, list):
        return set()
    result = set()
    for event in events:
        if not isinstance(event, dict):
            continue
        if event.get("type") not in (
            "session_participant_replaced",
            "session_takeover",
        ):
            continue
        details = event.get("details")
        if isinstance(details, dict) and isinstance(
            details.get("new_share_id"), str
        ):
            result.add(details["new_share_id"])
    return result


def _verify_historical_signatures(
    wallet_id: str, files: dict[str, bytes], scratch: WalletStore
) -> None:
    """每条已完成签名都能用其**签名时刻**的钱包公钥独立验通（连续可验）。

    签名时刻公钥由审计轮换链确定：首个激活事件的 previous_public_key 为
    创世公钥；每次激活的 public_key 自其 seq 起生效。签名以对应
    request_signed 事件 seq 定位公钥。签名记录与 signed 事件必须一一对应、
    message 一致；任一不符 fail-closed（503）。
    """
    from . import audit as audit_mod
    from . import crypto

    sig_rel = f"signatures/{wallet_id}.json"
    if sig_rel not in files:
        # 没有签名文件：有 signed 事件也算不一致（下方事件侧对账）
        signatures = {}
    else:
        signatures = _load_json_object(files[sig_rel], "signatures file")
    sig_by_id: dict[str, dict] = {}
    for key, record in signatures.items():
        if not isinstance(key, str) or not _SAFE_ID.match(key) or not isinstance(
            record, dict
        ):
            raise BackupError(503, "signatures file is malformed")
        message = record.get("message")
        signature_hex = record.get("signature")
        if not isinstance(message, str) or not isinstance(signature_hex, str):
            raise BackupError(503, "signature record is malformed")
        try:
            signature = bytes.fromhex(signature_hex)
        except ValueError:
            raise BackupError(503, "signature is not hex")
        if len(signature) != 128:
            raise BackupError(503, "aggregate signature has a bad length")
        sig_by_id[key] = {"message": message, "signature": signature}

    audit_store = audit_mod.AuditStore(scratch.data_dir)
    signed_events = audit_store.events_by_type(
        wallet_id, audit_mod.TYPE_REQUEST_SIGNED
    )
    activated = sorted(
        audit_store.activated_rotation_events(wallet_id).values(),
        key=lambda e: e.get("seq", 0),
    )

    wallet = _load_json_object(
        files[f"wallets/{wallet_id}.json"], "wallet file"
    )
    try:
        current_pub = bytes.fromhex(wallet["public_key"])
    except (KeyError, ValueError, TypeError):
        raise BackupError(503, "wallet public_key is invalid")
    genesis_pub = (
        bytes.fromhex(activated[0]["details"]["previous_public_key"])
        if activated
        else current_pub
    )
    if len(genesis_pub) != 64:
        raise BackupError(503, "genesis public key has a bad length")

    def public_key_at(seq: int) -> bytes:
        effective = genesis_pub
        for event in activated:
            if event["seq"] < seq:
                effective = bytes.fromhex(event["details"]["public_key"])
            else:
                break
        return effective

    signed_ids = set()
    for event in signed_events:
        rid = event.get("request_id")
        details = event.get("details")
        if not isinstance(rid, str) or not isinstance(details, dict):
            raise BackupError(503, "request_signed event is malformed")
        signed_ids.add(rid)
        record = sig_by_id.get(rid)
        if record is None:
            raise BackupError(503, "signed audit event has no matching signature")
        if details.get("message") != record["message"]:
            raise BackupError(503, "signed event disagrees with its signature record")
        public = public_key_at(event["seq"])
        payload = rid.encode("utf-8") + record["message"].encode("utf-8")
        halves_sig = (record["signature"][:64], record["signature"][64:])
        halves_pub = (public[:32], public[32:])
        for sig_half, pub_half in zip(halves_sig, halves_pub):
            if not crypto.verify_share(pub_half, payload, sig_half):
                raise BackupError(503, "historical signature does not verify")
    if set(sig_by_id) != signed_ids:
        raise BackupError(503, "signature records and signed events are inconsistent")


def _verify_requests_against_audit(
    wallet_id: str, files: dict[str, bytes], scratch: WalletStore
) -> None:
    """审批单文件与审计事件双向对账（启动恢复器不覆盖审批单，这里补全）。

    - 每条审批单必有 request_created 事件且 message 一致；反之每个
      request_created 事件必须有对应审批单；
    - signed/expired/rejected 状态必有同名终态事件；pending 不得有终态；
    - approved 的审批人集合/计数与 request_approved 事件一致；
    - 有 request_signed 事件的单状态必须是 signed。
    """
    from . import audit as audit_mod

    audit_store = audit_mod.AuditStore(scratch.data_dir)
    rel = f"requests/{wallet_id}.json"
    requests = (
        _load_json_object(files[rel], "requests file") if rel in files else {}
    )
    created = audit_store.events_by_type(
        wallet_id, audit_mod.TYPE_REQUEST_CREATED
    )
    approved = audit_store.events_by_type(
        wallet_id, audit_mod.TYPE_REQUEST_APPROVED
    )
    rejected = audit_store.events_by_type(
        wallet_id, audit_mod.TYPE_REQUEST_REJECTED
    )
    expired = audit_store.events_by_type(
        wallet_id, audit_mod.TYPE_REQUEST_EXPIRED
    )
    signed = audit_store.events_by_type(
        wallet_id, audit_mod.TYPE_REQUEST_SIGNED
    )
    by_rid: dict[str, dict[str, list[dict]]] = {}
    for kind, evs in (
        ("created", created), ("approved", approved), ("rejected", rejected),
        ("expired", expired), ("signed", signed),
    ):
        for ev in evs:
            rid = ev.get("request_id")
            if not isinstance(rid, str):
                raise BackupError(503, "request audit event lacks request_id")
            by_rid.setdefault(rid, {}).setdefault(kind, []).append(ev)

    for rid, record in requests.items():
        groups = by_rid.get(rid)
        c_evs = (groups or {}).get("created", [])
        if len(c_evs) != 1:
            raise BackupError(503, "request record and created events disagree")
        if c_evs[0].get("details", {}).get("message") != record["message"]:
            raise BackupError(503, "request created event disagrees with record")
        state = record["state"]
        terminal_events = {
            kind: len(groups.get(kind, [])) if groups else 0
            for kind in ("signed", "expired", "rejected")
        }
        # 记录终态与审计终态必须严格一致，不允许多余/缺失
        expected_terminal = {
            "pending": None, "approved": None,
            "signed": "signed", "expired": "expired", "rejected": "rejected",
        }[state]
        for kind, count in terminal_events.items():
            want = 1 if kind == expected_terminal else 0
            if count != want:
                raise BackupError(
                    503, "request terminal state disagrees with its events"
                )
        # 审批人集合（去重）与计数必须和 request_approved 事件一致；
        # pending 允许已有部分批准但未达门槛，approved 必须恰达门槛。
        approver_ids = [
            e.get("actor_id") for e in (groups or {}).get("approved", [])
        ]
        if any(not isinstance(a, str) for a in approver_ids):
            raise BackupError(503, "approve event lacks a valid actor_id")
        if set(approver_ids) != set(record["approvers"]):
            raise BackupError(503, "request approvers do not match its events")
        if state == "approved" and len(record["approvers"]) != record["req"]:
            raise BackupError(503, "approved request never reached its quorum")
    # 反向：每个 request_created 事件都必须有审批单。注意无审批策略时
    # /sign 可直接产生 request_signed 事件而没有审批单/created 事件，
    # 那种单不在此对账范围内（其连续性由历史签名校验负责）。
    for ev in created:
        rid = ev.get("request_id")
        if rid not in requests:
            raise BackupError(503, "created event has no request record")


def _verify_business_shapes(wallet_id: str, files: dict[str, bytes]) -> None:
    """对业务文件做严格形状与契约键校验（任何夹带/畸形一律 503）。

    覆盖：审批策略、交易策略、审批单、已完成签名、轮换记录。审计/账本/
    会话/暂存份额由线上恢复器做严格对账；此处补齐恢复器不逐键覆盖的
    文件，保证非份额文件不含任何 private_key 字段、每类文件只含契约键。
    """
    from .store import approval_policy_shape_ok, transaction_policy_shape_ok

    rel = f"policies/{wallet_id}.json"
    if rel in files:
        policy = _load_json_object(files[rel], "approval policy file")
        if set(policy) != _APPROVAL_POLICY_KEYS or not approval_policy_shape_ok(
            policy
        ):
            raise BackupError(503, "approval policy file is malformed")
    rel = f"transaction-policies/{wallet_id}.json"
    if rel in files:
        policy = _load_json_object(files[rel], "transaction policy file")
        if set(policy) != _TRANSACTION_POLICY_KEYS or not (
            transaction_policy_shape_ok(policy)
        ):
            raise BackupError(503, "transaction policy file is malformed")
    rel = f"requests/{wallet_id}.json"
    if rel in files:
        requests = _load_json_object(files[rel], "requests file")
        for key, record in requests.items():
            if not isinstance(key, str) or not _SAFE_ID.match(key) or not (
                _request_shape_ok(key, record)
            ):
                raise BackupError(503, "requests file is malformed")
    _verify_signatures_shapes(wallet_id, files)
    _verify_rotations_shapes(wallet_id, files)


def _verify_signatures_shapes(wallet_id: str, files: dict[str, bytes]) -> None:
    """signatures/<W>.json：顶层对象，每键安全标识，记录恰为
    {message, signature}，signature 为 128 字节 hex。绝不含私钥字段。"""
    rel = f"signatures/{wallet_id}.json"
    if rel not in files:
        return
    signatures = _load_json_object(files[rel], "signatures file")
    for key, record in signatures.items():
        if not isinstance(key, str) or not _SAFE_ID.match(key):
            raise BackupError(503, "signatures file has a bad request id")
        if not isinstance(record, dict) or set(record) != _SIGNATURE_RECORD_KEYS:
            raise BackupError(503, "signature record is malformed")
        message = record.get("message")
        signature_hex = record.get("signature")
        if not isinstance(message, str) or not message or not isinstance(
            signature_hex, str
        ):
            raise BackupError(503, "signature record is malformed")
        try:
            signature = bytes.fromhex(signature_hex)
        except ValueError:
            raise BackupError(503, "signature is not hex")
        if len(signature) != 128:
            raise BackupError(503, "aggregate signature has a bad length")


def _verify_rotations_shapes(wallet_id: str, files: dict[str, bytes]) -> None:
    """rotations/<W>.json：顶层对象，每键安全标识且等于记录 rotation_id，
    记录只允许轮换契约键，state/share_ids/public_key 形状严格。"""
    rel = f"rotations/{wallet_id}.json"
    if rel not in files:
        return
    rotations = _load_json_object(files[rel], "rotations file")
    for key, record in rotations.items():
        if not isinstance(key, str) or not _SAFE_ID.match(key):
            raise BackupError(503, "rotations file has a bad rotation id")
        if not isinstance(record, dict) or not set(record) <= _ROTATION_RECORD_KEYS:
            raise BackupError(503, "rotation record is malformed")
        if record.get("rotation_id") != key:
            raise BackupError(503, "rotation record id does not match its key")
        state = record.get("state")
        if state not in ("prepared", "activating", "active"):
            raise BackupError(503, "rotation record has a bad state")
        share_ids = record.get("share_ids")
        if (
            not isinstance(share_ids, list)
            or len(share_ids) != 2
            or len(set(share_ids)) != 2
            or not all(
                isinstance(sid, str) and bool(_SAFE_SHARE_ID.match(sid))
                for sid in share_ids
            )
        ):
            raise BackupError(503, "rotation record has bad share_ids")
        try:
            if len(bytes.fromhex(record.get("public_key", ""))) != 64:
                raise ValueError
        except (ValueError, TypeError):
            raise BackupError(503, "rotation record has a bad public_key")
        created_at = record.get("created_at")
        if created_at is not None and not isinstance(created_at, str):
            raise BackupError(503, "rotation record has a bad created_at")
        previous = record.get("previous_public_key")
        if state == "prepared":
            if previous is not None:
                raise BackupError(503, "prepared rotation carries a previous key")
        elif previous is None:
            # 已激活轮必须携带 previous_public_key，连续轮换时间线据此重建
            raise BackupError(503, "active rotation lacks its previous key")
        if previous is not None:
            try:
                if len(bytes.fromhex(previous)) != 64:
                    raise ValueError
            except (ValueError, TypeError):
                raise BackupError(503, "rotation record has a bad previous key")


def _json_contains_key(value: object, forbidden: str) -> bool:
    """递归检查已解析 JSON 中是否出现名为 forbidden 的键。"""
    if isinstance(value, dict):
        if forbidden in value:
            return True
        return any(_json_contains_key(v, forbidden) for v in value.values())
    if isinstance(value, list):
        return any(_json_contains_key(v, forbidden) for v in value)
    return False


def _verify_no_private_key_in_business_files(
    wallet_id: str, files: dict[str, bytes]
) -> None:
    """非份额文件（wallets/业务目录）绝不得含任何 private_key 字段。

    shares/<W>/* 与 rotation-staging/<W>/<rid>/<share>.json 是全系统唯一
    允许存放份额私钥的位置；其余文件即使哈希自洽，夹带私钥字段也属隔离
    破坏，一律 503。
    """
    for rel, data in files.items():
        parts = rel.split("/")
        if parts[0] in ("shares", "rotation-staging"):
            continue
        try:
            value = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            # 非 JSON 的白名单文件不存在；形状校验在他处统一处理
            continue
        if _json_contains_key(value, _PRIVATE_KEY_FIELD):
            raise BackupError(503, "private key material outside share files")


def _verify_staging_shapes(wallet_id: str, files: dict[str, bytes]) -> None:
    """rotation-staging 中合法快照只能含 prepared 新份额（恰三契约键）。

    *.bak.json 激活备份已在 manifest 校验阶段拒绝；此处逐份校验暂存份额
    记录形状（share_id/public_key/private_key，hex 长度），密码学对应关系
    由 scratch 恢复器的 prepared 暂存校验负责。
    """
    prefix = f"rotation-staging/{wallet_id}/"
    for rel, data in files.items():
        if not rel.startswith(prefix):
            continue
        if rel.endswith(".bak.json") or rel.rsplit("/", 1)[-1] == "wallet.bak.json":
            raise BackupError(503, "snapshot must not carry transient backups")
        record = _load_json_object(data, "staged share file")
        if set(record) != _SHARE_RECORD_KEYS:
            raise BackupError(503, "staged share record is malformed")
        expected_share_id = rel.rsplit("/", 1)[-1][: -len(".json")]
        if record.get("share_id") != expected_share_id:
            raise BackupError(503, "staged share id does not match its file")
        try:
            if len(bytes.fromhex(record.get("public_key", ""))) != 32 or len(
                bytes.fromhex(record.get("private_key", ""))
            ) != 32:
                raise ValueError
        except (ValueError, TypeError):
            raise BackupError(503, "staged share key has a bad length")


def _verify_snapshot(
    service: WalletService,
    wallet_id: str,
    manifest: dict,
    files: dict[str, bytes],
) -> None:
    """锁内完整对账校验（失败抛 BackupError(503)，绝不写盘）。

    做法：把候选文件写入**临时目录**，在其上运行与线上完全相同的启动恢复
    （审计 seq 连续、轮换激活链、账本语义与 committed 事件、会话严格
    加载），再显式校验在用份额公私钥、策略/审批单形状与全部历史签名。
    合法快照是已对账现场，恢复器不得改动任何业务文件——若改动说明快照
    夹带了半状态，同样拒绝。
    """
    import tempfile

    from .store import CorruptDataError as _CD
    from .store import RecoveryError as _RE

    wallet = _load_json_object(
        files[f"wallets/{wallet_id}.json"], "wallet file"
    )
    if wallet.get("wallet_id") != wallet_id:
        raise BackupError(503, "wallet file id does not match its file name")
    _verify_no_private_key_in_business_files(wallet_id, files)
    _verify_audit_contract(wallet_id, files)
    _verify_inuse_shares(wallet, files, wallet_id)
    _verify_staging_shapes(wallet_id, files)
    _verify_business_shapes(wallet_id, files)

    scratch_dir = tempfile.mkdtemp(prefix="dr-verify-")
    try:
        for rel, data in files.items():
            target = os.path.join(scratch_dir, *rel.split("/"))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            fd, tmp = tempfile.mkstemp(
                dir=os.path.dirname(target), prefix=".v-", suffix=".tmp"
            )
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                os.replace(tmp, target)
            except BaseException:
                try:
                    os.unlink(tmp)
                except FileNotFoundError:
                    pass
                raise
        scratch_store = WalletStore(scratch_dir)
        scratch_service = WalletService(scratch_store, recover=False)
        try:
            # 与线上同一套恢复/对账（孤立临时目录，无需真加锁）
            scratch_service._recover_wallet(wallet_id)
        except (_RE, _CD, ValueError, OSError) as exc:
            raise BackupError(503, "snapshot cannot be reconciled") from exc

        # 恢复后业务文件必须与快照逐字节一致：合法快照是静止已对账现场，
        # 恢复器不应做任何归一化/前滚/回滚/清理。
        for rel, original in files.items():
            if rel == MANIFEST_MEMBER:
                continue
            path = os.path.join(scratch_dir, *rel.split("/"))
            try:
                with open(path, "rb") as f:
                    recovered = f.read()
            except OSError as exc:
                raise BackupError(503, "snapshot is not a settled scene") from exc
            if json.loads(recovered.decode("utf-8")) != json.loads(
                original.decode("utf-8")
            ):
                raise BackupError(503, "snapshot captures an unsettled scene")

        _verify_historical_signatures(wallet_id, files, scratch_store)
        _verify_requests_against_audit(wallet_id, files, scratch_store)
    finally:
        shutil.rmtree(scratch_dir, ignore_errors=True)


# ---- restore-txn 标记与落盘 ----------------------------------------------

def _txn_dir(data_dir: str, wallet_id: str, snapshot_id: str) -> str:
    return os.path.join(
        data_dir, RESTORE_TXN_DIRNAME, wallet_id, snapshot_id
    )


def _txn_old_dir(data_dir: str, wallet_id: str, snapshot_id: str) -> str:
    return os.path.join(_txn_dir(data_dir, wallet_id, snapshot_id), "old")


def _txn_new_dir(data_dir: str, wallet_id: str, snapshot_id: str) -> str:
    """新文件在事务目录内的暂存根（改名落位前），强杀残留也封闭于此。"""
    return os.path.join(_txn_dir(data_dir, wallet_id, snapshot_id), "new")


def _records_path(data_dir: str, wallet_id: str) -> str:
    return os.path.join(
        data_dir, RESTORE_RECORDS_DIRNAME, wallet_id + ".json"
    )


def _atomic_write_bytes(path: str, data: bytes) -> None:
    """原子写整份字节：同目录确定性临时文件 + os.replace。

    临时文件名固定为 ``.<basename>.tmp``（与目标同目录），而不是随机
    mkstemp 名：本事务只有持钱包锁的唯一写者，确定性名使**强杀/断电**
    （``SIGKILL``/``os._exit``，``except`` 清理不会执行）残留的半截临时
    文件在崩溃恢复时可被明确识别为"本事务自己的写中残留"并安全收敛，
    而不会与外部塞入的随机名 ``.tmp-*``/``*.bak.json``/未知文件相混
    （后者仍一律 fail-closed）。重写前先解链旧残留，再以 O_EXCL 建立
    0600 普通文件，绝不跟随既有符号链接。
    """
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    tmp = os.path.join(directory, "." + os.path.basename(path) + ".tmp")
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _atomic_write_json(path: str, value: dict) -> None:
    _atomic_write_bytes(
        path,
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")
        + b"\n",
    )


def _scan_restore_records_dir(data_dir: str) -> None:
    """封闭枚举跨目录登记根 ``restore-records/``（仅扫描，不读内容）。

    与 restore-txn 根同为**跨钱包共享**的扁平目录，其闭集成员恰为：

    - 任意安全标识钱包的正式记录 ``<id>.json``（普通文件）——目标钱包 W 的
      ``W.json`` 是本钱包登记，其他钱包的正式记录允许并存（restore 绝不
      解析或触碰其他钱包的文件）；
    - 任意安全标识钱包的确定性原子写临时名 ``.<id>.json.tmp``——这是
      ``_atomic_write_json`` 写 ``<id>.json`` 时的同目录临时文件：持对应钱包
      锁的写者强杀/断电，或他钱包此刻正持其自己的锁原子登记时，都可能合法
      在场。正式记录缺失时由下一次登记的原子写先解链再 O_EXCL 续作；正式
      记录存在时由 :func:`reconcile_restore_records` 锁内校验后清理。本扫描
      只判定闭集成员资格，绝不据此猜写或恢复（临时名只可能是半截内容）。

    除此之外的一切——符号链接（含指向目录/文件）、子目录、套接字/FIFO 等
    非常规条目、激活备份（``*.bak.json``）、随机原子临时名（``.tmp-*``、
    裸 ``*.tmp`` 等）、非法/越界命名——都意味着登记现场被动过，统一抛
    BackupError(503)，保留现场、fail-closed。

    根不存在视为空（首次恢复前）；根本身是符号链接或非目录同样拒绝。
    """
    root = os.path.join(data_dir, RESTORE_RECORDS_DIRNAME)
    if not os.path.exists(root) and not os.path.islink(root):
        return
    if os.path.islink(root) or not os.path.isdir(root):
        raise BackupError(503, "restore-records root is not a directory")
    try:
        with os.scandir(root) as it:
            entries = list(it)
    except OSError as exc:
        raise BackupError(503, "restore-records directory is unreadable") from exc
    for entry in entries:
        name = entry.name
        if entry.is_symlink():
            raise BackupError(
                503, f"refusing symbolic link in restore-records: {name!r}"
            )
        if not entry.is_file(follow_symlinks=False):
            # 子目录、套接字/FIFO/设备等非常规条目一律拒绝
            raise BackupError(
                503, f"unexpected non-file in restore-records: {name!r}"
            )
        # 正式记录：<safe-id>.json
        if name.endswith(".json") and bool(
            _SAFE_ID.match(name[: -len(".json")])
        ):
            continue
        # 确定性原子写临时名：.<safe-id>.json.tmp（含本钱包的 .W.json.tmp）
        if (
            name.startswith(".")
            and name.endswith(".json.tmp")
            and bool(_SAFE_ID.match(name[1: -len(".json.tmp")]))
        ):
            continue
        # 其余：*.bak.json 激活备份、.tmp-* 等随机临时名、裸 *.tmp、非法命名
        raise BackupError(
            503, f"unexpected entry in restore-records: {name!r}"
        )


def list_records_wallet_ids(data_dir: str) -> list[str]:
    """启动恢复扫描：restore-records/ 内存有正式记录的全部 wallet_id（升序）。

    根目录闭集由 :func:`_scan_restore_records_dir` 强制；任何非闭集条目都抛
    BackupError，由启动恢复 fail-closed（阻止就绪），绝不静默跳过。
    """
    root = os.path.join(data_dir, RESTORE_RECORDS_DIRNAME)
    if not os.path.exists(root) and not os.path.islink(root):
        return []
    _scan_restore_records_dir(data_dir)
    wallet_ids: list[str] = []
    with os.scandir(root) as it:
        for entry in it:
            name = entry.name
            if name.endswith(".json") and bool(
                _SAFE_ID.match(name[: -len(".json")])
            ):
                wallet_ids.append(name[: -len(".json")])
    return sorted(wallet_ids)


def _records_tmp_path(data_dir: str, wallet_id: str) -> str:
    """登记原子写的确定性同目录临时名（``restore-records/.<W>.json.tmp``）。"""
    return os.path.join(
        data_dir, RESTORE_RECORDS_DIRNAME, "." + wallet_id + ".json.tmp"
    )


def _read_restore_records(data_dir: str, wallet_id: str) -> dict:
    """读取 restore-records/<W>.json；不存在返回空结构，损坏抛 BackupError。

    读取前先对共享的 ``restore-records/`` 目录做封闭扫描：只许各钱包正式
    ``<id>.json`` 与其确定性 ``.<id>.json.tmp``；符号链接、目录、备份、任何
    随机临时/非法条目一律 503、保留现场。随后严格校验本钱包记录：

    - 形状：恰含 ``wallet_id``/``snapshots``，``wallet_id`` 与本钱包一致，
      ``snapshots`` 每项为 ``S -> {"manifest_sha256": <64 位小写 hex>}``；
    - 字节级规范形：UTF-8 无 BOM，且逐字节等于
      ``json.dumps(..., ensure_ascii=False, sort_keys=True, indent=2)+"\\n"``
      ——解析通过但重排/空白/缩进/尾换行/BOM 不符的**非规范**记录同样
      不可对账，一律 503、保留现场（绝不静默规范化后继续）。
    """
    _scan_restore_records_dir(data_dir)
    path = _records_path(data_dir, wallet_id)
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        return {"wallet_id": wallet_id, "snapshots": {}}
    except OSError as exc:
        raise BackupError(503, "restore records are unreadable") from exc
    try:
        records = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise BackupError(503, "restore records are corrupt") from exc
    if (
        not isinstance(records, dict)
        or set(records) != {"wallet_id", "snapshots"}
        or records.get("wallet_id") != wallet_id
        or not isinstance(records.get("snapshots"), dict)
    ):
        raise BackupError(503, "restore records are malformed")
    for sid, entry in records["snapshots"].items():
        digest = entry.get("manifest_sha256") if isinstance(entry, dict) else None
        if (
            not is_safe_id(sid)
            or not isinstance(entry, dict)
            or set(entry) != {"manifest_sha256"}
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
        ):
            raise BackupError(503, "restore records are malformed")
    canonical = (
        json.dumps(records, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    if raw != canonical:
        raise BackupError(503, "restore records are not in canonical form")
    return records


def _write_restore_records(
    data_dir: str, wallet_id: str, records: dict
) -> None:
    _atomic_write_json(_records_path(data_dir, wallet_id), records)


def _safe_join(base: str, rel: str) -> str:
    """把白名单相对路径接到 base 下，二次杜绝穿越。"""
    parts = rel.split("/")
    target = os.path.join(base, *parts)
    abs_base = os.path.abspath(base)
    abs_target = os.path.abspath(target)
    if abs_target != abs_base and not abs_target.startswith(abs_base + os.sep):
        raise BackupError(503, "illegal restore path")
    return target


def _list_current_relpaths(data_dir: str, wallet_id: str) -> list[str]:
    """当前 data-dir 中该钱包白名单内现存文件（复用备份期的严格枚举）。"""
    return _iter_whitelist_files(data_dir, wallet_id)


def _file_entry(data_dir: str, rel: str) -> dict:
    """读取白名单普通文件并生成 {path, bytes, sha256} 清单项。

    符号链接/非常规文件一律 BackupError(503)：备份清单与 committed 标记都
    只描述静止已对账现场中的相对普通文件。
    """
    data = _read_regular_file(_safe_join(data_dir, rel))
    return {"path": rel, "bytes": len(data), "sha256": sha256_hex(data)}


def _commit_restore(
    data_dir: str,
    wallet_id: str,
    snapshot_id: str,
    manifest: dict,
    files: dict[str, bytes],
) -> None:
    """prepared 标记之后执行替换：备份现状 → 暂存新文件 → 逐份改名落位。

    崩溃安全的关键在于：**未提交前任何写中残留都只落在本事务自有的
    restore-txn/<W>/<S>/ 命名空间内**，绝不落进业务目录——

    1. 现状逐份复制到 ``old/``，按落盘字节登记 prepared.old_files；
    2. 原子写 prepared.json（确定性临时名 ``.prepared.json.tmp``）；
    3. 快照新文件**先全部写入事务目录内的** ``new/<rel>`` 暂存；
    4. 再用同文件系统上的 ``os.replace`` 把每份暂存文件**改名**到业务
       目标位（改名是原子的，业务目录里永不会出现写中临时文件）；
    5. 删除目标集合之外的旧文件、清空叶子目录。

    这样即使在第 2~5 步任一处被 SIGKILL/断电强杀：业务目录要么仍是旧
    文件、要么已整体换成新文件，绝不会残留半截 ``.tmp-*``；写中残留
    只可能是事务目录内的 ``new/`` 暂存或确定性标记临时名，崩溃恢复据
    committed 是否落盘决定前滚/整体回滚（见 _resume_pending_restore）。

    prepared.json 的 ``old_files`` 携带替换前每个白名单文件的
    ``{path, bytes, sha256}``，是崩溃后"整体回滚"唯一可信依据：回滚前会
    逐项重新核对备份字节与哈希，任何缺失/类型/长度/哈希不符都 fail-closed。
    """
    txn = _txn_dir(data_dir, wallet_id, snapshot_id)
    old_root = _txn_old_dir(data_dir, wallet_id, snapshot_id)
    new_root = _txn_new_dir(data_dir, wallet_id, snapshot_id)
    current = _list_current_relpaths(data_dir, wallet_id)
    old_entries: list[dict] = []
    for rel in current:
        src = _safe_join(data_dir, rel)
        dst = _safe_join(old_root, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)
        # 复制后立即按落盘字节登记长度/哈希，与回滚期重新核对使用同一口径。
        old_entries.append(_file_entry(old_root, rel))
    prepared = {
        "wallet_id": wallet_id,
        "snapshot_id": snapshot_id,
        "manifest_sha256": manifest["manifest_sha256"],
        "old_files": old_entries,
    }
    _atomic_write_json(os.path.join(txn, MARKER_PREPARED), prepared)

    # 新文件先全部暂存进事务自有的 new/：这里产生的任何（含强杀留下的）
    # 半截文件都封闭在 restore-txn 内，恢复时随回滚/清理一并移除。
    for rel, data in files.items():
        staged = _safe_join(new_root, rel)
        _atomic_write_bytes(staged, data)

    # 同文件系统原子改名落位：os.replace 要么未发生、要么目标已是完整新
    # 文件，业务目录中不存在"写了一半的临时文件"窗口。
    for rel in files:
        staged = _safe_join(new_root, rel)
        target = _safe_join(data_dir, rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        os.replace(staged, target)

    target_set = set(files)
    for rel in current:
        if rel not in target_set:
            try:
                os.unlink(_safe_join(data_dir, rel))
            except FileNotFoundError:
                pass
    _prune_empty_leaf_dirs(data_dir, wallet_id)


def _prune_empty_leaf_dirs(data_dir: str, wallet_id: str) -> None:
    """删除替换后变空的钱包份额/暂存叶子目录（绝不删共享业务根目录）。"""
    staging_wallet = os.path.join(
        data_dir, "rotation-staging", wallet_id
    )
    if os.path.isdir(staging_wallet):
        for rid in list(os.listdir(staging_wallet)):
            rid_dir = os.path.join(staging_wallet, rid)
            try:
                if os.path.isdir(rid_dir) and not os.listdir(rid_dir):
                    os.rmdir(rid_dir)
            except OSError:
                pass
        try:
            if not os.listdir(staging_wallet):
                os.rmdir(staging_wallet)
        except OSError:
            pass
    shares_wallet = os.path.join(data_dir, "shares", wallet_id)
    try:
        if os.path.isdir(shares_wallet) and not os.listdir(shares_wallet):
            os.rmdir(shares_wallet)
    except OSError:
        pass


#: prepared / committed 标记允许的契约键
_PREPARED_MARKER_KEYS = frozenset(
    ("wallet_id", "snapshot_id", "manifest_sha256", "old_files")
)
_COMMITTED_MARKER_KEYS = frozenset(
    ("wallet_id", "snapshot_id", "manifest_sha256", "files")
)

#: 标记内每个 files/old_files 项允许的契约键（与 manifest entry 同形）
_MARKER_ENTRY_KEYS = frozenset(("path", "bytes", "sha256"))


def _validate_marker_entries(
    wallet_id: str, entries: object, what: str
) -> list[dict]:
    """严格校验标记内的文件清单，返回归一的 path/bytes/sha256 项列表。

    每项路径必须是目标钱包白名单内的相对普通文件形状（不判现存，只判形状/
    归属），不得重复、不得越界（``..``/绝对/反斜杠/盘符）；bytes 为非布尔
    非负整数，sha256 为 64 位小写 hex。任何不符抛 RecoveryError——标记损坏
    即无法安全对账，调用方必须保留现场 fail-closed。
    """
    if not isinstance(entries, list):
        raise RecoveryError(f"{what} marker file list is malformed")
    normalized: list[dict] = []
    seen: set[str] = set()
    prev_path: Optional[str] = None
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != _MARKER_ENTRY_KEYS:
            raise RecoveryError(f"{what} marker entry is malformed")
        rel = entry.get("path")
        nbytes = entry.get("bytes")
        digest = entry.get("sha256")
        if not isinstance(rel, str) or rel in seen:
            raise RecoveryError(f"{what} marker has a missing or duplicate path")
        # 契约要求清单项严格按 path 升序：乱序标记即形状损坏，绝不据其
        # 前滚/回滚（fail-closed 保留现场）。
        if prev_path is not None and rel <= prev_path:
            raise RecoveryError(f"{what} marker file list is not sorted by path")
        prev_path = rel
        seen.add(rel)
        try:
            _validate_member_name(rel)
        except BackupError as exc:
            raise RecoveryError(f"{what} marker lists an illegal path") from exc
        if not _is_whitelisted(wallet_id, rel):
            raise RecoveryError(f"{what} marker lists a non-whitelisted path")
        if (
            not isinstance(nbytes, int)
            or isinstance(nbytes, bool)
            or nbytes < 0
        ):
            raise RecoveryError(f"{what} marker entry has a bad byte count")
        if not isinstance(digest, str) or not _is_sha256_hex(digest):
            raise RecoveryError(f"{what} marker entry has a bad sha256")
        normalized.append(
            {"path": rel, "bytes": nbytes, "sha256": digest}
        )
    return normalized


def _read_txn_marker(path: str, what: str) -> dict:
    """读取并校验一个 restore-txn 标记为 JSON 对象（拒绝符号链接/非常规文件）。"""
    if os.path.islink(path) or not os.path.isfile(path):
        raise RecoveryError(f"{what} marker is not a regular file")
    try:
        with open(path, "rb") as f:
            value = json.loads(f.read().decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise RecoveryError(f"{what} marker is unreadable") from exc
    if not isinstance(value, dict):
        raise RecoveryError(f"{what} marker is malformed")
    return value


#: restore-txn/<W>/<S>/ 目录直接成员的唯一闭集
_TXN_OLD_DIRNAME = "old"
_TXN_NEW_DIRNAME = "new"

#: 两个标记确定性原子写临时名（与 _atomic_write_bytes 的命名一致）。
#: 它们是本事务**自己**强杀/断电后可能残留的写中临时文件，与外部塞入的
#: 随机名 ``.tmp-*`` 严格区分：只在对应最终标记尚未落盘时才可能出现。
_PREPARED_MARKER_TMP = "." + MARKER_PREPARED + ".tmp"
_COMMITTED_MARKER_TMP = "." + MARKER_COMMITTED + ".tmp"


def _scan_txn_snapshot_dir(txn_dir: str) -> dict[str, bool]:
    """封闭枚举单个 restore-txn/<W>/<S>/ 目录的直接成员。

    契约闭集：该目录**只**能含 ``prepared.json``、``committed.json``（普通
    文件）、``old/``、``new/``（目录）以及两个标记各自的**确定性**写中
    临时文件 ``.prepared.json.tmp`` / ``.committed.json.tmp``。

    任何符号链接、非常规文件、随机名原子临时文件（``.tmp-*.json``）、
    激活备份（``*.bak.json``）或其余未知文件/目录都意味着事务现场被动过，
    统一抛 RecoveryError（保留现场、fail-closed）。

    两个确定性临时名只在其最终标记**尚未**落盘时才可能残留（原子改名一旦
    完成临时名即消失）；若临时名与同名最终标记同时在场，属矛盾现场，同样
    fail-closed。

    返回各成员是否在场的标志，供调用方决定前滚/回滚/空目录清理。
    """
    if os.path.islink(txn_dir) or not os.path.isdir(txn_dir):
        raise RecoveryError("restore transaction entry is not a directory")
    try:
        with os.scandir(txn_dir) as it:
            entries = list(it)
    except OSError as exc:
        raise RecoveryError("restore transaction directory is unreadable") from exc
    flags = {
        MARKER_PREPARED: False,
        MARKER_COMMITTED: False,
        _TXN_OLD_DIRNAME: False,
        _TXN_NEW_DIRNAME: False,
        _PREPARED_MARKER_TMP: False,
        _COMMITTED_MARKER_TMP: False,
    }
    for entry in entries:
        name = entry.name
        if entry.is_symlink():
            raise RecoveryError(
                f"refusing symbolic link in restore transaction: {name!r}"
            )
        if name == MARKER_PREPARED or name == MARKER_COMMITTED:
            if not entry.is_file(follow_symlinks=False):
                raise RecoveryError(f"restore marker {name!r} is not a regular file")
            flags[name] = True
        elif name == _TXN_OLD_DIRNAME or name == _TXN_NEW_DIRNAME:
            if not entry.is_dir(follow_symlinks=False):
                raise RecoveryError(f"restore stage {name!r} is not a directory")
            flags[name] = True
        elif name == _PREPARED_MARKER_TMP or name == _COMMITTED_MARKER_TMP:
            if not entry.is_file(follow_symlinks=False):
                raise RecoveryError(f"restore temp {name!r} is not a regular file")
            flags[name] = True
        else:
            # 随机 .tmp-*、*.bak.json、未知文件、额外目录一律拒绝
            raise RecoveryError(
                f"unexpected entry in restore transaction directory: {name!r}"
            )
    # 原子改名完成后临时名必已消失：最终标记与其写中临时名同时在场只能是
    # 篡改/矛盾现场，绝不基于它做任何收敛。
    if flags[MARKER_PREPARED] and flags[_PREPARED_MARKER_TMP]:
        raise RecoveryError(
            "prepared marker and its write temp coexist in restore transaction"
        )
    if flags[MARKER_COMMITTED] and flags[_COMMITTED_MARKER_TMP]:
        raise RecoveryError(
            "committed marker and its write temp coexist in restore transaction"
        )
    return flags


def _scan_new_stage_tree(new_root: str, wallet_id: str) -> set[str]:
    """递归封闭枚举事务内 ``new/`` 暂存树，返回其中正式暂存文件相对路径集。

    ``new/`` 是**未提交前**的自有暂存命名空间（改名落位的源），任何收敛
    路径都不会信任或还原因其中内容：committed 未落盘时随整体回滚连同事务
    目录一并删除，committed 已落盘时只可能剩下空目录。这里仍做闭集结构
    校验，防止符号链接/越界/非常规条目混入：

    - 任何层级符号链接、套接字/FIFO/设备等非常规条目一律拒绝；
    - 每个路径段合法（拒绝 ``..``/绝对/反斜杠）；
    - 普通文件要么是该钱包白名单内相对路径的暂存正式文件，要么是其同目录
      确定性写中临时名 ``.<leaf>.tmp``，其余一律拒绝。
    """
    if not os.path.exists(new_root) and not os.path.islink(new_root):
        return set()
    if os.path.islink(new_root) or not os.path.isdir(new_root):
        raise RecoveryError("restore stage 'new' is not a directory")
    staged: set[str] = set()

    def walk(abs_dir: str, rel_dir: str) -> None:
        try:
            with os.scandir(abs_dir) as it:
                entries = list(it)
        except OSError as exc:
            raise RecoveryError("restore stage directory is unreadable") from exc
        for entry in entries:
            rel = entry.name if not rel_dir else f"{rel_dir}/{entry.name}"
            if entry.is_symlink():
                raise RecoveryError("refusing symbolic link in restore stage")
            if entry.is_dir(follow_symlinks=False):
                try:
                    _validate_member_name(rel)
                except BackupError as exc:
                    raise RecoveryError(
                        "restore stage contains an illegal directory"
                    ) from exc
                walk(entry.path, rel)
            elif entry.is_file(follow_symlinks=False):
                try:
                    _validate_member_name(rel)
                except BackupError as exc:
                    raise RecoveryError(
                        "restore stage contains an illegal path"
                    ) from exc
                if _is_whitelisted(wallet_id, rel):
                    staged.add(rel)
                    continue
                # 确定性写中临时名：".<leaf>.tmp"，其去掉前缀/后缀后的
                # 同目录目标必须是白名单暂存文件。
                dname, leaf = rel.rsplit("/", 1) if "/" in rel else ("", rel)
                if leaf.startswith(".") and leaf.endswith(".tmp"):
                    target_leaf = leaf[1:-len(".tmp")]
                    target_rel = (
                        target_leaf if not dname else f"{dname}/{target_leaf}"
                    )
                    if _is_whitelisted(wallet_id, target_rel):
                        continue
                raise RecoveryError(
                    "restore stage contains an unexpected file"
                )
            else:
                raise RecoveryError("non-regular entry in restore stage")

    walk(new_root, "")
    return staged


def _expected_backup_dirs(file_set: set[str]) -> set[str]:
    """备份文件集合隐含的全部祖先目录（相对 old/，不含 "."）。"""
    dirs: set[str] = set()
    for rel in file_set:
        parts = rel.split("/")
        for depth in range(1, len(parts)):
            dirs.add("/".join(parts[:depth]))
    return dirs


def _scan_old_backup_tree(old_root: str, wallet_id: str) -> tuple[set, set]:
    """递归封闭枚举 old/ 备份树，返回 (备份文件相对路径集, 子目录相对路径集)。

    与旧的纯文件枚举不同，这里**连目录也逐一对账**：

    - 任何层级的符号链接（含指向目录的链接）一律拒绝（绝不跟随）；
    - 套接字/FIFO/设备等非常规条目一律拒绝；
    - 每个文件路径段合法、整体属于目标钱包白名单（拒绝 ``..``/绝对/非白名单）；
    - 空子目录、与备份清单无关的额外目录也会出现在返回的目录集中，由调用方
      与"清单文件的祖先目录闭包"严格比对后拒绝。
    """
    if not os.path.exists(old_root) and not os.path.islink(old_root):
        return set(), set()
    if os.path.islink(old_root) or not os.path.isdir(old_root):
        raise RecoveryError("restore backup root is not a directory")
    files: set[str] = set()
    dirs: set[str] = set()

    def walk(abs_dir: str, rel_dir: str) -> None:
        try:
            with os.scandir(abs_dir) as it:
                entries = list(it)
        except OSError as exc:
            raise RecoveryError("restore backup directory is unreadable") from exc
        for entry in entries:
            rel = entry.name if not rel_dir else f"{rel_dir}/{entry.name}"
            if entry.is_symlink():
                raise RecoveryError(
                    "refusing symbolic link in restore backup"
                )
            if entry.is_dir(follow_symlinks=False):
                # 目录名也必须是合法、白名单内的路径段
                try:
                    _validate_member_name(rel)
                except BackupError as exc:
                    raise RecoveryError(
                        "restore backup contains an illegal directory"
                    ) from exc
                dirs.add(rel)
                walk(entry.path, rel)
            elif entry.is_file(follow_symlinks=False):
                try:
                    _validate_member_name(rel)
                except BackupError as exc:
                    raise RecoveryError(
                        "restore backup contains an illegal path"
                    ) from exc
                if not _is_whitelisted(wallet_id, rel):
                    raise RecoveryError(
                        "restore backup contains a non-whitelisted path"
                    )
                files.add(rel)
            else:
                raise RecoveryError("non-regular entry in restore backup")

    walk(old_root, "")
    return files, dirs


def _verify_old_backup(
    txn: str, wallet_id: str, snapshot_id: str, prepared: dict
) -> list[dict]:
    """严格校验一个已确认形状自洽的 prepared 标记所登记的 old/ 备份。

    - old_files 清单形状（路径/bytes/sha256、白名单、不重复/不越界）合法；
    - old/ 现存文件集合与清单**严格相等**，目录恰为清单文件的祖先目录闭包
      （额外/空目录、符号链接、非常规文件一律拒绝）；
    - 逐项核对备份字节数与 sha256。

    任一不符抛 RecoveryError（fail-closed，保留现场）。通过返回清单项列表。
    """
    old_root = os.path.join(txn, _TXN_OLD_DIRNAME)
    old_entries = _validate_marker_entries(
        wallet_id, prepared.get("old_files"), "prepared"
    )
    old_set = {entry["path"] for entry in old_entries}
    backup_files, backup_dirs = _scan_old_backup_tree(old_root, wallet_id)
    if backup_files != old_set:
        raise RecoveryError(
            f"restore-txn for {wallet_id!r}/{snapshot_id!r} backup set is "
            "inconsistent with its prepared marker"
        )
    if backup_dirs != _expected_backup_dirs(old_set):
        raise RecoveryError(
            f"restore-txn for {wallet_id!r}/{snapshot_id!r} backup tree has an "
            "unexpected directory"
        )
    # 逐项核对备份的字节数与 sha256（同时拒绝符号链接/非常规文件）。
    for entry in old_entries:
        try:
            data = _read_regular_file(_safe_join(old_root, entry["path"]))
        except BackupError as exc:
            raise RecoveryError(
                f"restore-txn for {wallet_id!r}/{snapshot_id!r} backup file "
                "cannot be safely read"
            ) from exc
        if len(data) != entry["bytes"] or sha256_hex(data) != entry["sha256"]:
            raise RecoveryError(
                f"restore-txn for {wallet_id!r}/{snapshot_id!r} backup file "
                "fails its recorded hash"
            )
    return old_entries


def _rollback_restore(
    data_dir: str, wallet_id: str, snapshot_id: str, prepared: dict
) -> None:
    """committed 标记缺失：先完整校验 old/ 备份，再整体回滚并清理事务目录。

    回滚是"无法安全还原就保持现场"的 fail-closed 操作：

    - prepared 标记形状（wallet_id/snapshot_id/manifest_sha256/old_files 契约
      键与身份）必须自洽；
    - 每个 old_files 项的备份文件必须以**普通文件**存在于 old/、字节数与
      sha256 与标记逐项一致，路径在白名单内且不重复/不越界；
    - old/ 中不得有清单之外的额外文件（闭集）。

    全部通过才删除回滚后不应存在的文件、逐份还原备份、清空空目录并删除
    事务目录；任一不符抛 RecoveryError，不补写、不删除、保持现场。
    """
    txn = _txn_dir(data_dir, wallet_id, snapshot_id)
    old_root = _txn_old_dir(data_dir, wallet_id, snapshot_id)
    # 事务目录闭集先行：回滚路径只允许 prepared.json、old/、未提交的 new/
    # 暂存与确定性标记写中临时名，绝不能已有 committed.json；任何随机名
    # .tmp-*/*.bak.json/未知文件/额外目录/符号链接都 fail-closed 保持现场。
    flags = _scan_txn_snapshot_dir(txn)
    if flags.get(MARKER_COMMITTED):
        raise RecoveryError(
            f"restore-txn for {wallet_id!r}/{snapshot_id!r} unexpectedly carries "
            "a committed marker during rollback"
        )
    if flags.get(_COMMITTED_MARKER_TMP):
        # committed.json 尚未原子落盘，但出现了它的写中临时名且 prepared 仍在
        # ——属未提交窗口，按回滚处理；结构上仍要求闭集合法（上方扫描已确保
        # 临时名不与同名最终标记共存）。这里无需额外动作，临时名随事务目录删除。
        pass
    if (
        set(prepared) != _PREPARED_MARKER_KEYS
        or prepared.get("wallet_id") != wallet_id
        or prepared.get("snapshot_id") != snapshot_id
    ):
        raise RecoveryError(
            f"restore-txn for {wallet_id!r}/{snapshot_id!r} prepared marker "
            "is malformed"
        )
    manifest_sha = prepared.get("manifest_sha256")
    if not isinstance(manifest_sha, str) or not _is_sha256_hex(manifest_sha):
        raise RecoveryError(
            f"restore-txn for {wallet_id!r}/{snapshot_id!r} prepared marker "
            "has a bad manifest hash"
        )

    # 闭集校验：old/ 必须存在，且其内文件集合、目录闭包、逐项字节/sha256
    # 全部与 prepared.old_files 一致。任何符号链接、非常规文件/套接字、额外
    # 文件或额外（含空）子目录都意味着备份现场被动过，绝不基于不可信备份
    # 整体回滚。
    if not flags.get(_TXN_OLD_DIRNAME):
        raise RecoveryError(
            f"restore-txn for {wallet_id!r}/{snapshot_id!r} prepared marker "
            "has no backup directory"
        )
    old_entries = _verify_old_backup(
        txn, wallet_id, snapshot_id, prepared
    )
    old_set = {entry["path"] for entry in old_entries}

    # new/ 是未提交暂存（强杀可能留下部分暂存文件与其确定性写中临时名）：
    # 回滚绝不读取或还原其中任何内容，只做闭集结构校验——符号链接/越界/
    # 非常规/白名单外条目意味着现场被篡改，fail-closed；合法暂存随后随事务
    # 目录整体删除。
    if flags.get(_TXN_NEW_DIRNAME):
        _scan_new_stage_tree(
            _txn_new_dir(data_dir, wallet_id, snapshot_id), wallet_id
        )

    target_paths = _list_current_relpaths(data_dir, wallet_id)
    # 删除回滚后不应存在的文件（含本次新写入的目标）。
    for rel in target_paths:
        if rel not in old_set:
            try:
                os.unlink(_safe_join(data_dir, rel))
            except FileNotFoundError:
                pass
    for entry in old_entries:
        rel = entry["path"]
        src = _safe_join(old_root, rel)
        dst = _safe_join(data_dir, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)
    _prune_empty_leaf_dirs(data_dir, wallet_id)
    # 有序清理：备份（old/）最后删。强杀于清理窗口时，prepared+完整 old 仍在
    # 则幂等重做回滚；prepared 已删而 old 残缺则按无标记垃圾清掉，绝不因备份
    # 残缺永久 fail-closed（业务现场此刻已整体还原）。
    _ordered_cleanup_rollback(data_dir, wallet_id, snapshot_id)


def _verify_committed_residual(
    txn: str,
    flags: dict,
    wallet_id: str,
    snapshot_id: str,
    manifest_sha256: str,
) -> None:
    """committed 权威前滚时，核对**仍残留**的 prepared.json/old/（若有）。

    正常提交后整个事务目录会被清掉；崩溃/被杀可能在清理中途留下完整或部分
    的 prepared.json 与 old/。committed 是唯一提交点，残留缺失可容忍，但
    **仍在的残留不得与 committed 矛盾**，否则现场被篡改，fail-closed：

    - prepared.json 在：必须恰为契约四键、身份一致、manifest_sha256 与
      committed 相同，old_files 清单形状合法；
    - old/ 也在：其文件闭集/目录闭包/逐项字节 sha256 必须与 prepared 一致
      （old/ 在而 prepared 已被清掉时无可比对清单，属无害残留，随目录清理）。
    """
    if not flags.get(MARKER_PREPARED):
        return
    prepared = _read_txn_marker(
        os.path.join(txn, MARKER_PREPARED), "prepared restore"
    )
    if (
        set(prepared) != _PREPARED_MARKER_KEYS
        or prepared.get("wallet_id") != wallet_id
        or prepared.get("snapshot_id") != snapshot_id
        or prepared.get("manifest_sha256") != manifest_sha256
    ):
        raise RecoveryError(
            f"committed restore for {wallet_id!r}/{snapshot_id!r} disagrees "
            "with its prepared marker"
        )
    if flags.get(_TXN_OLD_DIRNAME):
        _verify_old_backup(txn, wallet_id, snapshot_id, prepared)


def _rollforward_restore(
    data_dir: str, wallet_id: str, snapshot_id: str
) -> str:
    """committed 标记在：封闭校验通过后才前滚收敛，返回标记的 manifest_sha256。

    committed 是唯一提交点，只在全部目标文件原子落盘、多余文件删除**之后**
    才写入。崩溃恢复（启动或下一次持钱包锁访问）必须先用标记封闭核对现场，
    任一项不符都统一 fail-closed（RecoveryError）：**阻止 serve 就绪/该钱包
    访问返回 503、原样保留 restore-txn，不补写、不删除、不登记
    restore-records**。

    封闭校验内容：

    - 标记形状：恰为契约键，``wallet_id``/``snapshot_id`` 与目录一致，
      ``manifest_sha256`` 为 64 位小写 hex，``files`` 每项
      ``{path, bytes, sha256}``；
    - 路径：每个 path 为目标钱包白名单内相对普通文件，不重复、不越界；
    - 逐项：目标文件以**普通文件**（非符号链接/非常规）存在，字节数与
      sha256 逐项与标记一致，缺失即失败；
    - 目标集合：data-dir 现存该钱包白名单文件集合必须与标记集合**严格相等**
      ——既不能缺，也不能有标记之外的额外文件。

    校验通过仅表示现场已即提交结果：清掉空叶子目录（不改任何业务字节），
    restore-records 的补登与事务目录清理由 _finalize_committed_restore 完成。
    """
    txn = _txn_dir(data_dir, wallet_id, snapshot_id)
    committed_path = os.path.join(txn, MARKER_COMMITTED)
    # 事务目录闭集先行：前滚路径只允许 committed.json（必在）以及正常提交
    # 后尚未清理的 prepared.json/old/；任何未知文件/.tmp/*.bak.json/额外
    # 目录/符号链接都 fail-closed，原样保留事务目录。
    flags = _scan_txn_snapshot_dir(txn)
    committed = _read_txn_marker(committed_path, "committed restore")
    if (
        set(committed) != _COMMITTED_MARKER_KEYS
        or committed.get("wallet_id") != wallet_id
        or committed.get("snapshot_id") != snapshot_id
    ):
        raise RecoveryError(
            f"committed restore marker for {wallet_id!r}/{snapshot_id!r} "
            "is malformed"
        )
    manifest_sha = committed.get("manifest_sha256")
    if not isinstance(manifest_sha, str) or not _is_sha256_hex(manifest_sha):
        raise RecoveryError(
            f"committed restore marker for {wallet_id!r}/{snapshot_id!r} "
            "has a bad manifest hash"
        )
    entries = _validate_marker_entries(
        wallet_id, committed.get("files"), "committed"
    )
    wanted = {entry["path"]: entry for entry in entries}

    # 目标集合严格相等：现存白名单文件既不能缺也不能多。枚举本身对符号
    # 链接/非常规/越界条目 fail-closed。
    present = set(_list_current_relpaths(data_dir, wallet_id))
    wanted_set = set(wanted)
    if present != wanted_set:
        raise RecoveryError(
            f"committed restore for {wallet_id!r}/{snapshot_id!r} target set "
            "does not match its committed marker"
        )
    # 逐项核对现存目标文件的字节数与 sha256（并再次拒绝符号链接/非常规文件）。
    for rel, entry in wanted.items():
        try:
            data = _read_regular_file(_safe_join(data_dir, rel))
        except BackupError as exc:
            raise RecoveryError(
                f"committed restore target {rel!r} is not a readable regular "
                "file"
            ) from exc
        if len(data) != entry["bytes"] or sha256_hex(data) != entry["sha256"]:
            raise RecoveryError(
                f"committed restore target {rel!r} fails its recorded hash"
            )
    # committed 自身封闭校验全部通过后，再核对仍残留的 prepared/old（若在），
    # 残留与 committed 矛盾同样 fail-closed。
    _verify_committed_residual(
        txn, flags, wallet_id, snapshot_id, manifest_sha
    )
    # committed 落盘意味着 new/ 暂存已全部改名落位：若 new/ 里仍留有暂存
    # 正式文件，则替换并未真正完成却存在 committed，属矛盾现场，fail-closed
    # （空目录残留无害，随事务目录清理）。
    if flags.get(_TXN_NEW_DIRNAME):
        leftover = _scan_new_stage_tree(
            _txn_new_dir(data_dir, wallet_id, snapshot_id), wallet_id
        )
        if leftover:
            raise RecoveryError(
                f"committed restore for {wallet_id!r}/{snapshot_id!r} still "
                "holds uncommitted staged files"
            )
    _prune_empty_leaf_dirs(data_dir, wallet_id)
    return manifest_sha


def _finalize_committed_restore(
    data_dir: str, wallet_id: str, snapshot_id: str, manifest_sha256: str
) -> None:
    """committed 前滚成功后：补登 restore-records（幂等）并有序清理事务目录。

    先补登、后清理：登记原子写本身崩溃（留半截 ``.W.json.tmp``）时事务目录
    仍在，下一次持锁/启动经前滚路径再次进入本函数——记录已在则不重写、缺失
    则原子续作（先解链再 O_EXCL），保证至多登记一次。随后的事务目录清理是
    **有序**的（committed 标记最后删），强杀于清理窗口也只会再次前滚或被当作
    无标记空事务清掉，绝不会把已提交恢复误回滚。
    """
    records = _read_restore_records(data_dir, wallet_id)
    existing = records["snapshots"].get(snapshot_id)
    if existing is None:
        records["snapshots"][snapshot_id] = {
            "manifest_sha256": manifest_sha256
        }
        _write_restore_records(data_dir, wallet_id, records)
    elif existing.get("manifest_sha256") != manifest_sha256:
        raise RecoveryError(
            f"restore record for {snapshot_id!r} disagrees with committed marker"
        )
    _ordered_cleanup_committed(data_dir, wallet_id, snapshot_id)


def _remove_tree_best_effort(path: str) -> None:
    """递归删除一个目录（含其全部内容），OSError 静默（best-effort）。

    仅用于有序清理中删除已被权威标记（committed）或已核验备份（prepared）
    **逻辑覆盖**的暂存/备份目录：删除在每个提交/回滚路径上都会幂等重做，
    单次删除中断留下的任何残留只可能在下一次持锁收敛时再被删除，绝不影响
    业务现场。
    """
    shutil.rmtree(path, ignore_errors=True)


def _remove_file_best_effort(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError:
        pass


def _ordered_cleanup_committed(data_dir: str, wallet_id: str, snapshot_id: str) -> None:
    """committed 前滚成功后的**有序**事务清理（强杀于清理窗口也可收敛）。

    清理顺序刻意保证任一切点残留都能被重启/下一次持锁自愈正确判定——

    1. ``new/``（提交后必为空目录，残留暂存属垃圾）；
    2. ``prepared.json`` 标记；
    3. ``old/`` 备份目录；
    4. ``committed.json``——**唯一提交点标记最后删除**；
    5. ``restore-txn/<W>/<S>``、``restore-txn/<W>``、``restore-txn/`` 空目录。

    强杀于第 1~3 步：committed.json 仍在，重启走前滚（封闭校验通过，因业务
    现场未在清理中被触碰），重做本清理；强杀于第 4 步（committed.json 已删）：
    此时 prepared.json 与 old/ 已不在，只剩空目录/空 new，重启进入无标记空
    事务分支，整体删除即可——**绝不可能把已提交恢复误判成 prepared 回滚**
    （prepared 与 old 必先于 committed 删除）。restore-records 已在调用本函数
    前补登，故收敛幂等、至多登记一次。
    """
    txn = _txn_dir(data_dir, wallet_id, snapshot_id)
    _remove_tree_best_effort(_txn_new_dir(data_dir, wallet_id, snapshot_id))
    # 标记写中临时名先于其最终标记删除：原子改名完成后它们本不存在，此处
    # 仅防御性清理。若反过来（先删 committed 后删其 tmp），清理窗口被杀会
    # 留下孤立的 .committed.json.tmp，被无标记分支误判为矛盾现场而永久
    # fail-closed。
    _remove_file_best_effort(os.path.join(txn, _PREPARED_MARKER_TMP))
    _remove_file_best_effort(os.path.join(txn, _COMMITTED_MARKER_TMP))
    _remove_file_best_effort(os.path.join(txn, MARKER_PREPARED))
    _remove_tree_best_effort(_txn_old_dir(data_dir, wallet_id, snapshot_id))
    _remove_file_best_effort(os.path.join(txn, MARKER_COMMITTED))
    _remove_tree_best_effort(txn)
    _prune_empty_txn_parents(data_dir, wallet_id)


def _ordered_cleanup_rollback(data_dir: str, wallet_id: str, snapshot_id: str) -> None:
    """prepared 回滚成功后的**有序**事务清理（强杀于清理窗口也可收敛）。

    调用前业务文件已整体还原为 old/ 备份现场。清理顺序——

    1. ``new/`` 未提交暂存（绝不信任其中内容）；
    2. ``committed.json`` 的写中临时名（若在，属未提交窗口残留）；
    3. ``prepared.json`` 标记；
    4. ``old/`` 备份目录——**备份最后删除**；
    5. 事务目录与空父目录。

    强杀于第 1~3 步：prepared.json 与完整 old/ 仍在，重启重做回滚（备份闭集
    与逐项哈希仍可核验，业务现场已还原，重做为幂等 no-op）；强杀于第 4 步
    （prepared 已删、old/ 残缺）：无 committed、无 prepared，重启进入空事务
    分支删除垃圾——**绝不会因备份残缺而永久 fail-closed**（备份已无用，业务
    现场已还原）。
    """
    txn = _txn_dir(data_dir, wallet_id, snapshot_id)
    _remove_tree_best_effort(_txn_new_dir(data_dir, wallet_id, snapshot_id))
    # 写中临时名先于其最终标记删除（与 committed 有序清理同理）：避免清理
    # 窗口被杀后留下孤立标记临时名，被无标记分支按矛盾现场 fail-closed。
    _remove_file_best_effort(os.path.join(txn, _COMMITTED_MARKER_TMP))
    _remove_file_best_effort(os.path.join(txn, _PREPARED_MARKER_TMP))
    _remove_file_best_effort(os.path.join(txn, MARKER_PREPARED))
    _remove_tree_best_effort(_txn_old_dir(data_dir, wallet_id, snapshot_id))
    _remove_file_best_effort(os.path.join(txn, MARKER_COMMITTED))
    _remove_tree_best_effort(txn)
    _prune_empty_txn_parents(data_dir, wallet_id)


def _prune_empty_txn_parents(data_dir: str, wallet_id: str) -> None:
    """清理变空的 restore-txn/<W>/ 与 restore-txn/ 目录（best-effort）。"""
    wallet_root = os.path.join(data_dir, RESTORE_TXN_DIRNAME, wallet_id)
    top_root = os.path.join(data_dir, RESTORE_TXN_DIRNAME)
    for path in (wallet_root, top_root):
        try:
            if os.path.isdir(path) and not os.listdir(path):
                os.rmdir(path)
        except OSError:
            pass


def _resume_pending_restore(
    service: WalletService, wallet_id: str
) -> Optional[tuple[str, str]]:
    """在钱包锁内自愈未完成的 restore-txn（崩溃窗口残留）。

    - 只有 prepared、无 committed：回滚为备份现场，删除事务目录；
    - committed 在：前滚确认目标齐备，补登 restore-records，清理目录。

    返回本次完成提交的 (snapshot_id, manifest_sha256)（用于幂等返回），
    无残留返回 None。无法安全对账抛 RecoveryError（fail-closed）。
    """
    data_dir = service._store.data_dir
    # 根目录闭集先行：restore-txn/ 下只许安全 ID 普通目录；任何非安全项
    # （文件、符号链接、非法命名）都意味着事务现场不可信，fail-closed。
    _scan_txn_root(data_dir)
    wallet_txn_root = os.path.join(data_dir, RESTORE_TXN_DIRNAME, wallet_id)
    if not os.path.isdir(wallet_txn_root):
        return None
    result: Optional[tuple[str, str]] = None
    for snapshot_id in sorted(os.listdir(wallet_txn_root)):
        txn = os.path.join(wallet_txn_root, snapshot_id)
        if os.path.islink(txn) or not is_safe_id(snapshot_id) or not os.path.isdir(
            txn
        ):
            raise RecoveryError(
                f"unexpected restore-txn entry under wallet {wallet_id!r}"
            )
        prepared_path = os.path.join(txn, MARKER_PREPARED)
        # 闭集枚举：只允许 prepared.json/committed.json/old/，并据此判定前滚
        # 或回滚——绝不依赖裸 os.path.exists 而把未知文件/链接/临时文件静默
        # 留在事务目录里。
        flags = _scan_txn_snapshot_dir(txn)
        if flags[MARKER_COMMITTED]:
            # committed 是唯一提交点：封闭校验（标记身份/哈希/逐项目标集合，
            # 以及仍残留的 prepared/old）通过后返回其绑定哈希；任何不符在此抛
            # RecoveryError，保留现场。
            manifest_sha256 = _rollforward_restore(
                data_dir, wallet_id, snapshot_id
            )
            _finalize_committed_restore(
                data_dir, wallet_id, snapshot_id, manifest_sha256
            )
            result = (snapshot_id, manifest_sha256)
            continue
        if flags[MARKER_PREPARED]:
            prepared = _read_txn_marker(prepared_path, "prepared restore")
            _rollback_restore(data_dir, wallet_id, snapshot_id, prepared)
            continue
        # 无 prepared 也无 committed：
        # - 写顺序保证 new/ 暂存只可能在 prepared 原子落盘**之后**才出现，故
        #   此刻若 new/ 里有暂存正式文件而 prepared 缺失，是不可能由本事务产生
        #   的矛盾/篡改现场，fail-closed 保留，绝不静默删除。
        # - 否则替换从未开始、目标现场从未被触碰：空目录、备份中途的部分
        #   old/、prepared/committed 的确定性写中临时名都属无害残留，清掉整个
        #   事务目录，绝不猜写目标。
        if flags.get(_TXN_NEW_DIRNAME) and _scan_new_stage_tree(
            os.path.join(txn, _TXN_NEW_DIRNAME), wallet_id
        ):
            raise RecoveryError(
                f"restore-txn for {wallet_id!r}/{snapshot_id!r} holds staged "
                "files without a prepared marker"
            )
        if flags.get(_COMMITTED_MARKER_TMP):
            # committed 的写中临时名按写顺序只能在 prepared 已落盘之后出现；
            # 既无 committed 也无 prepared 却有它，是本事务不可能产生的矛盾
            # 现场（目标可能已被动过），fail-closed，绝不静默删除。
            raise RecoveryError(
                f"restore-txn for {wallet_id!r}/{snapshot_id!r} holds a "
                "committed write temp without a prepared marker"
            )
        shutil.rmtree(txn, ignore_errors=True)
        _prune_empty_txn_parents(data_dir, wallet_id)
    try:
        if os.path.isdir(wallet_txn_root) and not os.listdir(wallet_txn_root):
            os.rmdir(wallet_txn_root)
    except OSError:
        pass
    return result


def _read_marker(path: str) -> dict:
    try:
        with open(path, "rb") as f:
            value = json.loads(f.read().decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise RecoveryError(f"restore marker {path!r} is unreadable") from exc
    if not isinstance(value, dict):
        raise RecoveryError(f"restore marker {path!r} is malformed")
    return value


def _scan_txn_root(data_dir: str) -> list[str]:
    """封闭枚举 restore-txn/ 根目录，返回有未完成事务的 wallet_id（升序）。

    根目录只许**安全 ID 的普通目录**（每个对应一个钱包的事务命名空间）：
    符号链接、普通文件、非法命名、隐藏临时文件或任何非常规条目都意味着
    灾备事务现场被动过，无法安全对账——统一抛 RecoveryError（启动/持锁
    fail-closed；backup/restore 由调用方转成 BackupError(503)），绝不
    静默跳过。根目录不存在返回空列表；根自身是符号链接/非目录同样拒绝。
    """
    root = os.path.join(data_dir, RESTORE_TXN_DIRNAME)
    if not os.path.exists(root) and not os.path.islink(root):
        return []
    if os.path.islink(root) or not os.path.isdir(root):
        raise RecoveryError("restore-txn root is not a directory")
    try:
        with os.scandir(root) as it:
            entries = list(it)
    except OSError as exc:
        raise RecoveryError("restore-txn root is unreadable") from exc
    wallet_ids: list[str] = []
    for entry in entries:
        if (
            entry.is_symlink()
            or not _SAFE_ID.match(entry.name)
            or not entry.is_dir(follow_symlinks=False)
        ):
            raise RecoveryError(
                f"unexpected entry in restore-txn root: {entry.name!r}"
            )
        wallet_ids.append(entry.name)
    return sorted(wallet_ids)


def list_txn_wallet_ids(data_dir: str) -> list[str]:
    """启动恢复扫描：存在 restore-txn 钱包目录的全部 wallet_id。

    根目录闭集由 _scan_txn_root 强制：任何非安全项都抛 RecoveryError，
    由启动恢复 fail-closed（阻止就绪），绝不静默忽略。
    """
    return _scan_txn_root(data_dir)


def reconcile_restore_records(data_dir: str, wallet_id: str) -> None:
    """持锁/启动时对 ``restore-records/`` 闭集与本钱包记录做对账并收敛残留。

    崩溃可能发生在登记（``restore-records/W.json`` 原子写）阶段：此时
    restore-txn 可能已清理，但登记目录仍可能留有非闭集条目、损坏/非规范的
    本钱包记录，或原子改名前被强杀留下的确定性写中临时名。任何持钱包锁的
    访问与启动恢复都必须先校验：

    - 目录闭集：只许 ``<id>.json`` 正式记录与确定性 ``.<id>.json.tmp``；
      符号链接/目录/备份/随机临时名一律 BackupError(503)；
    - 本钱包记录（若在）：恰含 wallet_id/snapshots，逐项 S 为安全标识、
      ``{manifest_sha256}`` 为 64 位小写 hex，且字节为规范形（UTF-8 无
      BOM、sort_keys、2 空格缩进、末尾换行）；损坏或非规范一律 503、
      保留现场。

    残留收敛（调用方已持本钱包锁，临时名属本锁域）：

    - **正式记录存在**且通过上述校验：``.W.json.tmp`` 只可能是"重写登记
      被强杀于原子改名之前"的半截残留——正式记录即最后一致状态，闭集
      扫描已保证该临时名是普通文件（非链接），锁内校验后清理；
    - **正式记录缺失**：不在此清理——该临时名由下一次登记的原子写
      （先解链再 O_EXCL）续作，中断可重试且不改业务，绝不据此猜写或
      恢复其半截内容。
    """
    _read_restore_records(data_dir, wallet_id)
    if not os.path.lexists(_records_path(data_dir, wallet_id)):
        return
    tmp = _records_tmp_path(data_dir, wallet_id)
    if os.path.lexists(tmp):
        os.unlink(tmp)


def _restore_body(
    status: int,
    wallet_id: str,
    snapshot_id: str,
    manifest_sha256: str,
    manifest: dict,
) -> dict:
    return {
        "status": status,
        "wallet_id": wallet_id,
        "snapshot_id": snapshot_id,
        "manifest_sha256": manifest_sha256,
        "manifest": manifest,
    }


def restore(data_dir: str, wallet_id: str, input_path: str) -> tuple[int, dict]:
    """执行一次对账恢复，返回 (201|200, 响应体)；失败抛 BackupError。

    参数类型错误/空值/ID 非法一律 BackupError(400)（确定性的调用方错误，
    发生在读包与任何磁盘对账之前）；归属冲突 409；缺文件、JSON/哈希/形状错、
    不可对账或 OSError 一律 BackupError(503) 且保留现场。
    """
    if not isinstance(data_dir, str) or not data_dir:
        raise BackupError(400, "--data-dir must be a non-empty path")
    if not isinstance(input_path, str) or not input_path:
        raise BackupError(400, "--input must be a non-empty path")
    if not isinstance(wallet_id, str) or not is_safe_id(wallet_id):
        raise BackupError(400, "invalid wallet_id")

    # 读包与 manifest 形状/哈希绑定校验不依赖锁，先做快速失败。
    manifest, files = _read_snapshot(input_path)
    if manifest["wallet_id"] != wallet_id:
        raise BackupError(409, "snapshot belongs to a different wallet")
    snapshot_id = manifest["snapshot_id"]
    manifest_sha256 = manifest["manifest_sha256"]

    try:
        service = WalletService(WalletStore(data_dir), recover=False)
        with service._wallet_lock(wallet_id):
            # 先完成上一次崩溃残留的 restore 前滚/回滚，再做线上现场自愈，
            # 确保任何判定都不基于半状态。
            _resume_pending_restore(service, wallet_id)
            service._heal_wallet(wallet_id)

            records = _read_restore_records(data_dir, wallet_id)
            existing = records["snapshots"].get(snapshot_id)
            if existing is not None:
                if existing.get("manifest_sha256") == manifest_sha256:
                    # 同 S 同 manifest：200 同体（重放包的 S 绑定哈希已在
                    # 读包阶段验通且与记录一致，故其 manifest 即原 manifest）。
                    return 200, _restore_body(
                        200, wallet_id, snapshot_id, manifest_sha256, manifest
                    )
                # 同 S 不同内容：409，绝不覆盖既有恢复点
                raise BackupError(
                    409,
                    f"snapshot {snapshot_id!r} was already restored from "
                    "different content",
                )

            # 全量对账校验（临时目录内运行线上恢复器）；失败绝不写盘。
            _verify_snapshot(service, wallet_id, manifest, files)

            txn = _txn_dir(data_dir, wallet_id, snapshot_id)
            os.makedirs(txn, exist_ok=True)
            prepared_path = os.path.join(txn, MARKER_PREPARED)
            committed_path = os.path.join(txn, MARKER_COMMITTED)
            try:
                _commit_restore(
                    data_dir, wallet_id, snapshot_id, manifest, files
                )
                # committed 标记记录与 manifest 同形的完整 files 项
                # （path/bytes/sha256）：前滚据此对目标现场做封闭校验，
                # 而不是只记路径名。
                committed = {
                    "wallet_id": wallet_id,
                    "snapshot_id": snapshot_id,
                    "manifest_sha256": manifest_sha256,
                    "files": [
                        {
                            "path": entry["path"],
                            "bytes": entry["bytes"],
                            "sha256": entry["sha256"],
                        }
                        for entry in manifest["files"]
                    ],
                }
                _atomic_write_json(committed_path, committed)
            except BaseException:
                if os.path.exists(committed_path):
                    # 提交点已落盘即不可撤回：落到下方统一封闭前滚收敛，
                    # 绝不回滚。
                    pass
                else:
                    # committed 未确认落盘：prepared 在则凭完整校验过的 old/
                    # 整体回滚（无法安全还原时 _rollback_restore 抛错，保持
                    # 现场 fail-closed）；prepared 也不在则清掉空事务目录。
                    if os.path.exists(prepared_path):
                        _rollback_restore(
                            data_dir, wallet_id, snapshot_id,
                            _read_txn_marker(prepared_path, "prepared restore"),
                        )
                    else:
                        shutil.rmtree(txn, ignore_errors=True)
                    raise

            # committed 已落盘：提交不可撤回。正常路径与崩溃自愈共用同一套
            # 封闭前滚校验（身份/绑定哈希/逐项 bytes+sha256/目标集合严格
            # 相等）；通过后才补登唯一 restore-records 并清理事务目录。
            _rollforward_restore(data_dir, wallet_id, snapshot_id)
            _finalize_committed_restore(
                data_dir, wallet_id, snapshot_id, manifest_sha256
            )
    except BackupError:
        raise
    except RecoveryError as exc:
        raise BackupError(503, "restore cannot be reconciled") from exc
    except (CorruptDataError, ValueError, OSError) as exc:
        raise BackupError(503, "restore failed, data left untouched") from exc
    return 201, _restore_body(
        201, wallet_id, snapshot_id, manifest_sha256, manifest
    )
