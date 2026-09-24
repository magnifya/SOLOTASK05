"""restore 崩溃窗口严格封闭校验测试。

覆盖契约：committed 标记在时，启动或下一次持钱包锁访问必须先用标记封闭
校验 wallet_id、snapshot_id、manifest_sha256 与 files 项（path/bytes/
sha256）——路径为目标钱包白名单内相对普通文件，不能重复、越界、缺失、
符号链接或额外；逐项核对 bytes/sha256，并核对目标集合严格相等。任一不符
统一 fail-closed（serve 拒绝就绪 / 常驻请求 503），保留 restore-txn，
不补写、不删除、不登记 restore-records。prepared 无 committed 时先完整
校验 old/ 备份再整体回滚，无法安全还原保持现场。恢复不新增审计、不改
余额/version；记录哈希冲突 503，匹配重放 200 同体。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from tests.helpers import http_server, make_harness
from threshold_wallet import drbackup
from threshold_wallet.service import WalletService
from threshold_wallet.store import RecoveryError, WalletStore


class _CrashScene(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.src = f"{self.tmp}/src"
        self.dst = f"{self.tmp}/dst"
        hs = make_harness(self.src)
        hs.service.create_wallet("alice", 2)
        hs.service.put_policy("alice", 1, 3600)
        self.pack = f"{self.tmp}/b.tar"
        self.backup_body = drbackup.backup(
            self.src, "alice", "S1", self.pack
        )
        self.mhash = self.backup_body["manifest"]["manifest_sha256"]
        hd = make_harness(self.dst)
        hd.service.create_wallet("alice", 2)
        hd.service.put_policy("alice", 2, 99)
        self.manifest, self.files = drbackup._read_snapshot(self.pack)
        self.txn = drbackup._txn_dir(self.dst, "alice", "S1")
        self.records_path = drbackup._records_path(self.dst, "alice")

    def _plant_committed(self, *, marker_overrides=None, corrupt=None):
        """摆出 committed 崩溃窗口：替换已发生、committed 已写。

        marker_overrides: 覆盖 committed 标记字段；corrupt: 在写完标记后
        对目标现场做篡改（缺/多/改/链接）。
        """
        os.makedirs(self.txn, exist_ok=True)
        drbackup._commit_restore(
            self.dst, "alice", "S1", self.manifest, self.files
        )
        marker = {
            "wallet_id": "alice",
            "snapshot_id": "S1",
            "manifest_sha256": self.mhash,
            "files": [
                {
                    "path": e["path"],
                    "bytes": e["bytes"],
                    "sha256": e["sha256"],
                }
                for e in self.manifest["files"]
            ],
        }
        if marker_overrides:
            marker.update(marker_overrides)
        drbackup._atomic_write_json(
            os.path.join(self.txn, "committed.json"), marker
        )
        if corrupt:
            corrupt(self)

    def _assert_scene_preserved(self):
        """fail-closed：restore-txn 保留，restore-records 不登记。"""
        self.assertTrue(os.path.isdir(self.txn))
        self.assertTrue(
            os.path.isfile(os.path.join(self.txn, "committed.json"))
        )
        self.assertFalse(os.path.exists(self.records_path))

    def _plant_prepared(self, *, corrupt_backup=None):
        os.makedirs(self.txn, exist_ok=True)
        drbackup._commit_restore(
            self.dst, "alice", "S1", self.manifest, self.files
        )
        self.assertFalse(
            os.path.exists(os.path.join(self.txn, "committed.json"))
        )
        if corrupt_backup:
            corrupt_backup(self)


class CommittedClosedVerificationTest(_CrashScene):
    def test_clean_committed_rolls_forward_and_records_once(self):
        self._plant_committed()
        WalletService(WalletStore(self.dst))  # 启动封闭校验 + 前滚
        records = drbackup._read_restore_records(self.dst, "alice")
        self.assertEqual(
            records["snapshots"]["S1"]["manifest_sha256"], self.mhash
        )
        self.assertFalse(os.path.exists(self.txn))
        # 再次启动不重复登记、无异常
        WalletService(WalletStore(self.dst))
        records = drbackup._read_restore_records(self.dst, "alice")
        self.assertEqual(len(records["snapshots"]), 1)
        # 此后重放按原契约 200 同体
        status, body = drbackup.restore(self.dst, "alice", self.pack)
        self.assertEqual(status, 200)
        self.assertEqual(body["manifest"], self.backup_body["manifest"])
        # 恢复不新增审计：审计条数与源端一致
        from threshold_wallet.audit import AuditStore

        self.assertEqual(
            len(AuditStore(self.dst).list_events("alice")),
            len(AuditStore(self.src).list_events("alice")),
        )

    def test_marker_wallet_id_mismatch_blocks(self):
        self._plant_committed(marker_overrides={"wallet_id": "bob"})
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self._assert_scene_preserved()

    def test_marker_snapshot_id_mismatch_blocks(self):
        self._plant_committed(marker_overrides={"snapshot_id": "OTHER"})
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self._assert_scene_preserved()

    def test_marker_bad_manifest_hash_blocks(self):
        self._plant_committed(
            marker_overrides={"manifest_sha256": "00" * 64}
        )
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self._assert_scene_preserved()

    def test_marker_extra_key_blocks(self):
        self._plant_committed(marker_overrides={"bogus": 1})
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self._assert_scene_preserved()

    def test_marker_entry_extra_key_blocks(self):
        entries = [dict(e) for e in self.manifest["files"]]
        entries[0]["evil"] = 1
        self._plant_committed(marker_overrides={"files": entries})
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self._assert_scene_preserved()

    def test_marker_duplicate_path_blocks(self):
        entries = [dict(e) for e in self.manifest["files"]]
        entries.append(dict(entries[0]))
        self._plant_committed(marker_overrides={"files": entries})
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self._assert_scene_preserved()

    def test_marker_path_outside_whitelist_blocks(self):
        entries = [dict(e) for e in self.manifest["files"]]
        entries.append(
            {"path": "../escape.json", "bytes": 1,
             "sha256": "aa" * 32}
        )
        self._plant_committed(marker_overrides={"files": entries})
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self._assert_scene_preserved()

    def test_marker_path_lock_file_blocks(self):
        entries = [dict(e) for e in self.manifest["files"]]
        entries.append(
            {"path": "locks/alice.lock", "bytes": 1,
             "sha256": "aa" * 32}
        )
        self._plant_committed(marker_overrides={"files": entries})
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self._assert_scene_preserved()

    def test_missing_target_file_blocks_without_writing(self):
        def corrupt(scene):
            os.unlink(os.path.join(scene.dst, "wallets/alice.json"))

        self._plant_committed(corrupt=corrupt)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self._assert_scene_preserved()
        # 不补写缺失文件
        self.assertFalse(
            os.path.exists(os.path.join(self.dst, "wallets/alice.json"))
        )

    def test_extra_target_file_blocks_without_deleting(self):
        def corrupt(scene):
            extra = os.path.join(scene.dst, "sign-sessions", "alice.json")
            os.makedirs(os.path.dirname(extra), exist_ok=True)
            with open(extra, "wb") as f:
                f.write(b"{}")

        self._plant_committed(corrupt=corrupt)
        extra = os.path.join(self.dst, "sign-sessions", "alice.json")
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self._assert_scene_preserved()
        # 不删除额外文件
        self.assertTrue(os.path.exists(extra))

    def test_target_hash_mismatch_blocks(self):
        def corrupt(scene):
            p = os.path.join(scene.dst, "wallets/alice.json")
            with open(p, "rb") as f:
                raw = f.read()
            data = json.loads(raw.decode())
            data["created_at"] = "2026-01-01T00:00:00Z"
            with open(p, "wb") as f:
                f.write(json.dumps(data).encode())

        self._plant_committed(corrupt=corrupt)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self._assert_scene_preserved()

    def test_target_byte_count_mismatch_blocks(self):
        def corrupt(scene):
            p = os.path.join(scene.dst, "wallets/alice.json")
            with open(p, "ab") as f:
                f.write(b" ")

        self._plant_committed(corrupt=corrupt)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self._assert_scene_preserved()

    def test_target_symlink_blocks(self):
        def corrupt(scene):
            p = os.path.join(scene.dst, "wallets/alice.json")
            os.unlink(p)
            os.symlink("/etc/hostname", p)

        self._plant_committed(corrupt=corrupt)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self._assert_scene_preserved()

    def test_committed_prepared_hash_disagreement_blocks(self):
        # committed 与 prepared 同时存在但记录的 manifest 哈希不一致
        self._plant_committed(marker_overrides={"manifest_sha256": "11" * 32})
        # files 仍自洽原内容，故封闭集合/哈希校验通过，但身份哈希与
        # prepared 矛盾 -> fail-closed。先让 committed files 绑定到坏哈希
        # 不影响 files 项内容核对（files 项仍是文件真实 hash）。
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self._assert_scene_preserved()

    def test_restore_record_hash_conflict_is_503(self):
        # 已存在同 S 但不同 manifest 哈希的恢复记录：前滚补登冲突 -> 503。
        def corrupt(scene):
            drbackup._write_restore_records(
                scene.dst,
                "alice",
                {"wallet_id": "alice",
                 "snapshots": {"S1": {"manifest_sha256": "cc" * 32}}},
            )

        self._plant_committed(corrupt=corrupt)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        # 事务现场保留，未被前滚清理
        self.assertTrue(os.path.isdir(self.txn))

    def test_serve_refuses_to_start(self):
        from threshold_wallet import cli

        self._plant_committed(marker_overrides={"wallet_id": "bob"})
        code = cli.main(
            ["serve", "--host", "127.0.0.1", "--port", "0",
             "--data-dir", self.dst]
        )
        self.assertNotEqual(code, 0)

    def test_http_request_returns_503_and_preserves_scene(self):
        # 健康服务就绪后，他进程摆出无法封闭核对的 committed 现场
        with http_server(self.dst) as srv:
            self._plant_committed(marker_overrides={"wallet_id": "bob"})
            status, body = srv.request("GET", "/v1/wallets/alice")
            self.assertEqual(status, 503, body)
            self.assertIn("error", body)
            self.assertNotIn("private", json.dumps(body))
        self._assert_scene_preserved()

    def test_heal_path_converges_valid_committed(self):
        # 不走构造期启动恢复：首次持锁访问自愈前滚
        self._plant_committed()
        svc = WalletService(WalletStore(self.dst), recover=False)
        svc.get_wallet("alice")
        records = drbackup._read_restore_records(self.dst, "alice")
        self.assertEqual(
            records["snapshots"]["S1"]["manifest_sha256"], self.mhash
        )
        self.assertFalse(os.path.exists(self.txn))


class PreparedRollbackStrictTest(_CrashScene):
    def _tree(self):
        out = {}
        for dp, _, fns in os.walk(self.dst):
            for fn in fns:
                p = os.path.join(dp, fn)
                rel = os.path.relpath(p, self.dst)
                if rel.split(os.sep)[0] in ("locks",):
                    continue
                with open(p, "rb") as f:
                    out[rel] = f.read()
        return out

    def test_clean_prepared_rolls_back_fully(self):
        # 原现场：审批策略 2/99；快照里是 1/3600
        self._plant_prepared()
        WalletService(WalletStore(self.dst))
        self.assertFalse(os.path.exists(self.txn))
        self.assertFalse(
            os.path.exists(os.path.join(self.dst, "restore-txn"))
        )
        self.assertFalse(os.path.exists(self.records_path))
        self.assertEqual(
            WalletStore(self.dst).get_policy("alice")["required_approvals"],
            2,
        )

    def test_missing_backup_file_blocks_and_preserves_scene(self):
        def corrupt(scene):
            old = os.path.join(
                scene.txn, "old", "wallets/alice.json"
            )
            os.unlink(old)

        self._plant_prepared(corrupt_backup=corrupt)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        # 保持现场：txn 保留，未做整体回滚（目标仍是快照的 1/3600）
        self.assertTrue(os.path.isdir(self.txn))
        self.assertEqual(
            WalletStore(self.dst).get_policy("alice")["required_approvals"],
            1,
        )

    def test_backup_hash_mismatch_blocks(self):
        def corrupt(scene):
            old = os.path.join(
                scene.txn, "old", "policies/alice.json"
            )
            with open(old, "rb") as f:
                data = json.loads(f.read().decode())
            data["timeout_seconds"] = 1
            with open(old, "w") as f:
                json.dump(data, f)

        self._plant_prepared(corrupt_backup=corrupt)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self.assertTrue(os.path.isdir(self.txn))

    def test_extra_backup_file_blocks(self):
        def corrupt(scene):
            extra = os.path.join(
                scene.txn, "old", "sign-sessions", "alice.json"
            )
            os.makedirs(os.path.dirname(extra), exist_ok=True)
            with open(extra, "wb") as f:
                f.write(b"{}")

        self._plant_prepared(corrupt_backup=corrupt)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self.assertTrue(os.path.isdir(self.txn))

    def test_backup_symlink_blocks(self):
        def corrupt(scene):
            old = os.path.join(scene.txn, "old", "wallets/alice.json")
            os.unlink(old)
            os.symlink("/etc/hostname", old)

        self._plant_prepared(corrupt_backup=corrupt)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self.assertTrue(os.path.isdir(self.txn))

    def test_prepared_marker_bad_shape_blocks(self):
        self._plant_prepared()
        p = os.path.join(self.txn, "prepared.json")
        marker = drbackup._read_marker(p)
        marker["old_files"] = ["wallets/alice.json"]  # 旧的纯路径形状
        drbackup._atomic_write_json(p, marker)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self.assertTrue(os.path.isdir(self.txn))


class TxnDirClosedSetTest(_CrashScene):
    """restore-txn/<W>/<S>/ 是闭集：只允许 prepared.json、committed.json、
    old/。任何未知文件、原子临时文件（.tmp-*）、激活备份（*.bak.json）、
    额外目录或符号链接都必须 fail-closed（启动恢复抛 RecoveryError、serve
    拒绝就绪、常驻请求 503），现场保留且不登记 restore-records。"""

    # ---- prepared（回滚）侧 --------------------------------------------

    def test_prepared_extra_unknown_file_blocks(self):
        self._plant_prepared()
        with open(os.path.join(self.txn, "evil.json"), "wb") as f:
            f.write(b"{}")
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self.assertTrue(os.path.isdir(self.txn))
        self.assertTrue(os.path.isfile(os.path.join(self.txn, "evil.json")))
        self.assertFalse(os.path.exists(self.records_path))

    def test_prepared_atomic_tmp_file_blocks(self):
        self._plant_prepared()
        with open(os.path.join(self.txn, ".tmp-abc.json"), "wb") as f:
            f.write(b"{}")
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self.assertTrue(os.path.isdir(self.txn))
        self.assertFalse(os.path.exists(self.records_path))

    def test_prepared_bak_file_blocks(self):
        self._plant_prepared()
        with open(os.path.join(self.txn, "wallet.bak.json"), "wb") as f:
            f.write(b"{}")
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self.assertTrue(os.path.isdir(self.txn))
        self.assertFalse(os.path.exists(self.records_path))

    def test_prepared_extra_directory_blocks(self):
        self._plant_prepared()
        os.makedirs(os.path.join(self.txn, "weird"))
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self.assertTrue(os.path.isdir(self.txn))
        self.assertFalse(os.path.exists(self.records_path))

    def test_prepared_symlink_in_txn_blocks(self):
        self._plant_prepared()
        os.symlink("/etc/hostname", os.path.join(self.txn, "link"))
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self.assertTrue(os.path.isdir(self.txn))
        self.assertFalse(os.path.exists(self.records_path))

    def test_prepared_empty_extra_dir_under_old_blocks(self):
        self._plant_prepared()
        os.makedirs(os.path.join(self.txn, "old", "emptydir"))
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self.assertTrue(os.path.isdir(self.txn))
        self.assertFalse(os.path.exists(self.records_path))

    # ---- committed（前滚）侧 -------------------------------------------

    def test_committed_extra_unknown_file_blocks(self):
        self._plant_committed()
        with open(os.path.join(self.txn, "evil.json"), "wb") as f:
            f.write(b"{}")
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self._assert_scene_preserved()
        self.assertTrue(os.path.isfile(os.path.join(self.txn, "evil.json")))

    def test_committed_atomic_tmp_file_blocks(self):
        self._plant_committed()
        with open(os.path.join(self.txn, ".tmp-abc.json"), "wb") as f:
            f.write(b"{}")
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self._assert_scene_preserved()

    def test_committed_bak_file_blocks(self):
        self._plant_committed()
        with open(os.path.join(self.txn, "x.bak.json"), "wb") as f:
            f.write(b"{}")
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self._assert_scene_preserved()

    def test_committed_extra_directory_blocks(self):
        self._plant_committed()
        os.makedirs(os.path.join(self.txn, "weird"))
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self._assert_scene_preserved()

    def test_committed_symlink_in_txn_blocks(self):
        self._plant_committed()
        os.symlink("/etc/hostname", os.path.join(self.txn, "link"))
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self._assert_scene_preserved()

    def test_committed_residual_old_extra_file_blocks(self):
        # committed 与 prepared 都在（正常崩溃窗口），但残留 old/ 被塞入额外
        # 文件：残留与 prepared.old_files 闭集矛盾，必须 fail-closed。
        self._plant_committed()
        extra = os.path.join(self.txn, "old", "sign-sessions", "alice.json")
        os.makedirs(os.path.dirname(extra), exist_ok=True)
        with open(extra, "wb") as f:
            f.write(b"{}")
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self._assert_scene_preserved()

    def test_committed_extra_file_http_503(self):
        from tests.helpers import http_server

        # 服务先于损坏现场就绪（模拟他进程在服务常驻期间摆出无法封闭核对的
        # committed 现场）；持锁访问自愈时命中闭集违规 -> 503。
        with http_server(self.dst) as srv:
            self._plant_committed()
            with open(os.path.join(self.txn, "evil.json"), "wb") as f:
                f.write(b"{}")
            status, body = srv.request("GET", "/v1/wallets/alice")
            self.assertEqual(status, 503, body)
            self.assertNotIn("private", json.dumps(body))
        self._assert_scene_preserved()

    def test_committed_extra_file_blocks_serve(self):
        from threshold_wallet import cli

        self._plant_committed()
        with open(os.path.join(self.txn, "evil.json"), "wb") as f:
            f.write(b"{}")
        code = cli.main(
            ["serve", "--host", "127.0.0.1", "--port", "0",
             "--data-dir", self.dst]
        )
        self.assertNotEqual(code, 0)
        self._assert_scene_preserved()


class HardTerminationConvergenceTest(_CrashScene):
    """SIGKILL/断电（Python ``except`` 清理不执行）后只可能留下本事务自己的
    确定性残留：标记的 ``.<name>.tmp`` 写中临时名与事务内 ``new/`` 暂存树。
    恢复必须据 committed 是否落盘前滚/核验 old 后回滚，绝不永久 fail-closed，
    也不把业务文件暴露成半状态；外部塞入的随机名临时文件仍须 fail-closed。"""

    def _build_prepared(self):
        """复制 old/ 并写 prepared 标记（不做 new/ 暂存与改名），返回 old_root。"""
        old_root = drbackup._txn_old_dir(self.dst, "alice", "S1")
        old_entries = []
        for rel in drbackup._list_current_relpaths(self.dst, "alice"):
            src = drbackup._safe_join(self.dst, rel)
            dstp = drbackup._safe_join(old_root, rel)
            os.makedirs(os.path.dirname(dstp), exist_ok=True)
            shutil.copy2(src, dstp)
            old_entries.append(drbackup._file_entry(old_root, rel))
        prepared = {
            "wallet_id": "alice",
            "snapshot_id": "S1",
            "manifest_sha256": self.mhash,
            "old_files": old_entries,
        }
        drbackup._atomic_write_json(
            os.path.join(self.txn, "prepared.json"), prepared
        )
        return old_root

    def _stage_new(self, rels):
        new_root = drbackup._txn_new_dir(self.dst, "alice", "S1")
        for rel in rels:
            p = drbackup._safe_join(new_root, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(self.files[rel])
        return new_root

    def test_kill_during_prepared_write_converges(self):
        # 强杀于 prepared.json 原子改名前：old/ 已复制、仅留半截确定性临时名，
        # 无任何标记，目标现场从未被触碰。
        os.makedirs(self.txn, exist_ok=True)
        self._build_prepared()
        os.unlink(os.path.join(self.txn, "prepared.json"))
        with open(os.path.join(self.txn, ".prepared.json.tmp"), "wb") as f:
            f.write(b"{half")
        WalletService(WalletStore(self.dst))
        self.assertFalse(os.path.exists(os.path.join(self.dst, "restore-txn")))
        self.assertEqual(
            WalletStore(self.dst).get_policy("alice")["required_approvals"], 2
        )
        status, _ = drbackup.restore(self.dst, "alice", self.pack)
        self.assertEqual(status, 201)

    def test_kill_during_new_stage_with_partial_temp_rolls_back(self):
        # 强杀于 new/ 暂存阶段：prepared 已在，部分暂存正式文件与一份半截
        # 确定性写中临时名残留，业务目标尚未改名。
        os.makedirs(self.txn, exist_ok=True)
        self._build_prepared()
        new_root = self._stage_new(["audit/alice.json"])
        with open(os.path.join(new_root, "audit", ".alice.json.tmp"), "wb") as f:
            f.write(b"{partial")
        WalletService(WalletStore(self.dst))
        self.assertFalse(os.path.exists(os.path.join(self.dst, "restore-txn")))
        self.assertEqual(
            WalletStore(self.dst).get_policy("alice")["required_approvals"], 2
        )
        status, _ = drbackup.restore(self.dst, "alice", self.pack)
        self.assertEqual(status, 201)

    def test_kill_mid_rename_partial_new_scene_rolls_back_fully(self):
        # 强杀于改名落位中途：prepared 在、new/ 仍有未改名暂存，且一份业务
        # 目标已被换成快照内容（policies 1/360）。无 committed，必须核验 old
        # 后整体回滚为原现场（2/99）。
        os.makedirs(self.txn, exist_ok=True)
        self._build_prepared()
        rels = sorted(self.files)
        new_root = self._stage_new(rels)
        # 改名一份 policies 到业务位，并从 new/ 删除其暂存，模拟中途现场
        os.replace(
            drbackup._safe_join(new_root, "policies/alice.json"),
            drbackup._safe_join(self.dst, "policies/alice.json"),
        )
        self.assertEqual(
            WalletStore(self.dst).get_policy("alice")["required_approvals"], 1
        )
        # 再留一份半截暂存写中临时名
        with open(
            drbackup._safe_join(new_root, "wallets/.alice.json.tmp"), "wb"
        ) as f:
            f.write(b"{half")
        WalletService(WalletStore(self.dst))
        self.assertFalse(os.path.exists(os.path.join(self.dst, "restore-txn")))
        self.assertEqual(
            WalletStore(self.dst).get_policy("alice")["required_approvals"], 2
        )

    def test_kill_before_committed_rename_rolls_back(self):
        # 全部目标已改名落位（现场已是快照），但 committed.json 在原子改名前
        # 被杀：committed 是唯一提交点，缺失即核验 old 后整体回滚。
        os.makedirs(self.txn, exist_ok=True)
        self._build_prepared()
        new_root = self._stage_new(sorted(self.files))
        for rel in sorted(self.files):
            target = drbackup._safe_join(self.dst, rel)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            os.replace(drbackup._safe_join(new_root, rel), target)
        with open(os.path.join(self.txn, ".committed.json.tmp"), "wb") as f:
            f.write(b"{half")
        WalletService(WalletStore(self.dst))
        self.assertFalse(os.path.exists(os.path.join(self.dst, "restore-txn")))
        self.assertEqual(
            WalletStore(self.dst).get_policy("alice")["required_approvals"], 2
        )

    def test_committed_with_empty_new_dir_rolls_forward(self):
        # committed 在、目标齐备，仅残留一个空的 new/ 暂存目录：前滚成功并
        # 补登 restore-records。
        self._plant_committed()
        os.makedirs(os.path.join(self.txn, "new"), exist_ok=True)
        WalletService(WalletStore(self.dst))
        records = drbackup._read_restore_records(self.dst, "alice")
        self.assertEqual(
            records["snapshots"]["S1"]["manifest_sha256"], self.mhash
        )
        self.assertFalse(os.path.exists(self.txn))

    def test_random_named_stage_temp_still_blocks(self):
        # 外部塞入的随机名 .tmp-* 不得借 new/ 通道被静默吞掉。
        os.makedirs(self.txn, exist_ok=True)
        self._build_prepared()
        new_root = self._stage_new(["audit/alice.json"])
        with open(os.path.join(new_root, ".tmp-abc.json"), "wb") as f:
            f.write(b"{}")
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self.assertTrue(os.path.isdir(self.txn))

    def test_staged_file_without_prepared_blocks(self):
        # 写顺序保证 new/ 暂存只可能在 prepared 落盘之后出现；有暂存正式文件
        # 却无 prepared 是本事务不可能产生的矛盾现场，fail-closed 保留。
        os.makedirs(self.txn, exist_ok=True)
        self._stage_new(["audit/alice.json"])
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self.assertTrue(os.path.isdir(self.txn))


class PostCommitCleanupWindowTest(_CrashScene):
    """committed 是提交点；补登 restore-records 后的**清理窗口**（有序删除
    new → old → prepared → committed）被强杀时的收敛契约：

    - committed 在 ⇒ 提交必已发生：业务目标严格等于 committed.files，残留
      old/prepared 即使被清理删掉一半（现存项为清单子集且逐项哈希自洽）也
      正常前滚、补登幂等一次、清掉事务目录，绝不永久 fail-closed；
    - committed 缺失却已登记 S（旧的乱序 rmtree / 篡改才可能产生）：缺
      committed.files 无法重验目标闭集，fail-closed 保留现场，**绝不把已提交
      快照整体回滚成恢复前现场**而与登记发散。
    """

    def _register(self):
        drbackup._write_restore_records(
            self.dst,
            "alice",
            {"wallet_id": "alice",
             "snapshots": {"S1": {"manifest_sha256": self.mhash}}},
        )

    def _one_old_file(self):
        old = os.path.join(self.txn, "old")
        for dp, _, fns in os.walk(old):
            for fn in fns:
                return os.path.join(dp, fn)
        raise AssertionError("expected at least one file under old/")

    def _assert_converged_to_snapshot(self):
        # 事务清空、登记恰好一次、现场是快照（policy 1/3600），重放 200
        self.assertFalse(os.path.exists(self.txn))
        records = drbackup._read_restore_records(self.dst, "alice")
        self.assertEqual(
            records["snapshots"], {"S1": {"manifest_sha256": self.mhash}}
        )
        self.assertEqual(
            WalletStore(self.dst).get_policy("alice")["required_approvals"], 1
        )
        status, _ = drbackup.restore(self.dst, "alice", self.pack)
        self.assertEqual(status, 200)

    def test_partial_old_deleted_with_committed_rolls_forward(self):
        # committed+prepared 在（提交已完成、已登记），有序清理删 old/ 中途
        # 被杀：一份备份已删。现存 old 是清单子集，前滚必须容忍而非拒服。
        self._plant_committed()
        self._register()
        os.unlink(self._one_old_file())
        WalletService(WalletStore(self.dst))
        self._assert_converged_to_snapshot()

    def test_old_fully_deleted_committed_present_rolls_forward(self):
        self._plant_committed()
        self._register()
        shutil.rmtree(os.path.join(self.txn, "old"), ignore_errors=True)
        WalletService(WalletStore(self.dst))
        self._assert_converged_to_snapshot()

    def test_prepared_and_old_gone_committed_present_rolls_forward(self):
        # 清理已删完 old/ 与 prepared.json，只差 committed.json：前滚照常。
        self._plant_committed()
        self._register()
        shutil.rmtree(os.path.join(self.txn, "old"), ignore_errors=True)
        os.unlink(os.path.join(self.txn, "prepared.json"))
        WalletService(WalletStore(self.dst))
        self._assert_converged_to_snapshot()

    def test_tampered_residual_old_file_blocks(self):
        # old/ 残留文件被改成与 prepared 哈希不符（非清理删除，而是篡改）：
        # 子集容忍也必须 fail-closed，不得前滚。
        self._plant_committed()
        self._register()
        target = self._one_old_file()
        with open(target, "wb") as f:
            f.write(b"not the backup bytes")
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self.assertTrue(os.path.isdir(self.txn))
        self.assertTrue(os.path.isfile(os.path.join(self.txn, "committed.json")))

    def test_extra_residual_old_file_blocks(self):
        # old/ 多出 prepared.old_files 之外的文件：清理不可能"删出"额外项，
        # 属篡改，fail-closed。
        self._plant_committed()
        self._register()
        extra = os.path.join(self.txn, "old", "sign-sessions", "alice.json")
        os.makedirs(os.path.dirname(extra), exist_ok=True)
        with open(extra, "wb") as f:
            f.write(b"{}")
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        self.assertTrue(os.path.isdir(self.txn))

    def test_committed_gone_but_registered_does_not_roll_back(self):
        # 旧乱序清理（committed 先于 prepared/old 被删）且 restore-records 已
        # 登记 S：业务目标此刻是已提交快照（policy 1）。绝不能回滚成恢复前
        # 现场（policy 2）与登记发散——fail-closed 保留现场，不猜写不回滚。
        self._plant_committed()
        self._register()
        os.unlink(os.path.join(self.txn, "committed.json"))
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))
        # serve 必须拒绝就绪（非零退出）
        from threshold_wallet import cli

        code = cli.main(
            ["serve", "--host", "127.0.0.1", "--port", "0",
             "--data-dir", self.dst]
        )
        self.assertNotEqual(code, 0)
        # 现场保留：txn 仍在、记录未改、业务目标仍是快照（未被回滚）
        self.assertTrue(os.path.isdir(self.txn))
        self.assertTrue(
            os.path.isfile(os.path.join(self.txn, "prepared.json"))
        )
        records = drbackup._read_restore_records(self.dst, "alice")
        self.assertEqual(
            records["snapshots"]["S1"]["manifest_sha256"], self.mhash
        )
        self.assertEqual(
            WalletStore(self.dst).get_policy("alice")["required_approvals"], 1
        )

    def test_committed_gone_registered_http_503_and_preserved(self):
        # 先干净恢复一次（现场即快照、records 已登记 S1、无 txn）使服务健康
        # 就绪，再于常驻期间摆出 committed 丢失而 prepared/old 残留的提交后
        # 清理现场：持锁访问 fail-closed（HTTP 503），不回滚、不泄露私钥。
        # serve 启动拒绝就绪由 test_committed_gone_but_registered_does_not_
        # roll_back 的 WalletService RecoveryError 覆盖。
        status, _ = drbackup.restore(self.dst, "alice", self.pack)
        self.assertEqual(status, 201)
        with http_server(self.dst) as srv:
            self._plant_committed()
            os.unlink(os.path.join(self.txn, "committed.json"))
            status, body = srv.request("GET", "/v1/wallets/alice")
            self.assertEqual(status, 503, body)
            self.assertNotIn("private", json.dumps(body))
        # 现场保留且业务未被回滚
        self.assertTrue(os.path.isdir(self.txn))
        self.assertEqual(
            WalletStore(self.dst).get_policy("alice")["required_approvals"], 1
        )


if __name__ == "__main__":
    unittest.main()
