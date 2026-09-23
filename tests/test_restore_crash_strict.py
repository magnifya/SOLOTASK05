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


if __name__ == "__main__":
    unittest.main()
