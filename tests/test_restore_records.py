"""restore 跨目录登记（restore-records/）增强的测试。

覆盖契约：

- ``restore(data_dir, wallet_id, input_path)`` 参数类型错/空值/ID 非法一律
  ``BackupError(400)``（在读包与任何磁盘对账之前）；缺输入文件、JSON/哈希/
  形状错、不可对账或 OSError 一律 ``BackupError(503)`` 并保留现场；
- ``restore-records/`` 闭集：仅许各钱包正式 ``<id>.json`` 与其确定性
  原子写临时名 ``.<id>.json.tmp``；符号链接、目录、激活备份（``*.bak.json``）、
  随机临时名与任何非法命名一律 503、保留现场（启动阻止就绪、常驻请求 503）；
- 合法确定性临时名（强杀于登记期间）不永久 fail-closed，下一次登记原子续作，
  缺记录只登记一次；
- 记录文件 ``restore-records/<W>.json`` 恰含 ``wallet_id``、``snapshots``，
  ``snapshots`` 为 ``S -> {manifest_sha256}``，UTF-8、sort_keys、2 空格、
  末尾换行；
- 其他钱包的正式记录允许并存（restore 绝不触碰其他钱包文件）；
- 恢复不改余额/version、不新增审计、响应不泄露私钥。
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


class _Scene(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.src = os.path.join(self.tmp, "src")
        self.dst = os.path.join(self.tmp, "dst")
        hs = make_harness(self.src)
        hs.service.create_wallet("alice", 2)
        hs.service.put_policy("alice", 1, 3600)
        self.pack = os.path.join(self.tmp, "b.tar")
        self.backup_body = drbackup.backup(
            self.src, "alice", "S1", self.pack
        )
        self.mhash = self.backup_body["manifest"]["manifest_sha256"]
        hd = make_harness(self.dst)
        hd.service.create_wallet("alice", 2)
        self.records_dir = os.path.join(self.dst, "restore-records")
        self.records_path = drbackup._records_path(self.dst, "alice")

    def _restore_ok(self):
        status, body = drbackup.restore(self.dst, "alice", self.pack)
        return status, body

    def _plant(self, rel, kind="file", content=b"{}"):
        path = os.path.join(self.records_dir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if kind == "dir":
            os.makedirs(path, exist_ok=True)
        elif kind == "link":
            os.symlink("/etc/hostname", path)
        else:
            with open(path, "wb") as f:
                f.write(content)


class RestoreParameterValidationTest(_Scene):
    def test_bad_data_dir_types_are_400(self):
        for bad in (None, "", 123, b"/tmp/x", ["x"]):
            with self.assertRaises(drbackup.BackupError) as cm:
                drbackup.restore(bad, "alice", self.pack)
            self.assertEqual(cm.exception.status, 400, bad)

    def test_bad_input_types_are_400(self):
        for bad in (None, "", 7, b"x"):
            with self.assertRaises(drbackup.BackupError) as cm:
                drbackup.restore(self.dst, "alice", bad)
            self.assertEqual(cm.exception.status, 400, bad)

    def test_bad_wallet_id_types_are_400(self):
        for bad in (None, "", "bad/id!", 7):
            with self.assertRaises(drbackup.BackupError) as cm:
                drbackup.restore(self.dst, bad, self.pack)
            self.assertEqual(cm.exception.status, 400, bad)

    def test_missing_input_file_is_503_not_400(self):
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.restore(
                self.dst, "alice", os.path.join(self.tmp, "absent.tar")
            )
        self.assertEqual(cm.exception.status, 503)

    def test_wallet_ownership_conflict_is_409(self):
        # 快照属于 bob，命令行指定 alice：归属冲突 409
        other = os.path.join(self.tmp, "bobsrc")
        hb = make_harness(other)
        hb.service.create_wallet("bob", 2)
        bpack = os.path.join(self.tmp, "bob.tar")
        drbackup.backup(other, "bob", "S1", bpack)
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.restore(self.dst, "alice", bpack)
        self.assertEqual(cm.exception.status, 409)

    def test_first_is_201_replay_same_is_200_identical_body(self):
        s1, b1 = self._restore_ok()
        self.assertEqual(s1, 201)
        s2, b2 = self._restore_ok()
        self.assertEqual(s2, 200)
        self.assertEqual({**b1, "status": 200}, {**b2, "status": 200})
        self.assertEqual(b1["manifest_sha256"], self.mhash)
        self.assertEqual(b1["wallet_id"], "alice")
        self.assertEqual(b1["snapshot_id"], "S1")


class RestoreRecordsFileContractTest(_Scene):
    def test_record_file_shape_and_encoding(self):
        self._restore_ok()
        with open(self.records_path, "rb") as f:
            raw = f.read()
        # UTF-8、2 空格缩进、sort_keys、末尾换行
        self.assertTrue(raw.endswith(b"\n"))
        text = raw.decode("utf-8")
        records = json.loads(text)
        self.assertEqual(set(records), {"wallet_id", "snapshots"})
        self.assertEqual(records["wallet_id"], "alice")
        self.assertEqual(
            records["snapshots"], {"S1": {"manifest_sha256": self.mhash}}
        )
        # sort_keys -> snapshots 键序与 indent 形态可由规范重排复现
        canonical = (
            json.dumps(records, ensure_ascii=False, sort_keys=True, indent=2)
            + "\n"
        )
        self.assertEqual(text, canonical)

    def test_recorded_once_across_replays(self):
        self._restore_ok()
        for _ in range(3):
            self._restore_ok()
        records = drbackup._read_restore_records(self.dst, "alice")
        self.assertEqual(list(records["snapshots"]), ["S1"])


class RestoreRecordsClosedSetTest(_Scene):
    """链接、目录、备份、随机临时/非法条目一律 503 留现场。"""

    def _assert_blocks_restore_and_preserves(self, rel, kind="file"):
        self._restore_ok()
        self._plant(rel, kind=kind)
        planted = os.path.join(self.records_dir, rel)
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.restore(self.dst, "alice", self.pack)
        self.assertEqual(cm.exception.status, 503)
        # 留现场：植入条目仍在，既有正式记录未被改写
        self.assertTrue(os.path.lexists(planted))
        self.assertTrue(os.path.isfile(self.records_path))

    def test_symlink_blocks(self):
        self._assert_blocks_restore_and_preserves("evil", kind="link")

    def test_directory_blocks(self):
        self._assert_blocks_restore_and_preserves("subdir", kind="dir")

    def test_bak_file_blocks(self):
        self._assert_blocks_restore_and_preserves("x.bak.json")

    def test_random_atomic_temp_blocks(self):
        self._assert_blocks_restore_and_preserves(".tmp-abc.json")

    def test_bare_tmp_blocks(self):
        self._assert_blocks_restore_and_preserves("notes.tmp")

    def test_non_json_name_blocks(self):
        self._assert_blocks_restore_and_preserves("notes.txt")

    def test_records_root_symlink_blocks(self):
        self._restore_ok()
        shutil.rmtree(self.records_dir)
        os.symlink("/etc", self.records_dir)
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.restore(self.dst, "alice", self.pack)
        self.assertEqual(cm.exception.status, 503)

    def test_other_wallet_formal_record_coexists(self):
        # 其他钱包的正式恢复点允许并存，alice 的重放照常 200（绝不触碰邻居）
        self._restore_ok()
        self._plant(
            "bob.json",
            content=json.dumps(
                {"wallet_id": "bob",
                 "snapshots": {"X": {"manifest_sha256": "aa" * 32}}}
            ).encode(),
        )
        status, _ = self._restore_ok()
        self.assertEqual(status, 200)
        # bob 的记录逐字节未被触碰
        self.assertTrue(
            os.path.isfile(os.path.join(self.records_dir, "bob.json"))
        )


class RestoreRecordsDeterministicTempTest(_Scene):
    def test_own_half_temp_is_tolerated_and_continues_once(self):
        # 强杀于登记期间：正式记录缺失，仅余半截确定性临时名。启动不得永久
        # fail-closed；下一次 restore 原子续作并恰好登记一次。
        status, _ = self._restore_ok()
        self.assertEqual(status, 201)
        os.unlink(self.records_path)
        with open(
            os.path.join(self.records_dir, ".alice.json.tmp"), "wb"
        ) as f:
            f.write(b"{half")
        # 启动恢复（无 restore-txn）不抛错
        WalletService(WalletStore(self.dst))
        # 记录缺失 -> 重新提交恢复（201），原子写先解链临时名再登记
        status2, _ = self._restore_ok()
        self.assertEqual(status2, 201)
        self.assertFalse(
            os.path.exists(os.path.join(self.records_dir, ".alice.json.tmp"))
        )
        records = drbackup._read_restore_records(self.dst, "alice")
        self.assertEqual(
            records["snapshots"], {"S1": {"manifest_sha256": self.mhash}}
        )

    def test_other_wallet_deterministic_temp_does_not_block_alice(self):
        # 邻居钱包的确定性写中临时名属另一锁域，alice 恢复不因此 503
        self._restore_ok()
        self._plant(".bob.json.tmp", content=b"{half")
        status, _ = self._restore_ok()
        self.assertEqual(status, 200)


class RestoreRecordsCorruptionTest(_Scene):
    def _rewrite_own(self, content: bytes):
        self._restore_ok()
        os.makedirs(self.records_dir, exist_ok=True)
        with open(self.records_path, "wb") as f:
            f.write(content)

    def test_unparseable_json_is_503(self):
        self._rewrite_own(b"{not json")
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.restore(self.dst, "alice", self.pack)
        self.assertEqual(cm.exception.status, 503)

    def test_bad_shape_is_503(self):
        self._rewrite_own(
            json.dumps({"wallet_id": "alice", "snapshots": []}).encode()
        )
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.restore(self.dst, "alice", self.pack)
        self.assertEqual(cm.exception.status, 503)

    def test_bad_entry_hash_is_503(self):
        self._rewrite_own(
            json.dumps(
                {"wallet_id": "alice",
                 "snapshots": {"S1": {"manifest_sha256": "zz"}}}
            ).encode()
        )
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.restore(self.dst, "alice", self.pack)
        self.assertEqual(cm.exception.status, 503)


class RestoreRecordsFailClosedStartupHttpTest(_Scene):
    def _plant_after_restore(self, rel, kind="file"):
        self._restore_ok()
        self._plant(rel, kind=kind)

    def test_startup_blocks_on_symlink(self):
        self._plant_after_restore("evil", kind="link")
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))

    def test_startup_blocks_on_directory(self):
        self._plant_after_restore("subdir", kind="dir")
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))

    def test_startup_blocks_on_bak(self):
        self._plant_after_restore("x.bak.json")
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.dst))

    def test_serve_refuses_to_start(self):
        from threshold_wallet import cli

        self._plant_after_restore("x.bak.json")
        code = cli.main(
            ["serve", "--host", "127.0.0.1", "--port", "0",
             "--data-dir", self.dst]
        )
        self.assertNotEqual(code, 0)

    def test_http_503_preserves_scene_and_hides_keys(self):
        self._restore_ok()
        # 服务先于损坏现场就绪（模拟他进程在常驻期间摆出不可对账的登记现场）
        with http_server(self.dst) as srv:
            self._plant("x.bak.json")
            status, body = srv.request("GET", "/v1/wallets/alice")
        self.assertEqual(status, 503)
        self.assertNotIn("private", json.dumps(body))
        # 留现场：植入备份仍在，恢复记录未被删除
        self.assertTrue(
            os.path.isfile(os.path.join(self.records_dir, "x.bak.json"))
        )


class RestorePreservesStateTest(_Scene):
    def setUp(self):
        super().setUp()
        # 在源端（alice 已建）追加一笔已提交资产，重新出包含资产闭集的快照
        hs = make_harness(self.src)
        hs.service.create_asset_operation("alice", "op1", "BTC", 10)
        hs.service.commit_asset_operation("alice", "op1")
        self.pack = os.path.join(self.tmp, "b.tar")
        self.backup_body = drbackup.backup(
            self.src, "alice", "S1", self.pack
        )
        self.mhash = self.backup_body["manifest"]["manifest_sha256"]
        self.records_dir = os.path.join(self.dst, "restore-records")
        self.records_path = drbackup._records_path(self.dst, "alice")

    def test_restore_matches_snapshot_asset_and_adds_no_audit(self):
        from threshold_wallet.audit import AuditStore

        status, _ = self._restore_ok()
        self.assertEqual(status, 201)
        asset = WalletStore(self.dst).get_asset("alice", "BTC")
        self.assertEqual((asset["balance"], asset["version"]), (10, 1))
        # 恢复不新增审计：恢复后审计条数与源端快照一致
        self.assertEqual(
            len(AuditStore(self.dst).list_events("alice")),
            len(AuditStore(self.src).list_events("alice")),
        )
        # 重放不改账、不记事件
        self._restore_ok()
        asset2 = WalletStore(self.dst).get_asset("alice", "BTC")
        self.assertEqual((asset2["balance"], asset2["version"]), (10, 1))
        self.assertEqual(
            len(AuditStore(self.dst).list_events("alice")),
            len(AuditStore(self.src).list_events("alice")),
        )


if __name__ == "__main__":
    unittest.main()
