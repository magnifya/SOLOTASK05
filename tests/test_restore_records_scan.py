"""restore-records 跨目录登记的闭集校验与崩溃收敛测试。

覆盖增强契约（CLI/HTTP/backup 不变，仅 restore）：

- ``restore-records/`` 是多钱包共享根：目标钱包 W 的写者只产普通文件
  ``W.json`` 与确定性写中临时名 ``.W.json.tmp``；其他钱包的正式
  ``<safe-id>.json`` 命名合法、只读不碰；任何符号链接、（含空）目录、激活
  备份（*.bak.json）、随机/他钱包临时名或杂项命名一律 503 且保留现场；
- 登记文件恰为 {"wallet_id","snapshots":{S:{"manifest_sha256"}}}，
  UTF-8、sort_keys、2 空格缩进、末尾换行；JSON/形状/哈希错 503；
- 强杀于登记写中窗口：半截 ``.W.json.tmp``（含与上一版 W.json 同时在场）
  被原子解链重写续作，缺记录只登记一次，登记已在时清掉残留；
- restore(data_dir, wallet_id, input_path) 参数类型/空值/ID 错为 400，
  且在触碰文件系统之前判定；
- 闭集违规同样阻止 serve 就绪、常驻持锁访问返回 503（现场保留）。
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
from threshold_wallet.store import WalletStore


class _RecordsScene(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.src = os.path.join(self.tmp, "src")
        hs = make_harness(self.src)
        hs.service.create_wallet("alice", 2)
        hs.service.put_policy("alice", 1, 3600)
        self.pack = os.path.join(self.tmp, "b.tar")
        self.body = drbackup.backup(self.src, "alice", "S1", self.pack)
        self.mhash = self.body["manifest"]["manifest_sha256"]
        self.manifest, self.files = drbackup._read_snapshot(self.pack)
        self._n = 0

    def records_dir(self, dst):
        return os.path.join(dst, drbackup.RESTORE_RECORDS_DIRNAME)

    def record_path(self, dst):
        return drbackup._records_path(dst, "alice")

    def restore_expect_503(self, dst):
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.restore(dst, "alice", self.pack)
        self.assertEqual(cm.exception.status, 503)

    def plant_bytes(self, dst, name, raw=b"{}"):
        rdir = self.records_dir(dst)
        os.makedirs(rdir, exist_ok=True)
        path = os.path.join(rdir, name)
        with open(path, "wb") as f:
            f.write(raw)
        return path

    def plant_json(self, dst, name, value):
        return self.plant_bytes(
            dst, name, json.dumps(value).encode("utf-8")
        )

    def dst(self):
        d = os.path.join(self.tmp, f"dst-{self._n}")
        self._n += 1
        hd = make_harness(d)
        hd.service.create_wallet("alice", 2)
        hd.service.put_policy("alice", 2, 99)
        return d


class RestoreRecordsClosedSetTest(_RecordsScene):
    def test_record_written_in_canonical_form(self):
        dst = self.dst()
        status, body = drbackup.restore(dst, "alice", self.pack)
        self.assertEqual(status, 201)
        with open(self.record_path(dst), "rb") as f:
            raw = f.read()
        records = json.loads(raw.decode("utf-8"))
        self.assertEqual(
            records,
            {"wallet_id": "alice",
             "snapshots": {"S1": {"manifest_sha256": self.mhash}}},
        )
        # UTF-8、sort_keys、2 空格缩进、单个末尾换行
        expected = (
            json.dumps(records, ensure_ascii=False, sort_keys=True, indent=2)
            .encode("utf-8") + b"\n"
        )
        self.assertEqual(raw, expected)
        self.assertEqual(body["manifest_sha256"], self.mhash)

    def test_symlink_record_is_503_and_preserved(self):
        dst = self.dst()
        rdir = self.records_dir(dst)
        os.makedirs(rdir, exist_ok=True)
        link = os.path.join(rdir, "alice.json")
        os.symlink("/etc/hostname", link)
        self.restore_expect_503(dst)
        self.assertTrue(os.path.islink(link))

    def test_directory_named_record_is_503(self):
        dst = self.dst()
        rdir = self.records_dir(dst)
        os.makedirs(os.path.join(rdir, "alice.json"))
        self.restore_expect_503(dst)
        self.assertTrue(os.path.isdir(self.record_path(dst)))

    def test_backup_file_is_503(self):
        dst = self.dst()
        p = self.plant_bytes(dst, "alice.bak.json")
        self.restore_expect_503(dst)
        self.assertTrue(os.path.exists(p))

    def test_random_named_temp_is_503(self):
        dst = self.dst()
        p = self.plant_bytes(dst, ".tmp-abc.json")
        self.restore_expect_503(dst)
        self.assertTrue(os.path.exists(p))

    def test_other_wallet_write_temp_is_503(self):
        dst = self.dst()
        p = self.plant_bytes(dst, ".bob.json.tmp")
        self.restore_expect_503(dst)
        self.assertTrue(os.path.exists(p))

    def test_stray_non_json_entry_is_503(self):
        dst = self.dst()
        p = self.plant_bytes(dst, "notes.txt", b"x")
        self.restore_expect_503(dst)
        self.assertTrue(os.path.exists(p))

    def test_records_root_symlink_is_503(self):
        dst = self.dst()
        rdir = self.records_dir(dst)
        elsewhere = os.path.join(self.tmp, "elsewhere")
        os.makedirs(elsewhere)
        os.symlink(elsewhere, rdir)
        self.restore_expect_503(dst)
        self.assertTrue(os.path.islink(rdir))

    def test_other_wallet_formal_record_is_left_untouched(self):
        dst = self.dst()
        other = os.path.join(self.records_dir(dst), "bob.json")
        os.makedirs(self.records_dir(dst), exist_ok=True)
        payload = {"wallet_id": "bob", "snapshots": {}}
        with open(other, "wb") as f:
            f.write(json.dumps(payload).encode("utf-8"))
        status, _ = drbackup.restore(dst, "alice", self.pack)
        self.assertEqual(status, 201)
        with open(other, "rb") as f:
            self.assertEqual(json.loads(f.read().decode()), payload)

    def test_record_bad_json_is_503(self):
        dst = self.dst()
        self.plant_bytes(dst, "alice.json", b"{not json")
        self.restore_expect_503(dst)

    def test_record_bad_shape_is_503(self):
        dst = self.dst()
        self.plant_json(dst, "alice.json", {"wallet_id": "alice"})
        self.restore_expect_503(dst)

    def test_record_bad_snapshot_id_is_503(self):
        dst = self.dst()
        self.plant_json(dst, "alice.json", {
            "wallet_id": "alice",
            "snapshots": {"bad/id": {"manifest_sha256": "a" * 64}},
        })
        self.restore_expect_503(dst)

    def test_record_bad_digest_is_503(self):
        dst = self.dst()
        self.plant_json(dst, "alice.json", {
            "wallet_id": "alice",
            "snapshots": {"S1": {"manifest_sha256": "XYZ"}},
        })
        self.restore_expect_503(dst)

    def test_record_wallet_mismatch_is_503(self):
        dst = self.dst()
        self.plant_json(dst, "alice.json",
                        {"wallet_id": "bob", "snapshots": {}})
        self.restore_expect_503(dst)

    def test_backup_entry_blocks_serve_startup(self):
        dst = self.dst()
        drbackup.restore(dst, "alice", self.pack)
        evil = self.plant_bytes(dst, "alice.bak.json")
        with self.assertRaises(Exception):
            WalletService(WalletStore(dst))
        self.assertTrue(os.path.exists(evil))

    def test_backup_entry_via_locked_heal_is_503(self):
        dst = self.dst()
        with http_server(dst) as srv:
            drbackup.restore(dst, "alice", self.pack)
            evil = self.plant_bytes(dst, "alice.bak.json")
            status, body = srv.request("GET", "/v1/wallets/alice")
            self.assertEqual(status, 503, body)
            self.assertNotIn("private", json.dumps(body))
        self.assertTrue(os.path.exists(evil))


class OwnWriteTempConvergenceTest(_RecordsScene):
    def test_own_tmp_without_record_is_continued_once(self):
        dst = self.dst()
        rdir = self.records_dir(dst)
        os.makedirs(rdir, exist_ok=True)
        with open(os.path.join(rdir, ".alice.json.tmp"), "wb") as f:
            f.write(b"{half-written")
        status, _ = drbackup.restore(dst, "alice", self.pack)
        self.assertEqual(status, 201)
        records = drbackup._read_restore_records(dst, "alice")
        self.assertEqual(list(records["snapshots"]), ["S1"])
        self.assertFalse(os.path.exists(os.path.join(rdir, ".alice.json.tmp")))
        # 重放 200 同体
        status, body = drbackup.restore(dst, "alice", self.pack)
        self.assertEqual(status, 200)
        self.assertEqual(body["manifest"], self.body["manifest"])

    def test_own_tmp_coexisting_during_second_registration(self):
        dst = self.dst()
        drbackup.restore(dst, "alice", self.pack)
        src2 = os.path.join(self.tmp, "src2")
        shutil.copytree(self.src, src2)
        h2 = make_harness(src2)
        h2.service.create_asset_operation("alice", "op1", "BTC", 5)
        h2.service.commit_asset_operation("alice", "op1")
        pack2 = os.path.join(self.tmp, "b2.tar")
        body2 = drbackup.backup(src2, "alice", "S2", pack2)
        rdir = self.records_dir(dst)
        # 强杀于重写 W.json 的写中窗口：上一版 W.json 权威在盘 + 半截临时名
        with open(os.path.join(rdir, ".alice.json.tmp"), "wb") as f:
            f.write(b"{half")
        status, _ = drbackup.restore(dst, "alice", pack2)
        self.assertEqual(status, 201)
        records = drbackup._read_restore_records(dst, "alice")
        self.assertEqual(set(records["snapshots"]), {"S1", "S2"})
        self.assertEqual(
            records["snapshots"]["S2"]["manifest_sha256"],
            body2["manifest"]["manifest_sha256"],
        )
        self.assertFalse(os.path.exists(os.path.join(rdir, ".alice.json.tmp")))

    def test_committed_then_own_tmp_converges_on_startup(self):
        dst = self.dst()
        txn = drbackup._txn_dir(dst, "alice", "S1")
        os.makedirs(txn, exist_ok=True)
        drbackup._commit_restore(dst, "alice", "S1", self.manifest, self.files)
        drbackup._atomic_write_json(os.path.join(txn, "committed.json"), {
            "wallet_id": "alice", "snapshot_id": "S1",
            "manifest_sha256": self.mhash,
            "files": list(self.manifest["files"]),
        })
        rdir = self.records_dir(dst)
        os.makedirs(rdir, exist_ok=True)
        with open(os.path.join(rdir, ".alice.json.tmp"), "wb") as f:
            f.write(b"{half")
        WalletService(WalletStore(dst))  # 启动前滚 + 唯一登记
        records = drbackup._read_restore_records(dst, "alice")
        self.assertEqual(list(records["snapshots"]), ["S1"])
        self.assertFalse(os.path.exists(txn))
        self.assertFalse(os.path.exists(os.path.join(rdir, ".alice.json.tmp")))
        # 再启动不重复登记
        WalletService(WalletStore(dst))
        self.assertEqual(
            len(drbackup._read_restore_records(dst, "alice")["snapshots"]), 1
        )


class RestoreParameterValidationTest(_RecordsScene):
    def test_bad_params_are_400_before_filesystem(self):
        dst = self.dst()
        cases = [
            (None, "alice", self.pack),
            ("", "alice", self.pack),
            (123, "alice", self.pack),
            (dst, None, self.pack),
            (dst, 123, self.pack),
            (dst, "", self.pack),
            (dst, "bad/id", self.pack),
            (dst, "alice", None),
            (dst, "alice", ""),
            (dst, "alice", 456),
        ]
        for args in cases:
            with self.subTest(args=tuple(type(a).__name__ for a in args)):
                with self.assertRaises(drbackup.BackupError) as cm:
                    drbackup.restore(*args)
                self.assertEqual(cm.exception.status, 400)

    def test_same_snapshot_same_manifest_is_200_identical(self):
        dst = self.dst()
        s1, b1 = drbackup.restore(dst, "alice", self.pack)
        s2, b2 = drbackup.restore(dst, "alice", self.pack)
        self.assertEqual((s1, s2), (201, 200))
        self.assertEqual(b1 | {"status": 200}, b2 | {"status": 200})


if __name__ == "__main__":
    unittest.main()
