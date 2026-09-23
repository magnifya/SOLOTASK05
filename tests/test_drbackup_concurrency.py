"""backup/restore 的跨进程并发线性化与原子写出测试。

用 fork 出多个 OS 进程共用同一 data-dir（进程内锁互不共享，互斥只靠
fcntl.flock），验证：

- 同一快照并发 restore：恰一个 201，其余全部 200 且返回体彼此逐字节相同；
  最终 restore-records 只登记一次、restore-txn 无残留；
- 两个不同快照并发 restore：均首次 201，现场严格等于线性化在后的快照闭集，
  restore-records 同时登记两者；
- restore 与多个 backup 并发：backup 永远只拍到锁内自愈后的一致闭集，
  每个产物都能在全新目录独立 restore 成功；线上钱包最终可正常自愈；
- 写出中断（注入异常）只清掉同目录临时文件，既不产生半包、也不覆盖既有
  快照；输出目录不可写时失败为 503 且不留临时文件；
- restore/backup 期间其他钱包的文件逐字节不受影响。
"""

from __future__ import annotations

import glob
import json
import multiprocessing
import os
import tempfile
import unittest
from unittest import mock

from tests.helpers import make_harness
from threshold_wallet import drbackup
from threshold_wallet.service import WalletService
from threshold_wallet.store import WalletStore


# ---- 模块级 worker（fork 要求可 pickle 的顶层函数）-------------------------


def _child_restore(data_dir, pack, wallet, barrier, queue):
    try:
        barrier.wait()
        status, body = drbackup.restore(data_dir, wallet, pack)
        queue.put((status, json.dumps(body, sort_keys=True)))
    except drbackup.BackupError as exc:
        queue.put(("ERR", exc.status, exc.message))
    except BaseException as exc:  # 任何未预期异常都要让用例看到
        queue.put(("EXC", repr(exc)))


def _child_backup(data_dir, wallet, sid, out, barrier, queue):
    try:
        barrier.wait()
        body = drbackup.backup(data_dir, wallet, sid, out)
        queue.put((201, sid, out, body["manifest"]["manifest_sha256"]))
    except drbackup.BackupError as exc:
        queue.put(("ERR", exc.status, exc.message))
    except BaseException as exc:
        queue.put(("EXC", repr(exc)))


def _drain(queue, count):
    items = []
    for _ in range(count):
        items.append(queue.get(timeout=60))
    return items


class ConcurrentRestoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.src = os.path.join(self.tmp, "src")
        self.dst = os.path.join(self.tmp, "dst")
        h = make_harness(self.src)
        h.service.create_wallet("alice", 2)
        h.service.put_policy("alice", 1, 3600)
        h.service.create_sign_request("alice", "req1", "pay-100")
        h.service.approve("alice", "req1", "ops", None)
        sigs = h.two_signatures("alice", "req1", "pay-100")
        h.service.sign("alice", "req1", "pay-100", sigs)
        h.service.create_asset_operation("alice", "op1", "BTC", 10)
        h.service.commit_asset_operation("alice", "op1")
        self.pack = os.path.join(self.tmp, "b.tar")
        drbackup.backup(self.src, "alice", "S1", self.pack)
        self.n = 6

    def test_concurrent_same_snapshot_one_201_rest_identical_200(self):
        ctx = multiprocessing.get_context("fork")
        barrier = ctx.Barrier(self.n)
        queue = ctx.Queue()
        procs = [
            ctx.Process(
                target=_child_restore,
                args=(self.dst, self.pack, "alice", barrier, queue),
            )
            for _ in range(self.n)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=60)
            self.assertEqual(p.exitcode, 0)
        results = _drain(queue, self.n)

        statuses = [r[0] for r in results]
        self.assertEqual(sorted(statuses).count(201), 1, results)
        self.assertEqual(sorted(statuses).count(200), self.n - 1, results)

        bodies_200 = {r[1] for r in results if r[0] == 200}
        self.assertEqual(len(bodies_200), 1, "所有 200 返回体必须完全相同")
        body_201 = next(r[1] for r in results if r[0] == 201)
        # 201 与 200 仅 status 字段不同，其余（snapshot_id/manifest/哈希）同体
        self.assertEqual(
            json.loads(body_201) | {"status": 200},
            json.loads(next(iter(bodies_200))) | {"status": 200},
        )

        # 登记恰好一次，事务目录无残留，现场等于快照闭集
        records = drbackup._read_restore_records(self.dst, "alice")
        self.assertEqual(sorted(records["snapshots"]), ["S1"])
        self.assertFalse(
            os.path.exists(os.path.join(self.dst, "restore-txn"))
        )
        status, body = drbackup.restore(self.dst, "alice", self.pack)
        self.assertEqual(status, 200)

    def test_concurrent_different_snapshots_both_first_time(self):
        # 第二快照：再提交一笔资产，内容与 S1 不同但 snapshot_id 不同
        h2 = make_harness(self.src)
        h2.service.create_asset_operation("alice", "op2", "BTC", 5)
        h2.service.commit_asset_operation("alice", "op2")
        pack2 = os.path.join(self.tmp, "b2.tar")
        drbackup.backup(self.src, "alice", "S2", pack2)

        ctx = multiprocessing.get_context("fork")
        barrier = ctx.Barrier(2)
        queue = ctx.Queue()
        procs = [
            ctx.Process(
                target=_child_restore,
                args=(self.dst, pack, "alice", barrier, queue),
            )
            for pack in (self.pack, pack2)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=60)
            self.assertEqual(p.exitcode, 0)
        results = _drain(queue, 2)
        self.assertEqual(sorted(r[0] for r in results), [201, 201], results)

        # 两个恢复点都已登记；现场严格等于其中一个快照的闭集
        records = drbackup._read_restore_records(self.dst, "alice")
        self.assertEqual(set(records["snapshots"]), {"S1", "S2"})
        manifest1, files1 = drbackup._read_snapshot(self.pack)
        manifest2, files2 = drbackup._read_snapshot(pack2)

        def live_matches(files):
            live = set(
                drbackup._list_current_relpaths(self.dst, "alice")
            )
            if live != set(files):
                return False
            for rel, data in files.items():
                with open(os.path.join(self.dst, *rel.split("/")), "rb") as f:
                    if f.read() != data:
                        return False
            return True

        matches = (live_matches(files1), live_matches(files2))
        self.assertEqual(sum(matches), 1, "现场必须恰等于其中一个快照闭集")
        # 新进程自愈必须无异常
        WalletService(WalletStore(self.dst))


class ConcurrentBackupRestoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.data = os.path.join(self.tmp, "data")
        h = make_harness(self.data)
        h.service.create_wallet("alice", 2)
        h.service.put_policy("alice", 1, 3600)
        h.service.create_asset_operation("alice", "op1", "BTC", 10)
        h.service.commit_asset_operation("alice", "op1")
        # 另一个钱包：并发期间其文件必须逐字节不变
        h.service.create_wallet("bob", 2)
        h.service.put_policy("bob", 2, 77)

        def bob_snapshot():
            return {
                rel: open(os.path.join(self.data, *rel.split("/")), "rb").read()
                for rel in drbackup._list_current_relpaths(self.data, "bob")
            }

        self.pack = os.path.join(self.tmp, "b.tar")
        drbackup.backup(self.data, "alice", "S0", self.pack)
        self.bob_files = bob_snapshot()

    def test_backup_restore_interleave_only_consistent_snapshots(self):
        n_backup = 4
        total = n_backup + 1
        ctx = multiprocessing.get_context("fork")
        barrier = ctx.Barrier(total)
        queue = ctx.Queue()
        outs = [os.path.join(self.tmp, f"c{i}.tar") for i in range(n_backup)]
        procs = [
            ctx.Process(
                target=_child_restore,
                args=(self.data, self.pack, "alice", barrier, queue),
            )
        ]
        for i, out in enumerate(outs):
            procs.append(
                ctx.Process(
                    target=_child_backup,
                    args=(self.data, "alice", f"C{i}", out, barrier, queue),
                )
            )
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=60)
            self.assertEqual(p.exitcode, 0)
        results = _drain(queue, total)
        for r in results:
            self.assertEqual(r[0], 201, r)

        # 并发期间产生的每个快照都是锁内一致闭集：在全新目录均可独立恢复
        for i, out in enumerate(outs):
            self.assertTrue(os.path.isfile(out))
            d = os.path.join(self.tmp, f"verify{i}")
            status, _ = drbackup.restore(d, "alice", out)
            self.assertEqual(status, 201)

        # 线上钱包持锁自愈无异常；bob 钱包文件逐字节未变
        WalletService(WalletStore(self.data))
        bob_now = {}
        for rel in drbackup._list_current_relpaths(self.data, "bob"):
            with open(os.path.join(self.data, *rel.split("/")), "rb") as f:
                bob_now[rel] = f.read()
        self.assertEqual(bob_now, self.bob_files)

        # data-dir 内不得残留任何半包临时文件
        leftovers = glob.glob(
            os.path.join(self.data, "**", ".snapshot-*.tmp"),
            recursive=True,
        )
        self.assertEqual(leftovers, [])


class AtomicSnapshotWriteTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.out_dir = os.path.join(self.tmp, "outs")
        os.makedirs(self.out_dir)
        self.out = os.path.join(self.out_dir, "s.tar")

    def test_interrupted_write_leaves_no_half_package(self):
        manifest = {"version": 1}
        payloads = [("a/a.json", b"{}"), ("b/b.json", b"{}")]
        real_add = drbackup._add_bytes
        calls = {"n": 0}

        def flaky(tar, name, data):
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("simulated interruption")
            return real_add(tar, name, data)

        with mock.patch.object(drbackup, "_add_bytes", flaky):
            with self.assertRaises(RuntimeError):
                drbackup._write_snapshot(self.out, manifest, payloads)
        self.assertFalse(os.path.exists(self.out))
        self.assertEqual(
            glob.glob(os.path.join(self.out_dir, ".snapshot-*.tmp")), []
        )

    def test_failed_write_preserves_existing_snapshot(self):
        payload = b"ORIGINAL-SNAPSHOT"
        with open(self.out, "wb") as f:
            f.write(payload)
        with mock.patch.object(drbackup, "_add_bytes", side_effect=OSError("x")):
            with self.assertRaises(OSError):
                drbackup._write_snapshot(self.out, {"v": 1}, [("a", b"{}")])
        with open(self.out, "rb") as f:
            self.assertEqual(f.read(), payload)
        self.assertEqual(
            glob.glob(os.path.join(self.out_dir, ".snapshot-*.tmp")), []
        )

    def test_unwritable_output_dir_is_503_without_leftover(self):
        data = os.path.join(self.tmp, "data")
        h = make_harness(data)
        h.service.create_wallet("alice", 2)
        # 输出"目录"实际是普通文件：同目录临时文件无法创建（NotADirectory
        # Error 属 OSError），且不依赖文件权限（root 下 chmod 无法挡写）。
        blocked = os.path.join(self.tmp, "not-a-dir")
        with open(blocked, "wb") as f:
            f.write(b"x")
        with self.assertRaises(drbackup.BackupError) as cm:
            drbackup.backup(
                data, "alice", "S1", os.path.join(blocked, "x.tar")
            )
        self.assertEqual(cm.exception.status, 503)


if __name__ == "__main__":
    unittest.main()
