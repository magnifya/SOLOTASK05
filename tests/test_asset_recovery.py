"""资产提交崩溃一致性测试（可独立运行）。

覆盖任务契约：
- 提交事务 = 操作状态 + 余额/version+1 + 唯一 asset_operation_committed
  事件；进程在任一落盘阶段被强杀后，同一 data-dir 重启先恢复：
  事件已持久化则保留并补齐 committed 结果，未持久化则恢复 pending
  与提交前余额/版本；
- 恢复后不出现提交无事件、事件与余额不符、重复版本或重复事件；
- 普通写入/事件追加失败恢复 pending 与提交前状态，无事件、无 seq
  缺口，可重试；
- 多进程并发提交同一操作恰一个 201，其余 200 同体；
- GET assets 响应严格为 {asset_id, balance, version}；
- 恢复数据（提交意图日志）不含私钥材料。

运行：python -m unittest tests.test_asset_recovery -v
"""

from __future__ import annotations

import json
import multiprocessing
import os
import shutil
import tempfile
import unittest

from threshold_wallet import audit
from threshold_wallet.audit import AuditStore
from threshold_wallet.service import WalletService
from threshold_wallet.store import WalletStore


def _make_service(data_dir):
    return WalletService(WalletStore(data_dir))


def _journal_path(data_dir, wallet_id):
    return os.path.join(data_dir, "asset-commit-journal", wallet_id + ".json")


def _child_commit_crash_before_event(data_dir, wallet_id, operation_id):
    """子进程：账本已提交、事件尚未追加时 os._exit 模拟强杀。"""
    service = _make_service(data_dir)

    def crash_emit(wid, event):
        os._exit(1)

    service._emit = crash_emit
    try:
        service.commit_asset_operation(wallet_id, operation_id)
    except BaseException:
        pass
    os._exit(0)


def _child_commit_crash_after_event(data_dir, wallet_id, operation_id):
    """子进程：事件已持久化、恢复意图尚未清除时 os._exit 模拟强杀。"""
    service = _make_service(data_dir)
    real_emit = service._emit

    def emit_then_crash(wid, event):
        real_emit(wid, event)
        os._exit(1)

    service._emit = emit_then_crash
    try:
        service.commit_asset_operation(wallet_id, operation_id)
    except BaseException:
        pass
    os._exit(0)


def _child_commit(data_dir, wallet_id, operation_id, result_queue):
    """子进程：提交资产操作，回报 (状态码, 响应体)。"""
    service = _make_service(data_dir)
    try:
        status, body = service.commit_asset_operation(wallet_id, operation_id)
        result_queue.put((status, json.dumps(body, sort_keys=True)))
    except Exception as exc:  # noqa: BLE001 - 测试回报任意失败
        result_queue.put(("error", repr(exc)))


class AssetCommitCrashRecoveryTest(unittest.TestCase):
    """各故障点强杀后，同一 data-dir 重启的恢复定论。"""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.data_dir, ignore_errors=True)
        self.ctx = multiprocessing.get_context("fork")
        service = _make_service(self.data_dir)
        service.create_wallet("w1", 2)
        # 先有一笔已提交操作：资产 btc = (100, 1)
        service.create_asset_operation("w1", "op-seed", "btc", 100)
        status, self.seed_body = service.commit_asset_operation("w1", "op-seed")
        self.assertEqual(status, 201)
        # 待提交的 pending 操作：delta -30
        service.create_asset_operation("w1", "op-1", "btc", -30)
        self.store = WalletStore(self.data_dir)

    def _run_crash_child(self, target):
        proc = self.ctx.Process(target=target, args=(self.data_dir, "w1", "op-1"))
        proc.start()
        proc.join(timeout=30)
        self.assertNotEqual(proc.exitcode, 0)
        self.assertIsNotNone(proc.exitcode)

    def _events(self):
        return _make_service(self.data_dir).get_audit_events("w1")["events"]

    def _committed_events(self):
        return [
            e for e in self._events()
            if e["type"] == audit.TYPE_ASSET_OPERATION_COMMITTED
        ]

    def test_crash_before_event_rolls_back_to_pending(self):
        self._run_crash_child(_child_commit_crash_before_event)
        # 崩溃现场：意图与 committed 账本已落盘，事件未持久化
        self.assertTrue(os.path.exists(_journal_path(self.data_dir, "w1")))
        self.assertEqual(len(self._committed_events()), 1)  # 仅 op-seed

        service = _make_service(self.data_dir)  # 重启触发恢复
        # 恢复 pending 与提交前余额/版本；意图已清理
        record = self.store.get_asset_operation("w1", "op-1")
        self.assertEqual(record["state"], "pending")
        self.assertEqual(record["balance"], 100)
        self.assertEqual(record["version"], 1)
        self.assertEqual(
            service.get_asset("w1", "btc"),
            {"asset_id": "btc", "balance": 100, "version": 1},
        )
        self.assertFalse(os.path.exists(_journal_path(self.data_dir, "w1")))
        # 恢复不产生事件、不产生 seq 缺口
        events = self._events()
        self.assertEqual(len(self._committed_events()), 1)
        self.assertEqual([e["seq"] for e in events], list(range(1, len(events) + 1)))
        # 之后可重试：唯一首次 201，余额只应用一次，事件唯一
        status, body = service.commit_asset_operation("w1", "op-1")
        self.assertEqual(status, 201)
        self.assertEqual(body["state"], "committed")
        self.assertEqual((body["balance"], body["version"]), (70, 2))
        self.assertEqual(
            service.get_asset("w1", "btc"),
            {"asset_id": "btc", "balance": 70, "version": 2},
        )
        committed = self._committed_events()
        self.assertEqual(len(committed), 2)
        self.assertEqual(committed[-1]["request_id"], "op-1")
        self.assertIsNone(committed[-1]["actor_id"])
        self.assertIsNone(committed[-1]["reason"])
        self.assertEqual(committed[-1]["details"], body)
        events = self._events()
        self.assertEqual([e["seq"] for e in events], list(range(1, len(events) + 1)))

    def test_crash_after_event_keeps_committed_result(self):
        self._run_crash_child(_child_commit_crash_after_event)
        # 崩溃现场：事件已持久化，恢复意图残留
        self.assertTrue(os.path.exists(_journal_path(self.data_dir, "w1")))
        self.assertEqual(len(self._committed_events()), 2)

        service = _make_service(self.data_dir)  # 重启触发恢复
        # 保留事件并补齐唯一 committed 结果；事件与余额一致
        record = self.store.get_asset_operation("w1", "op-1")
        self.assertEqual(record["state"], "committed")
        self.assertEqual((record["balance"], record["version"]), (70, 2))
        self.assertEqual(
            service.get_asset("w1", "btc"),
            {"asset_id": "btc", "balance": 70, "version": 2},
        )
        self.assertFalse(os.path.exists(_journal_path(self.data_dir, "w1")))
        committed = self._committed_events()
        self.assertEqual(len(committed), 2)  # 恢复不重复记事件
        self.assertEqual(committed[-1]["details"], record)
        # 重放 200 同体，不改余额、版本或审计
        status, body = service.commit_asset_operation("w1", "op-1")
        self.assertEqual(status, 200)
        self.assertEqual(body, record)
        self.assertEqual(
            service.get_asset("w1", "btc"),
            {"asset_id": "btc", "balance": 70, "version": 2},
        )
        self.assertEqual(len(self._committed_events()), 2)
        events = self._events()
        self.assertEqual([e["seq"] for e in events], list(range(1, len(events) + 1)))

    def test_crash_before_ledger_write_leaves_pending(self):
        # 只有恢复意图落盘（账本未动、无事件）
        intent = {
            "operation_id": "op-1",
            "asset_id": "btc",
            "operation_before": self.store.get_asset_operation("w1", "op-1"),
            "asset_before": self.store.get_asset("w1", "btc"),
            "operation_after": {},
            "asset_after": {},
        }
        self.store.save_asset_commit_intent("w1", intent)
        service = _make_service(self.data_dir)
        record = self.store.get_asset_operation("w1", "op-1")
        self.assertEqual(record["state"], "pending")
        self.assertEqual(
            service.get_asset("w1", "btc"),
            {"asset_id": "btc", "balance": 100, "version": 1},
        )
        self.assertFalse(os.path.exists(_journal_path(self.data_dir, "w1")))
        self.assertEqual(len(self._committed_events()), 1)
        # 重试成功
        status, _ = service.commit_asset_operation("w1", "op-1")
        self.assertEqual(status, 201)

    def test_lazy_recovery_on_query_without_restart(self):
        # 不重启：正在运行的进程通过懒惰恢复定论另一进程留下的现场
        service = _make_service(self.data_dir)  # 启动时无残留
        # 另一"进程"崩溃留下：意图 + committed 账本，无事件
        record = self.store.get_asset_operation("w1", "op-1")
        asset = self.store.get_asset("w1", "btc")
        committed = dict(record, state="committed", balance=70, version=2)
        self.store.save_asset_commit_intent(
            "w1",
            {
                "operation_id": "op-1",
                "asset_id": "btc",
                "operation_before": record,
                "asset_before": asset,
                "operation_after": committed,
                "asset_after": {"balance": 70, "version": 2},
            },
        )
        self.store.commit_asset_operation(
            "w1", "op-1", committed, "btc", {"balance": 70, "version": 2}
        )
        # 查询触发懒惰恢复：不得看到半完成余额
        self.assertEqual(
            service.get_asset("w1", "btc"),
            {"asset_id": "btc", "balance": 100, "version": 1},
        )
        self.assertEqual(
            self.store.get_asset_operation("w1", "op-1")["state"], "pending"
        )
        self.assertFalse(os.path.exists(_journal_path(self.data_dir, "w1")))


class AssetCommitWriteFailureTest(unittest.TestCase):
    """普通写入/事件追加失败：恢复 pending 与提交前状态，可重试。"""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.data_dir, ignore_errors=True)
        self.service = _make_service(self.data_dir)
        self.service.create_wallet("w1", 2)
        self.service.create_asset_operation("w1", "op-seed", "btc", 100)
        self.service.commit_asset_operation("w1", "op-seed")
        self.service.create_asset_operation("w1", "op-1", "btc", -30)
        # 打补丁须作用于 service 内部使用的同一个 store 实例
        self.store = self.service._store

    def _assert_pending_unchanged(self):
        record = self.store.get_asset_operation("w1", "op-1")
        self.assertEqual(record["state"], "pending")
        self.assertEqual(
            self.store.get_asset("w1", "btc"),
            {"balance": 100, "version": 1},
        )
        self.assertFalse(os.path.exists(_journal_path(self.data_dir, "w1")))
        committed = [
            e
            for e in self.service.get_audit_events("w1")["events"]
            if e["type"] == audit.TYPE_ASSET_OPERATION_COMMITTED
        ]
        self.assertEqual(len(committed), 1)  # 仅 op-seed，无 seq 缺口

    def test_event_append_failure_rolls_back(self):
        real_emit = self.service._emit

        def boom(wallet_id, event):
            raise OSError("audit disk full")

        self.service._emit = boom
        try:
            with self.assertRaises(OSError):
                self.service.commit_asset_operation("w1", "op-1")
        finally:
            self.service._emit = real_emit
        self._assert_pending_unchanged()
        # 重试成功：恰一个首次 201
        status, body = self.service.commit_asset_operation("w1", "op-1")
        self.assertEqual(status, 201)
        self.assertEqual((body["balance"], body["version"]), (70, 2))

    def test_ledger_write_failure_rolls_back(self):
        original = self.store.commit_asset_operation

        def boom(*args):
            raise OSError("ledger disk full")

        self.store.commit_asset_operation = boom
        try:
            with self.assertRaises(OSError):
                self.service.commit_asset_operation("w1", "op-1")
        finally:
            self.store.commit_asset_operation = original
        self._assert_pending_unchanged()
        status, _ = self.service.commit_asset_operation("w1", "op-1")
        self.assertEqual(status, 201)

    def test_intent_cleanup_failure_still_commits_and_recovers(self):
        # 提交完成后清除意图失败：事务已提交，残留意图由恢复幂等定论
        real_delete = self.store.delete_asset_commit_intent
        failures = {"n": 0}

        def flaky_delete(wallet_id):
            failures["n"] += 1
            if failures["n"] == 1:
                raise OSError("transient unlink failure")
            return real_delete(wallet_id)

        self.store.delete_asset_commit_intent = flaky_delete
        status, body = self.service.commit_asset_operation("w1", "op-1")
        self.assertEqual(status, 201)
        self.assertTrue(os.path.exists(_journal_path(self.data_dir, "w1")))
        self.store.delete_asset_commit_intent = real_delete
        # 重启恢复：按已持久化事件定论，状态不变、不重复记事件
        service = _make_service(self.data_dir)
        self.assertFalse(os.path.exists(_journal_path(self.data_dir, "w1")))
        self.assertEqual(
            service.get_asset("w1", "btc"),
            {"asset_id": "btc", "balance": 70, "version": 2},
        )
        status, replay = service.commit_asset_operation("w1", "op-1")
        self.assertEqual(status, 200)
        self.assertEqual(replay, body)
        committed = [
            e
            for e in service.get_audit_events("w1")["events"]
            if e["type"] == audit.TYPE_ASSET_OPERATION_COMMITTED
        ]
        self.assertEqual(len(committed), 2)


class AssetCommitMultiProcessTest(unittest.TestCase):
    """多进程并发提交同一操作：恰一个首次 201，其余 200 同体。"""

    def test_concurrent_commit_across_processes(self):
        data_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, data_dir, ignore_errors=True)
        service = _make_service(data_dir)
        service.create_wallet("w1", 2)
        service.create_asset_operation("w1", "op-1", "btc", 100)
        ctx = multiprocessing.get_context("fork")
        queue = ctx.Queue()
        procs = [
            ctx.Process(
                target=_child_commit, args=(data_dir, "w1", "op-1", queue)
            )
            for _ in range(4)
        ]
        for proc in procs:
            proc.start()
        for proc in procs:
            proc.join(timeout=30)
        results = [queue.get(timeout=30) for _ in procs]
        statuses = sorted(status for status, _ in results)
        self.assertEqual(statuses, [200, 200, 200, 201])
        # 所有响应体一致：同一个 committed R
        self.assertEqual(len({body for _, body in results}), 1)
        # 余额只应用一次、事件唯一、seq 连续
        service = _make_service(data_dir)
        self.assertEqual(
            service.get_asset("w1", "btc"),
            {"asset_id": "btc", "balance": 100, "version": 1},
        )
        events = service.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in events], [1])
        self.assertEqual(events[0]["type"], audit.TYPE_ASSET_OPERATION_COMMITTED)


class AssetRecoveryBoundaryTest(unittest.TestCase):
    """恢复数据私钥边界与 GET 响应形状。"""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.data_dir, ignore_errors=True)
        self.service = _make_service(self.data_dir)
        self.service.create_wallet("w1", 2)
        # 打补丁须作用于 service 内部使用的同一个 store 实例
        self.store = self.service._store

    def test_journal_contains_no_private_key_material(self):
        self.service.create_asset_operation("w1", "op-1", "btc", 100)
        # 让提交后的意图清理失败，使恢复意图留盘接受检查
        real_delete = self.store.delete_asset_commit_intent

        def keep_journal(wallet_id):
            raise OSError("keep journal")

        self.store.delete_asset_commit_intent = keep_journal
        try:
            status, _ = self.service.commit_asset_operation("w1", "op-1")
            self.assertEqual(status, 201)
        finally:
            self.store.delete_asset_commit_intent = real_delete
        with open(_journal_path(self.data_dir, "w1"), encoding="utf-8") as f:
            raw = f.read()
        self.assertNotIn("private", raw)
        for sid in ("share-1", "share-2"):
            private_hex = self.store.get_share("w1", sid)["private_key"]
            self.assertNotIn(private_hex, raw)
        intent = json.loads(raw)
        self.assertEqual(intent["operation_id"], "op-1")
        # 重启恢复后意图被清理
        _make_service(self.data_dir)
        self.assertFalse(os.path.exists(_journal_path(self.data_dir, "w1")))

    def test_get_asset_response_shape_is_strict(self):
        self.service.create_asset_operation("w1", "op-1", "btc", 100)
        self.service.commit_asset_operation("w1", "op-1")
        view = self.service.get_asset("w1", "btc")
        self.assertEqual(
            view, {"asset_id": "btc", "balance": 100, "version": 1}
        )
        self.assertEqual(set(view), {"asset_id", "balance", "version"})


if __name__ == "__main__":
    unittest.main()
