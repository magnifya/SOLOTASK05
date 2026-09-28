"""已结算跨链派发的重组补偿（POST /v1/wallets/{W}/chain/{D}/confirm
在派发已结算后的重组分支）与 settle 响应 R 键序归一测试。

覆盖：
- settle 的 201/200 响应 R 键序统一为
  operation_id,asset_id,delta,state,balance,version；
- 已结算派发的 confirm 仅接受 adapter 匹配、tx 或区块改变、
  confirmations 低于阈值且高度回退 <= reorg_window 的新 B；adapter
  不符、未移动、确认数达阈值、回退越界/高度前进一律 409 且零副作用；
  历史同体仍 200；
- 以 D 为 operation_id 创建同资产、反向 delta 的补偿操作：ID 占用或
  余额将负为 409 且零副作用；成功 201 返回既有七键 V（state=reorged）；
  同 B 重放 200 同 V、异体 409、并发仅一 201；
- 锁内原子追加连续的 chain_dispatch_confirmation（details=V）、
  chain_dispatch_reorged（details={dispatch_id:D,operation_id:D}）、
  asset_operation_committed（details=R），request_id=D、
  actor_id=adapter_id、reason=null；三者俱在前滚、俱无回滚；
- 事件写失败整体回滚（补偿操作被删除）且可重试；残缺/矛盾的
  三事件批、错序 details 均为 RecoveryError 留现场；坏 JSON/I/O
  分别 CorruptDataError/OSError，HTTP 503。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import RecoveryError

from tests.helpers import http_server, make_harness

TX1 = "ab" * 32
TX2 = "cd" * 32
BH1 = "01" * 32
BH2 = "02" * 32


def _msg(operation_id="op1", dispatch_id="dp1", adapter_id="ad1",
         chain_id="chain-1"):
    return json.dumps(
        {
            "operation_id": operation_id,
            "dispatch_id": dispatch_id,
            "adapter_id": adapter_id,
            "chain_id": chain_id,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


class _SceneMixin:
    """建钱包/策略/审批/派发/播链结果/finalized 确认/结算的共用装配。"""

    def _build_settled(self, delta=100, required=3, window=2, height=10,
                       confirmations=3):
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 600)
        code, _ = self.svc.create_asset_operation("w1", "op1", "BTC", delta)
        self.assertEqual(code, 201)
        self.svc.put_chain_policy(
            "w1", "BTC", "chain-1", True, required, window
        )
        code, _ = self.svc.create_sign_request("w1", "ap1", _msg())
        self.assertEqual(code, 201)
        self.svc.approve("w1", "ap1", "boss")
        code, _ = self.svc.post_chain_dispatch(
            "w1", "op1", "dp1", "ad1", "ap1"
        )
        self.assertEqual(code, 201)
        code, _ = self.svc.post_chain_dispatch_result(
            "w1", "dp1", "ad1", "broadcasted", TX1
        )
        self.assertEqual(code, 201)
        code, _ = self.svc.post_chain_dispatch_confirmation(
            "w1", "dp1", "ad1", TX1, height, BH1, confirmations
        )
        self.assertEqual(code, 201)
        code, r = self.svc.settle_chain_dispatch("w1", "dp1")
        self.assertEqual(code, 201)
        return r

    def _reorg(self, wallet="w1", dispatch_id="dp1", adapter_id="ad1",
               tx_id=TX1, block_height=9, block_hash=BH2, confirmations=1):
        try:
            return self.svc.post_chain_dispatch_confirmation(
                wallet, dispatch_id, adapter_id, tx_id,
                block_height, block_hash, confirmations,
            )
        except ServiceError as exc:
            return exc.status, {"error": exc.message}

    def _events(self, types=None):
        events = self.svc.get_audit_events("w1")["events"]
        if types is None:
            return events
        return [e for e in events if e["type"] in types]


class SettleViewKeyOrderTest(_SceneMixin, unittest.TestCase):
    """settle 的 201/200 响应 R 键序统一。"""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service

    def test_settle_201_and_200_share_canonical_key_order(self):
        r1 = self._build_settled()
        self.assertEqual(
            list(r1),
            ["operation_id", "asset_id", "delta", "state", "balance",
             "version"],
        )
        self.assertEqual(
            r1,
            {
                "operation_id": "op1",
                "asset_id": "BTC",
                "delta": 100,
                "state": "committed",
                "balance": 100,
                "version": 1,
            },
        )
        code, r2 = self.svc.settle_chain_dispatch("w1", "dp1")
        self.assertEqual(code, 200)
        self.assertEqual(list(r2), list(r1))
        self.assertEqual(r2, r1)
        # 重启后重放键序仍归一
        h2 = make_harness(self.d)
        code, r3 = h2.service.settle_chain_dispatch("w1", "dp1")
        self.assertEqual(code, 200)
        self.assertEqual(list(r3), list(r1))
        self.assertEqual(r3, r1)


class ReorgServiceTest(_SceneMixin, unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service

    def test_reorg_201_view_events_and_compensation(self):
        self._build_settled()
        status, v = self._reorg()
        self.assertEqual(status, 201)
        self.assertEqual(
            list(v),
            ["dispatch_id", "adapter_id", "tx_id", "block_height",
             "block_hash", "confirmations", "state"],
        )
        self.assertEqual(
            v,
            {
                "dispatch_id": "dp1",
                "adapter_id": "ad1",
                "tx_id": TX1,
                "block_height": 9,
                "block_hash": BH2,
                "confirmations": 1,
                "state": "reorged",
            },
        )
        # 补偿操作以 D 为 id、同资产、反向 delta，已 committed
        comp = self.h.store.get_asset_operation("w1", "dp1")
        self.assertEqual(
            comp,
            {
                "operation_id": "dp1",
                "asset_id": "BTC",
                "state": "committed",
                "delta": -100,
                "balance": 0,
                "version": 2,
            },
        )
        self.assertEqual(
            self.h.store.get_asset("w1", "BTC"),
            {"balance": 0, "version": 2},
        )
        # 三事件连续、request_id=D、actor_id=adapter_id、reason=null
        events = self._events(
            {
                "chain_dispatch_confirmation",
                "chain_dispatch_reorged",
                "asset_operation_committed",
            }
        )[-3:]
        self.assertEqual(len(events), 3)
        confirmation, reorged, committed = events
        self.assertEqual(confirmation["seq"] + 1, reorged["seq"])
        self.assertEqual(reorged["seq"] + 1, committed["seq"])
        self.assertEqual(confirmation["type"], "chain_dispatch_confirmation")
        self.assertEqual(confirmation["details"], v)
        self.assertEqual(reorged["type"], "chain_dispatch_reorged")
        self.assertEqual(
            list(reorged["details"]), ["dispatch_id", "operation_id"]
        )
        self.assertEqual(
            reorged["details"],
            {"dispatch_id": "dp1", "operation_id": "dp1"},
        )
        self.assertEqual(committed["type"], "asset_operation_committed")
        self.assertEqual(committed["details"]["delta"], -100)
        for event in events:
            self.assertEqual(event["request_id"], "dp1")
            self.assertEqual(event["actor_id"], "ad1")
            self.assertIsNone(event["reason"])
        # 落盘 details 键序保序
        with open(os.path.join(self.d, "audit", "w1.json"),
                  encoding="utf-8") as f:
            log = json.load(f)
        stored = [
            e for e in log["events"]
            if e["type"] == "chain_dispatch_reorged"
        ][0]
        self.assertEqual(
            list(stored),
            ["actor_id", "at", "details", "reason", "request_id", "seq",
             "type"],
        )
        self.assertEqual(
            list(stored["details"]), ["dispatch_id", "operation_id"]
        )

    def test_reorg_tx_changed_accepted(self):
        self._build_settled()
        # tx 改变、区块不变（同高度哈希不同）也构成重组
        status, v = self._reorg(tx_id=TX2, block_height=10, block_hash=BH1)
        self.assertEqual(status, 201)
        self.assertEqual(v["tx_id"], TX2)
        self.assertEqual(v["state"], "reorged")

    def test_replay_200_same_view_no_new_events(self):
        self._build_settled()
        status, v1 = self._reorg()
        self.assertEqual(status, 201)
        events_before = self._events()
        status, v2 = self._reorg()
        self.assertEqual(status, 200)
        self.assertEqual(v2, v1)
        self.assertEqual(self._events(), events_before)

    def test_different_body_after_reorg_409(self):
        self._build_settled()
        status, _ = self._reorg()
        self.assertEqual(status, 201)
        status, _ = self._reorg(block_height=8, confirmations=2)
        self.assertEqual(status, 409)
        # 历史同体（finalized 那条）仍 200
        status, v = self._reorg(
            tx_id=TX1, block_height=10, block_hash=BH1, confirmations=3
        )
        self.assertEqual(status, 200)
        self.assertEqual(v["state"], "finalized")

    def test_reject_non_reorg_reports_409_zero_side_effects(self):
        self._build_settled()
        events_before = self._events()
        # adapter 不符
        status, _ = self._reorg(adapter_id="ad2")
        self.assertEqual(status, 409)
        # 未移动（tx 与区块全同、确认数不同）
        status, _ = self._reorg(block_height=10, block_hash=BH1,
                                confirmations=2)
        self.assertEqual(status, 409)
        # 确认数达阈值
        status, _ = self._reorg(confirmations=3)
        self.assertEqual(status, 409)
        # 高度回退越窗（window=2，10->7 回退 3）
        status, _ = self._reorg(block_height=7)
        self.assertEqual(status, 409)
        # 高度前进（回退为负）
        status, _ = self._reorg(block_height=11)
        self.assertEqual(status, 409)
        # 零副作用：无新事件、无补偿操作、账本不变
        self.assertEqual(self._events(), events_before)
        self.assertIsNone(self.h.store.get_asset_operation("w1", "dp1"))
        self.assertEqual(
            self.h.store.get_asset("w1", "BTC"),
            {"balance": 100, "version": 1},
        )
        self.assertEqual(self.h.store.list_asset_intents("w1"), [])

    def test_operation_id_occupied_409_zero_side_effects(self):
        self._build_settled()
        code, _ = self.svc.create_asset_operation("w1", "dp1", "BTC", 5)
        self.assertEqual(code, 201)
        events_before = self._events()
        status, _ = self._reorg()
        self.assertEqual(status, 409)
        self.assertEqual(self._events(), events_before)
        self.assertEqual(
            self.h.store.get_asset_operation("w1", "dp1")["state"],
            "pending",
        )
        self.assertEqual(self.h.store.list_asset_intents("w1"), [])

    def test_compensation_would_go_negative_409(self):
        self._build_settled()
        # 再结算一笔等额支出：余额归零，补偿 -100 将使余额为负
        code, _ = self.svc.create_asset_operation("w1", "op2", "BTC", -100)
        self.assertEqual(code, 201)
        code, _ = self.svc.create_sign_request(
            "w1", "ap2", _msg("op2", "dp2", "ad1")
        )
        self.assertEqual(code, 201)
        self.svc.approve("w1", "ap2", "boss")
        code, _ = self.svc.post_chain_dispatch(
            "w1", "op2", "dp2", "ad1", "ap2"
        )
        self.assertEqual(code, 201)
        code, _ = self.svc.post_chain_dispatch_result(
            "w1", "dp2", "ad1", "broadcasted", TX1
        )
        self.assertEqual(code, 201)
        code, _ = self.svc.post_chain_dispatch_confirmation(
            "w1", "dp2", "ad1", TX1, 10, BH1, 3
        )
        self.assertEqual(code, 201)
        code, _ = self.svc.settle_chain_dispatch("w1", "dp2")
        self.assertEqual(code, 201)
        self.assertEqual(
            self.h.store.get_asset("w1", "BTC"),
            {"balance": 0, "version": 2},
        )
        events_before = self._events()
        status, _ = self._reorg()
        self.assertEqual(status, 409)
        # 零副作用
        self.assertEqual(self._events(), events_before)
        self.assertIsNone(self.h.store.get_asset_operation("w1", "dp1"))
        self.assertEqual(
            self.h.store.get_asset("w1", "BTC"),
            {"balance": 0, "version": 2},
        )
        self.assertEqual(self.h.store.list_asset_intents("w1"), [])

    def test_concurrent_only_one_201(self):
        self._build_settled()
        results = []
        barrier = threading.Barrier(8)
        lock = threading.Lock()

        def worker():
            barrier.wait()
            status, _ = self._reorg()
            with lock:
                results.append(status)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(results).count(201), 1)
        self.assertEqual(sorted(results).count(200), 7)
        self.assertEqual(
            len(self._events({"chain_dispatch_reorged"})), 1
        )

    def test_restart_preserves_reorg(self):
        self._build_settled()
        status, v1 = self._reorg()
        self.assertEqual(status, 201)
        events_before = self._events()
        h2 = make_harness(self.d)
        status, v2 = h2.service.post_chain_dispatch_confirmation(
            "w1", "dp1", "ad1", TX1, 9, BH2, 1
        )
        self.assertEqual(status, 200)
        self.assertEqual(v2, v1)
        self.assertEqual(
            [
                (e["type"], e["seq"])
                for e in h2.service.get_audit_events("w1")["events"]
            ],
            [(e["type"], e["seq"]) for e in events_before],
        )
        # 异体仍 409
        with self.assertRaises(ServiceError) as ctx:
            h2.service.post_chain_dispatch_confirmation(
                "w1", "dp1", "ad1", TX1, 8, BH2, 1
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_event_write_failure_rolls_back_and_is_retryable(self):
        self._build_settled()
        original = self.svc._audit.append_events

        def boom(*args, **kwargs):
            raise OSError("simulated write failure")

        self.svc._audit.append_events = boom
        with self.assertRaises(OSError):
            self.svc.post_chain_dispatch_confirmation(
                "w1", "dp1", "ad1", TX1, 9, BH2, 1
            )
        self.svc._audit.append_events = original
        # 俱无回滚：补偿操作被删除、无事件、无意图残留、余额复原
        self.assertIsNone(self.h.store.get_asset_operation("w1", "dp1"))
        self.assertEqual(self._events({"chain_dispatch_reorged"}), [])
        self.assertEqual(self.h.store.list_asset_intents("w1"), [])
        self.assertEqual(
            self.h.store.get_asset("w1", "BTC"),
            {"balance": 100, "version": 1},
        )
        # 可重试：三事件俱在前滚
        status, v = self._reorg()
        self.assertEqual(status, 201)
        self.assertEqual(v["state"], "reorged")
        self.assertEqual(
            self.h.store.get_asset("w1", "BTC"),
            {"balance": 0, "version": 2},
        )

    def _strip_events(self, predicate):
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        log["events"] = [e for e in log["events"] if not predicate(e)]
        # 重新编号保持 seq 连续：本测试要验证的是事件链**语义矛盾**
        # （RecoveryError），而非 seq 缺口这类结构性审计损坏
        # （CorruptDataError）。
        for index, event in enumerate(log["events"], 1):
            event["seq"] = index
        log["next_seq"] = len(log["events"]) + 1
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)

    def test_missing_committed_event_is_unreconcilable(self):
        self._build_settled()
        status, _ = self._reorg()
        self.assertEqual(status, 201)
        # 删掉三事件批的收尾提交事件：残缺批即矛盾现场
        self._strip_events(
            lambda e: e["type"] == "asset_operation_committed"
            and e["request_id"] == "dp1"
        )
        with self.assertRaises(RecoveryError):
            make_harness(self.d)
        with self.assertRaises(RecoveryError):
            self.svc.get_chain_dispatch_finality("w1", "dp1")

    def test_missing_reorged_event_is_unreconcilable(self):
        self._build_settled()
        status, _ = self._reorg()
        self.assertEqual(status, 201)
        self._strip_events(
            lambda e: e["type"] == "chain_dispatch_reorged"
        )
        with self.assertRaises(RecoveryError):
            make_harness(self.d)

    def test_reorged_details_out_of_order_is_unreconcilable(self):
        self._build_settled()
        status, _ = self._reorg()
        self.assertEqual(status, 201)
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for e in log["events"]:
            if e["type"] == "chain_dispatch_reorged":
                e["details"] = {
                    "operation_id": "dp1",
                    "dispatch_id": "dp1",
                }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            make_harness(self.d)

    def test_reorg_committed_details_use_r_key_order(self):
        # 重组补偿的 asset_operation_committed.details 须按 R 序
        # operation_id,asset_id,delta,state,balance,version 落盘与恢复；
        # 普通（结算）提交事件维持既有 sort_keys 序不变。
        self._build_settled()
        status, _ = self._reorg()
        self.assertEqual(status, 201)
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        committed = [
            e for e in log["events"]
            if e["type"] == "asset_operation_committed"
        ]
        settle_commit = next(
            e for e in committed if e["request_id"] == "op1"
        )
        reorg_commit = next(
            e for e in committed if e["request_id"] == "dp1"
        )
        self.assertEqual(
            list(reorg_commit["details"]),
            ["operation_id", "asset_id", "delta", "state",
             "balance", "version"],
        )
        self.assertEqual(
            list(settle_commit["details"]),
            ["asset_id", "balance", "delta", "operation_id",
             "state", "version"],
        )
        # 重启恢复后重组提交事件 details 仍为 R 序
        h2 = make_harness(self.d)
        events = h2.service.get_audit_events("w1")["events"]
        recovered = next(
            e for e in events
            if e["type"] == "asset_operation_committed"
            and e["request_id"] == "dp1"
        )
        self.assertEqual(
            list(recovered["details"]),
            ["operation_id", "asset_id", "delta", "state",
             "balance", "version"],
        )

    def test_reorg_committed_details_out_of_order_is_unreconcilable(self):
        self._build_settled()
        status, _ = self._reorg()
        self.assertEqual(status, 201)
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for e in log["events"]:
            if (
                e["type"] == "asset_operation_committed"
                and e["request_id"] == "dp1"
            ):
                d = e["details"]
                e["details"] = {
                    "operation_id": d["operation_id"],
                    "asset_id": d["asset_id"],
                    "state": d["state"],
                    "delta": d["delta"],
                    "balance": d["balance"],
                    "version": d["version"],
                }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            make_harness(self.d)

    def test_orphan_reorged_event_is_unreconcilable(self):
        self._build_settled()
        status, _ = self._reorg()
        self.assertEqual(status, 201)
        # 删掉重组确认事件：重组事件缺失紧邻前驱即矛盾现场
        self._strip_events(
            lambda e: e["type"] == "chain_dispatch_confirmation"
            and e["details"].get("state") == "reorged"
        )
        with self.assertRaises(RecoveryError):
            make_harness(self.d)

    def test_crash_before_events_rolls_back_on_restart(self):
        self._build_settled()
        # 强杀发生在事件落盘前：账本已改、意图残留、三事件俱无
        original_append = self.svc._audit.append_events
        original_delete = self.svc._store.delete_asset_commit_intent

        def boom(*args, **kwargs):
            raise OSError("simulated crash")

        self.svc._audit.append_events = boom
        self.svc._store.delete_asset_commit_intent = lambda *a, **k: None
        with self.assertRaises(OSError):
            self.svc.post_chain_dispatch_confirmation(
                "w1", "dp1", "ad1", TX1, 9, BH2, 1
            )
        self.svc._audit.append_events = original_append
        self.svc._store.delete_asset_commit_intent = original_delete
        # 现场：意图在、补偿操作已 committed、无重组事件
        self.assertEqual(len(self.h.store.list_asset_intents("w1")), 1)
        # 重启恢复：三事件俱无 → 回滚（删除新建补偿操作、复原余额、
        # 清意图），不新增事件
        events_before = self._events()
        h2 = make_harness(self.d)
        self.assertIsNone(h2.store.get_asset_operation("w1", "dp1"))
        self.assertEqual(
            h2.store.get_asset("w1", "BTC"),
            {"balance": 100, "version": 1},
        )
        self.assertEqual(h2.store.list_asset_intents("w1"), [])
        self.assertEqual(
            [
                (e["type"], e["seq"])
                for e in h2.service.get_audit_events("w1")["events"]
            ],
            [(e["type"], e["seq"]) for e in events_before],
        )
        # 可重试：三事件俱在前滚
        status, v = h2.service.post_chain_dispatch_confirmation(
            "w1", "dp1", "ad1", TX1, 9, BH2, 1
        )
        self.assertEqual(status, 201)
        self.assertEqual(v["state"], "reorged")

    def test_crash_after_events_forward_rolls_on_restart(self):
        self._build_settled()
        # 强杀发生在三事件落盘后、意图清理前：重启按事件前滚补齐
        original_delete = self.svc._store.delete_asset_commit_intent
        self.svc._store.delete_asset_commit_intent = lambda *a, **k: None
        try:
            status, v1 = self._reorg()
            self.assertEqual(status, 201)
        finally:
            self.svc._store.delete_asset_commit_intent = original_delete
        self.assertEqual(len(self.h.store.list_asset_intents("w1")), 1)
        events_before = self._events()
        h2 = make_harness(self.d)
        # 前滚：账本一致、意图清理、不新增事件
        self.assertEqual(h2.store.list_asset_intents("w1"), [])
        self.assertEqual(
            h2.store.get_asset("w1", "BTC"),
            {"balance": 0, "version": 2},
        )
        self.assertEqual(
            [
                (e["type"], e["seq"])
                for e in h2.service.get_audit_events("w1")["events"]
            ],
            [(e["type"], e["seq"]) for e in events_before],
        )
        status, v2 = h2.service.post_chain_dispatch_confirmation(
            "w1", "dp1", "ad1", TX1, 9, BH2, 1
        )
        self.assertEqual(status, 200)
        self.assertEqual(v2, v1)

    def test_intent_with_partial_events_is_unreconcilable(self):
        self._build_settled()
        # 意图残留 + 重组事件在而提交事件缺失：崩溃窗口外的矛盾现场
        original_delete = self.svc._store.delete_asset_commit_intent
        self.svc._store.delete_asset_commit_intent = lambda *a, **k: None
        try:
            status, _ = self._reorg()
            self.assertEqual(status, 201)
        finally:
            self.svc._store.delete_asset_commit_intent = original_delete
        self._strip_events(
            lambda e: e["type"] == "asset_operation_committed"
            and e["request_id"] == "dp1"
        )
        with self.assertRaises(RecoveryError):
            make_harness(self.d)



class ReorgHttpTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self._cm = http_server(self.d)
        self.srv = self._cm.__enter__()
        self.addCleanup(self._cm.__exit__, None, None, None)
        self.svc = self.srv.harness.service
        svc = self.svc
        svc.create_wallet("w1", 2)
        svc.put_policy("w1", 1, 600)
        svc.create_asset_operation("w1", "op1", "BTC", 100)
        svc.put_chain_policy("w1", "BTC", "chain-1", True, 3, 2)
        code, _ = svc.create_sign_request("w1", "ap1", _msg())
        self.assertEqual(code, 201)
        svc.approve("w1", "ap1", "boss")
        svc.post_chain_dispatch("w1", "op1", "dp1", "ad1", "ap1")
        svc.post_chain_dispatch_result(
            "w1", "dp1", "ad1", "broadcasted", TX1
        )
        svc.post_chain_dispatch_confirmation(
            "w1", "dp1", "ad1", TX1, 10, BH1, 3
        )

    def _confirm(self, body, wallet="w1", dispatch_id="dp1"):
        return self.srv.request(
            "POST", f"/v1/wallets/{wallet}/chain/{dispatch_id}/confirm",
            body,
        )

    def _settle(self):
        return self.srv.request("POST", "/v1/wallets/w1/chain/dp1/settle")

    def test_settle_wire_r_key_order(self):
        status, raw = self._raw(
            "POST", "/v1/wallets/w1/chain/dp1/settle", None
        )
        self.assertEqual(status, 201)
        self.assertEqual(
            raw,
            b'{"operation_id":"op1","asset_id":"BTC","delta":100,'
            b'"state":"committed","balance":100,"version":1}',
        )
        status, raw2 = self._raw(
            "POST", "/v1/wallets/w1/chain/dp1/settle", None
        )
        self.assertEqual(status, 200)
        self.assertEqual(raw2, raw)

    def _raw(self, method, path, raw):
        headers = {"Accept": "application/json"}
        if raw is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(
            self.srv.base_url + path, data=raw, method=method, headers=headers
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def test_reorg_http_201_replay_200(self):
        status, _ = self._settle()
        self.assertEqual(status, 201)
        body = {
            "adapter_id": "ad1",
            "tx_id": TX1,
            "block_height": 9,
            "block_hash": BH2,
            "confirmations": 1,
        }
        status, v = self._confirm(body)
        self.assertEqual(status, 201)
        self.assertEqual(v["state"], "reorged")
        status, v2 = self._confirm(body)
        self.assertEqual(status, 200)
        self.assertEqual(v2, v)
        # 异体 409
        status, err = self._confirm(dict(body, confirmations=2))
        self.assertEqual(status, 409)
        self.assertEqual(list(err), ["error"])
        # finality 反映重组后的最后进展
        status, f = self.srv.request(
            "GET", "/v1/wallets/w1/chain/dp1/finality"
        )
        self.assertEqual(status, 200)
        self.assertEqual(f["confirmation"]["state"], "reorged")
        # 资产视图反映补偿后的余额
        status, asset = self.srv.request("GET", "/v1/wallets/w1/assets/BTC")
        self.assertEqual(status, 200)
        self.assertEqual(asset, {"asset_id": "BTC", "balance": 0,
                                 "version": 2})

    def test_reorg_wire_compact(self):
        status, _ = self._settle()
        self.assertEqual(status, 201)
        raw_body = (
            b'{"adapter_id":"ad1","tx_id":"' + TX1.encode()
            + b'","block_height":9,"block_hash":"' + BH2.encode()
            + b'","confirmations":1}'
        )
        status, raw = self._raw(
            "POST", "/v1/wallets/w1/chain/dp1/confirm", raw_body
        )
        self.assertEqual(status, 201)
        self.assertNotIn(b": ", raw)
        self.assertNotIn(b", ", raw)
        self.assertFalse(raw.endswith(b"\n"))
        self.assertTrue(raw.startswith(b'{"dispatch_id":"dp1",'))
        self.assertIn(b'"state":"reorged"', raw)

    def test_503_on_corrupt_scene(self):
        status, _ = self._settle()
        self.assertEqual(status, 201)
        body = {
            "adapter_id": "ad1",
            "tx_id": TX1,
            "block_height": 9,
            "block_hash": BH2,
            "confirmations": 1,
        }
        status, _ = self._confirm(body)
        self.assertEqual(status, 201)
        # 删掉三事件批的收尾提交事件：残缺批即矛盾现场
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        log["events"] = [
            e for e in log["events"]
            if not (
                e["type"] == "asset_operation_committed"
                and e["request_id"] == "dp1"
            )
        ]
        log["next_seq"] = len(log["events"]) + 1
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        status, err = self._confirm(body)
        self.assertEqual(status, 503)
        self.assertEqual(list(err), ["error"])
        self.assertNotIn("dp1", json.dumps(err))


if __name__ == "__main__":
    unittest.main()
