"""跨链派发链上确认（POST /v1/wallets/{W}/chain/{D}/confirm）测试。

覆盖：
- 体恰含 adapter_id,tx_id,block_height,block_hash,confirmations 五键；
  D/adapter_id 为安全标识；两 hex 为 64 位小写；两数为非布尔非负 int；
  键集/类型/值错 400；钱包/派发未知 404；
- 无 broadcasted 结果、归属/迁移冲突、同块确认数下降、换块越界、
  finalized 后异体进展一律 409；
- 派发前阈值/窗口快照：同块确认数不降；换块仅 confirming 且回退不超
  reorg_window；达 required_confirmations 为 finalized；
- 新进展 201 返回 V（七键固定序），历史同体重放优先 200 原 V；
- chain_dispatch_confirmation 为唯一提交点：request_id=D、
  actor_id=adapter、reason=null、details=V 七键固定序，重放不记；
- 恢复按 seq 复核 result 在先、归属、迁移、状态机；坏形状/错序/矛盾
  fail-closed（RecoveryError/CorruptDataError → 503、serve 拒绝就绪），
  重启/灾备保状态与 seq。
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
from threshold_wallet.store import CorruptDataError, RecoveryError, WalletStore

from tests.helpers import http_server, make_harness

TX1 = "ab" * 32
TX2 = "cd" * 32
BH1 = "11" * 32
BH2 = "22" * 32
BH3 = "33" * 32


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


def _call(fn, *args):
    try:
        return fn(*args)
    except ServiceError as exc:
        return exc.status, {"error": exc.message}


class DispatchConfirmationServiceTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 600)
        code, _ = self.svc.create_asset_operation("w1", "op1", "BTC", 100)
        self.assertEqual(code, 201)
        # 门槛 3、重组窗口 2
        self.svc.put_chain_policy("w1", "BTC", "chain-1", True, 3, 2)
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

    def _confirm(self, wallet="w1", dispatch_id="dp1", adapter_id="ad1",
                 tx_id=TX1, block_height=10, block_hash=BH1,
                 confirmations=1):
        return _call(
            self.svc.post_chain_dispatch_confirmation,
            wallet, dispatch_id, adapter_id, tx_id, block_height,
            block_hash, confirmations,
        )

    def _events(self, svc=None, event_type="chain_dispatch_confirmation"):
        svc = svc or self.svc
        return [
            e for e in svc.get_audit_events("w1")["events"]
            if e["type"] == event_type
        ]

    def _audit_path(self):
        return os.path.join(self.d, "audit", "w1.json")

    def _rewrite(self, mutate, reseq=False):
        path = self._audit_path()
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        mutate(log)
        if reseq:
            for i, event in enumerate(log["events"], start=1):
                event["seq"] = i
            log["next_seq"] = len(log["events"]) + 1
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)

    def _setup_dispatch_without_result(self, op="op3", dp="dp3", ap="ap3"):
        code, _ = self.svc.create_asset_operation("w1", op, "BTC", 50)
        self.assertEqual(code, 201)
        code, _ = self.svc.create_sign_request(
            "w1", ap, _msg(operation_id=op, dispatch_id=dp)
        )
        self.assertEqual(code, 201)
        self.svc.approve("w1", ap, "boss")
        code, _ = self.svc.post_chain_dispatch("w1", op, dp, "ad1", ap)
        self.assertEqual(code, 201)

    def _setup_failed_dispatch(self, op="op2", dp="dp2", ap="ap2"):
        code, _ = self.svc.create_asset_operation("w1", op, "BTC", 60)
        self.assertEqual(code, 201)
        code, _ = self.svc.create_sign_request(
            "w1", ap, _msg(operation_id=op, dispatch_id=dp)
        )
        self.assertEqual(code, 201)
        self.svc.approve("w1", ap, "boss")
        code, _ = self.svc.post_chain_dispatch("w1", op, dp, "ad1", ap)
        self.assertEqual(code, 201)
        code, _ = self.svc.post_chain_dispatch_result(
            "w1", dp, "ad1", "failed", None
        )
        self.assertEqual(code, 201)

    # ---- 201 / 视图 / 事件形状 --------------------------------------------

    def test_first_confirm_201_view_and_event(self):
        code, v = self._confirm()
        self.assertEqual(code, 201)
        self.assertEqual(
            v,
            {
                "dispatch_id": "dp1",
                "adapter_id": "ad1",
                "tx_id": TX1,
                "block_height": 10,
                "block_hash": BH1,
                "confirmations": 1,
                "state": "confirming",
            },
        )
        self.assertEqual(
            list(v),
            ["dispatch_id", "adapter_id", "tx_id", "block_height",
             "block_hash", "confirmations", "state"],
        )
        (event,) = self._events()
        self.assertEqual(event["request_id"], "dp1")
        self.assertEqual(event["actor_id"], "ad1")
        self.assertIsNone(event["reason"])
        self.assertEqual(event["details"], v)
        self.assertEqual(
            list(event["details"]),
            ["dispatch_id", "adapter_id", "tx_id", "block_height",
             "block_hash", "confirmations", "state"],
        )
        with open(self._audit_path(), encoding="utf-8") as f:
            log = json.load(f)
        stored = [
            e for e in log["events"]
            if e["type"] == "chain_dispatch_confirmation"
        ][0]
        self.assertEqual(
            list(stored),
            ["actor_id", "at", "details", "reason", "request_id", "seq",
             "type"],
        )
        self.assertEqual(
            list(stored["details"]),
            ["dispatch_id", "adapter_id", "tx_id", "block_height",
             "block_hash", "confirmations", "state"],
        )

    def test_state_confirming_then_finalized(self):
        code, v = self._confirm(confirmations=2)
        self.assertEqual(code, 201)
        self.assertEqual(v["state"], "confirming")
        code, v = self._confirm(confirmations=3)
        self.assertEqual(code, 201)
        self.assertEqual(v["state"], "finalized")

    # ---- 400 --------------------------------------------------------------

    def test_invalid_ids_400(self):
        for kwargs in (
            {"dispatch_id": "bad id"},
            {"dispatch_id": ""},
            {"dispatch_id": 1},
            {"adapter_id": "bad id"},
            {"adapter_id": None},
            {"adapter_id": 12},
        ):
            code, _ = self._confirm(**kwargs)
            self.assertEqual(code, 400, kwargs)
        self.assertEqual(self._events(), [])

    def test_hex_and_int_shapes_400(self):
        for kwargs in (
            {"tx_id": None},
            {"tx_id": "ab"},
            {"tx_id": "AB" * 32},
            {"tx_id": "zz" * 32},
            {"tx_id": 12},
            {"tx_id": True},
            {"block_hash": None},
            {"block_hash": "ab"},
            {"block_hash": "AB" * 32},
            {"block_height": -1},
            {"block_height": True},
            {"block_height": 1.5},
            {"block_height": "10"},
            {"confirmations": -1},
            {"confirmations": False},
            {"confirmations": 2.0},
            {"confirmations": None},
        ):
            code, _ = self._confirm(**kwargs)
            self.assertEqual(code, 400, kwargs)
        self.assertEqual(self._events(), [])

    # ---- 404 --------------------------------------------------------------

    def test_unknown_wallet_404(self):
        code, _ = self._confirm(wallet="w2")
        self.assertEqual(code, 404)

    def test_unknown_dispatch_404(self):
        code, _ = self._confirm(dispatch_id="dp9")
        self.assertEqual(code, 404)
        self.assertEqual(self._events(), [])

    # ---- 409 --------------------------------------------------------------

    def test_no_result_409(self):
        self._setup_dispatch_without_result()
        code, _ = self._confirm(dispatch_id="dp3")
        self.assertEqual(code, 409)
        self.assertEqual(self._events(), [])

    def test_failed_result_409(self):
        self._setup_failed_dispatch()
        code, _ = self._confirm(dispatch_id="dp2")
        self.assertEqual(code, 409)
        self.assertEqual(self._events(), [])

    def test_adapter_mismatch_409(self):
        code, _ = self._confirm(adapter_id="ad2")
        self.assertEqual(code, 409)
        self.assertEqual(self._events(), [])

    def test_tx_migration_409(self):
        code, _ = self._confirm(tx_id=TX2)
        self.assertEqual(code, 409)
        self.assertEqual(self._events(), [])

    def test_same_block_confirmations_decrease_409(self):
        self.assertEqual(self._confirm(confirmations=2)[0], 201)
        code, _ = self._confirm(confirmations=1)
        self.assertEqual(code, 409)
        self.assertEqual(len(self._events()), 1)

    def test_block_regression_within_window_allowed(self):
        self.assertEqual(self._confirm(block_height=10)[0], 201)
        # 回退 2 == reorg_window，仍允许（换块后确认数可降）
        code, v = self._confirm(
            block_height=8, block_hash=BH2, confirmations=1
        )
        self.assertEqual(code, 201)
        self.assertEqual(v["state"], "confirming")
        # 同高度异哈希：回退 0，允许
        code, _ = self._confirm(
            block_height=8, block_hash=BH3, confirmations=1
        )
        self.assertEqual(code, 201)

    def test_block_regression_beyond_window_409(self):
        self.assertEqual(self._confirm(block_height=10)[0], 201)
        # 回退 3 > reorg_window(2)
        code, _ = self._confirm(
            block_height=7, block_hash=BH2, confirmations=1
        )
        self.assertEqual(code, 409)
        # 高度上升同样越界
        code, _ = self._confirm(
            block_height=11, block_hash=BH2, confirmations=1
        )
        self.assertEqual(code, 409)
        self.assertEqual(len(self._events()), 1)

    def test_block_change_after_finalized_409(self):
        self.assertEqual(self._confirm(confirmations=3)[0], 201)
        # 终态后异体（即使同高度更高确认数也是异体）409
        code, _ = self._confirm(
            block_height=10, block_hash=BH2, confirmations=4
        )
        self.assertEqual(code, 409)
        self.assertEqual(len(self._events()), 1)

    # ---- 幂等 / 派发前阈值 / 并发 ------------------------------------------

    def test_same_body_replay_200_no_new_event(self):
        code, v1 = self._confirm()
        self.assertEqual(code, 201)
        code, v2 = self._confirm()
        self.assertEqual(code, 200)
        self.assertEqual(v2, v1)
        self.assertEqual(len(self._events()), 1)

    def test_historical_same_body_replay_after_progression(self):
        # h10/c1（confirming）→ h10/c3（finalized）后，重放历史 h10/c1
        # 同体优先 200 返回原 V（state 仍为当时的 confirming）
        code, v1 = self._confirm(block_height=10, confirmations=1)
        self.assertEqual(code, 201)
        self.assertEqual(v1["state"], "confirming")
        code, _ = self._confirm(block_height=10, confirmations=3)
        self.assertEqual(code, 201)
        code, v3 = self._confirm(block_height=10, confirmations=1)
        self.assertEqual(code, 200)
        self.assertEqual(v3, v1)
        self.assertEqual(v3["state"], "confirming")
        self.assertEqual(len(self._events()), 2)

    def test_reorg_back_and_forth_historical_replay(self):
        self.assertEqual(self._confirm(block_height=10, block_hash=BH1)[0], 201)
        self.assertEqual(
            self._confirm(
                block_height=9, block_hash=BH2, confirmations=1
            )[0],
            201,
        )
        # 回到 h10/BH1 同体重放（历史体）200，不产生事件
        code, v = self._confirm(block_height=10, block_hash=BH1)
        self.assertEqual(code, 200)
        self.assertEqual(v["block_height"], 10)
        self.assertEqual(len(self._events()), 2)

    def test_threshold_and_window_use_pre_dispatch_snapshot(self):
        # 派发后把门槛提高到 5、窗口缩为 0：在途确认仍按派发前快照
        # （required=3、window=2）判定
        self.svc.put_chain_policy("w1", "BTC", "chain-1", True, 5, 0)
        code, v = self._confirm(block_height=10, confirmations=3)
        self.assertEqual(code, 201)
        self.assertEqual(v["state"], "finalized")
        # 窗口快照仍为 2：回退 1 合法
        code, _ = self._confirm(
            block_height=9, block_hash=BH2, confirmations=1
        )
        # 已 finalized，异体不允许 → 409（终态优先于窗口）
        self.assertEqual(code, 409)

    def test_window_snapshot_while_confirming(self):
        # 先有一条 confirming，再收紧窗口，回退 1 仍按旧窗口 2 允许
        self.assertEqual(
            self._confirm(block_height=10, confirmations=1)[0], 201
        )
        self.svc.put_chain_policy("w1", "BTC", "chain-1", True, 5, 0)
        code, v = self._confirm(
            block_height=9, block_hash=BH2, confirmations=1
        )
        self.assertEqual(code, 201)
        self.assertEqual(v["state"], "confirming")

    def test_replay_preferred_over_current_scene(self):
        code, v1 = self._confirm()
        self.assertEqual(code, 201)
        # 事后停用/收紧策略不影响历史同体重放
        self.svc.put_chain_policy("w1", "BTC", "chain-1", False, 3, 2)
        code, v2 = self._confirm()
        self.assertEqual(code, 200)
        self.assertEqual(v2, v1)
        self.assertEqual(len(self._events()), 1)

    def test_concurrent_single_201(self):
        codes = []
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            codes.append(self._confirm()[0])

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(codes), [200] * 7 + [201])
        self.assertEqual(len(self._events()), 1)
        seqs = [
            e["seq"] for e in self.svc.get_audit_events("w1")["events"]
        ]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))

    # ---- 恢复 ---------------------------------------------------------------

    def test_restart_keeps_confirmation_and_seq(self):
        self.assertEqual(self._confirm()[0], 201)
        before = self.svc.get_audit_events("w1")["events"]
        svc2 = WalletService(self.h.store)
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)
        code, v = _call(
            svc2.post_chain_dispatch_confirmation,
            "w1", "dp1", "ad1", TX1, 10, BH1, 1,
        )
        self.assertEqual(code, 200)
        self.assertEqual(v["state"], "confirming")
        self.assertEqual(len(self._events(svc2)), 1)

    def test_tampered_state_fail_closed(self):
        self.assertEqual(self._confirm(confirmations=1)[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_confirmation":
                    e["details"]["state"] = "finalized"

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_tampered_confirmations_fail_closed(self):
        self.assertEqual(self._confirm(confirmations=3)[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_confirmation":
                    # finalized 事件的确认数被降到门槛以下：状态重算不符
                    e["details"]["confirmations"] = 1

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_confirmation_without_result_fail_closed(self):
        self.assertEqual(self._confirm()[0], 201)

        def mutate(log):
            log["events"] = [
                e for e in log["events"]
                if e["type"] != "chain_dispatch_result"
            ]

        self._rewrite(mutate, reseq=True)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_confirmation_after_failed_result_fail_closed(self):
        self.assertEqual(self._confirm()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_result":
                    e["details"]["state"] = "failed"
                    e["details"]["tx_id"] = None

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_confirmation_before_result_fail_closed(self):
        self.assertEqual(self._confirm()[0], 201)

        def mutate(log):
            result = confirmation = None
            for e in log["events"]:
                if e["type"] == "chain_dispatch_result":
                    result = e
                elif e["type"] == "chain_dispatch_confirmation":
                    confirmation = e
            result["seq"], confirmation["seq"] = (
                confirmation["seq"],
                result["seq"],
            )

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_ownership_mismatch_fail_closed(self):
        self.assertEqual(self._confirm()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_confirmation":
                    e["actor_id"] = "ad2"
                    e["details"]["adapter_id"] = "ad2"

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_tx_mismatch_fail_closed(self):
        self.assertEqual(self._confirm()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_confirmation":
                    e["details"]["tx_id"] = TX2

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_same_block_decrease_chain_fail_closed(self):
        self.assertEqual(self._confirm(confirmations=2)[0], 201)
        self.assertEqual(self._confirm(confirmations=3)[0], 201)

        def mutate(log):
            confirms = [
                e for e in log["events"]
                if e["type"] == "chain_dispatch_confirmation"
            ]
            # 后一条确认数被改成低于前一条
            confirms[-1]["details"]["confirmations"] = 1
            confirms[-1]["details"]["state"] = "confirming"

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_block_regression_beyond_window_fail_closed(self):
        self.assertEqual(self._confirm(block_height=10)[0], 201)
        # 追加一条回退 3（> 窗口 2）的伪造确认
        forged = {
            "actor_id": "ad1",
            "at": self._events()[0]["at"],
            "details": {
                "dispatch_id": "dp1",
                "adapter_id": "ad1",
                "tx_id": TX1,
                "block_height": 7,
                "block_hash": BH2,
                "confirmations": 1,
                "state": "confirming",
            },
            "reason": None,
            "request_id": "dp1",
            "seq": 0,
            "type": "chain_dispatch_confirmation",
        }

        def mutate(log):
            forged["seq"] = len(log["events"]) + 1
            log["events"].append(dict(forged))
            log["next_seq"] = len(log["events"]) + 1

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_block_change_after_finalized_fail_closed(self):
        self.assertEqual(self._confirm(confirmations=3)[0], 201)
        forged = {
            "actor_id": "ad1",
            "at": self._events()[0]["at"],
            "details": {
                "dispatch_id": "dp1",
                "adapter_id": "ad1",
                "tx_id": TX1,
                "block_height": 11,
                "block_hash": BH2,
                "confirmations": 1,
                "state": "confirming",
            },
            "reason": None,
            "request_id": "dp1",
            "seq": 0,
            "type": "chain_dispatch_confirmation",
        }

        def mutate(log):
            forged["seq"] = len(log["events"]) + 1
            log["events"].append(dict(forged))
            log["next_seq"] = len(log["events"]) + 1

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_duplicate_same_body_fail_closed(self):
        self.assertEqual(self._confirm()[0], 201)

        def mutate(log):
            src = [
                e for e in log["events"]
                if e["type"] == "chain_dispatch_confirmation"
            ][0]
            dup = dict(src)
            dup["seq"] = len(log["events"]) + 1
            log["events"].append(dup)
            log["next_seq"] = len(log["events"]) + 1

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_details_reordered_before_normalization_fail_closed(self):
        self.assertEqual(self._confirm()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_confirmation":
                    d = e["details"]
                    e["details"] = {
                        "state": d["state"],
                        "dispatch_id": d["dispatch_id"],
                        "adapter_id": d["adapter_id"],
                        "tx_id": d["tx_id"],
                        "block_height": d["block_height"],
                        "block_hash": d["block_hash"],
                        "confirmations": d["confirmations"],
                    }

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            self.svc._audit.chain_dispatch_confirmation_events("w1")
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_outer_fields_reordered_fail_closed(self):
        self.assertEqual(self._confirm()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_confirmation":
                    reordered = {
                        "seq": e["seq"],
                        "type": e["type"],
                        "at": e["at"],
                        "request_id": e["request_id"],
                        "actor_id": e["actor_id"],
                        "reason": e["reason"],
                        "details": e["details"],
                    }
                    e.clear()
                    e.update(reordered)

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_bad_json_is_corrupt_data(self):
        self.assertEqual(self._confirm()[0], 201)
        with open(self._audit_path(), "wb") as f:
            f.write(b"{broken")
        with self.assertRaises(CorruptDataError):
            self.svc._audit.chain_dispatch_confirmation_events("w1")
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_healthy_log_loads(self):
        self.assertEqual(self._confirm(confirmations=2)[0], 201)
        grouped = self.svc._audit.chain_dispatch_confirmation_events("w1")
        self.assertEqual(len(grouped["dp1"]), 1)
        self.assertEqual(
            list(grouped["dp1"][0]["details"]),
            ["dispatch_id", "adapter_id", "tx_id", "block_height",
             "block_hash", "confirmations", "state"],
        )

    def test_backup_restore_keeps_confirmation_and_seq(self):
        from threshold_wallet import drbackup

        self.assertEqual(self._confirm()[0], 201)
        out = os.path.join(tempfile.mkdtemp(), "snap.tar")
        self.addCleanup(
            shutil.rmtree, os.path.dirname(out), ignore_errors=True
        )
        body = drbackup.backup(self.d, "w1", "S1", out)
        self.assertEqual(body["status"], 201)
        dst = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, dst, ignore_errors=True)
        status, _ = drbackup.restore(dst, "w1", out)
        self.assertEqual(status, 201)
        svc2 = WalletService(WalletStore(dst))
        before = self.svc.get_audit_events("w1")["events"]
        after = svc2.get_audit_events("w1")["events"]
        self.assertEqual(before, after)
        code, v = _call(
            svc2.post_chain_dispatch_confirmation,
            "w1", "dp1", "ad1", TX1, 10, BH1, 1,
        )
        self.assertEqual(code, 200)
        self.assertEqual(v["state"], "confirming")
        self.assertEqual(svc2.get_audit_events("w1")["events"], after)


class DispatchConfirmationHttpTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.ctx = http_server(self.d)
        self.srv = self.ctx.__enter__()
        self.addCleanup(self.ctx.__exit__, None, None, None)
        srv = self.srv
        srv.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
        srv.request(
            "PUT", "/v1/wallets/w1/approval-policy",
            {"required_approvals": 1, "timeout_seconds": 600},
        )
        srv.request(
            "POST", "/v1/wallets/w1/asset-operations",
            {"operation_id": "op1", "asset_id": "BTC", "delta": 100},
        )
        srv.request(
            "PUT", "/v1/wallets/w1/chain/BTC",
            {"chain_id": "chain-1", "enabled": True,
             "required_confirmations": 3, "reorg_window": 2},
        )
        srv.request(
            "POST", "/v1/wallets/w1/sign-requests",
            {"id": "ap1", "message": _msg()},
        )
        srv.request(
            "POST", "/v1/wallets/w1/sign-requests/ap1/approve",
            {"approver_id": "boss"},
        )
        status, _ = srv.request(
            "POST", "/v1/wallets/w1/chain/op1/dispatch",
            {"dispatch_id": "dp1", "adapter_id": "ad1",
             "approval_request_id": "ap1"},
        )
        self.assertEqual(status, 201)
        status, _ = srv.request(
            "POST", "/v1/wallets/w1/chain/dp1/result",
            {"adapter_id": "ad1", "state": "broadcasted", "tx_id": TX1},
        )
        self.assertEqual(status, 201)

    def _confirm(self, body, wallet="w1", dispatch_id="dp1"):
        return self.srv.request(
            "POST", f"/v1/wallets/{wallet}/chain/{dispatch_id}/confirm",
            body,
        )

    def _body(self, **overrides):
        body = {
            "adapter_id": "ad1",
            "tx_id": TX1,
            "block_height": 10,
            "block_hash": BH1,
            "confirmations": 1,
        }
        body.update(overrides)
        return body

    def _raw_post(self, path, body):
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            self.srv.base_url + path, data=data, method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def test_http_happy_path_and_replay(self):
        status, v = self._confirm(self._body())
        self.assertEqual(status, 201)
        self.assertEqual(
            list(v),
            ["dispatch_id", "adapter_id", "tx_id", "block_height",
             "block_hash", "confirmations", "state"],
        )
        self.assertEqual(v["state"], "confirming")
        status, v2 = self._confirm(self._body(confirmations=3))
        self.assertEqual(status, 201)
        self.assertEqual(v2["state"], "finalized")
        status, v3 = self._confirm(self._body())
        self.assertEqual(status, 200)
        self.assertEqual(v3["state"], "confirming")

    def test_http_body_key_set_400(self):
        for body in (
            {},
            {"adapter_id": "ad1", "tx_id": TX1, "block_height": 10,
             "block_hash": BH1},
            self._body(extra=1),
            self._body(confirmations=None),
        ):
            status, _ = self._confirm(body)
            self.assertEqual(status, 400, body)
        # 键名拼错
        status, _ = self._confirm(
            {"adapter_id": "ad1", "tx_id": TX1, "block_height": 10,
             "block_hash": BH1, "confirmation": 1}
        )
        self.assertEqual(status, 400)

    def test_http_value_400_and_unknown_404(self):
        status, _ = self._confirm(self._body(tx_id="ab"))
        self.assertEqual(status, 400)
        status, _ = self._confirm(self._body(block_hash="AB" * 32))
        self.assertEqual(status, 400)
        status, _ = self._confirm(self._body(block_height=True))
        self.assertEqual(status, 400)
        status, _ = self._confirm(self._body(confirmations=-1))
        self.assertEqual(status, 400)
        status, _ = self._confirm(self._body(), dispatch_id="dp9")
        self.assertEqual(status, 404)
        status, _ = self._confirm(self._body(), wallet="w9")
        self.assertEqual(status, 404)

    def test_http_conflicts_409(self):
        # 适配器不符
        status, _ = self._confirm(self._body(adapter_id="ad2"))
        self.assertEqual(status, 409)
        # tx 迁移
        status, _ = self._confirm(self._body(tx_id=TX2))
        self.assertEqual(status, 409)
        # 进展后同块确认数下降
        self.assertEqual(self._confirm(self._body(confirmations=2))[0], 201)
        status, _ = self._confirm(self._body(confirmations=1))
        self.assertEqual(status, 409)

    def test_http_get_and_put_not_allowed(self):
        status, _ = self.srv.request(
            "GET", "/v1/wallets/w1/chain/dp1/confirm"
        )
        self.assertEqual(status, 404)
        status, _ = self.srv.request(
            "PUT", "/v1/wallets/w1/chain/dp1/confirm", self._body()
        )
        self.assertEqual(status, 404)

    def test_http_wire_compact_no_trailing_newline(self):
        status, raw = self._raw_post(
            "/v1/wallets/w1/chain/dp1/confirm", self._body()
        )
        self.assertEqual(status, 201)
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)
        self.assertFalse(raw.endswith(b"\n"))
        self.assertTrue(raw.startswith(b'{"dispatch_id":"dp1",'))
        # 错误体同样紧凑
        status, raw = self._raw_post(
            "/v1/wallets/w1/chain/dp9/confirm", self._body()
        )
        self.assertEqual(status, 404)
        self.assertNotIn(b": ", raw)
        self.assertFalse(raw.endswith(b"\n"))
        self.assertIn(b'"error"', raw)

    def test_http_503_on_corrupt_scene(self):
        status, _ = self._confirm(self._body())
        self.assertEqual(status, 201)
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for e in log["events"]:
            if e["type"] == "chain_dispatch_confirmation":
                e["details"]["state"] = "done"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        status, body = self._confirm(self._body(confirmations=2))
        self.assertEqual(status, 503)
        self.assertEqual(list(body), ["error"])
        self.assertIsInstance(body["error"], str)
        self.assertNotIn("dp1", json.dumps(body))


if __name__ == "__main__":
    unittest.main()
