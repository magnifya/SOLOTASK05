"""跨链派发最终性查询与资产结算（GET .../finality、POST .../settle）测试。

覆盖：
- GET /v1/wallets/{W}/chain/{D}/finality 返回
  F={operation_id,chain_id,confirmation}（键序固定，confirmation 取最后
  一条 confirm 七键 V 的 confirmations）；未 broadcasted 或无确认 409；
  纯只读（不写文件/事件/seq）；
- 空体 POST .../settle（非空体 400）：归属、tx 与事件链一致、V 为
  finalized、操作 pending 时结算；confirming、余额不足或别处已提交 409
  且无副作用；首提 201 返回既有 R，重放优先 200 同体，并发仅一 201；
- chain_dispatch_settled 与紧邻 asset_operation_committed 两事件原子
  提交（seq n、n+1；request_id/actor_id/reason/details 固定形状）；
- 恢复逐条复核：请求/广播结果在前、finalized 在前、归属一致、紧邻提交；
  坏形状/错序/孤立事件/矛盾 fail-closed（RecoveryError/CorruptDataError
  → 503、serve 拒绝就绪），重启/灾备保状态与 seq。
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
BH1 = "cd" * 32


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


class DispatchSettleServiceTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 600)
        code, _ = self.svc.create_asset_operation("w1", "op1", "BTC", 100)
        self.assertEqual(code, 201)
        self.svc.put_chain_policy("w1", "BTC", "chain-1", True, 3, 2)
        code, _ = self.svc.create_sign_request("w1", "ap1", _msg())
        self.assertEqual(code, 201)
        self.svc.approve("w1", "ap1", "boss")
        code, _ = self.svc.post_chain_dispatch(
            "w1", "op1", "dp1", "ad1", "ap1"
        )
        self.assertEqual(code, 201)

    def _result(self, state="broadcasted", tx_id=TX1):
        return _call(
            self.svc.post_chain_dispatch_result,
            "w1", "dp1", "ad1", state, tx_id,
        )

    def _confirm(self, confirmations, block_height=1, block_hash=BH1,
                 tx_id=TX1):
        return _call(
            self.svc.post_chain_dispatch_confirmation,
            "w1", "dp1", "ad1", tx_id, block_height, block_hash,
            confirmations,
        )

    def _settle(self, dispatch_id="dp1"):
        return _call(
            self.svc.post_chain_dispatch_settle, "w1", dispatch_id
        )

    def _finality(self, dispatch_id="dp1"):
        try:
            return 200, self.svc.get_chain_dispatch_finality(
                "w1", dispatch_id
            )
        except ServiceError as exc:
            return exc.status, {"error": exc.message}

    def _events(self, event_type):
        return [
            e for e in self.svc.get_audit_events("w1")["events"]
            if e["type"] == event_type
        ]

    def _audit_path(self):
        return os.path.join(self.d, "audit", "w1.json")

    def _rewrite(self, mutate):
        path = self._audit_path()
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        mutate(log)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)

    def _to_finalized(self, tx_id=TX1, block_hash=BH1):
        self.assertEqual(self._result()[0], 201)
        self.assertEqual(self._confirm(3, block_hash=block_hash, tx_id=tx_id)[0], 201)

    # ---- finality ---------------------------------------------------------

    def test_finality_view_keys_and_value(self):
        self._to_finalized()
        code, v = self._finality()
        self.assertEqual(code, 200)
        self.assertEqual(
            v,
            {"operation_id": "op1", "chain_id": "chain-1", "confirmation": 3},
        )
        self.assertEqual(list(v), ["operation_id", "chain_id", "confirmation"])

    def test_finality_takes_last_confirmation_while_confirming(self):
        self.assertEqual(self._result()[0], 201)
        self.assertEqual(self._confirm(1)[0], 201)
        code, v = self._finality()
        self.assertEqual(code, 200)
        self.assertEqual(v["confirmation"], 1)
        self.assertEqual(self._confirm(2)[0], 201)
        code, v = self._finality()
        self.assertEqual(code, 200)
        self.assertEqual(v["confirmation"], 2)

    def test_finality_not_broadcasted_409(self):
        # 无结果
        code, _ = self._finality()
        self.assertEqual(code, 409)
        # failed 结果
        self.assertEqual(self._result(state="failed", tx_id=None)[0], 201)
        code, _ = self._finality()
        self.assertEqual(code, 409)

    def test_finality_no_confirmation_409(self):
        self.assertEqual(self._result()[0], 201)
        code, _ = self._finality()
        self.assertEqual(code, 409)

    def test_finality_400_and_404(self):
        self._to_finalized()
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_chain_dispatch_finality("w1", "bad id!")
        self.assertEqual(ctx.exception.status, 400)
        code, _ = self._finality("dp9")
        self.assertEqual(code, 404)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_chain_dispatch_finality("w9", "dp1")
        self.assertEqual(ctx.exception.status, 404)

    def test_finality_is_read_only(self):
        self._to_finalized()
        before = self.svc.get_audit_events("w1")["events"]
        code, _ = self._finality()
        self.assertEqual(code, 200)
        # 多次查询不新增事件、不改 seq、不改文件
        self._finality()
        self._finality()
        after = self.svc.get_audit_events("w1")["events"]
        self.assertEqual(before, after)

    # ---- settle: 201 / 200 / 事件形状 --------------------------------------

    def test_settle_201_view_and_two_events(self):
        self._to_finalized()
        code, r = self._settle()
        self.assertEqual(code, 201)
        self.assertEqual(
            r,
            {
                "operation_id": "op1",
                "asset_id": "BTC",
                "state": "committed",
                "delta": 100,
                "balance": 100,
                "version": 1,
            },
        )
        self.assertEqual(
            list(r),
            ["operation_id", "asset_id", "state", "delta", "balance",
             "version"],
        )
        settled = self._events("chain_dispatch_settled")
        committed = self._events("asset_operation_committed")
        self.assertEqual(len(settled), 1)
        self.assertEqual(len(committed), 1)
        event = settled[0]
        self.assertEqual(event["request_id"], "dp1")
        self.assertEqual(event["actor_id"], "ad1")
        self.assertIsNone(event["reason"])
        self.assertEqual(
            event["details"],
            {"dispatch_id": "dp1", "operation_id": "op1"},
        )
        self.assertEqual(list(event["details"]), ["dispatch_id", "operation_id"])
        # 两事件紧邻同批：seq 为 n、n+1
        self.assertEqual(committed[0]["seq"], event["seq"] + 1)
        self.assertEqual(committed[0]["details"], r)
        # 落盘外层规范序、details 键序
        with open(self._audit_path(), encoding="utf-8") as f:
            log = json.load(f)
        stored = [
            e for e in log["events"]
            if e["type"] == "chain_dispatch_settled"
        ][0]
        self.assertEqual(
            list(stored),
            ["actor_id", "at", "details", "reason", "request_id", "seq",
             "type"],
        )
        self.assertEqual(list(stored["details"]), ["dispatch_id", "operation_id"])

    def test_settle_applies_balance_once(self):
        self._to_finalized()
        code, _ = self._settle()
        self.assertEqual(code, 201)
        self.assertEqual(self.svc.get_asset("w1", "BTC"),
                         {"asset_id": "BTC", "balance": 100, "version": 1})
        record = self.h.store.get_asset_operation("w1", "op1")
        self.assertEqual(record["state"], "committed")

    def test_settle_replay_200_same_body_no_new_event(self):
        self._to_finalized()
        _, first = self._settle()
        code, second = self._settle()
        self.assertEqual(code, 200)
        self.assertEqual(first, second)
        self.assertEqual(
            list(second),
            ["operation_id", "asset_id", "state", "delta", "balance",
             "version"],
        )
        self.assertEqual(len(self._events("chain_dispatch_settled")), 1)
        self.assertEqual(len(self._events("asset_operation_committed")), 1)

    def test_settle_confirming_409_no_side_effects(self):
        self.assertEqual(self._result()[0], 201)
        self.assertEqual(self._confirm(2)[0], 201)
        code, _ = self._settle()
        self.assertEqual(code, 409)
        # 无结算/提交事件、操作仍 pending、余额未动
        self.assertEqual(self._events("chain_dispatch_settled"), [])
        self.assertEqual(self._events("asset_operation_committed"), [])
        self.assertEqual(
            self.h.store.get_asset_operation("w1", "op1")["state"], "pending"
        )
        self.assertIsNone(self.h.store.get_asset("w1", "BTC"))

    def test_settle_without_broadcast_or_confirmation_409(self):
        code, _ = self._settle()
        self.assertEqual(code, 409)
        self.assertEqual(self._result()[0], 201)
        code, _ = self._settle()
        self.assertEqual(code, 409)

    def test_settle_insufficient_balance_409_no_side_effects(self):
        # op2 delta=-50，BTC 初始余额 0：finalized 后结算必然余额不足。
        code, _ = self.svc.create_asset_operation("w1", "op2", "BTC", -50)
        self.assertEqual(code, 201)
        msg2 = _msg(operation_id="op2", dispatch_id="dp2")
        code, _ = self.svc.create_sign_request("w1", "ap2", msg2)
        self.assertEqual(code, 201)
        self.svc.approve("w1", "ap2", "boss")
        code, _ = self.svc.post_chain_dispatch(
            "w1", "op2", "dp2", "ad1", "ap2"
        )
        self.assertEqual(code, 201)
        code, _ = _call(
            self.svc.post_chain_dispatch_result,
            "w1", "dp2", "ad1", "broadcasted", "ef" * 32,
        )
        self.assertEqual(code, 201)
        code, _ = _call(
            self.svc.post_chain_dispatch_confirmation,
            "w1", "dp2", "ad1", "ef" * 32, 1, BH1, 3,
        )
        self.assertEqual(code, 201)
        code, _ = _call(
            self.svc.post_chain_dispatch_settle, "w1", "dp2"
        )
        self.assertEqual(code, 409)
        self.assertEqual(
            [e for e in self.svc.get_audit_events("w1")["events"]
             if e["type"] == "chain_dispatch_settled"],
            [],
        )
        self.assertEqual(
            [e for e in self.svc.get_audit_events("w1")["events"]
             if e["type"] == "asset_operation_committed"],
            [],
        )
        self.assertEqual(
            self.h.store.get_asset_operation("w1", "op2")["state"], "pending"
        )
        self.assertIsNone(self.h.store.get_asset("w1", "BTC"))
        # 无残留意图；再结一次仍 409 且现场不变（可重试）
        self.assertEqual(self.h.store.list_asset_intents("w1"), [])
        code, _ = _call(
            self.svc.post_chain_dispatch_settle, "w1", "dp2"
        )
        self.assertEqual(code, 409)
        self.assertEqual(
            self.h.store.get_asset_operation("w1", "op2")["state"], "pending"
        )

    def test_settle_after_committed_elsewhere_409(self):
        # op1 已 finalized 但在结算前由达门槛 chain_report 提交
        self.assertEqual(self._result()[0], 201)
        self.assertEqual(self._confirm(3)[0], 201)
        code, _ = self.svc.post_chain_report(
            "w1", "op1", "chain-1", "99" * 32, 1, BH1, 3
        )
        self.assertEqual(code, 201)
        code, _ = self._settle()
        self.assertEqual(code, 409)
        self.assertEqual(self._events("chain_dispatch_settled"), [])

    def test_settle_unknown_dispatch_404_and_bad_id_400(self):
        code, _ = self._settle("dp9")
        self.assertEqual(code, 404)
        code, _ = _call(
            self.svc.post_chain_dispatch_settle, "w1", "bad id!"
        )
        self.assertEqual(code, 400)
        code, _ = _call(
            self.svc.post_chain_dispatch_settle, "w9", "dp1"
        )
        self.assertEqual(code, 404)

    def test_concurrent_single_201(self):
        self._to_finalized()
        results = []

        def fire():
            results.append(self._settle())

        threads = [threading.Thread(target=fire) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        statuses = sorted(code for code, _ in results)
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(200), 7)
        self.assertEqual(len(self._events("chain_dispatch_settled")), 1)
        self.assertEqual(len(self._events("asset_operation_committed")), 1)
        self.assertEqual(
            self.h.store.get_asset("w1", "BTC")["balance"], 100
        )

    def test_restart_keeps_settlement_and_seq(self):
        self._to_finalized()
        code, first = self._settle()
        self.assertEqual(code, 201)
        before = self.svc.get_audit_events("w1")["events"]

        svc2 = WalletService(WalletStore(self.d))
        code, second = _call(svc2.post_chain_dispatch_settle, "w1", "dp1")
        self.assertEqual(code, 200)
        self.assertEqual(first, second)
        try:
            v = svc2.get_chain_dispatch_finality("w1", "dp1")
        except ServiceError as exc:
            self.fail(f"finality after restart failed: {exc.status}")
        self.assertEqual(v["confirmation"], 3)
        after = svc2.get_audit_events("w1")["events"]
        self.assertEqual(before, after)
        seqs = [e["seq"] for e in after]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))

    # ---- fail-closed：形状 / 错序 / 矛盾 -----------------------------------

    def test_tampered_details_shape_fail_closed(self):
        self._to_finalized()
        self.assertEqual(self._settle()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_settled":
                    e["details"].pop("operation_id")

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_details_reordered_before_normalization_fail_closed(self):
        self._to_finalized()
        self.assertEqual(self._settle()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_settled":
                    d = e["details"]
                    e["details"] = {
                        "operation_id": d["operation_id"],
                        "dispatch_id": d["dispatch_id"],
                    }

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            self.svc._audit.chain_dispatch_settled_events("w1")
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_outer_fields_reordered_fail_closed(self):
        self._to_finalized()
        self.assertEqual(self._settle()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_settled":
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

    def test_settled_actor_mismatch_fail_closed(self):
        self._to_finalized()
        self.assertEqual(self._settle()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_settled":
                    e["actor_id"] = "ad2"

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_settled_reason_non_null_fail_closed(self):
        self._to_finalized()
        self.assertEqual(self._settle()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_settled":
                    e["reason"] = "why"

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_duplicate_settled_fail_closed(self):
        self._to_finalized()
        self.assertEqual(self._settle()[0], 201)

        def mutate(log):
            for e in list(log["events"]):
                if e["type"] == "chain_dispatch_settled":
                    dup = dict(e)
                    dup["seq"] = len(log["events"]) + 1
                    log["events"].append(dup)
                    log["next_seq"] = len(log["events"]) + 1

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_settled_without_adjacent_commit_fail_closed(self):
        self._to_finalized()
        self.assertEqual(self._settle()[0], 201)

        def mutate(log):
            # 删除紧邻的 asset_operation_committed，留下孤立结算事件
            log["events"] = [
                e for e in log["events"]
                if e["type"] != "asset_operation_committed"
            ]
            log["next_seq"] = len(log["events"]) + 1

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_settled_before_finalized_fail_closed(self):
        self.assertEqual(self._result()[0], 201)
        self.assertEqual(self._confirm(2)[0], 201)

        def mutate(log):
            # 伪造一条结算 + 紧邻提交（confirming 阶段结算，矛盾）
            at = log["events"][-1]["at"]
            n = len(log["events"]) + 1
            log["events"].append(
                {
                    "actor_id": "ad1",
                    "at": at,
                    "details": {"dispatch_id": "dp1", "operation_id": "op1"},
                    "reason": None,
                    "request_id": "dp1",
                    "seq": n,
                    "type": "chain_dispatch_settled",
                }
            )
            log["events"].append(
                {
                    "actor_id": None,
                    "at": at,
                    "details": {
                        "operation_id": "op1",
                        "asset_id": "BTC",
                        "state": "committed",
                        "delta": 100,
                        "balance": 100,
                        "version": 1,
                    },
                    "reason": None,
                    "request_id": "op1",
                    "seq": n + 1,
                    "type": "asset_operation_committed",
                }
            )
            log["next_seq"] = len(log["events"]) + 1

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_settled_operation_mismatch_fail_closed(self):
        self._to_finalized()
        self.assertEqual(self._settle()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_settled":
                    e["details"]["operation_id"] = "op9"

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_bad_json_is_corrupt_data(self):
        self._to_finalized()
        self.assertEqual(self._settle()[0], 201)
        with open(self._audit_path(), "wb") as f:
            f.write(b"{broken")
        with self.assertRaises(CorruptDataError):
            self.svc._audit.chain_dispatch_settled_events("w1")
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_backup_restore_keeps_settlement_and_seq(self):
        from threshold_wallet import drbackup

        self._to_finalized()
        self.assertEqual(self._settle()[0], 201)
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
        code, v = _call(svc2.post_chain_dispatch_settle, "w1", "dp1")
        self.assertEqual(code, 200)
        self.assertEqual(v["state"], "committed")
        self.assertEqual(svc2.get_audit_events("w1")["events"], after)

    def test_settle_intent_without_events_rolls_back(self):
        # 手工制造崩溃窗口：写了 settle 提交意图但两事件从未落盘。
        self._to_finalized()
        record = self.h.store.get_asset_operation("w1", "op1")
        asset = self.h.store.get_asset("w1", "BTC")
        intent = {
            "operation_id": "op1",
            "asset_id": "BTC",
            "delta": 100,
            "old_asset": asset,
            "pending": record,
            "new_balance": 100,
            "new_version": 1,
            "settle": {"dispatch_id": "dp1", "operation_id": "op1"},
        }
        self.svc._store.write_asset_commit_intent("w1", "op1", intent)
        svc2 = WalletService(WalletStore(self.d))
        # 回滚为 pending、无事件残留、可正常结算
        self.assertEqual(
            self.h.store.get_asset_operation("w1", "op1")["state"], "pending"
        )
        self.assertEqual(self.h.store.list_asset_intents("w1"), [])
        code, r = _call(svc2.post_chain_dispatch_settle, "w1", "dp1")
        self.assertEqual(code, 201)
        self.assertEqual(r["state"], "committed")


class DispatchSettleHttpTest(unittest.TestCase):
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

    def _to_finalized(self):
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/chain/dp1/result",
            {"adapter_id": "ad1", "state": "broadcasted", "tx_id": TX1},
        )
        self.assertEqual(status, 201)
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/chain/dp1/confirm",
            {"adapter_id": "ad1", "tx_id": TX1, "block_height": 1,
             "block_hash": BH1, "confirmations": 3},
        )
        self.assertEqual(status, 201)

    def _raw_request(self, method, path, data, ctype=None):
        headers = {"Accept": "application/json"}
        if ctype is not None:
            headers["Content-Type"] = ctype
        req = urllib.request.Request(
            self.srv.base_url + path, data=data, method=method,
            headers=headers,
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def test_http_finality_and_settle_happy_path(self):
        status, body = self.srv.request(
            "GET", "/v1/wallets/w1/chain/dp1/finality"
        )
        self.assertEqual(status, 409)
        self._to_finalized()
        status, body = self.srv.request(
            "GET", "/v1/wallets/w1/chain/dp1/finality"
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            body,
            {"operation_id": "op1", "chain_id": "chain-1", "confirmation": 3},
        )
        status, body = self._raw_request(
            "POST", "/v1/wallets/w1/chain/dp1/settle", b"",
            ctype="application/json",
        )
        self.assertEqual(status, 201)
        self.assertEqual(
            json.loads(body),
            {"operation_id": "op1", "asset_id": "BTC", "state": "committed",
             "delta": 100, "balance": 100, "version": 1},
        )
        # 重放 200 同体
        status2, body2 = self._raw_request(
            "POST", "/v1/wallets/w1/chain/dp1/settle", b"",
            ctype="application/json",
        )
        self.assertEqual(status2, 200)
        self.assertEqual(body2, body)

    def test_http_settle_non_empty_body_400(self):
        self._to_finalized()
        for data, ctype in (
            (b"{}", "application/json"),
            (b'{"x":1}', "application/json"),
            (b" ", "application/json"),
        ):
            status, _ = self._raw_request(
                "POST", "/v1/wallets/w1/chain/dp1/settle", data,
                ctype=ctype,
            )
            self.assertEqual(status, 400, data)

    def test_http_finality_400_404_and_wrong_method(self):
        self._to_finalized()
        status, _ = self.srv.request(
            "GET", "/v1/wallets/w1/chain/bad%20id/finality"
        )
        self.assertEqual(status, 400)
        status, _ = self.srv.request(
            "GET", "/v1/wallets/w1/chain/dp9/finality"
        )
        self.assertEqual(status, 404)
        status, _ = self.srv.request(
            "POST", "/v1/wallets/w1/chain/dp1/finality", {}
        )
        self.assertEqual(status, 404)

    def test_http_wire_compact_no_trailing_newline(self):
        self._to_finalized()
        status, raw = self._raw_request(
            "GET", "/v1/wallets/w1/chain/dp1/finality", None
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            raw,
            b'{"operation_id":"op1","chain_id":"chain-1","confirmation":3}',
        )
        self.assertFalse(raw.endswith(b"\n"))
        # settle 成功体同样紧凑
        status, raw = self._raw_request(
            "POST", "/v1/wallets/w1/chain/dp1/settle", b"",
            ctype="application/json",
        )
        self.assertEqual(status, 201)
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)
        self.assertFalse(raw.endswith(b"\n"))
        self.assertTrue(raw.startswith(b'{"operation_id":"op1",'))
        # 非空体错误也紧凑
        status, raw = self._raw_request(
            "POST", "/v1/wallets/w1/chain/dp1/settle", b"{}",
            ctype="application/json",
        )
        self.assertEqual(status, 400)
        self.assertFalse(raw.endswith(b"\n"))
        self.assertIn(b'"error"', raw)

    def test_http_503_on_corrupt_scene(self):
        self._to_finalized()
        status, _ = self._raw_request(
            "POST", "/v1/wallets/w1/chain/dp1/settle", b"",
            ctype="application/json",
        )
        self.assertEqual(status, 201)
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for e in log["events"]:
            if e["type"] == "chain_dispatch_settled":
                e["actor_id"] = "ad2"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        status, raw = self._raw_request(
            "GET", "/v1/wallets/w1/chain/dp1/finality", None
        )
        self.assertEqual(status, 503)
        body = json.loads(raw)
        self.assertEqual(list(body), ["error"])
        self.assertNotIn("dp1", json.dumps(body))


if __name__ == "__main__":
    unittest.main()
