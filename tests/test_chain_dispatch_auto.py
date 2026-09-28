"""健康感知自动派发
（POST /v1/wallets/{W}/chain/{O}/dispatch-auto）测试。

覆盖：
- 体恰含 dispatch_id,approval_request_id 两键，值须安全标识，键集/值错
  400；钱包/操作/策略/同钱包审批单未知 404；
- 首提限 pending 且策略启用；锁内取当前健康表中 ASCII 最小的 up 适配器；
  健康表未配置或无 up、审批非 approved、message 不等于按
  operation_id,dispatch_id,chain_id 序的三键紧凑 JSON（不含
  adapter_id）均 409；
- 成功 201 返回 V（dispatch_id,operation_id,adapter_id,chain_id,state，
  state=requested）；同 D 同 O 同体（含审批单）重放 200 同 V（优先于
  状态/健康/审批判定）；同 D 异参、或该操作已有派发（手动或自动）409；
- chain_dispatch_auto_requested 为唯一提交点（request_id=D、
  actor_id=审批 ID、reason=null、details=V 五键固定序），并发仅一 201；
- 与手动 chain_dispatch_requested 的 dispatch_id / 操作全局互斥；
- 后续 result/confirm/finality/settle 沿用 dispatch；
- 恢复按提交前现场复核策略、审批单、健康快照及首选适配器；矛盾/坏 JSON
  fail-closed（RecoveryError/CorruptDataError → 503、serve 拒绝就绪），
  重启/灾备保状态与 seq，不增事件或 seq。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import unittest

from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import CorruptDataError, RecoveryError, WalletStore

from tests.helpers import http_server, make_harness


def _amsg(operation_id="op1", dispatch_id="dp1", chain_id="chain-1"):
    """自动派发审批单 message：三键紧凑 JSON（不含 adapter_id）。"""
    return json.dumps(
        {
            "operation_id": operation_id,
            "dispatch_id": dispatch_id,
            "chain_id": chain_id,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _mmsg(operation_id="op1", dispatch_id="dm", adapter_id="ad1",
          chain_id="chain-1"):
    """手动派发审批单 message：四键紧凑 JSON（含 adapter_id）。"""
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


class DispatchAutoServiceTest(unittest.TestCase):
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

    def _approve(self, rid="ap1", message=None):
        msg = message if message is not None else _amsg()
        code, _ = self.svc.create_sign_request("w1", rid, msg)
        self.assertEqual(code, 201)
        self.svc.approve("w1", rid, "boss")

    def _auto(self, wallet="w1", operation_id="op1", dispatch_id="dp1",
              approval="ap1"):
        return _call(
            self.svc.post_chain_dispatch_auto,
            wallet, operation_id, dispatch_id, approval,
        )

    def _manual(self, wallet="w1", operation_id="op1", dispatch_id="dm",
                adapter_id="ad1", approval="apm"):
        return _call(
            self.svc.post_chain_dispatch,
            wallet, operation_id, dispatch_id, adapter_id, approval,
        )

    def _adapters(self, table):
        return self.svc.put_chain_adapters("w1", table)

    def _events(self, svc=None):
        svc = svc or self.svc
        return [
            e for e in svc.get_audit_events("w1")["events"]
            if e["type"] == "chain_dispatch_auto_requested"
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

    # ---- 201 / 自动选择 / 视图 / 事件形状 ---------------------------------

    def test_first_auto_picks_ascii_min_up_adapter(self):
        self._approve()
        # b2/c1 为 down，缺席的适配器不参与；a1 与 a9 为 up，取 ASCII 最小
        self._adapters({"a1": "up", "a9": "up", "b2": "down", "c1": "down"})
        code, v = self._auto()
        self.assertEqual(code, 201)
        self.assertEqual(
            v,
            {
                "dispatch_id": "dp1",
                "operation_id": "op1",
                "adapter_id": "a1",
                "chain_id": "chain-1",
                "state": "requested",
            },
        )
        self.assertEqual(
            list(v),
            ["dispatch_id", "operation_id", "adapter_id", "chain_id",
             "state"],
        )

    def test_auto_skips_down_and_picks_next_up(self):
        self._approve()
        # ASCII 最小的 a1 显式 down，自动选择必须跳过它取 a9
        self._adapters({"a1": "down", "a9": "up"})
        code, v = self._auto()
        self.assertEqual(code, 201)
        self.assertEqual(v["adapter_id"], "a9")

    def test_view_and_event_shape(self):
        self._approve()
        self._adapters({"a1": "up"})
        code, v = self._auto()
        self.assertEqual(code, 201)
        (event,) = self._events()
        self.assertEqual(event["request_id"], "dp1")
        self.assertEqual(event["actor_id"], "ap1")
        self.assertIsNone(event["reason"])
        self.assertEqual(event["details"], v)
        self.assertEqual(
            list(event["details"]),
            ["dispatch_id", "operation_id", "adapter_id", "chain_id",
             "state"],
        )
        with open(self._audit_path(), encoding="utf-8") as f:
            log = json.load(f)
        stored = [
            e for e in log["events"]
            if e["type"] == "chain_dispatch_auto_requested"
        ][0]
        self.assertEqual(
            list(stored),
            ["actor_id", "at", "details", "reason", "request_id", "seq",
             "type"],
        )
        self.assertEqual(
            list(stored["details"]),
            ["dispatch_id", "operation_id", "adapter_id", "chain_id",
             "state"],
        )

    def test_auto_does_not_change_operation_state(self):
        self._approve()
        self._adapters({"a1": "up"})
        self.assertEqual(self._auto()[0], 201)
        self.assertEqual(
            self.h.store.get_asset_operation("w1", "op1")["state"], "pending"
        )

    # ---- 400 --------------------------------------------------------------

    def test_invalid_ids_400(self):
        self._approve()
        self._adapters({"a1": "up"})
        for kwargs in (
            {"dispatch_id": "bad id"},
            {"dispatch_id": ""},
            {"dispatch_id": 1},
            {"dispatch_id": None},
            {"approval": "bad id"},
            {"approval": 12},
            {"operation_id": "bad id"},
        ):
            code, _ = self._auto(**kwargs)
            self.assertEqual(code, 400, kwargs)
        self.assertEqual(self._events(), [])

    # ---- 404 --------------------------------------------------------------

    def test_unknown_wallet_404(self):
        self._approve()
        self._adapters({"a1": "up"})
        self.assertEqual(self._auto(wallet="w2")[0], 404)

    def test_unknown_operation_404(self):
        self._approve()
        self._adapters({"a1": "up"})
        self.assertEqual(self._auto(operation_id="op2")[0], 404)

    def test_missing_policy_404(self):
        self._approve()
        self._adapters({"a1": "up"})
        code, _ = self.svc.create_asset_operation("w1", "op2", "ETH", 5)
        self.assertEqual(code, 201)
        self.assertEqual(self._auto(operation_id="op2")[0], 404)

    def test_unknown_approval_404(self):
        self._adapters({"a1": "up"})
        self.assertEqual(self._auto(approval="ap9")[0], 404)

    # ---- 409 --------------------------------------------------------------

    def test_no_health_table_409(self):
        self._approve()
        code, _ = self._auto()
        self.assertEqual(code, 409)
        self.assertEqual(self._events(), [])

    def test_no_up_adapter_409(self):
        self._approve()
        self._adapters({"a1": "down", "a2": "down"})
        code, _ = self._auto()
        self.assertEqual(code, 409)
        self.assertEqual(self._events(), [])

    def test_operation_not_pending_409(self):
        self._approve()
        self._adapters({"a1": "up"})
        code, _ = self.svc.post_chain_report(
            "w1", "op1", "chain-1", "ab" * 32, 1, "cd" * 32, 3
        )
        self.assertEqual(code, 201)
        self.assertEqual(self._auto()[0], 409)
        self.assertEqual(self._events(), [])

    def test_policy_disabled_409(self):
        self._approve()
        self._adapters({"a1": "up"})
        self.svc.put_chain_policy("w1", "BTC", "chain-1", False, 3, 2)
        self.assertEqual(self._auto()[0], 409)
        self.assertEqual(self._events(), [])

    def test_approval_not_approved_409(self):
        self._adapters({"a1": "up"})
        code, _ = self.svc.create_sign_request("w1", "ap1", _amsg())
        self.assertEqual(code, 201)
        self.assertEqual(self._auto()[0], 409)
        self.svc.reject("w1", "ap1", "boss")
        self.assertEqual(self._auto()[0], 409)
        self.assertEqual(self._events(), [])

    def test_approval_message_mismatch_409(self):
        self._adapters({"a1": "up"})
        # 四键（含 adapter_id）的手动 message 不满足自动派发三键契约
        self._approve(message=_mmsg())
        self.assertEqual(self._auto()[0], 409)
        # 键序不同同样不符
        self._approve(
            rid="ap2",
            message=json.dumps(
                {
                    "dispatch_id": "dp1",
                    "operation_id": "op1",
                    "chain_id": "chain-1",
                },
                separators=(",", ":"),
            ),
        )
        self.assertEqual(self._auto(approval="ap2")[0], 409)
        # chain_id 不符
        self._approve(rid="ap3", message=_amsg(chain_id="other"))
        self.assertEqual(self._auto(approval="ap3")[0], 409)
        self.assertEqual(self._events(), [])

    # ---- 幂等 / 冲突 --------------------------------------------------------

    def test_replay_same_params_200_no_new_event(self):
        self._approve()
        self._adapters({"a1": "up"})
        self.assertEqual(self._auto()[0], 201)
        code, v2 = self._auto()
        self.assertEqual(code, 200)
        self.assertEqual(
            v2,
            {
                "dispatch_id": "dp1",
                "operation_id": "op1",
                "adapter_id": "a1",
                "chain_id": "chain-1",
                "state": "requested",
            },
        )
        self.assertEqual(len(self._events()), 1)

    def test_replay_ignores_health_and_policy_changes(self):
        self._approve()
        self._adapters({"a1": "up", "a9": "up"})
        self.assertEqual(self._auto()[0], 201)
        # 事后把首选适配器翻 down、清空 up、停用策略：同参重放仍 200 同 V，
        # 不复查健康/策略/审批现状。
        self._adapters({"a1": "down", "a9": "down"})
        self.svc.put_chain_policy("w1", "BTC", "chain-1", False, 3, 2)
        code, v = self._auto()
        self.assertEqual(code, 200)
        self.assertEqual(v["adapter_id"], "a1")
        self.assertEqual(v["state"], "requested")
        self.assertEqual(len(self._events()), 1)

    def test_same_dispatch_id_different_params_409(self):
        self._approve()
        self._adapters({"a1": "up"})
        self.assertEqual(self._auto()[0], 201)
        # 更换审批单
        self.assertEqual(self._auto(approval="ap9")[0], 409)
        # 更换路径操作
        code, _ = self.svc.create_asset_operation("w1", "op2", "BTC", 5)
        self.assertEqual(code, 201)
        self.svc.put_chain_policy("w1", "BTC", "chain-1", True, 3, 2)
        self.assertEqual(self._auto(operation_id="op2")[0], 409)
        self.assertEqual(len(self._events()), 1)

    def test_operation_with_manual_dispatch_blocks_auto_409(self):
        self._adapters({"ad1": "up"})
        self._approve(rid="apm", message=_mmsg())
        self.assertEqual(self._manual()[0], 201)
        self._approve(rid="ap2", message=_amsg(dispatch_id="da"))
        self.assertEqual(
            self._auto(dispatch_id="da", approval="ap2")[0], 409
        )
        # 同 dispatch_id 已被手动派发占用，自动端点同样 409
        self.assertEqual(
            self._auto(dispatch_id="dm", approval="apm")[0], 409
        )
        self.assertEqual(len(self._events()), 0)

    def test_operation_with_auto_dispatch_blocks_manual_409(self):
        self._approve()
        self._adapters({"ad1": "up"})
        self.assertEqual(self._auto()[0], 201)
        self._approve(rid="apm", message=_mmsg(dispatch_id="dm2"))
        self.assertEqual(
            self._manual(dispatch_id="dm2", approval="apm")[0], 409
        )

    def test_concurrent_single_201(self):
        self._approve()
        self._adapters({"a1": "up"})
        codes = []
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            codes.append(self._auto()[0])

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

    # ---- 后续沿用 dispatch ------------------------------------------------

    def test_follow_on_result_confirm_settle(self):
        self._approve()
        self._adapters({"a1": "up"})
        self.assertEqual(self._auto()[0], 201)
        code, _ = self.svc.post_chain_dispatch_result(
            "w1", "dp1", "a1", "broadcasted", "ab" * 32
        )
        self.assertEqual(code, 201)
        code, cf = self.svc.post_chain_dispatch_confirmation(
            "w1", "dp1", "a1", "ab" * 32, 1, "cd" * 32, 3
        )
        self.assertEqual(code, 201)
        self.assertEqual(cf["state"], "finalized")
        finality = self.svc.get_chain_dispatch_finality("w1", "dp1")
        self.assertEqual(finality["operation_id"], "op1")
        code, settled = self.svc.settle_chain_dispatch("w1", "dp1")
        self.assertEqual(code, 201)
        self.assertEqual(settled["state"], "committed")
        self.assertEqual(
            self.h.store.get_asset_operation("w1", "op1")["state"],
            "committed",
        )

    # ---- 恢复 ---------------------------------------------------------------

    def test_restart_keeps_auto_dispatch_and_seq(self):
        self._approve()
        self._adapters({"a1": "up"})
        self.assertEqual(self._auto()[0], 201)
        before = self.svc.get_audit_events("w1")["events"]
        svc2 = WalletService(self.h.store)
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)
        code, v = _call(
            svc2.post_chain_dispatch_auto, "w1", "op1", "dp1", "ap1"
        )
        self.assertEqual(code, 200)
        self.assertEqual(v["dispatch_id"], "dp1")
        self.assertEqual(v["adapter_id"], "a1")
        self.assertEqual(len(self._events(svc2)), 1)

    def test_recovery_rejects_non_preferred_adapter(self):
        self._approve()
        self._adapters({"a1": "up", "a9": "up"})
        self.assertEqual(self._auto()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_auto_requested":
                    e["details"]["adapter_id"] = "a9"

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_recovery_rejects_missing_health_snapshot(self):
        self._approve()
        self._adapters({"a1": "up"})
        self.assertEqual(self._auto()[0], 201)

        def mutate(log):
            log["events"] = [
                e for e in log["events"]
                if e["type"] != "chain_adapter_health"
            ]
            for i, e in enumerate(log["events"], 1):
                e["seq"] = i
            log["next_seq"] = len(log["events"]) + 1

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_recovery_rejects_when_preferred_was_down(self):
        self._approve()
        self._adapters({"a1": "down", "a9": "up"})
        self.assertEqual(self._auto()[0], 201)
        # 事后把事前快照里的 a9 改为 down、a1 改为 up 会改变首选，使记录的
        # a9 与当时首选 a1 不符（改链直接破坏恢复核验）。
        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_adapter_health":
                    e["details"]["adapters"] = {"a1": "up", "a9": "down"}

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_details_reordered_before_normalization_fail_closed(self):
        self._approve()
        self._adapters({"a1": "up"})
        self.assertEqual(self._auto()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_auto_requested":
                    d = e["details"]
                    e["details"] = {
                        "state": d["state"],
                        "dispatch_id": d["dispatch_id"],
                        "operation_id": d["operation_id"],
                        "adapter_id": d["adapter_id"],
                        "chain_id": d["chain_id"],
                    }

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            self.svc._audit.chain_dispatch_auto_requested_events("w1")
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_duplicate_dispatch_id_fail_closed(self):
        self._approve()
        self._adapters({"a1": "up"})
        self.assertEqual(self._auto()[0], 201)

        def mutate(log):
            for e in list(log["events"]):
                if e["type"] == "chain_dispatch_auto_requested":
                    dup = dict(e)
                    dup["seq"] = len(log["events"]) + 1
                    log["events"].append(dup)
                    log["next_seq"] = len(log["events"]) + 1

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_bad_json_is_corrupt_data(self):
        self._approve()
        self._adapters({"a1": "up"})
        self.assertEqual(self._auto()[0], 201)
        with open(self._audit_path(), "wb") as f:
            f.write(b"{broken")
        with self.assertRaises(CorruptDataError):
            self.svc._audit.chain_dispatch_auto_requested_events("w1")
        with self.assertRaises(CorruptDataError):
            WalletService(self.h.store)

    def test_backup_restore_keeps_auto_dispatch_and_seq(self):
        from threshold_wallet import drbackup

        self._approve()
        self._adapters({"a1": "up"})
        self.assertEqual(self._auto()[0], 201)
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
            svc2.post_chain_dispatch_auto, "w1", "op1", "dp1", "ap1"
        )
        self.assertEqual(code, 200)
        self.assertEqual(v["adapter_id"], "a1")
        self.assertEqual(svc2.get_audit_events("w1")["events"], after)


class DispatchAutoHttpTest(unittest.TestCase):
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
            {"id": "ap1", "message": _amsg()},
        )
        srv.request(
            "POST", "/v1/wallets/w1/sign-requests/ap1/approve",
            {"approver_id": "boss"},
        )

    def _auto(self, body, wallet="w1", operation_id="op1"):
        return self.srv.request(
            "POST",
            f"/v1/wallets/{wallet}/chain/{operation_id}/dispatch-auto",
            body,
        )

    def test_http_happy_path_and_replay(self):
        self.srv.request(
            "PUT", "/v1/wallets/w1/chain-adapters",
            {"adapters": {"a1": "up", "a2": "up"}},
        )
        status, v = self._auto(
            {"dispatch_id": "dp1", "approval_request_id": "ap1"}
        )
        self.assertEqual(status, 201)
        self.assertEqual(
            list(v),
            ["dispatch_id", "operation_id", "adapter_id", "chain_id",
             "state"],
        )
        self.assertEqual(v["state"], "requested")
        self.assertEqual(v["adapter_id"], "a1")
        status, v2 = self._auto(
            {"dispatch_id": "dp1", "approval_request_id": "ap1"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(v2, v)

    def test_http_body_key_set_400(self):
        for body in (
            {},
            {"dispatch_id": "dp1"},
            {"approval_request_id": "ap1"},
            {"dispatch_id": "dp1", "approval_request_id": "ap1",
             "adapter_id": "a1"},
            {"dispatch_id": "dp1", "approval": "ap1"},
        ):
            status, _ = self._auto(body)
            self.assertEqual(status, 400, body)

    def test_http_value_400_and_unknown_404(self):
        self.srv.request(
            "PUT", "/v1/wallets/w1/chain-adapters",
            {"adapters": {"a1": "up"}},
        )
        status, _ = self._auto(
            {"dispatch_id": "bad id", "approval_request_id": "ap1"}
        )
        self.assertEqual(status, 400)
        status, _ = self._auto(
            {"dispatch_id": "dp1", "approval_request_id": "ap9"}
        )
        self.assertEqual(status, 404)
        status, _ = self._auto(
            {"dispatch_id": "dp1", "approval_request_id": "ap1"},
            operation_id="op9",
        )
        self.assertEqual(status, 404)
        status, _ = self._auto(
            {"dispatch_id": "dp1", "approval_request_id": "ap1"},
            wallet="w9",
        )
        self.assertEqual(status, 404)

    def test_http_no_health_409(self):
        status, body = self._auto(
            {"dispatch_id": "dp1", "approval_request_id": "ap1"}
        )
        self.assertEqual(status, 409)
        self.assertNotIn("a1", json.dumps(body))

    def test_http_get_and_put_not_allowed(self):
        status, _ = self.srv.request(
            "GET", "/v1/wallets/w1/chain/op1/dispatch-auto"
        )
        self.assertEqual(status, 404)
        status, _ = self.srv.request(
            "PUT", "/v1/wallets/w1/chain/op1/dispatch-auto",
            {"dispatch_id": "dp1", "approval_request_id": "ap1"},
        )
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
