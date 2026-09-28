"""健康感知自动派发（POST /v1/wallets/{W}/chain/{O}/dispatch-auto）测试。

覆盖：
- 体恰含 dispatch_id,approval_request_id 两键，值与路径须安全标识，
  键集/值错 400；钱包/操作/策略/同钱包审批单未知 404；
- 首提须操作 pending、策略启用、健康表已配置且至少一个 up（锁内取
  ASCII 最小的 up 适配器）、审批单懒过期后 approved 且 message 为按
  operation_id,dispatch_id,chain_id 序的紧凑 JSON（无 adapter_id），
  否则 409 且现场不变；成功 201 返回五键 V（state=requested）；
- 同 dispatch_id 同参 200 同 V（优先于状态/健康/审批判定），异参或
  该操作已有派发（手工或自动）409；并发仅一 201；
- chain_dispatch_auto_requested 为唯一提交点：request_id=dispatch_id、
  actor_id=approval_request_id、reason=null、details=V 五键固定序，
  失败/重放不记事件；
- 自动派发后续沿用 dispatch 契约（result/confirm/finality/settle）；
- 恢复按事前策略/审批单/健康快照及首选适配器逐条复核；错序/矛盾
  fail-closed（RecoveryError/CorruptDataError），重启/灾备不增事件或
  seq。
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


def _auto_msg(operation_id="op1", dispatch_id="dp1", chain_id="chain-1"):
    return json.dumps(
        {
            "operation_id": operation_id,
            "dispatch_id": dispatch_id,
            "chain_id": chain_id,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _manual_msg(operation_id="op1", dispatch_id="dp1", adapter_id="ad1",
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
        message = message if message is not None else _auto_msg()
        code, _ = self.svc.create_sign_request("w1", rid, message)
        self.assertEqual(code, 201)
        self.svc.approve("w1", rid, "boss")

    def _auto(self, wallet="w1", operation_id="op1", dispatch_id="dp1",
              approval="ap1"):
        return _call(
            self.svc.post_chain_dispatch_auto,
            wallet, operation_id, dispatch_id, approval,
        )

    def _manual(self, wallet="w1", operation_id="op1", dispatch_id="dpM",
                adapter_id="ad1", approval="apM"):
        return _call(
            self.svc.post_chain_dispatch,
            wallet, operation_id, dispatch_id, adapter_id, approval,
        )

    def _health(self, adapters):
        return self.svc.put_chain_adapters("w1", adapters)

    def _auto_events(self, svc=None):
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

    # ---- 409 前置 ---------------------------------------------------------

    def test_no_health_table_409_no_event(self):
        self._approve()
        code, _ = self._auto()
        self.assertEqual(code, 409)
        self.assertEqual(self._auto_events(), [])

    def test_no_up_adapter_409_no_event(self):
        self._approve()
        self._health({"a-ad": "down", "b-ad": "down"})
        code, _ = self._auto()
        self.assertEqual(code, 409)
        self.assertEqual(self._auto_events(), [])

    def test_disabled_policy_409(self):
        self.svc.put_chain_policy("w1", "BTC", "chain-1", False, 3, 2)
        self._approve()
        self._health({"a-ad": "up"})
        code, _ = self._auto()
        self.assertEqual(code, 409)
        self.assertEqual(self._auto_events(), [])

    def test_operation_not_pending_409(self):
        # 用链上确认达门槛把 op1 提交，操作转 committed
        self._health({"a-ad": "up"})
        self._approve()
        code, v = self._auto()
        self.assertEqual((code, v["state"]), (201, "requested"))
        code, _ = _call(
            self.svc.post_chain_dispatch_result,
            "w1", "dp1", "a-ad", "broadcasted", "a" * 64,
        )
        self.assertEqual(code, 201)
        for i in range(1, 4):
            code, cv = _call(
                self.svc.post_chain_dispatch_confirmation,
                "w1", "dp1", "a-ad", "a" * 64, 7, "b" * 64, i,
            )
        self.assertEqual((code, cv["state"]), (201, "finalized"))
        code, _ = _call(self.svc.settle_chain_dispatch, "w1", "dp1")
        self.assertEqual(code, 201)
        # 同操作再次自动派发：操作已 committed
        self._approve("ap2", _auto_msg("op1", "dp2"))
        code, _ = self._auto(dispatch_id="dp2", approval="ap2")
        self.assertEqual(code, 409)
        self.assertEqual(len(self._auto_events()), 1)

    def test_approval_message_mismatch_409(self):
        # message 含 adapter_id（手工派发形态）一律不符
        self._approve("ap1", _manual_msg(adapter_id="a-ad"))
        self._health({"a-ad": "up"})
        code, _ = self._auto()
        self.assertEqual(code, 409)

    def test_approval_not_approved_409(self):
        code, _ = self.svc.create_sign_request("w1", "ap1", _auto_msg())
        self.assertEqual(code, 201)
        self._health({"a-ad": "up"})
        code, _ = self._auto()
        self.assertEqual(code, 409)

    # ---- 400 / 404 --------------------------------------------------------

    def test_invalid_ids_400(self):
        self._health({"a-ad": "up"})
        self._approve()
        for args in (
            ("w1", "op1", "bad id", "ap1"),
            ("w1", "op1", 123, "ap1"),
            ("w1", "op1", "dp1", None),
            ("w1", object(), "dp1", "ap1"),
        ):
            code, _ = _call(self.svc.post_chain_dispatch_auto, *args)
            self.assertEqual(code, 400, args)

    def test_unknowns_404(self):
        self._health({"a-ad": "up"})
        self._approve()
        code, _ = self._auto(wallet="w9")
        self.assertEqual(code, 404)
        code, _ = self._auto(operation_id="op9")
        self.assertEqual(code, 404)
        # 无策略资产：建操作但不 PUT chain policy
        code, _ = self.svc.create_asset_operation("w1", "op2", "ETH", 3)
        self.assertEqual(code, 201)
        code, _ = self._auto(operation_id="op2")
        self.assertEqual(code, 404)
        code, _ = self._auto(approval="ap9")
        self.assertEqual(code, 404)

    # ---- 201 / 视图 / 事件 ------------------------------------------------

    def test_first_auto_201_picks_ascii_smallest_up(self):
        self._approve()
        self._health({"A-ad": "down", "a-ad": "up", "b-ad": "up"})
        code, v = self._auto()
        self.assertEqual(code, 201)
        # ASCII：大写 A(65) 虽最小但为 down；小写里 a-ad 先于 b-ad
        self.assertEqual(
            v,
            {
                "dispatch_id": "dp1",
                "operation_id": "op1",
                "adapter_id": "a-ad",
                "chain_id": "chain-1",
                "state": "requested",
            },
        )
        self.assertEqual(
            list(v),
            ["dispatch_id", "operation_id", "adapter_id", "chain_id",
             "state"],
        )
        (event,) = self._auto_events()
        self.assertEqual(event["request_id"], "dp1")
        self.assertEqual(event["actor_id"], "ap1")
        self.assertIsNone(event["reason"])
        self.assertEqual(event["details"], v)
        self.assertEqual(
            list(event["details"]),
            ["dispatch_id", "operation_id", "adapter_id", "chain_id",
             "state"],
        )
        # 落盘外层规范序
        raw = json.loads(open(self._audit_path(), encoding="utf-8").read())
        stored = [
            e for e in raw["events"]
            if e["type"] == "chain_dispatch_auto_requested"
        ][0]
        self.assertEqual(
            list(stored),
            ["actor_id", "at", "details", "reason", "request_id", "seq",
             "type"],
        )

    def test_adapters_absent_from_health_table_treated_as_unavailable(self):
        # 自动派发只选**表中**显式 up 的适配器；未配置即 409（与手工
        # dispatch "缺席视为 up" 的熔断语义不同——自动派发必须有可选
        # 目标）。
        self._approve()
        code, _ = self._auto()
        self.assertEqual(code, 409)

    # ---- 幂等与冲突 -------------------------------------------------------

    def test_replay_200_ignores_health_and_state_changes(self):
        self._approve()
        self._health({"a-ad": "up", "b-ad": "up"})
        code, v = self._auto()
        self.assertEqual(code, 201)
        # 事后把 a-ad 翻为 down：同参重放仍 200 同 V
        self._health({"a-ad": "down", "b-ad": "up"})
        code, v2 = self._auto()
        self.assertEqual(code, 200)
        self.assertEqual(v2, v)
        self.assertEqual(len(self._auto_events()), 1)

    def test_different_approval_same_dispatch_409(self):
        self._approve("ap1")
        self._health({"a-ad": "up"})
        code, _ = self._auto()
        self.assertEqual(code, 201)
        self._approve("ap2", _auto_msg("op1", "dp1"))
        code, _ = self._auto(approval="ap2")
        self.assertEqual(code, 409)

    def test_operation_already_dispatched_manual_then_auto_409(self):
        self._approve("apM", _manual_msg("op1", "dpM", "ad1"))
        code, _ = self._manual()
        self.assertEqual(code, 201)
        self._approve("apA", _auto_msg("op1", "dpA"))
        self._health({"ad1": "up"})
        code, _ = self._auto(dispatch_id="dpA", approval="apA")
        self.assertEqual(code, 409)
        self.assertEqual(self._auto_events(), [])

    def test_operation_already_dispatched_auto_then_manual_409(self):
        self._approve()
        self._health({"ad1": "up"})
        code, _ = self._auto()
        self.assertEqual(code, 201)
        self._approve("apM", _manual_msg("op1", "dpM", "ad1"))
        code, _ = self._manual()
        self.assertEqual(code, 409)

    def test_same_dispatch_id_cross_types_is_recovery_error(self):
        # 同一 dispatch_id 同时存在手工与自动事件属不可对账现场：两个事件
        # 分属不同操作（各自的操作唯一/审批/健康前置都成立），专门触发
        # 跨类型重复 dispatch_id 检查。
        from threshold_wallet import audit

        code, _ = self.svc.create_asset_operation("w1", "op2", "BTC", 5)
        self.assertEqual(code, 201)
        self._approve("apM", _manual_msg("op1", "dp1", "ad1"))
        self._approve("apA", _auto_msg("op2", "dp1"))
        # ad1 不被熔断（缺席视为 up）；自动派发须快照中 a-ad 为最小 up
        self._health({"a-ad": "up", "ad1": "up"})
        self.svc._audit.append_event(
            "w1",
            self.svc._audit_event(
                audit.TYPE_CHAIN_DISPATCH_REQUESTED,
                request_id="dp1",
                actor_id="apM",
                reason=None,
                details=self.svc._dispatch_view(
                    "dp1", "op1", "ad1", "chain-1"
                ),
            ),
        )
        self.svc._audit.append_event(
            "w1",
            self.svc._audit_event(
                audit.TYPE_CHAIN_DISPATCH_AUTO_REQUESTED,
                request_id="dp1",
                actor_id="apA",
                reason=None,
                details=self.svc._dispatch_view(
                    "dp1", "op2", "a-ad", "chain-1"
                ),
            ),
        )
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.d))

    # ---- 后续沿用 dispatch 契约 -------------------------------------------

    def test_downstream_result_confirm_settle_on_auto_dispatch(self):
        self._approve()
        self._health({"a-ad": "up"})
        code, v = self._auto()
        self.assertEqual(code, 201)
        code, res = _call(
            self.svc.post_chain_dispatch_result,
            "w1", "dp1", "a-ad", "broadcasted", "a" * 64,
        )
        self.assertEqual(code, 201)
        self.assertEqual(res["operation_id"], "op1")
        self.assertEqual(res["chain_id"], "chain-1")
        last = None
        for i in range(1, 4):
            code, last = _call(
                self.svc.post_chain_dispatch_confirmation,
                "w1", "dp1", "a-ad", "a" * 64, 9, "b" * 64, i,
            )
        self.assertEqual((code, last["state"]), (201, "finalized"))
        finality = self.svc.get_chain_dispatch_finality("w1", "dp1")
        self.assertEqual(
            list(finality), ["operation_id", "chain_id", "confirmation"]
        )
        code, settled = _call(self.svc.settle_chain_dispatch, "w1", "dp1")
        self.assertEqual(code, 201)
        self.assertEqual(settled["operation_id"], "op1")
        self.assertEqual(settled["state"], "committed")
        # 同参重放
        code, _ = _call(self.svc.settle_chain_dispatch, "w1", "dp1")
        self.assertEqual(code, 200)

    def test_result_from_other_adapter_404_then_409_flow(self):
        self._approve()
        self._health({"a-ad": "up", "b-ad": "up"})
        code, _ = self._auto()
        self.assertEqual(code, 201)
        # 非归属适配器回执：409
        code, _ = _call(
            self.svc.post_chain_dispatch_result,
            "w1", "dp1", "b-ad", "failed", None,
        )
        self.assertEqual(code, 409)

    # ---- 并发 -------------------------------------------------------------

    def test_concurrent_only_one_201(self):
        self._approve()
        self._health({"a-ad": "up"})
        outcomes = []
        lock = threading.Lock()

        def worker():
            code, _ = self._auto()
            with lock:
                outcomes.append(code)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(outcomes.count(201), 1)
        self.assertEqual(outcomes.count(200), 7)
        self.assertEqual(len(self._auto_events()), 1)

    # ---- 重启 / 恢复 ------------------------------------------------------

    def test_restart_replay_no_new_events(self):
        self._approve()
        self._health({"a-ad": "up"})
        code, v = self._auto()
        self.assertEqual(code, 201)
        after = self.svc.get_audit_events("w1")["events"]
        svc2 = WalletService(WalletStore(self.d))
        code, v2 = _call(
            svc2.post_chain_dispatch_auto, "w1", "op1", "dp1", "ap1"
        )
        self.assertEqual(code, 200)
        self.assertEqual(v2, v)
        self.assertEqual(svc2.get_audit_events("w1")["events"], after)

    def test_recovery_reordered_details_fail_closed(self):
        self._approve()
        self._health({"a-ad": "up"})
        code, _ = self._auto()
        self.assertEqual(code, 201)

        def mutate(log):
            for event in log["events"]:
                if event["type"] == "chain_dispatch_auto_requested":
                    details = event["details"]
                    event["details"] = {
                        "state": details["state"],
                        "chain_id": details["chain_id"],
                        "adapter_id": details["adapter_id"],
                        "operation_id": details["operation_id"],
                        "dispatch_id": details["dispatch_id"],
                    }

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.d))

    def test_recovery_picked_adapter_must_be_snapshot_smallest_up(self):
        self._approve()
        self._health({"a-ad": "up", "b-ad": "up"})
        code, _ = self._auto()
        self.assertEqual(code, 201)
        # 篡改首选适配器为 b-ad（快照中 a-ad 仍 up）
        self._rewrite(
            lambda log: [
                event["details"].__setitem__("adapter_id", "b-ad")
                for event in log["events"]
                if event["type"] == "chain_dispatch_auto_requested"
            ]
        )
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.d))

    def test_recovery_requires_preceding_health_snapshot(self):
        self._approve()
        self._health({"a-ad": "up"})
        code, _ = self._auto()
        self.assertEqual(code, 201)
        # 删除健康快照并重排 seq 连续：自动事件失去事前快照
        path = self._audit_path()
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        log["events"] = [
            event for event in log["events"]
            if event["type"] != "chain_adapter_health"
        ]
        for index, event in enumerate(log["events"], 1):
            event["seq"] = index
        log["next_seq"] = len(log["events"]) + 1
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.d))

    def test_recovery_approval_message_mismatch_fail_closed(self):
        self._approve()
        self._health({"a-ad": "up"})
        code, _ = self._auto()
        self.assertEqual(code, 201)
        # 事后改写审批单 message（审批记录文件）即与事件不符
        request_path = os.path.join(self.d, "requests", "w1.json")
        with open(request_path, encoding="utf-8") as f:
            records = json.load(f)
        records["ap1"]["message"] = _manual_msg(adapter_id="a-ad")
        with open(request_path, "w", encoding="utf-8") as f:
            json.dump(records, f)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.d))

    def test_recovery_bad_json_is_corrupt_data(self):
        self._approve()
        self._health({"a-ad": "up"})
        code, _ = self._auto()
        self.assertEqual(code, 201)
        with open(self._audit_path(), "w", encoding="utf-8") as f:
            f.write("{not json")
        with self.assertRaises(CorruptDataError):
            WalletService(WalletStore(self.d))


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
            {"id": "ap1", "message": _auto_msg()},
        )
        srv.request(
            "POST", "/v1/wallets/w1/sign-requests/ap1/approve",
            {"approver_id": "boss"},
        )

    def _auto(self, body, operation_id="op1", wallet="w1"):
        return self.srv.request(
            "POST",
            f"/v1/wallets/{wallet}/chain/{operation_id}/dispatch-auto",
            body,
        )

    def test_http_body_key_set_400(self):
        for body in (
            {},
            {"dispatch_id": "dp1"},
            {"approval_request_id": "ap1"},
            {"dispatch_id": "dp1", "approval_request_id": "ap1",
             "adapter_id": "a-ad"},
        ):
            status, _ = self._auto(body)
            self.assertEqual(status, 400, body)

    def test_http_happy_path_201_replay_200(self):
        status, _ = self.srv.request(
            "PUT", "/v1/wallets/w1/chain-adapters",
            {"adapters": {"a-ad": "up", "b-ad": "down"}},
        )
        self.assertEqual(status, 200)
        status, v = self._auto(
            {"dispatch_id": "dp1", "approval_request_id": "ap1"}
        )
        self.assertEqual(status, 201)
        self.assertEqual(v["adapter_id"], "a-ad")
        self.assertEqual(v["state"], "requested")
        status, v2 = self._auto(
            {"dispatch_id": "dp1", "approval_request_id": "ap1"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(v2, v)

    def test_http_no_health_table_409(self):
        status, body = self._auto(
            {"dispatch_id": "dp1", "approval_request_id": "ap1"}
        )
        self.assertEqual(status, 409)
        self.assertIn("error", body)

    def test_http_get_put_404(self):
        status, _ = self.srv.request(
            "GET", "/v1/wallets/w1/chain/op1/dispatch-auto"
        )
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
