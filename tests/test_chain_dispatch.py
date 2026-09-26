"""跨链派发（dispatch）与 chain_dispatch_requested 恢复测试。

覆盖：
- P=POST /v1/wallets/{W}/chain/{O}/dispatch：体恰含
  dispatch_id,adapter_id,approval_request_id 三键；值非安全 ID 400；
  钱包/操作/链策略/同钱包审批单任一未知 404；
- 首提须 O 为 pending、策略启用、审批单经锁内懒过期后为 approved 且
  message 逐字为按 operation_id,dispatch_id,adapter_id,chain_id 序的
  紧凑 JSON，否则 409 且现场不变；成功 201 返回
  V={dispatch_id,operation_id,adapter_id,chain_id,state=requested}
  （键序如列）；
- 同 dispatch_id 同参重放 200 同 V（优先于状态/审批复查），异参或
  O 已有派发 409；并发仅一 201，失败/重放不记事件；
- chain_dispatch_requested 为唯一提交点：request_id=dispatch_id、
  actor_id=approval_request_id、reason=null、details=V 且五键固定序，
  落盘外层七字段为规范序；事件之外不写状态文件；
- 重启/恢复后视图与 seq 连续不变；篡改事件（外层键序、state、重复
  提交点、未知审批）或审计损坏 fail-closed（RecoveryError → 503、
  启动恢复阻止就绪）。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone

from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import RecoveryError

from tests.helpers import http_server, make_harness

CHAIN = "bitcoin"


def _msg(
    operation_id="op1",
    dispatch_id="dp1",
    adapter_id="ad1",
    chain_id=CHAIN,
):
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
    """把 ServiceError 归一为 (status, {"error": ...})，便于断言状态码。"""
    try:
        return fn(*args)
    except ServiceError as exc:
        return exc.status, {"error": exc.message}


class DispatchServiceTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 600)
        self.svc.put_chain_policy("w1", "btc", CHAIN, True, 3, 2)
        code, _ = _call(
            self.svc.create_asset_operation, "w1", "op1", "btc", 100
        )
        self.assertEqual(code, 201)

    # ---- 辅助 -------------------------------------------------------------

    def _approve(self, rid="ap1", message=None, approve=True):
        msg = _msg() if message is None else message
        code, _ = _call(self.svc.create_sign_request, "w1", rid, msg)
        self.assertEqual(code, 201)
        if approve:
            self.svc.approve("w1", rid, "boss")
        return rid

    def _dispatch(self, wallet="w1", op="op1", dispatch_id="dp1",
                  adapter_id="ad1", approval="ap1"):
        return _call(
            self.svc.post_chain_dispatch,
            wallet, op, dispatch_id, adapter_id, approval,
        )

    def _events(self, event_type, svc=None):
        svc = svc or self.svc
        return [
            e for e in svc.get_audit_events("w1")["events"]
            if e["type"] == event_type
        ]

    def _commit_op1(self):
        code, _ = _call(
            self.svc.post_chain_report,
            "w1", "op1", CHAIN, "ab" * 32, 100, "11" * 32, 3,
        )
        self.assertEqual(code, 201)

    # ---- 首提与视图 -------------------------------------------------------

    def test_first_dispatch_201_view_and_event(self):
        self._approve()
        code, view = self._dispatch()
        self.assertEqual(code, 201)
        self.assertEqual(
            list(view),
            ["dispatch_id", "operation_id", "adapter_id", "chain_id",
             "state"],
        )
        self.assertEqual(
            view,
            {"dispatch_id": "dp1", "operation_id": "op1",
             "adapter_id": "ad1", "chain_id": CHAIN, "state": "requested"},
        )
        # 唯一提交点：恰一条 chain_dispatch_requested，七字段语义固定
        events = self._events("chain_dispatch_requested")
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["request_id"], "dp1")
        self.assertEqual(event["actor_id"], "ap1")
        self.assertIsNone(event["reason"])
        self.assertEqual(event["details"], view)
        # 落盘：外层七字段规范序、details 五键既定序
        with open(
            os.path.join(self.d, "audit", "w1.json"), encoding="utf-8"
        ) as f:
            log = json.load(f)
        stored = [
            e for e in log["events"]
            if e["type"] == "chain_dispatch_requested"
        ]
        self.assertEqual(len(stored), 1)
        self.assertEqual(
            list(stored[0]),
            ["actor_id", "at", "details", "reason", "request_id", "seq",
             "type"],
        )
        self.assertEqual(
            list(stored[0]["details"]),
            ["dispatch_id", "operation_id", "adapter_id", "chain_id",
             "state"],
        )
        # 事件之外不写任何派发状态文件
        for root, _dirs, files in os.walk(self.d):
            for name in files:
                self.assertNotIn("dispatch", name)

    def test_replay_same_params_200_no_new_event(self):
        self._approve()
        code, view = self._dispatch()
        self.assertEqual(code, 201)
        # 同 dispatch_id 同参重放：200 同 V，不记事件；审批单事后推进
        # （此处直接再发同参请求，复查现状与否不影响幂等结果）
        code, again = self._dispatch()
        self.assertEqual(code, 200)
        self.assertEqual(again, view)
        self.assertEqual(len(self._events("chain_dispatch_requested")), 1)

    def test_same_dispatch_id_different_params_409(self):
        self._approve()
        code, _ = self._dispatch()
        self.assertEqual(code, 201)
        # 异 adapter_id
        self._approve(rid="ap2", message=_msg(adapter_id="ad2"))
        code, _ = self._dispatch(adapter_id="ad2", approval="ap2")
        self.assertEqual(code, 409)
        # 异 approval_request_id（其余同）
        self._approve(rid="ap3", message=_msg())
        code, _ = self._dispatch(approval="ap3")
        self.assertEqual(code, 409)
        # 异 operation_id（同 dispatch_id 绑定另一操作）
        code, _ = _call(
            self.svc.create_asset_operation, "w1", "op2", "btc", 5
        )
        self.assertEqual(code, 201)
        self._approve(rid="ap4", message=_msg(operation_id="op2"))
        code, _ = self._dispatch(op="op2", approval="ap4")
        self.assertEqual(code, 409)
        self.assertEqual(len(self._events("chain_dispatch_requested")), 1)

    def test_operation_already_dispatched_409(self):
        self._approve()
        code, _ = self._dispatch()
        self.assertEqual(code, 201)
        # 同一操作换新 dispatch_id：O 已有派发
        self._approve(rid="ap2", message=_msg(dispatch_id="dp2"))
        code, _ = self._dispatch(dispatch_id="dp2", approval="ap2")
        self.assertEqual(code, 409)
        self.assertEqual(len(self._events("chain_dispatch_requested")), 1)

    # ---- 400 / 404 --------------------------------------------------------

    def test_non_safe_id_values_400(self):
        self._approve()
        for kwargs in (
            {"dispatch_id": "bad id"},
            {"dispatch_id": "x" * 129},
            {"dispatch_id": 1},
            {"adapter_id": "bad/id"},
            {"adapter_id": None},
            {"approval": "bad id"},
        ):
            code, _ = self._dispatch(**kwargs)
            self.assertEqual(code, 400, kwargs)
        code, _ = self._dispatch(op="bad op")
        self.assertEqual(code, 400)
        self.assertEqual(len(self._events("chain_dispatch_requested")), 0)

    def test_unknown_wallet_operation_policy_approval_404(self):
        self._approve()
        # 钱包未知
        code, _ = self._dispatch(wallet="w9")
        self.assertEqual(code, 404)
        # 操作未知
        code, _ = self._dispatch(op="op9")
        self.assertEqual(code, 404)
        # 链策略未配置（资产无策略）
        code, _ = _call(
            self.svc.create_asset_operation, "w1", "op2", "eth", 5
        )
        self.assertEqual(code, 201)
        self._approve(rid="ap2", message=_msg(operation_id="op2"))
        code, _ = self._dispatch(op="op2", approval="ap2")
        self.assertEqual(code, 404)
        # 审批单未知
        code, _ = self._dispatch(approval="ap9")
        self.assertEqual(code, 404)
        self.assertEqual(len(self._events("chain_dispatch_requested")), 0)

    # ---- 409 前置 ---------------------------------------------------------

    def test_operation_not_pending_409(self):
        self._approve()
        self._commit_op1()
        code, _ = self._dispatch()
        self.assertEqual(code, 409)
        self.assertEqual(len(self._events("chain_dispatch_requested")), 0)

    def test_policy_disabled_409(self):
        self.svc.put_chain_policy("w1", "btc2", CHAIN, False, 3, 2)
        code, _ = _call(
            self.svc.create_asset_operation, "w1", "op2", "btc2", 5
        )
        self.assertEqual(code, 201)
        self._approve(rid="ap2", message=_msg(operation_id="op2"))
        code, _ = self._dispatch(op="op2", approval="ap2")
        self.assertEqual(code, 409)
        self.assertEqual(len(self._events("chain_dispatch_requested")), 0)

    def test_approval_not_approved_409(self):
        # pending 审批单
        self._approve(approve=False)
        code, _ = self._dispatch()
        self.assertEqual(code, 409)
        # rejected 审批单
        self._approve(rid="ap2", approve=False)
        self.svc.reject("w1", "ap2", "boss")
        code, _ = self._dispatch(approval="ap2")
        self.assertEqual(code, 409)
        self.assertEqual(len(self._events("chain_dispatch_requested")), 0)

    def test_approval_lazy_expired_409(self):
        self._approve(approve=False)
        # 把 t1 改到过去：锁内懒过期后状态为 expired
        record = dict(self.h.store.get_request("w1", "ap1"))
        record["t1"] = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat().replace("+00:00", "Z")
        self.h.store.update_request("w1", "ap1", record)
        code, _ = self._dispatch()
        self.assertEqual(code, 409)
        # 懒过期原子记一次 request_expired；派发事件不记
        self.assertEqual(len(self._events("request_expired")), 1)
        self.assertEqual(len(self._events("chain_dispatch_requested")), 0)

    def test_approval_message_mismatch_409(self):
        # message 中 dispatch_id 不符
        self._approve(message=_msg(dispatch_id="dpX"))
        code, _ = self._dispatch()
        self.assertEqual(code, 409)
        # message 非紧凑 JSON（带空格）
        self._approve(rid="ap2", message=_msg() + " ")
        code, _ = self._dispatch(approval="ap2")
        self.assertEqual(code, 409)
        # message 键序不符
        self._approve(
            rid="ap3",
            message=json.dumps(
                {
                    "dispatch_id": "dp1",
                    "operation_id": "op1",
                    "adapter_id": "ad1",
                    "chain_id": CHAIN,
                },
                separators=(",", ":"),
            ),
        )
        code, _ = self._dispatch(approval="ap3")
        self.assertEqual(code, 409)
        self.assertEqual(len(self._events("chain_dispatch_requested")), 0)

    # ---- 并发与恢复 -------------------------------------------------------

    def test_concurrent_dispatch_single_201(self):
        self._approve()
        codes = []
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            code, _ = self._dispatch()
            codes.append(code)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(codes), [200] * 7 + [201])
        self.assertEqual(len(self._events("chain_dispatch_requested")), 1)
        seqs = [
            e["seq"] for e in self.svc.get_audit_events("w1")["events"]
        ]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))

    def test_restart_keeps_view_and_seq(self):
        self._approve()
        code, view = self._dispatch()
        self.assertEqual(code, 201)
        before = self.svc.get_audit_events("w1")["events"]
        svc2 = WalletService(self.h.store)
        # 恢复不新增审计事件，seq 连续；重放仍 200 同 V
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)
        code, again = _call(
            svc2.post_chain_dispatch, "w1", "op1", "dp1", "ad1", "ap1"
        )
        self.assertEqual(code, 200)
        self.assertEqual(again, view)
        seqs = [e["seq"] for e in svc2.get_audit_events("w1")["events"]]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))

    # ---- 恢复 fail-closed -------------------------------------------------

    def _committed_dispatch(self):
        self._approve()
        code, view = self._dispatch()
        self.assertEqual(code, 201)
        return view

    def _rewrite_audit(self, mutate):
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        mutate(log)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        return path

    def test_tampered_dispatch_state_is_fail_closed(self):
        self._committed_dispatch()

        def mutate(log):
            for event in log["events"]:
                if event["type"] == "chain_dispatch_requested":
                    event["details"]["state"] = "done"

        self._rewrite_audit(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_reordered_dispatch_outer_fields_is_fail_closed(self):
        self._committed_dispatch()

        def mutate(log):
            for i, event in enumerate(log["events"]):
                if event["type"] == "chain_dispatch_requested":
                    # 重排落盘外层七字段（值不变，仅键序非规范序）
                    reordered = {"type": event["type"]}
                    for key, value in event.items():
                        if key != "type":
                            reordered[key] = value
                    log["events"][i] = reordered

        path = self._rewrite_audit(mutate)
        with open(path, "rb") as f:
            before = f.read()
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)
        # 恢复 fail-closed 且绝不写盘：乱序现场原样保留
        with open(path, "rb") as f:
            self.assertEqual(f.read(), before)

    def test_duplicate_dispatch_event_is_fail_closed(self):
        self._committed_dispatch()

        def mutate(log):
            for event in list(log["events"]):
                if event["type"] == "chain_dispatch_requested":
                    dup = dict(event)
                    dup["seq"] = len(log["events"]) + 1
                    log["events"].append(dup)
                    log["next_seq"] = len(log["events"]) + 1

        self._rewrite_audit(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_dispatch_with_unknown_approval_is_fail_closed(self):
        self._committed_dispatch()

        def mutate(log):
            for event in log["events"]:
                if event["type"] == "chain_dispatch_requested":
                    event["actor_id"] = "ap9"

        self._rewrite_audit(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_corrupt_audit_is_fail_closed(self):
        self._committed_dispatch()
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write("{not json")
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)


class DispatchHttpTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self._ctx = http_server(self.tmpdir)
        self.srv = self._ctx.__enter__()
        self.addCleanup(self._ctx.__exit__, None, None, None)
        status, _ = self.srv.request(
            "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
        )
        self.assertEqual(status, 201)
        status, _ = self.srv.request(
            "PUT",
            "/v1/wallets/w1/approval-policy",
            {"required_approvals": 1, "timeout_seconds": 600},
        )
        self.assertEqual(status, 200)
        status, _ = self.srv.request(
            "PUT",
            "/v1/wallets/w1/chain/btc",
            {
                "chain_id": CHAIN,
                "enabled": True,
                "required_confirmations": 3,
                "reorg_window": 2,
            },
        )
        self.assertEqual(status, 200)
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/w1/asset-operations",
            {"operation_id": "op1", "asset_id": "btc", "delta": 100},
        )
        self.assertEqual(status, 201)
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/w1/sign-requests",
            {"id": "ap1", "message": _msg()},
        )
        self.assertEqual(status, 201)
        status, _ = self.srv.request(
            "POST",
            "/v1/wallets/w1/sign-requests/ap1/approve",
            {"approver_id": "boss"},
        )
        self.assertEqual(status, 200)

    def _dispatch(self, body, wallet="w1", op="op1"):
        return self.srv.request(
            "POST", f"/v1/wallets/{wallet}/chain/{op}/dispatch", body
        )

    def test_body_key_set_400(self):
        good = {
            "dispatch_id": "dp1",
            "adapter_id": "ad1",
            "approval_request_id": "ap1",
        }
        # 缺键 / 多键一律 400
        for body in (
            {},
            {"dispatch_id": "dp1"},
            {**good, "extra": 1},
            {"dispatch_id": "dp1", "adapter_id": "ad1"},
        ):
            status, _ = self._dispatch(body)
            self.assertEqual(status, 400, body)
        # 合法体 201，重放 200
        status, view = self._dispatch(good)
        self.assertEqual(status, 201)
        self.assertEqual(view["state"], "requested")
        status, again = self._dispatch(good)
        self.assertEqual(status, 200)
        self.assertEqual(again, view)

    def test_unknown_wallet_404(self):
        status, _ = self._dispatch(
            {
                "dispatch_id": "dp1",
                "adapter_id": "ad1",
                "approval_request_id": "ap1",
            },
            wallet="w9",
        )
        self.assertEqual(status, 404)

    def test_get_dispatch_route_not_found(self):
        status, _ = self.srv.request(
            "GET", "/v1/wallets/w1/chain/op1/dispatch"
        )
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
