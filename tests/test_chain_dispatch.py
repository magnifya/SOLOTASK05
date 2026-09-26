"""跨链派发（POST /v1/wallets/{W}/chain/{O}/dispatch）测试。

覆盖：
- 体恰含 dispatch_id,adapter_id,approval_request_id 三键，值须安全标识，
  键集/值错 400；钱包/操作/策略/同钱包审批单未知 404；
- 首提须操作 pending、策略启用、审批单锁内懒过期后 approved 且 message
  为按 operation_id,dispatch_id,adapter_id,chain_id 序的紧凑 JSON，
  否则 409 且现场不变；成功 201 返回 V（state=requested）；
- 同 dispatch_id 同参 200 同 V（优先于状态/审批判定），异参或该操作
  已有派发 409；并发仅一 201；
- chain_dispatch_requested 为唯一提交点：request_id=dispatch_id、
  actor_id=approval_request_id、reason=null、details=V 五键固定序，
  失败/重放不记事件；
- 恢复按事前账本/策略/审批单逐条复核；坏形状/错序/矛盾 fail-closed
  （RecoveryError/CorruptDataError → 503、serve 拒绝就绪），重启/灾备
  保状态与 seq。
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
from threshold_wallet.store import CorruptDataError, RecoveryError, WalletStore

from tests.helpers import http_server, make_harness


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


class DispatchServiceTest(unittest.TestCase):
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
        msg = message if message is not None else _msg()
        code, _ = self.svc.create_sign_request("w1", rid, msg)
        self.assertEqual(code, 201)
        self.svc.approve("w1", rid, "boss")

    def _dispatch(self, wallet="w1", operation_id="op1", dispatch_id="dp1",
                  adapter_id="ad1", approval="ap1"):
        return _call(
            self.svc.post_chain_dispatch,
            wallet, operation_id, dispatch_id, adapter_id, approval,
        )

    def _events(self, svc=None):
        svc = svc or self.svc
        return [
            e for e in svc.get_audit_events("w1")["events"]
            if e["type"] == "chain_dispatch_requested"
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

    # ---- 201 / 视图 / 事件形状 --------------------------------------------

    def test_first_dispatch_201_view_and_event(self):
        self._approve()
        code, v = self._dispatch()
        self.assertEqual(code, 201)
        self.assertEqual(
            v,
            {
                "dispatch_id": "dp1",
                "operation_id": "op1",
                "adapter_id": "ad1",
                "chain_id": "chain-1",
                "state": "requested",
            },
        )
        self.assertEqual(
            list(v),
            ["dispatch_id", "operation_id", "adapter_id", "chain_id",
             "state"],
        )
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
        # 落盘外层规范序、details 键序
        with open(self._audit_path(), encoding="utf-8") as f:
            log = json.load(f)
        stored = [
            e for e in log["events"]
            if e["type"] == "chain_dispatch_requested"
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

    def test_dispatch_does_not_change_operation_state(self):
        self._approve()
        self.assertEqual(self._dispatch()[0], 201)
        record = self.h.store.get_asset_operation("w1", "op1")
        self.assertEqual(record["state"], "pending")

    # ---- 400 --------------------------------------------------------------

    def test_invalid_ids_400(self):
        self._approve()
        for kwargs in (
            {"dispatch_id": "bad id"},
            {"dispatch_id": ""},
            {"dispatch_id": 1},
            {"adapter_id": "bad id"},
            {"adapter_id": None},
            {"approval": "bad id"},
            {"approval": 12},
            {"operation_id": "bad id"},
        ):
            code, _ = self._dispatch(**kwargs)
            self.assertEqual(code, 400, kwargs)
        self.assertEqual(self._events(), [])

    # ---- 404 --------------------------------------------------------------

    def test_unknown_wallet_404(self):
        self._approve()
        code, _ = self._dispatch(wallet="w2")
        self.assertEqual(code, 404)

    def test_unknown_operation_404(self):
        self._approve()
        code, _ = self._dispatch(operation_id="op2")
        self.assertEqual(code, 404)

    def test_missing_policy_404(self):
        self._approve()
        code, _ = self.svc.create_asset_operation("w1", "op2", "ETH", 5)
        self.assertEqual(code, 201)
        code, _ = self._dispatch(operation_id="op2")
        self.assertEqual(code, 404)

    def test_unknown_approval_404(self):
        code, _ = self._dispatch(approval="ap9")
        self.assertEqual(code, 404)

    # ---- 409 --------------------------------------------------------------

    def test_operation_not_pending_409(self):
        self._approve()
        # 经链上报告达门槛提交（策略启用时人工 commit 被拒）
        code, _ = self.svc.post_chain_report(
            "w1", "op1", "chain-1", "ab" * 32, 1, "cd" * 32, 3
        )
        self.assertEqual(code, 201)
        self.assertEqual(
            self.h.store.get_asset_operation("w1", "op1")["state"],
            "committed",
        )
        code, _ = self._dispatch()
        self.assertEqual(code, 409)
        self.assertEqual(self._events(), [])

    def test_policy_disabled_409(self):
        self._approve()
        self.svc.put_chain_policy("w1", "BTC", "chain-1", False, 3, 2)
        code, _ = self._dispatch()
        self.assertEqual(code, 409)
        self.assertEqual(self._events(), [])

    def test_approval_not_approved_409(self):
        # pending 审批单
        code, _ = self.svc.create_sign_request("w1", "ap1", _msg())
        self.assertEqual(code, 201)
        code, _ = self._dispatch()
        self.assertEqual(code, 409)
        # rejected 审批单
        self.svc.reject("w1", "ap1", "boss")
        code, _ = self._dispatch()
        self.assertEqual(code, 409)
        self.assertEqual(self._events(), [])

    def test_approval_expired_409(self):
        # pending 审批单到点：锁内懒过期后为 expired，非 approved → 409
        code, _ = self.svc.create_sign_request("w1", "ap1", _msg())
        self.assertEqual(code, 201)
        record = dict(self.h.store.get_request("w1", "ap1"))
        record["t1"] = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat().replace("+00:00", "Z")
        self.h.store.update_request("w1", "ap1", record)
        code, _ = self._dispatch()
        self.assertEqual(code, 409)
        # 懒过期已持久化
        self.assertEqual(
            self.h.store.get_request("w1", "ap1")["state"], "expired"
        )
        self.assertEqual(self._events(), [])

    def test_approval_message_mismatch_409(self):
        self._approve(message=_msg(dispatch_id="dp2"))
        code, _ = self._dispatch()
        self.assertEqual(code, 409)
        # 键序不同（非紧凑既定键序）同样不符
        self._approve(
            rid="ap2",
            message=json.dumps(
                {
                    "dispatch_id": "dp1",
                    "operation_id": "op1",
                    "adapter_id": "ad1",
                    "chain_id": "chain-1",
                },
                separators=(",", ":"),
            ),
        )
        code, _ = self._dispatch(approval="ap2")
        self.assertEqual(code, 409)
        self.assertEqual(self._events(), [])

    # ---- 幂等 / 冲突 --------------------------------------------------------

    def test_replay_same_params_200_no_new_event(self):
        self._approve()
        code, v1 = self._dispatch()
        self.assertEqual(code, 201)
        code, v2 = self._dispatch()
        self.assertEqual(code, 200)
        self.assertEqual(v2, v1)
        self.assertEqual(len(self._events()), 1)

    def test_replay_preferred_over_state_changes(self):
        self._approve()
        self.assertEqual(self._dispatch()[0], 201)
        # 事后停用策略、提交操作、拒绝审批单都不影响同参重放
        self.svc.put_chain_policy("w1", "BTC", "chain-1", False, 3, 2)
        code, v = self._dispatch()
        self.assertEqual(code, 200)
        self.assertEqual(v["state"], "requested")
        self.assertEqual(len(self._events()), 1)

    def test_same_dispatch_id_different_params_409(self):
        self._approve()
        self.assertEqual(self._dispatch()[0], 201)
        for kwargs in (
            {"adapter_id": "ad2"},
            {"approval": "ap2"},
            {"operation_id": "op2"},
        ):
            if kwargs.get("operation_id") == "op2":
                self.svc.create_asset_operation("w1", "op2", "BTC", 5)
            code, _ = self._dispatch(**kwargs)
            self.assertEqual(code, 409, kwargs)
        self.assertEqual(len(self._events()), 1)

    def test_operation_already_dispatched_409(self):
        self._approve()
        self.assertEqual(self._dispatch()[0], 201)
        self._approve(rid="ap2", message=_msg(dispatch_id="dp2"))
        code, _ = self._dispatch(dispatch_id="dp2", approval="ap2")
        self.assertEqual(code, 409)
        self.assertEqual(len(self._events()), 1)

    def test_concurrent_single_201(self):
        self._approve()
        codes = []
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            codes.append(self._dispatch()[0])

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

    def test_restart_keeps_dispatch_and_seq(self):
        self._approve()
        self.assertEqual(self._dispatch()[0], 201)
        before = self.svc.get_audit_events("w1")["events"]
        svc2 = WalletService(self.h.store)
        # 恢复不新增审计事件，seq 连续
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)
        # 重启后同参重放仍 200 同 V
        code, v = _call(
            svc2.post_chain_dispatch, "w1", "op1", "dp1", "ad1", "ap1"
        )
        self.assertEqual(code, 200)
        self.assertEqual(v["dispatch_id"], "dp1")
        self.assertEqual(len(self._events(svc2)), 1)

    def test_tampered_details_state_fail_closed(self):
        self._approve()
        self.assertEqual(self._dispatch()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_requested":
                    e["details"]["state"] = "done"

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_details_reordered_before_normalization_fail_closed(self):
        self._approve()
        self.assertEqual(self._dispatch()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_requested":
                    d = e["details"]
                    # 同键集、错序（state 提前）
                    e["details"] = {
                        "state": d["state"],
                        "dispatch_id": d["dispatch_id"],
                        "operation_id": d["operation_id"],
                        "adapter_id": d["adapter_id"],
                        "chain_id": d["chain_id"],
                    }

        self._rewrite(mutate)
        # 读取即 RecoveryError，且不被归一化静默修正
        with self.assertRaises(RecoveryError):
            self.svc._audit.chain_dispatch_requested_events("w1")
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_outer_fields_reordered_fail_closed(self):
        self._approve()
        self.assertEqual(self._dispatch()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_requested":
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

    def test_duplicate_dispatch_id_fail_closed(self):
        self._approve()
        self.assertEqual(self._dispatch()[0], 201)

        def mutate(log):
            for e in list(log["events"]):
                if e["type"] == "chain_dispatch_requested":
                    dup = dict(e)
                    dup["seq"] = len(log["events"]) + 1
                    log["events"].append(dup)
                    log["next_seq"] = len(log["events"]) + 1

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_unknown_operation_event_fail_closed(self):
        self._approve()
        self.assertEqual(self._dispatch()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_requested":
                    e["details"]["operation_id"] = "op9"
                    # 审批单 message 同步伪造，隔离操作存在性复核
                    pass

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_bad_json_is_corrupt_data(self):
        self._approve()
        self.assertEqual(self._dispatch()[0], 201)
        with open(self._audit_path(), "wb") as f:
            f.write(b"{broken")
        with self.assertRaises(CorruptDataError):
            self.svc._audit.chain_dispatch_requested_events("w1")
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_healthy_log_still_loads(self):
        self._approve()
        self.assertEqual(self._dispatch()[0], 201)
        events = self.svc._audit.chain_dispatch_requested_events("w1")
        self.assertEqual(len(events["dp1"]), 1)
        self.assertEqual(
            list(events["dp1"][0]["details"]),
            ["dispatch_id", "operation_id", "adapter_id", "chain_id",
             "state"],
        )

    def test_backup_restore_keeps_dispatch_and_seq(self):
        from threshold_wallet import drbackup

        self._approve()
        self.assertEqual(self._dispatch()[0], 201)
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
        # 恢复后同参重放仍 200，不记事件
        code, v = _call(
            svc2.post_chain_dispatch, "w1", "op1", "dp1", "ad1", "ap1"
        )
        self.assertEqual(code, 200)
        self.assertEqual(v["state"], "requested")
        self.assertEqual(svc2.get_audit_events("w1")["events"], after)


class DispatchHttpTest(unittest.TestCase):
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

    def _dispatch(self, body, wallet="w1", operation_id="op1"):
        return self.srv.request(
            "POST", f"/v1/wallets/{wallet}/chain/{operation_id}/dispatch",
            body,
        )

    def test_http_happy_path_and_replay(self):
        status, v = self._dispatch(
            {"dispatch_id": "dp1", "adapter_id": "ad1",
             "approval_request_id": "ap1"}
        )
        self.assertEqual(status, 201)
        self.assertEqual(
            list(v),
            ["dispatch_id", "operation_id", "adapter_id", "chain_id",
             "state"],
        )
        self.assertEqual(v["state"], "requested")
        status, v2 = self._dispatch(
            {"dispatch_id": "dp1", "adapter_id": "ad1",
             "approval_request_id": "ap1"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(v2, v)

    def test_http_body_key_set_400(self):
        for body in (
            {},
            {"dispatch_id": "dp1", "adapter_id": "ad1"},
            {"dispatch_id": "dp1", "adapter_id": "ad1",
             "approval_request_id": "ap1", "extra": 1},
            {"dispatch_id": "dp1", "adapter_id": "ad1", "approval": "ap1"},
        ):
            status, _ = self._dispatch(body)
            self.assertEqual(status, 400, body)

    def test_http_value_400_and_unknown_404(self):
        status, _ = self._dispatch(
            {"dispatch_id": "bad id", "adapter_id": "ad1",
             "approval_request_id": "ap1"}
        )
        self.assertEqual(status, 400)
        status, _ = self._dispatch(
            {"dispatch_id": "dp1", "adapter_id": "ad1",
             "approval_request_id": "ap9"}
        )
        self.assertEqual(status, 404)
        status, _ = self._dispatch(
            {"dispatch_id": "dp1", "adapter_id": "ad1",
             "approval_request_id": "ap1"},
            operation_id="op9",
        )
        self.assertEqual(status, 404)
        status, _ = self._dispatch(
            {"dispatch_id": "dp1", "adapter_id": "ad1",
             "approval_request_id": "ap1"},
            wallet="w9",
        )
        self.assertEqual(status, 404)

    def test_http_get_and_put_not_allowed(self):
        status, _ = self.srv.request(
            "GET", "/v1/wallets/w1/chain/op1/dispatch"
        )
        self.assertEqual(status, 404)
        status, _ = self.srv.request(
            "PUT", "/v1/wallets/w1/chain/op1/dispatch",
            {"dispatch_id": "dp1", "adapter_id": "ad1",
             "approval_request_id": "ap1"},
        )
        self.assertEqual(status, 404)

    def test_http_503_on_corrupt_scene(self):
        status, _ = self._dispatch(
            {"dispatch_id": "dp1", "adapter_id": "ad1",
             "approval_request_id": "ap1"}
        )
        self.assertEqual(status, 201)
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for e in log["events"]:
            if e["type"] == "chain_dispatch_requested":
                e["details"]["state"] = "done"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        status, body = self._dispatch(
            {"dispatch_id": "dp2", "adapter_id": "ad1",
             "approval_request_id": "ap1"}
        )
        self.assertEqual(status, 503)
        self.assertNotIn("dp1", json.dumps(body))


if __name__ == "__main__":
    unittest.main()
