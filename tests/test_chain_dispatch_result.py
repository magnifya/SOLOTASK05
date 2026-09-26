"""跨链派发结果回执（POST /v1/wallets/{W}/chain/{D}/result）测试。

覆盖：
- 体恰含 adapter_id,state,tx_id 三键；D/adapter_id 为安全标识；
  state=broadcasted 时 tx_id 为 64 位小写 hex，failed 时为 null；
  键集/类型/值错 400；钱包/派发未知 404；adapter 不符或异参重报 409；
- 首提 201 返回 V（六键固定序），同参重放 200 同 V（优先于一切现状
  判定），并发仅一 201；
- chain_dispatch_result 为唯一提交点：request_id=dispatch_id、
  actor_id=adapter_id、reason=null、details=V 六键固定序，重放不记；
- 恢复按 seq 复核请求先于结果、归属一致、每派发至多一结果；坏形状/
  错序/矛盾 fail-closed（RecoveryError/CorruptDataError → 503、serve
  拒绝就绪），重启/灾备保状态与 seq。
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


class DispatchResultServiceTest(unittest.TestCase):
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

    def _result(self, wallet="w1", dispatch_id="dp1", adapter_id="ad1",
                state="broadcasted", tx_id=TX1):
        return _call(
            self.svc.post_chain_dispatch_result,
            wallet, dispatch_id, adapter_id, state, tx_id,
        )

    def _events(self, svc=None):
        svc = svc or self.svc
        return [
            e for e in svc.get_audit_events("w1")["events"]
            if e["type"] == "chain_dispatch_result"
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

    def test_first_result_201_view_and_event(self):
        code, v = self._result()
        self.assertEqual(code, 201)
        self.assertEqual(
            v,
            {
                "dispatch_id": "dp1",
                "operation_id": "op1",
                "adapter_id": "ad1",
                "chain_id": "chain-1",
                "state": "broadcasted",
                "tx_id": TX1,
            },
        )
        self.assertEqual(
            list(v),
            ["dispatch_id", "operation_id", "adapter_id", "chain_id",
             "state", "tx_id"],
        )
        (event,) = self._events()
        self.assertEqual(event["request_id"], "dp1")
        self.assertEqual(event["actor_id"], "ad1")
        self.assertIsNone(event["reason"])
        self.assertEqual(event["details"], v)
        self.assertEqual(
            list(event["details"]),
            ["dispatch_id", "operation_id", "adapter_id", "chain_id",
             "state", "tx_id"],
        )
        # 落盘外层规范序、details 键序
        with open(self._audit_path(), encoding="utf-8") as f:
            log = json.load(f)
        stored = [
            e for e in log["events"]
            if e["type"] == "chain_dispatch_result"
        ][0]
        self.assertEqual(
            list(stored),
            ["actor_id", "at", "details", "reason", "request_id", "seq",
             "type"],
        )
        self.assertEqual(
            list(stored["details"]),
            ["dispatch_id", "operation_id", "adapter_id", "chain_id",
             "state", "tx_id"],
        )

    def test_failed_result_tx_id_null(self):
        code, v = self._result(state="failed", tx_id=None)
        self.assertEqual(code, 201)
        self.assertEqual(v["state"], "failed")
        self.assertIsNone(v["tx_id"])

    def test_result_after_operation_committed_still_201(self):
        # 结果只归属派发，不校验操作当前状态
        code, _ = self.svc.post_chain_report(
            "w1", "op1", "chain-1", TX1, 1, TX2, 3
        )
        self.assertEqual(code, 201)
        self.assertEqual(
            self.h.store.get_asset_operation("w1", "op1")["state"],
            "committed",
        )
        code, v = self._result()
        self.assertEqual(code, 201)
        self.assertEqual(v["state"], "broadcasted")

    # ---- 400 --------------------------------------------------------------

    def test_invalid_ids_and_state_400(self):
        for kwargs in (
            {"dispatch_id": "bad id"},
            {"dispatch_id": ""},
            {"dispatch_id": 1},
            {"adapter_id": "bad id"},
            {"adapter_id": None},
            {"adapter_id": 12},
            {"state": "done"},
            {"state": None},
            {"state": True},
            {"state": 1},
        ):
            code, _ = self._result(**kwargs)
            self.assertEqual(code, 400, kwargs)
        self.assertEqual(self._events(), [])

    def test_tx_id_shape_400(self):
        for tx_id in (
            None,               # broadcasted 必须有 tx_id
            "ab",               # 长度不足
            "AB" * 32,          # 非小写
            "zz" * 32,          # 非 hex
            12,                 # 非字符串
            True,
        ):
            code, _ = self._result(tx_id=tx_id)
            self.assertEqual(code, 400, tx_id)
        # failed 时 tx_id 必须 null
        code, _ = self._result(state="failed", tx_id=TX1)
        self.assertEqual(code, 400)
        self.assertEqual(self._events(), [])

    # ---- 404 --------------------------------------------------------------

    def test_unknown_wallet_404(self):
        code, _ = self._result(wallet="w2")
        self.assertEqual(code, 404)

    def test_unknown_dispatch_404(self):
        code, _ = self._result(dispatch_id="dp9")
        self.assertEqual(code, 404)
        self.assertEqual(self._events(), [])

    # ---- 409 --------------------------------------------------------------

    def test_adapter_mismatch_409(self):
        code, _ = self._result(adapter_id="ad2")
        self.assertEqual(code, 409)
        self.assertEqual(self._events(), [])

    def test_re_report_different_params_409(self):
        self.assertEqual(self._result()[0], 201)
        for kwargs in (
            {"tx_id": TX2},
            {"state": "failed", "tx_id": None},
            {"adapter_id": "ad2"},
        ):
            code, _ = self._result(**kwargs)
            self.assertEqual(code, 409, kwargs)
        self.assertEqual(len(self._events()), 1)

    # ---- 幂等 / 并发 --------------------------------------------------------

    def test_replay_same_params_200_no_new_event(self):
        code, v1 = self._result()
        self.assertEqual(code, 201)
        code, v2 = self._result()
        self.assertEqual(code, 200)
        self.assertEqual(v2, v1)
        self.assertEqual(len(self._events()), 1)

    def test_replay_preferred_over_state_changes(self):
        self.assertEqual(self._result()[0], 201)
        # 事后提交操作、停用策略都不影响同参重放
        code, _ = self.svc.post_chain_report(
            "w1", "op1", "chain-1", TX1, 1, TX2, 3
        )
        self.assertEqual(code, 201)
        self.svc.put_chain_policy("w1", "BTC", "chain-1", False, 3, 2)
        code, v = self._result()
        self.assertEqual(code, 200)
        self.assertEqual(v["state"], "broadcasted")
        self.assertEqual(len(self._events()), 1)

    def test_concurrent_single_201(self):
        codes = []
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            codes.append(self._result()[0])

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

    def test_restart_keeps_result_and_seq(self):
        self.assertEqual(self._result()[0], 201)
        before = self.svc.get_audit_events("w1")["events"]
        svc2 = WalletService(self.h.store)
        # 恢复不新增审计事件，seq 连续
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)
        # 重启后同参重放仍 200 同 V
        code, v = _call(
            svc2.post_chain_dispatch_result,
            "w1", "dp1", "ad1", "broadcasted", TX1,
        )
        self.assertEqual(code, 200)
        self.assertEqual(v["dispatch_id"], "dp1")
        self.assertEqual(len(self._events(svc2)), 1)

    def test_tampered_details_state_fail_closed(self):
        self.assertEqual(self._result()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_result":
                    e["details"]["state"] = "done"

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_tampered_broadcasted_tx_id_fail_closed(self):
        self.assertEqual(self._result()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_result":
                    e["details"]["tx_id"] = None

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_details_reordered_before_normalization_fail_closed(self):
        self.assertEqual(self._result()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_result":
                    d = e["details"]
                    # 同键集、错序（tx_id 提前）
                    e["details"] = {
                        "tx_id": d["tx_id"],
                        "dispatch_id": d["dispatch_id"],
                        "operation_id": d["operation_id"],
                        "adapter_id": d["adapter_id"],
                        "chain_id": d["chain_id"],
                        "state": d["state"],
                    }

        self._rewrite(mutate)
        # 读取即 RecoveryError，且不被归一化静默修正
        with self.assertRaises(RecoveryError):
            self.svc._audit.chain_dispatch_result_events("w1")
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_outer_fields_reordered_fail_closed(self):
        self.assertEqual(self._result()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_result":
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

    def test_duplicate_result_fail_closed(self):
        self.assertEqual(self._result()[0], 201)

        def mutate(log):
            for e in list(log["events"]):
                if e["type"] == "chain_dispatch_result":
                    dup = dict(e)
                    dup["seq"] = len(log["events"]) + 1
                    log["events"].append(dup)
                    log["next_seq"] = len(log["events"]) + 1

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_result_without_request_fail_closed(self):
        self.assertEqual(self._result()[0], 201)

        def mutate(log):
            # 伪造一条无对应派发请求的结果事件
            log["events"].append(
                {
                    "actor_id": "ad1",
                    "at": log["events"][-1]["at"],
                    "details": {
                        "dispatch_id": "dp9",
                        "operation_id": "op1",
                        "adapter_id": "ad1",
                        "chain_id": "chain-1",
                        "state": "failed",
                        "tx_id": None,
                    },
                    "reason": None,
                    "request_id": "dp9",
                    "seq": len(log["events"]) + 1,
                    "type": "chain_dispatch_result",
                }
            )
            log["next_seq"] = len(log["events"]) + 1

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_result_before_request_fail_closed(self):
        self.assertEqual(self._result()[0], 201)

        def mutate(log):
            # 交换请求与结果的 seq：结果先于请求即矛盾
            request = result = None
            for e in log["events"]:
                if e["type"] == "chain_dispatch_requested":
                    request = e
                elif e["type"] == "chain_dispatch_result":
                    result = e
            request["seq"], result["seq"] = result["seq"], request["seq"]

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_ownership_mismatch_fail_closed(self):
        self.assertEqual(self._result()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_result":
                    e["details"]["chain_id"] = "chain-2"

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_actor_id_mismatch_fail_closed(self):
        self.assertEqual(self._result()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_result":
                    e["actor_id"] = "ad2"

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_bad_json_is_corrupt_data(self):
        self.assertEqual(self._result()[0], 201)
        with open(self._audit_path(), "wb") as f:
            f.write(b"{broken")
        with self.assertRaises(CorruptDataError):
            self.svc._audit.chain_dispatch_result_events("w1")
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_healthy_log_still_loads(self):
        self.assertEqual(self._result()[0], 201)
        events = self.svc._audit.chain_dispatch_result_events("w1")
        self.assertEqual(len(events["dp1"]), 1)
        self.assertEqual(
            list(events["dp1"][0]["details"]),
            ["dispatch_id", "operation_id", "adapter_id", "chain_id",
             "state", "tx_id"],
        )

    def test_backup_restore_keeps_result_and_seq(self):
        from threshold_wallet import drbackup

        self.assertEqual(self._result()[0], 201)
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
            svc2.post_chain_dispatch_result,
            "w1", "dp1", "ad1", "broadcasted", TX1,
        )
        self.assertEqual(code, 200)
        self.assertEqual(v["state"], "broadcasted")
        self.assertEqual(svc2.get_audit_events("w1")["events"], after)


class DispatchResultHttpTest(unittest.TestCase):
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

    def _result(self, body, wallet="w1", dispatch_id="dp1"):
        return self.srv.request(
            "POST", f"/v1/wallets/{wallet}/chain/{dispatch_id}/result",
            body,
        )

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
        status, v = self._result(
            {"adapter_id": "ad1", "state": "broadcasted", "tx_id": TX1}
        )
        self.assertEqual(status, 201)
        self.assertEqual(
            list(v),
            ["dispatch_id", "operation_id", "adapter_id", "chain_id",
             "state", "tx_id"],
        )
        self.assertEqual(v["state"], "broadcasted")
        status, v2 = self._result(
            {"adapter_id": "ad1", "state": "broadcasted", "tx_id": TX1}
        )
        self.assertEqual(status, 200)
        self.assertEqual(v2, v)

    def test_http_body_key_set_400(self):
        for body in (
            {},
            {"adapter_id": "ad1", "state": "broadcasted"},
            {"adapter_id": "ad1", "state": "broadcasted", "tx_id": TX1,
             "extra": 1},
            {"adapter_id": "ad1", "state": "broadcasted", "tx": TX1},
        ):
            status, _ = self._result(body)
            self.assertEqual(status, 400, body)

    def test_http_value_400_and_unknown_404(self):
        status, _ = self._result(
            {"adapter_id": "ad1", "state": "done", "tx_id": TX1}
        )
        self.assertEqual(status, 400)
        status, _ = self._result(
            {"adapter_id": "ad1", "state": "broadcasted", "tx_id": "ab"}
        )
        self.assertEqual(status, 400)
        status, _ = self._result(
            {"adapter_id": "ad1", "state": "failed", "tx_id": TX1}
        )
        self.assertEqual(status, 400)
        status, _ = self._result(
            {"adapter_id": "ad1", "state": "broadcasted", "tx_id": TX1},
            dispatch_id="dp9",
        )
        self.assertEqual(status, 404)
        status, _ = self._result(
            {"adapter_id": "ad1", "state": "broadcasted", "tx_id": TX1},
            wallet="w9",
        )
        self.assertEqual(status, 404)

    def test_http_adapter_mismatch_409(self):
        status, _ = self._result(
            {"adapter_id": "ad2", "state": "broadcasted", "tx_id": TX1}
        )
        self.assertEqual(status, 409)

    def test_http_get_and_put_not_allowed(self):
        status, _ = self.srv.request(
            "GET", "/v1/wallets/w1/chain/dp1/result"
        )
        self.assertEqual(status, 404)
        status, _ = self.srv.request(
            "PUT", "/v1/wallets/w1/chain/dp1/result",
            {"adapter_id": "ad1", "state": "broadcasted", "tx_id": TX1},
        )
        self.assertEqual(status, 404)

    def test_http_wire_compact_no_trailing_newline(self):
        status, raw = self._raw_post(
            "/v1/wallets/w1/chain/dp1/result",
            {"adapter_id": "ad1", "state": "broadcasted", "tx_id": TX1},
        )
        self.assertEqual(status, 201)
        # 紧凑 JSON：无空白分隔符、无末换行
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)
        self.assertFalse(raw.endswith(b"\n"))
        self.assertTrue(raw.startswith(b'{"dispatch_id":"dp1",'))
        # 错误体同样紧凑
        status, raw = self._raw_post(
            "/v1/wallets/w1/chain/dp9/result",
            {"adapter_id": "ad1", "state": "broadcasted", "tx_id": TX1},
        )
        self.assertEqual(status, 404)
        self.assertNotIn(b": ", raw)
        self.assertFalse(raw.endswith(b"\n"))
        self.assertIn(b'"error"', raw)

    def test_http_503_on_corrupt_scene(self):
        status, _ = self._result(
            {"adapter_id": "ad1", "state": "broadcasted", "tx_id": TX1}
        )
        self.assertEqual(status, 201)
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for e in log["events"]:
            if e["type"] == "chain_dispatch_result":
                e["details"]["state"] = "done"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        status, body = self._result(
            {"adapter_id": "ad1", "state": "failed", "tx_id": None},
            dispatch_id="dp1",
        )
        self.assertEqual(status, 503)
        # 错误体仅 {"error": 字符串}，不泄露内部细节
        self.assertEqual(list(body), ["error"])
        self.assertIsInstance(body["error"], str)
        self.assertNotIn("dp1", json.dumps(body))


if __name__ == "__main__":
    unittest.main()
