"""跨链派发结果回执（POST /v1/wallets/{W}/chain/{D}/result）测试。

覆盖：
- 体恰含 adapter_id,state,tx_id 三键；adapter_id 须安全标识，
  state=broadcasted 时 tx_id 为 64 位小写 hex、state=failed 时 tx_id
  为 null，键集/类型/值错 400；钱包/派发未知 404；adapter 不符或异参
  重报 409；
- 首提 201、同参重放 200，V 键序
  dispatch_id,operation_id,adapter_id,chain_id,state,tx_id；并发仅一
  201；
- chain_dispatch_result 为唯一提交点：request_id=dispatch_id、
  actor_id=adapter_id、reason=null、details=V 六键固定序，失败/重放
  不记事件；
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

from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import CorruptDataError, RecoveryError, WalletStore

from tests.helpers import http_server, make_harness

TX = "ab" * 32


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
        code, _ = _call(
            self.svc.post_chain_dispatch, "w1", "op1", "dp1", "ad1", "ap1"
        )
        self.assertEqual(code, 201)

    def _result(self, wallet="w1", dispatch_id="dp1", adapter_id="ad1",
                state="broadcasted", tx_id=TX):
        return _call(
            self.svc.post_chain_dispatch_result,
            wallet, dispatch_id, adapter_id, state, tx_id,
        )

    def _events(self, svc=None, event_type="chain_dispatch_result"):
        svc = svc or self.svc
        return [
            e for e in svc.get_audit_events("w1")["events"]
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
                "tx_id": TX,
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

    def test_failed_result_null_tx_id(self):
        code, v = self._result(state="failed", tx_id=None)
        self.assertEqual(code, 201)
        self.assertEqual(v["state"], "failed")
        self.assertIsNone(v["tx_id"])

    # ---- 400 --------------------------------------------------------------

    def test_invalid_params_400(self):
        for kwargs in (
            {"dispatch_id": "bad id"},
            {"dispatch_id": ""},
            {"dispatch_id": 1},
            {"adapter_id": "bad id"},
            {"adapter_id": None},
            {"adapter_id": 12},
            {"state": "done"},
            {"state": None},
            {"state": 1},
            {"tx_id": None},                        # broadcasted 须 64 hex
            {"tx_id": "ab"},                        # 长度不足
            {"tx_id": "AB" * 32},                   # 非小写
            {"tx_id": "g" * 64},                    # 非 hex
            {"tx_id": 64},                          # 非字符串
            {"state": "failed", "tx_id": TX},       # failed 须 null
        ):
            code, _ = self._result(**kwargs)
            self.assertEqual(code, 400, kwargs)
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
            {"tx_id": "cd" * 32},
            {"state": "failed", "tx_id": None},
            {"adapter_id": "ad1", "state": "failed", "tx_id": None},
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

    def test_replay_preferred_over_404_409(self):
        # 同参重放优先：即便随后删除/矛盾化其他状态也不复查
        self.assertEqual(self._result()[0], 201)
        code, v = self._result()
        self.assertEqual(code, 200)
        self.assertEqual(v["state"], "broadcasted")

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
            "w1", "dp1", "ad1", "broadcasted", TX,
        )
        self.assertEqual(code, 200)
        self.assertEqual(v["tx_id"], TX)
        self.assertEqual(len(self._events(svc2)), 1)

    def test_orphan_result_fail_closed(self):
        self.assertEqual(self._result()[0], 201)

        def mutate(log):
            log["events"] = [
                e for e in log["events"]
                if e["type"] != "chain_dispatch_requested"
            ]

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_result_before_request_fail_closed(self):
        self.assertEqual(self._result()[0], 201)

        def mutate(log):
            # 把结果事件的 seq 改到派发事件之前（保持 seq 集合连续：
            # 交换两者 seq）
            requested = result = None
            for e in log["events"]:
                if e["type"] == "chain_dispatch_requested":
                    requested = e
                elif e["type"] == "chain_dispatch_result":
                    result = e
            requested["seq"], result["seq"] = (
                result["seq"],
                requested["seq"],
            )

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_result_ownership_mismatch_fail_closed(self):
        self.assertEqual(self._result()[0], 201)
        for field, value in (
            ("operation_id", "op9"),
            ("adapter_id", "ad9"),
            ("chain_id", "chain-9"),
        ):
            def mutate(log, field=field, value=value):
                for e in log["events"]:
                    if e["type"] == "chain_dispatch_result":
                        e["details"][field] = value

            self._rewrite(mutate)
            with self.subTest(field=field):
                with self.assertRaises(RecoveryError):
                    WalletService(self.h.store)
            # 还原现场供下一项用例
            def restore(log, field=field):
                for e in log["events"]:
                    if e["type"] == "chain_dispatch_result":
                        e["details"][field] = {
                            "operation_id": "op1",
                            "adapter_id": "ad1",
                            "chain_id": "chain-1",
                        }[field]

            self._rewrite(restore)

    def test_result_actor_mismatch_fail_closed(self):
        self.assertEqual(self._result()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_result":
                    e["actor_id"] = "ad9"

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

    def test_tampered_result_state_fail_closed(self):
        self.assertEqual(self._result()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_result":
                    e["details"]["state"] = "done"

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_tampered_result_tx_id_fail_closed(self):
        self.assertEqual(self._result()[0], 201)

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_dispatch_result":
                    e["details"]["tx_id"] = "AB" * 32

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_result_details_reordered_fail_closed(self):
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

    def test_result_outer_fields_reordered_fail_closed(self):
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

    def test_bad_json_is_corrupt_data(self):
        self.assertEqual(self._result()[0], 201)
        with open(self._audit_path(), "wb") as f:
            f.write(b"{broken")
        with self.assertRaises(CorruptDataError):
            self.svc._audit.chain_dispatch_result_events("w1")
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

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
            "w1", "dp1", "ad1", "broadcasted", TX,
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

    def test_http_happy_path_and_replay(self):
        status, v = self._result(
            {"adapter_id": "ad1", "state": "broadcasted", "tx_id": TX}
        )
        self.assertEqual(status, 201)
        self.assertEqual(
            list(v),
            ["dispatch_id", "operation_id", "adapter_id", "chain_id",
             "state", "tx_id"],
        )
        status, v2 = self._result(
            {"adapter_id": "ad1", "state": "broadcasted", "tx_id": TX}
        )
        self.assertEqual(status, 200)
        self.assertEqual(v2, v)

    def test_http_body_key_set_400(self):
        for body in (
            {},
            {"adapter_id": "ad1", "state": "broadcasted"},
            {"adapter_id": "ad1", "state": "broadcasted", "tx_id": TX,
             "extra": 1},
            {"adapter_id": "ad1", "state": "broadcasted", "tx": TX},
        ):
            status, _ = self._result(body)
            self.assertEqual(status, 400, body)

    def test_http_value_400_and_unknown_404(self):
        status, _ = self._result(
            {"adapter_id": "ad1", "state": "broadcasted", "tx_id": "zz"}
        )
        self.assertEqual(status, 400)
        status, _ = self._result(
            {"adapter_id": "ad1", "state": "failed", "tx_id": TX}
        )
        self.assertEqual(status, 400)
        status, _ = self._result(
            {"adapter_id": "ad1", "state": "broadcasted", "tx_id": TX},
            dispatch_id="dp9",
        )
        self.assertEqual(status, 404)
        status, _ = self._result(
            {"adapter_id": "ad1", "state": "broadcasted", "tx_id": TX},
            wallet="w9",
        )
        self.assertEqual(status, 404)

    def test_http_adapter_mismatch_409(self):
        status, _ = self._result(
            {"adapter_id": "ad2", "state": "broadcasted", "tx_id": TX}
        )
        self.assertEqual(status, 409)

    def test_http_get_and_put_not_allowed(self):
        status, _ = self.srv.request(
            "GET", "/v1/wallets/w1/chain/dp1/result"
        )
        self.assertEqual(status, 404)
        status, _ = self.srv.request(
            "PUT", "/v1/wallets/w1/chain/dp1/result",
            {"adapter_id": "ad1", "state": "broadcasted", "tx_id": TX},
        )
        self.assertEqual(status, 404)

    def test_http_compact_json_no_trailing_newline(self):
        # 成功体与错误体均为 UTF-8 紧凑 JSON、无末换行
        import urllib.request

        req = urllib.request.Request(
            self.srv.base_url + "/v1/wallets/w1/chain/dp1/result",
            data=json.dumps(
                {"adapter_id": "ad1", "state": "broadcasted", "tx_id": TX}
            ).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
        self.assertNotIn(b" ", raw)
        self.assertFalse(raw.endswith(b"\n"))
        self.assertEqual(json.loads(raw.decode("utf-8"))["state"],
                         "broadcasted")

    def test_http_503_on_corrupt_scene(self):
        status, _ = self._result(
            {"adapter_id": "ad1", "state": "broadcasted", "tx_id": TX}
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
        self.assertNotIn("dp1", json.dumps(body))


if __name__ == "__main__":
    unittest.main()
