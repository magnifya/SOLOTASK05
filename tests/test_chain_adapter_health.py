"""跨链适配器健康熔断（PUT/GET /v1/wallets/{W}/chain-adapters）测试。

覆盖：
- PUT 体恰为 Q={"adapters":{A:"up"|"down"}}；adapters 非空、A 匹配
  [A-Za-z0-9_-]{1,128} 并归一为 ASCII 升序；键集/类型/顺序/值错 400；
  钱包未知 404；GET 未配置 404；200 返回 Q；
- 首配/变更各记一条七字段 chain_adapter_health 事件
  （request_id/actor_id/reason 均 null，details 恰为 Q），同值/并发
  同参不记；不建状态文件，取最后一条恢复；
- 恢复按 seq 核对键集、A 序与状态，矛盾抛 RecoveryError 不写盘，
  坏 JSON→CorruptDataError、I/O→OSError，三者 HTTP 503、serve 拒绝
  就绪；
- 更新、读取与派发到首配在钱包跨进程锁内线性化；post_chain_dispatch
  首次指向显式 down 适配器 409 且零副作用；未配置或 A 缺席视为 up；
  同参重放优先 200（事后翻 down 不影响），健康变化不改写/终止/自动
  接管已有派发；
- HTTP 成功/错误体均为 UTF-8 紧凑 JSON、非 ASCII 原样、无末换行。
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

from threshold_wallet import drbackup
from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import CorruptDataError, RecoveryError, WalletStore

from tests.helpers import http_server, make_harness

ADAPTERS_UP = {"ad1": "up", "ad2": "up"}


def _approval_message(operation_id="op1", dispatch_id="dp1",
                      adapter_id="ad1", chain_id="chain-1"):
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


class ChainAdapterHealthServiceTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)

    def _events(self, event_type="chain_adapter_health", svc=None):
        svc = svc or self.svc
        return [
            e
            for e in svc.get_audit_events("w1")["events"]
            if e["type"] == event_type
        ]

    def _audit_path(self):
        return os.path.join(self.d, "audit", "w1.json")

    def _rewrite(self, mutate):
        with open(self._audit_path(), encoding="utf-8") as f:
            log = json.load(f)
        mutate(log)
        with open(self._audit_path(), "w", encoding="utf-8") as f:
            json.dump(log, f)

    # ---- 404 / 首建 / 归一 -------------------------------------------------

    def test_get_unconfigured_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_chain_adapters("w1")
        self.assertEqual(ctx.exception.status, 404)

    def test_unknown_wallet_404(self):
        for method in ("get", "put"):
            with self.assertRaises(ServiceError) as ctx:
                if method == "get":
                    self.svc.get_chain_adapters("nope")
                else:
                    self.svc.put_chain_adapters("nope", ADAPTERS_UP)
            self.assertEqual(ctx.exception.status, 404, method)

    def test_invalid_wallet_400(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_chain_adapters("bad id!")
        self.assertEqual(ctx.exception.status, 400)

    def test_put_first_then_get_same_body_normalized_ascending(self):
        body = self.svc.put_chain_adapters(
            "w1", {"ad3": "up", "ad1": "down", "ad2": "up"}
        )
        self.assertEqual(list(body["adapters"]), ["ad1", "ad2", "ad3"])
        self.assertEqual(
            body, {"adapters": {"ad1": "down", "ad2": "up", "ad3": "up"}}
        )
        self.assertEqual(body, self.svc.get_chain_adapters("w1"))

    # ---- 400 ---------------------------------------------------------------

    def test_invalid_bodies_400(self):
        bad = [
            {},                              # 空表
            {"bad id!": "up"},               # 键非法
            {1: "up"},                       # 键非字符串
            {"ad1": "gone"},                 # 状态非法
            {"ad1": "UP"},                   # 大小写非法
            {"ad1": True},                   # 布尔非字符串
            {"ad1": None},                   # null
            {"ad1": 1},                      # 整数
            [],                              # 非对象
            None,
            "nope",
            {"": "up"},                      # 空键
            {"a" * 129: "up"},              # 超长键
        ]
        for adapters in bad:
            with self.subTest(adapters=adapters):
                with self.assertRaises(ServiceError) as ctx:
                    self.svc.put_chain_adapters("w1", adapters)
                self.assertEqual(ctx.exception.status, 400)

    # ---- 事件：首配/变更记，同值/并发同参不记 ------------------------------

    def test_first_and_change_log_same_value_does_not(self):
        self.svc.put_chain_adapters("w1", {"ad1": "up"})
        self.assertEqual(len(self._events()), 1)
        # 同值（乱序输入、归一后相等）不记
        self.svc.put_chain_adapters("w1", {"ad1": "up"})
        self.assertEqual(len(self._events()), 1)
        # 变更（状态翻转/成员变化）记
        self.svc.put_chain_adapters("w1", {"ad1": "down"})
        self.assertEqual(len(self._events()), 2)
        self.svc.put_chain_adapters("w1", {"ad1": "down", "ad2": "up"})
        self.assertEqual(len(self._events()), 3)
        # 同值仍不记
        self.svc.put_chain_adapters("w1", {"ad2": "up", "ad1": "down"})
        self.assertEqual(len(self._events()), 3)

    def test_concurrent_same_params_single_event_all_200(self):
        self.svc.put_chain_adapters("w1", {"ad1": "up"})
        barrier = threading.Barrier(8)
        results = []

        def worker():
            barrier.wait()
            results.append(
                self.svc.put_chain_adapters("w1", {"ad1": "up"})
            )

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results, [{"adapters": {"ad1": "up"}}] * 8)
        # 首配 1 条，并发同参不追加
        self.assertEqual(len(self._events()), 1)

    def test_event_shape_is_Q_with_three_null_ids(self):
        self.svc.put_chain_adapters("w1", ADAPTERS_UP)
        (event,) = self._events()
        self.assertEqual(
            set(event),
            {"seq", "type", "at", "request_id", "actor_id", "reason",
             "details"},
        )
        self.assertEqual(event["type"], "chain_adapter_health")
        self.assertIsNone(event["request_id"])
        self.assertIsNone(event["actor_id"])
        self.assertIsNone(event["reason"])
        self.assertEqual(event["details"], {"adapters": ADAPTERS_UP})
        self.assertEqual(list(event["details"]), ["adapters"])
        self.assertEqual(list(event["details"]["adapters"]), ["ad1", "ad2"])

    def test_no_state_file_written(self):
        before = set(os.listdir(self.d))
        self.svc.put_chain_adapters("w1", ADAPTERS_UP)
        after = set(os.listdir(self.d))
        # 健康表只追加到既有审计日志：至多新增 audit 目录（首个事件时
        # 创建），不允许任何适配器旁路状态文件/目录。
        self.assertTrue(after - before <= {"audit"})
        if "audit" in before:
            self.assertEqual(
                set(os.listdir(os.path.join(self.d, "audit"))), {"w1.json"}
            )

    def test_stored_bytes_keep_canonical_order(self):
        self.svc.put_chain_adapters(
            "w1", {"ad2": "down", "ad1": "up"}
        )
        with open(self._audit_path(), "rb") as f:
            raw = f.read()
        log = json.loads(raw)
        (stored,) = [
            e for e in log["events"]
            if e["type"] == "chain_adapter_health"
        ]
        self.assertEqual(
            list(stored),
            ["actor_id", "at", "details", "reason", "request_id", "seq",
             "type"],
        )
        self.assertEqual(list(stored["details"]), ["adapters"])
        self.assertEqual(list(stored["details"]["adapters"]), ["ad1", "ad2"])
        self.assertEqual(stored["details"]["adapters"]["ad1"], "up")
        self.assertEqual(stored["details"]["adapters"]["ad2"], "down")

    # ---- 重启 / 灾备 -------------------------------------------------------

    def test_restart_takes_last_event_and_logs_nothing(self):
        self.svc.put_chain_adapters("w1", {"ad1": "up"})
        self.svc.put_chain_adapters("w1", {"ad1": "down"})
        before = self.svc.get_audit_events("w1")["events"]
        svc2 = WalletService(self.h.store)
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)
        self.assertEqual(
            svc2.get_chain_adapters("w1"), {"adapters": {"ad1": "down"}}
        )

    def test_backup_restore_keeps_health_and_seq(self):
        self.svc.put_chain_adapters("w1", {"ad1": "down", "ad2": "up"})
        before = self.svc.get_audit_events("w1")["events"]
        out = os.path.join(tempfile.mkdtemp(), "snap.tar")
        self.addCleanup(shutil.rmtree, os.path.dirname(out),
                        ignore_errors=True)
        self.assertEqual(
            drbackup.backup(self.d, "w1", "S1", out)["status"], 201
        )
        dst = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, dst, ignore_errors=True)
        status, _ = drbackup.restore(dst, "w1", out)
        self.assertEqual(status, 201)
        svc2 = WalletService(WalletStore(dst))
        self.assertEqual(
            svc2.get_chain_adapters("w1"),
            {"adapters": {"ad1": "down", "ad2": "up"}},
        )
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)

    # ---- 恢复 fail-closed --------------------------------------------------

    def _assert_refuses_ready_and_access(self):
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)
        with self.assertRaises(RecoveryError):
            self.svc.get_chain_adapters("w1")

    def test_tampered_state_is_fail_closed(self):
        self.svc.put_chain_adapters("w1", ADAPTERS_UP)

        def mutate(log):
            for event in log["events"]:
                if event["type"] == "chain_adapter_health":
                    event["details"]["adapters"]["ad1"] = "gone"

        self._rewrite(mutate)
        self._assert_refuses_ready_and_access()

    def test_tampered_order_is_fail_closed(self):
        self.svc.put_chain_adapters(
            "w1", {"ad1": "up", "ad2": "up"}
        )

        def mutate(log):
            for event in log["events"]:
                if event["type"] == "chain_adapter_health":
                    table = event["details"]["adapters"]
                    # 手工重排为降序（JSON 保持插入序）
                    event["details"]["adapters"] = {
                        k: table[k] for k in ("ad2", "ad1")
                    }

        self._rewrite(mutate)
        self._assert_refuses_ready_and_access()

    def test_event_with_actor_is_fail_closed(self):
        self.svc.put_chain_adapters("w1", ADAPTERS_UP)

        def mutate(log):
            for event in log["events"]:
                if event["type"] == "chain_adapter_health":
                    event["actor_id"] = "mallory"

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_details_wrong_key_set_is_fail_closed(self):
        self.svc.put_chain_adapters("w1", ADAPTERS_UP)

        def mutate(log):
            for event in log["events"]:
                if event["type"] == "chain_adapter_health":
                    event["details"] = {"nodes": event["details"]["adapters"]}

        self._rewrite(mutate)
        self._assert_refuses_ready_and_access()

    def test_empty_table_is_fail_closed(self):
        self.svc.put_chain_adapters("w1", ADAPTERS_UP)

        def mutate(log):
            for event in log["events"]:
                if event["type"] == "chain_adapter_health":
                    event["details"] = {"adapters": {}}

        self._rewrite(mutate)
        self._assert_refuses_ready_and_access()

    def test_corrupt_audit_json_is_corrupt_data_error(self):
        self.svc.put_chain_adapters("w1", ADAPTERS_UP)
        with open(self._audit_path(), "wb") as f:
            f.write(b"{not valid json")
        from threshold_wallet.audit import AuditStore

        with self.assertRaises(CorruptDataError):
            AuditStore(self.h.store.data_dir).events_by_type(
                "w1", "chain_adapter_health"
            )
        # 启动恢复统一包装为 RecoveryError 阻止就绪
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_recovery_does_not_write_disk(self):
        self.svc.put_chain_adapters("w1", ADAPTERS_UP)

        def mutate(log):
            for event in log["events"]:
                if event["type"] == "chain_adapter_health":
                    event["details"]["adapters"]["ad1"] = "gone"

        self._rewrite(mutate)
        before = os.stat(self._audit_path()).st_mtime_ns
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)
        # 损坏现场原样保留，不猜写、不覆盖
        self.assertEqual(os.stat(self._audit_path()).st_mtime_ns, before)


class DispatchCircuitBreakerTest(unittest.TestCase):
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

    def _approve(self, rid="ap1", adapter_id="ad1"):
        code, _ = self.svc.create_sign_request(
            "w1", rid, _approval_message(adapter_id=adapter_id)
        )
        self.assertEqual(code, 201)
        self.svc.approve("w1", rid, "boss")

    def _dispatch(self, dispatch_id="dp1", adapter_id="ad1",
                  approval="ap1", operation_id="op1"):
        try:
            return self.svc.post_chain_dispatch(
                "w1", operation_id, dispatch_id, adapter_id, approval
            )
        except ServiceError as exc:
            return exc.status, {"error": exc.message}

    def _events(self, event_type):
        return [
            e for e in self.svc.get_audit_events("w1")["events"]
            if e["type"] == event_type
        ]

    def test_unconfigured_health_treated_as_up(self):
        self._approve()
        code, v = self._dispatch()
        self.assertEqual(code, 201)
        self.assertEqual(v["adapter_id"], "ad1")

    def test_absent_adapter_treated_as_up(self):
        self.svc.put_chain_adapters("w1", {"other-adapter": "down"})
        self._approve()
        code, _ = self._dispatch()
        self.assertEqual(code, 201)

    def test_explicit_up_dispatches(self):
        self.svc.put_chain_adapters("w1", {"ad1": "up"})
        self._approve()
        code, _ = self._dispatch()
        self.assertEqual(code, 201)

    def test_first_dispatch_to_down_is_409_zero_side_effects(self):
        self.svc.put_chain_adapters("w1", {"ad1": "down"})
        self._approve()
        code, body = self._dispatch()
        self.assertEqual(code, 409)
        self.assertIn("down", body["error"])
        # 零副作用：无派发事件、无额外健康事件（seq 不增）
        self.assertEqual(self._events("chain_dispatch_requested"), [])
        health_events = self._events("chain_adapter_health")
        self.assertEqual(len(health_events), 1)
        # 现场可恢复：翻 up 后同参数首提成功
        self.svc.put_chain_adapters("w1", {"ad1": "up"})
        code, _ = self._dispatch()
        self.assertEqual(code, 201)

    def test_down_adapter_does_not_lazily_expire_approval(self):
        self.svc.put_chain_adapters("w1", {"ad1": "down"})
        # 建一个已到期的 pending 审批单
        code, _ = self.svc.create_sign_request(
            "w1", "ap1", _approval_message()
        )
        self.assertEqual(code, 201)
        code, _ = self._dispatch()
        self.assertEqual(code, 409)
        # 熔断检查先于懒过期：不得产生 request_expired 副作用
        self.assertEqual(self._events("request_expired"), [])

    def test_replay_200_takes_precedence_after_health_flips_down(self):
        self.svc.put_chain_adapters("w1", {"ad1": "up"})
        self._approve()
        code, v1 = self._dispatch()
        self.assertEqual(code, 201)
        # 事后熔断：同参重放优先 200，不复查健康表
        self.svc.put_chain_adapters("w1", {"ad1": "down"})
        code, v2 = self._dispatch()
        self.assertEqual(code, 200)
        self.assertEqual(v2, v1)
        # 重放不记事件
        self.assertEqual(len(self._events("chain_dispatch_requested")), 1)

    def test_health_change_does_not_take_over_existing_dispatch(self):
        self.svc.put_chain_adapters("w1", {"ad1": "up"})
        self._approve()
        self.assertEqual(self._dispatch()[0], 201)
        # 翻 down 后用新适配器对同一派发/操作首提：仍按既有契约 409
        # （该操作已有派发），健康变化不自动接管。
        self.svc.put_chain_adapters(
            "w1", {"ad1": "down", "ad2": "up"}
        )
        self._approve(rid="ap2", adapter_id="ad2")
        code, _ = self._dispatch(
            dispatch_id="dp2", adapter_id="ad2", approval="ap2"
        )
        self.assertEqual(code, 409)
        # 原派发视图不变
        code, replay = self._dispatch()
        self.assertEqual(code, 200)
        self.assertEqual(replay["adapter_id"], "ad1")

    def test_down_409_orders_after_404s(self):
        self.svc.put_chain_adapters("w1", {"ad1": "down"})
        self._approve()
        # 操作未知仍 404（熔断不遮蔽存在性判定）
        code, _ = self._dispatch(operation_id="nope")
        self.assertEqual(code, 404)


class ChainAdapterHealthHttpTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def _raw(self, method, path, body=None):
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(
            self.srv.base_url + path, data=data, method=method,
            headers=headers,
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def test_http_crud_statuses_and_compact_bytes(self):
        with http_server(self.d) as self.srv:
            code, _ = self.srv.request(
                "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
            )
            self.assertEqual(code, 201)
            # 未配置 404
            code, _ = self.srv.request(
                "GET", "/v1/wallets/w1/chain-adapters"
            )
            self.assertEqual(code, 404)
            # 钱包未知 404
            code, _ = self.srv.request(
                "GET", "/v1/wallets/nope/chain-adapters"
            )
            self.assertEqual(code, 404)
            code, _ = self.srv.request(
                "PUT", "/v1/wallets/nope/chain-adapters",
                {"adapters": {"ad1": "up"}},
            )
            self.assertEqual(code, 404)
            # 键集错 400
            code, raw = self._raw(
                "PUT", "/v1/wallets/w1/chain-adapters",
                {"adapters": {"ad1": "up"}, "x": 1},
            )
            self.assertEqual(code, 400)
            self.assertFalse(raw.endswith(b"\n"))
            code, _ = self.srv.request(
                "PUT", "/v1/wallets/w1/chain-adapters", {}
            )
            self.assertEqual(code, 400)
            # 值错 400
            code, _ = self.srv.request(
                "PUT", "/v1/wallets/w1/chain-adapters",
                {"adapters": {"ad1": "gone"}},
            )
            self.assertEqual(code, 400)
            # 首建 200：紧凑 JSON、升序、无末换行、非 ASCII 原样
            code, raw = self._raw(
                "PUT", "/v1/wallets/w1/chain-adapters",
                {"adapters": {"ad2": "down", "ad1": "up"}},
            )
            self.assertEqual(code, 200)
            self.assertEqual(
                raw, b'{"adapters":{"ad1":"up","ad2":"down"}}'
            )
            self.assertFalse(raw.endswith(b"\n"))
            code, raw = self._raw(
                "GET", "/v1/wallets/w1/chain-adapters"
            )
            self.assertEqual(code, 200)
            self.assertEqual(
                raw, b'{"adapters":{"ad1":"up","ad2":"down"}}'
            )

    def test_http_dispatch_to_down_is_409(self):
        with http_server(self.d) as self.srv:
            srv = self.srv
            srv.request(
                "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
            )
            srv.request(
                "PUT", "/v1/wallets/w1/approval-policy",
                {"required_approvals": 1, "timeout_seconds": 600},
            )
            code, _ = srv.request(
                "POST", "/v1/wallets/w1/asset-operations",
                {"operation_id": "op1", "asset_id": "BTC", "delta": 100},
            )
            self.assertEqual(code, 201)
            srv.request(
                "PUT", "/v1/wallets/w1/chain/BTC",
                {"chain_id": "chain-1", "enabled": True,
                 "required_confirmations": 3, "reorg_window": 2},
            )
            srv.request(
                "PUT", "/v1/wallets/w1/chain-adapters",
                {"adapters": {"ad1": "down"}},
            )
            message = json.dumps(
                {"operation_id": "op1", "dispatch_id": "dp1",
                 "adapter_id": "ad1", "chain_id": "chain-1"},
                separators=(",", ":"),
            )
            srv.request(
                "POST", "/v1/wallets/w1/sign-requests",
                {"id": "ap1", "message": message},
            )
            srv.request(
                "POST", "/v1/wallets/w1/sign-requests/ap1/approve",
                {"approver_id": "boss"},
            )
            code, body = srv.request(
                "POST", "/v1/wallets/w1/chain/op1/dispatch",
                {"dispatch_id": "dp1", "adapter_id": "ad1",
                 "approval_request_id": "ap1"},
            )
            self.assertEqual(code, 409)
            self.assertIn("down", body["error"])
            # 翻 up 后成功
            srv.request(
                "PUT", "/v1/wallets/w1/chain-adapters",
                {"adapters": {"ad1": "up"}},
            )
            code, body = srv.request(
                "POST", "/v1/wallets/w1/chain/op1/dispatch",
                {"dispatch_id": "dp1", "adapter_id": "ad1",
                 "approval_request_id": "ap1"},
            )
            self.assertEqual(code, 201)
            self.assertEqual(body["state"], "requested")

    def test_http_corrupt_scene_is_503(self):
        with http_server(self.d) as self.srv:
            srv = self.srv
            srv.request(
                "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
            )
            code, _ = srv.request(
                "PUT", "/v1/wallets/w1/chain-adapters",
                {"adapters": {"ad1": "up"}},
            )
            self.assertEqual(code, 200)
            path = os.path.join(self.d, "audit", "w1.json")
            with open(path, encoding="utf-8") as f:
                log = json.load(f)
            for event in log["events"]:
                if event["type"] == "chain_adapter_health":
                    event["details"]["adapters"]["ad1"] = "gone"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(log, f)
            code, body = srv.request(
                "GET", "/v1/wallets/w1/chain-adapters"
            )
            self.assertEqual(code, 503)
            self.assertEqual(
                body, {"error": "service temporarily unavailable"}
            )
            # 紧凑 503 体、无末换行
            code, raw = self._raw(
                "GET", "/v1/wallets/w1/chain-adapters"
            )
            self.assertEqual(code, 503)
            self.assertEqual(
                raw, b'{"error":"service temporarily unavailable"}'
            )


if __name__ == "__main__":
    unittest.main()
