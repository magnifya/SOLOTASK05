"""跨链适配器健康熔断（PUT/GET /v1/wallets/{W}/chain-adapters）测试。

覆盖：
- PUT 体恰为 Q={"adapters":{A:"up"|"down"}}；adapters 非空、A 匹配
  [A-Za-z0-9_-]{1,128} 并归一为 ASCII 升序；键集/类型/顺序/值错 400；
  钱包未知 404；GET 未配置 404；200 返回 Q；
- 首配/变更各记一条七字段 chain_adapter_health 事件（request_id/
  actor_id/reason 均 null、details 恰为 Q），同值/并发同参不记；
- 恢复按 seq 核对键集、A 的 ASCII 序与状态：外层/details 错序、取值矛盾
  抛 RecoveryError 且不写盘；坏 JSON 为 CorruptDataError（启动包装为
  RecoveryError 拒绝就绪），三者 HTTP 503、留现场；重启/灾备后表与 seq
  不变；
- 派发熔断：post_chain_dispatch 首提指向显式 down 适配器 409 零副作用；
  未配置或 A 缺席视为 up；同参重放优先 200；健康变化不改写/终止/接管
  已有派发，其余派发契约不变；
- HTTP 成功体与错误体均为 UTF-8 紧凑 JSON（非 ASCII 原样、无末换行）。
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


def _dispatch_msg(operation_id="op1", dispatch_id="dp1", adapter_id="ad1",
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


class ChainAdaptersServiceTest(unittest.TestCase):
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
        path = self._audit_path()
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        mutate(log)
        with open(path, "w", encoding="utf-8") as f:
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
                    self.svc.put_chain_adapters(
                        "nope", {"ad1": "up"}
                    )
            self.assertEqual(ctx.exception.status, 404, method)

    def test_invalid_wallet_400(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_chain_adapters("bad id!")
        self.assertEqual(ctx.exception.status, 400)

    def test_put_first_then_get_same_body_sorted(self):
        # 请求体已按 ASCII 升序（数字 < 大写 < 小写）：200 原样返回
        body = self.svc.put_chain_adapters(
            "w1", {"Ad0": "up", "ad1": "up", "ad2": "down"}
        )
        self.assertEqual(list(body["adapters"]), ["Ad0", "ad1", "ad2"])
        self.assertEqual(
            body,
            {"adapters": {"Ad0": "up", "ad1": "up", "ad2": "down"}},
        )
        self.assertEqual(self.svc.get_chain_adapters("w1"), body)

    def test_unsorted_body_is_400(self):
        for adapters in (
            {"ad2": "up", "ad1": "up"},
            {"ad1": "up", "Ad0": "up", "ad2": "up"},
        ):
            with self.subTest(adapters=adapters):
                with self.assertRaises(ServiceError) as ctx:
                    self.svc.put_chain_adapters("w1", adapters)
                self.assertEqual(ctx.exception.status, 400)
        self.assertEqual(self._events(), [])

    # ---- 400 ---------------------------------------------------------------

    def test_invalid_bodies_400(self):
        bad = [
            {},                 # 空表
            [],                 # 非对象
            None,               # 非对象
            "up",               # 非对象
            {"bad id!": "up"},  # 键非法
            {"": "up"},         # 空键
            {1: "up"},          # 键非字符串
            {"ad1": "UP"},      # 大小写错
            {"ad1": "ban"},     # 非 up|down
            {"ad1": "gone"},
            {"ad1": True},      # 布尔非字符串
            {"ad1": 1},
            {"ad1": None},
        ]
        for adapters in bad:
            with self.subTest(adapters=adapters):
                with self.assertRaises(ServiceError) as ctx:
                    self.svc.put_chain_adapters("w1", adapters)
                self.assertEqual(ctx.exception.status, 400)
        # 任何 400 都不记事件
        self.assertEqual(self._events(), [])

    # ---- 事件：首配/变更记、同值不记 --------------------------------------

    def test_first_config_logs_one_event(self):
        body = self.svc.put_chain_adapters("w1", {"ad1": "up"})
        self.assertEqual(body, {"adapters": {"ad1": "up"}})
        (event,) = self._events()
        self.assertEqual(event["type"], "chain_adapter_health")
        self.assertIsNone(event["request_id"])
        self.assertIsNone(event["actor_id"])
        self.assertIsNone(event["reason"])
        self.assertEqual(event["details"], {"adapters": {"ad1": "up"}})
        self.assertEqual(list(event["details"]), ["adapters"])
        # 落盘外层规范序、details 键序、适配器升序
        with open(self._audit_path(), encoding="utf-8") as f:
            log = json.load(f)
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
        self.assertEqual(list(stored["details"]["adapters"]), ["ad1"])

    def test_same_value_does_not_log(self):
        self.svc.put_chain_adapters(
            "w1", {"ad1": "up", "ad2": "down"}
        )
        self.assertEqual(len(self._events()), 1)
        # 同值（重复提交）不记
        self.svc.put_chain_adapters(
            "w1", {"ad1": "up", "ad2": "down"}
        )
        self.assertEqual(len(self._events()), 1)
        # 状态翻转 / 成员增删都记
        self.svc.put_chain_adapters(
            "w1", {"ad1": "down", "ad2": "down"}
        )
        self.assertEqual(len(self._events()), 2)
        self.svc.put_chain_adapters(
            "w1", {"ad1": "down"}
        )
        self.assertEqual(len(self._events()), 3)
        self.svc.put_chain_adapters(
            "w1", {"ad1": "down", "ad3": "up"}
        )
        self.assertEqual(len(self._events()), 4)
        # 再同值不记
        self.svc.put_chain_adapters(
            "w1", {"ad1": "down", "ad3": "up"}
        )
        self.assertEqual(len(self._events()), 4)

    def test_concurrent_same_params_logs_once(self):
        self.svc.put_chain_adapters("w1", {"ad1": "up"})
        errors = []
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            try:
                self.svc.put_chain_adapters("w1", {"ad1": "up"})
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(self._events()), 1)

    def test_concurrent_first_config_single_event(self):
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            self.svc.put_chain_adapters("w1", {"ad1": "down"})

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # 锁内串行：首个首配落事件，其余读到同一当前表、同值不记
        self.assertEqual(len(self._events()), 1)
        self.assertEqual(
            self.svc.get_chain_adapters("w1"),
            {"adapters": {"ad1": "down"}},
        )

    def test_get_returns_last_snapshot(self):
        self.svc.put_chain_adapters("w1", {"ad1": "up"})
        self.svc.put_chain_adapters("w1", {"ad1": "down"})
        self.svc.put_chain_adapters("w1", {"ad1": "up"})  # 变更记
        self.assertEqual(
            self.svc.get_chain_adapters("w1"),
            {"adapters": {"ad1": "up"}},
        )
        self.assertEqual(len(self._events()), 3)

    # ---- 重启 / 灾备 -------------------------------------------------------

    def test_restart_keeps_table_and_seq(self):
        self.svc.put_chain_adapters(
            "w1", {"ad1": "up", "ad2": "down"}
        )
        before = self.svc.get_audit_events("w1")["events"]
        svc2 = WalletService(self.h.store)
        self.assertEqual(
            svc2.get_chain_adapters("w1"),
            {"adapters": {"ad1": "up", "ad2": "down"}},
        )
        # 恢复不新增事件、seq 连续
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)

    def test_backup_restore_keeps_table_and_seq(self):
        self.svc.put_chain_adapters(
            "w1", {"ad1": "up", "ad2": "down"}
        )
        before = self.svc.get_audit_events("w1")["events"]
        out = os.path.join(tempfile.mkdtemp(), "snap.tar")
        self.addCleanup(
            shutil.rmtree, os.path.dirname(out), ignore_errors=True
        )
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
            {"adapters": {"ad1": "up", "ad2": "down"}},
        )
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)

    # ---- 损坏/矛盾 fail-closed --------------------------------------------

    def test_tampered_state_is_fail_closed(self):
        self.svc.put_chain_adapters("w1", {"ad1": "up"})

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_adapter_health":
                    e["details"]["adapters"]["ad1"] = "gone"

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)
        with self.assertRaises(RecoveryError):
            self.svc.get_chain_adapters("w1")
        # 现场保留，不被写盘归一
        with open(self._audit_path(), encoding="utf-8") as f:
            log = json.load(f)
        self.assertEqual(
            next(
                e for e in log["events"]
                if e["type"] == "chain_adapter_health"
            )["details"]["adapters"]["ad1"],
            "gone",
        )

    def test_adapters_not_sorted_is_fail_closed(self):
        self.svc.put_chain_adapters(
            "w1", {"ad1": "up", "ad2": "down"}
        )

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_adapter_health":
                    d = e["details"]["adapters"]
                    e["details"]["adapters"] = {
                        "ad2": d["ad2"], "ad1": d["ad1"],
                    }

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_empty_adapters_is_fail_closed(self):
        self.svc.put_chain_adapters("w1", {"ad1": "up"})

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_adapter_health":
                    e["details"] = {"adapters": {}}

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_details_wrong_key_is_fail_closed(self):
        self.svc.put_chain_adapters("w1", {"ad1": "up"})

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_adapter_health":
                    e["details"] = {"nodes": {"ad1": "up"}}

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_outer_fields_reordered_is_fail_closed(self):
        self.svc.put_chain_adapters("w1", {"ad1": "up"})

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_adapter_health":
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

    def test_event_with_actor_is_fail_closed(self):
        self.svc.put_chain_adapters("w1", {"ad1": "up"})

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "chain_adapter_health":
                    e["actor_id"] = "mallory"

        self._rewrite(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_bad_json_is_corrupt_data_and_blocks_startup(self):
        self.svc.put_chain_adapters("w1", {"ad1": "up"})
        with open(self._audit_path(), "wb") as f:
            f.write(b"{broken")
        with self.assertRaises(CorruptDataError):
            self.svc._audit.events_by_type(
                "w1", "chain_adapter_health"
            )
        # 启动恢复保持 CorruptDataError 原类型（同样拒绝就绪、现场保留）
        with self.assertRaises(CorruptDataError):
            WalletService(self.h.store)

    def test_io_error_on_put_is_503_boundary(self):
        self.svc.put_chain_adapters("w1", {"ad1": "up"})

        def boom(*_a, **_k):
            raise OSError("audit disk unavailable")

        self.svc._audit.append_event = boom
        with self.assertRaises(OSError):
            # service 层 OSError 原样向上（HTTP 边界统一映射为 503）
            self.svc.put_chain_adapters("w1", {"ad1": "down"})
        # 落盘失败：现场仍是旧表
        self.assertEqual(
            self.svc.get_chain_adapters("w1"),
            {"adapters": {"ad1": "up"}},
        )


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

    def _approve(self, rid="ap1", message=None):
        msg = message if message is not None else _dispatch_msg()
        code, _ = self.svc.create_sign_request("w1", rid, msg)
        self.assertEqual(code, 201)
        self.svc.approve("w1", rid, "boss")

    def _dispatch(self, **kwargs):
        params = dict(
            wallet="w1", operation_id="op1", dispatch_id="dp1",
            adapter_id="ad1", approval="ap1",
        )
        params.update(kwargs)
        return _call(
            self.svc.post_chain_dispatch,
            params["wallet"],
            params["operation_id"],
            params["dispatch_id"],
            params["adapter_id"],
            params["approval"],
        )

    def _health_events(self):
        return [
            e for e in self.svc.get_audit_events("w1")["events"]
            if e["type"] == "chain_adapter_health"
        ]

    def _dispatch_events(self):
        return [
            e for e in self.svc.get_audit_events("w1")["events"]
            if e["type"] == "chain_dispatch_requested"
        ]

    def test_no_table_means_up(self):
        self._approve()
        self.assertEqual(self._dispatch()[0], 201)

    def test_absent_adapter_means_up(self):
        self.svc.put_chain_adapters("w1", {"ad-other": "down"})
        self._approve()
        self.assertEqual(self._dispatch()[0], 201)

    def test_explicit_up_dispatches(self):
        self.svc.put_chain_adapters("w1", {"ad1": "up"})
        self._approve()
        self.assertEqual(self._dispatch()[0], 201)

    def test_explicit_down_first_dispatch_409_zero_side_effects(self):
        self.svc.put_chain_adapters("w1", {"ad1": "down"})
        self._approve()
        code, body = self._dispatch()
        self.assertEqual(code, 409)
        self.assertIn("down", body["error"])
        # 零副作用：无派发事件、操作仍 pending、健康表不变化
        self.assertEqual(self._dispatch_events(), [])
        self.assertEqual(
            self.h.store.get_asset_operation("w1", "op1")["state"],
            "pending",
        )
        self.assertEqual(len(self._health_events()), 1)

    def test_down_then_up_allows_dispatch(self):
        self.svc.put_chain_adapters("w1", {"ad1": "down"})
        self._approve()
        self.assertEqual(self._dispatch()[0], 409)
        self.svc.put_chain_adapters("w1", {"ad1": "up"})
        self.assertEqual(self._dispatch()[0], 201)

    def test_replay_preferred_over_later_down(self):
        self._approve()
        self.assertEqual(self._dispatch()[0], 201)
        # 事后熔断：同参重放仍优先 200，不复查健康表
        self.svc.put_chain_adapters("w1", {"ad1": "down"})
        code, v = self._dispatch()
        self.assertEqual(code, 200)
        self.assertEqual(v["state"], "requested")
        # 只有首提一条派发事件
        self.assertEqual(len(self._dispatch_events()), 1)

    def test_health_change_does_not_touch_existing_dispatch_result(self):
        # 既有派发的适配器事后 down：result 仍可按原适配器上报，健康变化
        # 不终止/不改写/不自动接管。
        self._approve()
        self.assertEqual(self._dispatch()[0], 201)
        self.svc.put_chain_adapters("w1", {"ad1": "down"})
        code, v = _call(
            self.svc.post_chain_dispatch_result,
            "w1", "dp1", "ad1", "failed", None,
        )
        self.assertEqual(code, 201)
        self.assertEqual(v["state"], "failed")

    def test_down_blocks_new_dispatch_but_other_adapter_ok(self):
        # 首提用 ad1 派发成功后熔断 ad1：新操作指向 up 的 ad2 可派发，
        # 健康表不影响已有派发。
        self._approve()
        self.assertEqual(self._dispatch()[0], 201)
        self.svc.put_chain_adapters(
            "w1", {"ad1": "down", "ad2": "up"}
        )
        code, _ = self.svc.create_asset_operation("w1", "op2", "BTC", 7)
        self.assertEqual(code, 201)
        self._approve(
            rid="ap2",
            message=_dispatch_msg(
                operation_id="op2", dispatch_id="dp2", adapter_id="ad2"
            ),
        )
        code, v = _call(
            self.svc.post_chain_dispatch,
            "w1", "op2", "dp2", "ad2", "ap2",
        )
        self.assertEqual(code, 201)
        self.assertEqual(v["adapter_id"], "ad2")
        # 同操作指向 down 的 ad1 仍 409（熔断先于"操作已有派发"之外的
        # 正常判定；此处 op2 的新 dispatch_id 指向 ad1）
        self._approve(
            rid="ap3",
            message=_dispatch_msg(
                operation_id="op2", dispatch_id="dp3", adapter_id="ad1"
            ),
        )
        code, _ = _call(
            self.svc.post_chain_dispatch,
            "w1", "op2", "dp3", "ad1", "ap3",
        )
        self.assertEqual(code, 409)


class ChainAdaptersHttpTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.ctx = http_server(self.d)
        self.srv = self.ctx.__enter__()
        self.addCleanup(self.ctx.__exit__, None, None, None)
        self.srv.request(
            "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
        )

    def _raw(self, method, path, body=None):
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(
            self.srv.base_url + path, data=data, method=method, headers=headers
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def test_crud_statuses_and_sorting(self):
        # 未配置 404
        status, _ = self.srv.request("GET", "/v1/wallets/w1/chain-adapters")
        self.assertEqual(status, 404)
        # 钱包不存在 404
        status, _ = self.srv.request(
            "GET", "/v1/wallets/nope/chain-adapters"
        )
        self.assertEqual(status, 404)
        status, _ = self.srv.request(
            "PUT", "/v1/wallets/nope/chain-adapters",
            {"adapters": {"ad1": "up"}},
        )
        self.assertEqual(status, 404)
        # 首建 200（请求体已按 ASCII 升序）
        status, body = self.srv.request(
            "PUT", "/v1/wallets/w1/chain-adapters",
            {"adapters": {"ad1": "up", "ad2": "down"}},
        )
        self.assertEqual(status, 200)
        self.assertEqual(list(body["adapters"]), ["ad1", "ad2"])
        status, body = self.srv.request(
            "GET", "/v1/wallets/w1/chain-adapters"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, {"adapters": {"ad1": "up", "ad2": "down"}})

    def test_unsorted_keys_400(self):
        status, _ = self.srv.request(
            "PUT", "/v1/wallets/w1/chain-adapters",
            {"adapters": {"ad2": "down", "ad1": "up"}},
        )
        self.assertEqual(status, 400)

    def test_400_bodies_and_no_event_on_error(self):
        for body in (
            {},
            {"adapters": {}},
            {"adapters": {"ad1": "UP"}},
            {"adapters": {"ad1": "ban"}},
            {"adapters": {"ad1": True}},
            {"adapters": {"bad id!": "up"}},
            {"adapters": ["ad1"]},
            {"adapters": {"ad1": "up"}, "x": 1},
            [],
        ):
            status, _ = self.srv.request(
                "PUT", "/v1/wallets/w1/chain-adapters", body
            )
            self.assertEqual(status, 400, body)
        # GET 仍 404（没有任何成功写入）
        status, _ = self.srv.request("GET", "/v1/wallets/w1/chain-adapters")
        self.assertEqual(status, 404)

    def test_compact_utf8_json_no_trailing_newline(self):
        status, raw = self._raw(
            "PUT", "/v1/wallets/w1/chain-adapters",
            {"adapters": {"ad1": "up", "ad2": "down"}},
        )
        self.assertEqual(status, 200)
        # 紧凑（无 ": "/"， " 空白）、无末换行
        self.assertFalse(raw.endswith(b"\n"))
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b': ', raw)
        self.assertEqual(
            raw, b'{"adapters":{"ad1":"up","ad2":"down"}}'
        )
        status, raw = self._raw("GET", "/v1/wallets/w1/chain-adapters")
        self.assertEqual(status, 200)
        self.assertEqual(raw, b'{"adapters":{"ad1":"up","ad2":"down"}}')
        # 错误体同样紧凑、无末换行
        status, raw = self._raw(
            "PUT", "/v1/wallets/w1/chain-adapters",
            {"adapters": {"ad1": "BOGUS"}},
        )
        self.assertEqual(status, 400)
        self.assertFalse(raw.endswith(b"\n"))
        self.assertEqual(raw, b'{"error":"adapter state must be one of up, down"}')
        status, raw = self._raw("GET", "/v1/wallets/ghost/chain-adapters")
        self.assertEqual(status, 404)
        self.assertFalse(raw.endswith(b"\n"))

    def test_same_value_put_logs_once(self):
        for _ in range(3):
            status, _ = self.srv.request(
                "PUT", "/v1/wallets/w1/chain-adapters",
                {"adapters": {"ad1": "up"}},
            )
            self.assertEqual(status, 200)
        _, body = self.srv.request("GET", "/v1/wallets/w1/audit-events")
        events = [
            e for e in body["events"]
            if e["type"] == "chain_adapter_health"
        ]
        self.assertEqual(len(events), 1)

    def test_dispatch_to_down_adapter_409(self):
        # 审批 + pending 操作 + 启用策略
        srv = self.srv
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
            "PUT", "/v1/wallets/w1/chain-adapters",
            {"adapters": {"ad1": "down"}},
        )
        srv.request(
            "POST", "/v1/wallets/w1/sign-requests",
            {"id": "ap1", "message": _dispatch_msg()},
        )
        srv.request(
            "POST", "/v1/wallets/w1/sign-requests/ap1/approve",
            {"approver_id": "boss"},
        )
        status, body = srv.request(
            "POST", "/v1/wallets/w1/chain/op1/dispatch",
            {"dispatch_id": "dp1", "adapter_id": "ad1",
             "approval_request_id": "ap1"},
        )
        self.assertEqual(status, 409)
        self.assertIn("down", body["error"])
        # 翻 up 后首提成功
        srv.request(
            "PUT", "/v1/wallets/w1/chain-adapters",
            {"adapters": {"ad1": "up"}},
        )
        status, body = srv.request(
            "POST", "/v1/wallets/w1/chain/op1/dispatch",
            {"dispatch_id": "dp1", "adapter_id": "ad1",
             "approval_request_id": "ap1"},
        )
        self.assertEqual(status, 201)
        # 再熔断不影响同参重放
        srv.request(
            "PUT", "/v1/wallets/w1/chain-adapters",
            {"adapters": {"ad1": "down"}},
        )
        status, _ = srv.request(
            "POST", "/v1/wallets/w1/chain/op1/dispatch",
            {"dispatch_id": "dp1", "adapter_id": "ad1",
             "approval_request_id": "ap1"},
        )
        self.assertEqual(status, 200)

    def test_tampered_health_scene_is_503(self):
        status, _ = self.srv.request(
            "PUT", "/v1/wallets/w1/chain-adapters",
            {"adapters": {"ad1": "up"}},
        )
        self.assertEqual(status, 200)
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for e in log["events"]:
            if e["type"] == "chain_adapter_health":
                e["details"]["adapters"]["ad1"] = "gone"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        status, body = self.srv.request(
            "GET", "/v1/wallets/w1/chain-adapters"
        )
        self.assertEqual(status, 503)
        self.assertEqual(body, {"error": "service temporarily unavailable"})
        # PUT 同样 503
        status, _ = self.srv.request(
            "PUT", "/v1/wallets/w1/chain-adapters",
            {"adapters": {"ad1": "down"}},
        )
        self.assertEqual(status, 503)

    def test_bad_json_scene_is_503(self):
        status, _ = self.srv.request(
            "PUT", "/v1/wallets/w1/chain-adapters",
            {"adapters": {"ad1": "up"}},
        )
        self.assertEqual(status, 200)
        with open(os.path.join(self.d, "audit", "w1.json"), "wb") as f:
            f.write(b"{broken")
        status, body = self.srv.request(
            "GET", "/v1/wallets/w1/chain-adapters"
        )
        self.assertEqual(status, 503)
        self.assertEqual(body, {"error": "service temporarily unavailable"})

    def test_io_error_is_generic_503(self):
        status, _ = self.srv.request(
            "PUT", "/v1/wallets/w1/chain-adapters",
            {"adapters": {"ad1": "up"}},
        )
        self.assertEqual(status, 200)

        def boom(*_a, **_k):
            raise OSError("audit disk full")

        self.srv.harness.service._audit.append_event = boom
        status, body = self.srv.request(
            "PUT", "/v1/wallets/w1/chain-adapters",
            {"adapters": {"ad1": "down"}},
        )
        self.assertEqual(status, 503)
        self.assertEqual(body, {"error": "service temporarily unavailable"})


class ServeRefusalTest(unittest.TestCase):
    """serve 启动恢复遇 chain_adapter_health 矛盾现场时拒绝就绪。"""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        svc = make_harness(self.d).service
        svc.create_wallet("w1", 2)
        svc.put_chain_adapters("w1", {"ad1": "up", "ad2": "down"})

    def _rewrite(self, mutate):
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        mutate(log)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)

    def test_contradiction_refuses_ready(self):
        self._rewrite(
            lambda log: [
                e.__setitem__(
                    "details",
                    {"adapters": {"ad1": "weird"}},
                )
                for e in log["events"]
                if e["type"] == "chain_adapter_health"
            ]
        )
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.d))

    def test_corrupt_json_refuses_ready(self):
        with open(os.path.join(self.d, "audit", "w1.json"), "wb") as f:
            f.write(b"{not json")
        # 启动恢复保持 CorruptDataError 原类型（同样拒绝就绪、现场保留）。
        with self.assertRaises(CorruptDataError):
            WalletService(WalletStore(self.d))


if __name__ == "__main__":
    unittest.main()
