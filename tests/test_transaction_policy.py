"""冷热钱包交易策略测试。

覆盖：
- PUT/GET /v1/wallets/{id}/transaction-policy 的状态码与同体响应：
  200/404/400（类型、空值、重复或非法资产）；
- transaction_policy_updated 事件在每钱包事务锁内原子持久化，
  同值更新也记，details 恰为三项，seq 连续，重启保持；
- 有策略时 pending 资产操作**首次创建**按创建时刻策略检查白名单与
  abs(delta)<=max_delta：失败 409 且账本、version、状态、审计与幂等
  结果不变；committed 重放 200 不再校验；策略更新不影响既有 pending；
- cold 首签必须有同 id、同 message 且 approved 的审批单：无审批策略、
  无单、未 approved 均 409，重放 200；hot 沿用原审批规则；
- 策略文件不含私钥；share-sign 恢复失败输出 JSON 并非零退出。
"""

from __future__ import annotations

import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from tests.helpers import http_server, make_harness
from threshold_wallet.cli import main as cli_main
from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import RecoveryError, WalletStore

VALID_BODY = {"mode": "hot", "max_delta": 10, "allowed_assets": ["btc", "eth"]}


class TransactionPolicyHttpTest(unittest.TestCase):
    """PUT/GET 接口状态码、响应体与参数校验。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self._ctx = http_server(self.tmpdir)
        self.srv = self._ctx.__enter__()
        self.addCleanup(self._ctx.__exit__, None, None, None)
        self.assertEqual(
            self.srv.request(
                "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
            )[0],
            201,
        )
        self.path = "/v1/wallets/w1/transaction-policy"

    def _put(self, body, wallet_id="w1"):
        return self.srv.request(
            "PUT", f"/v1/wallets/{wallet_id}/transaction-policy", body
        )

    def _get(self, wallet_id="w1"):
        return self.srv.request(
            "GET", f"/v1/wallets/{wallet_id}/transaction-policy"
        )

    def test_get_unconfigured_returns_404(self):
        status, body = self._get()
        self.assertEqual(status, 404)
        self.assertIn("error", body)

    def test_put_returns_200_same_body_and_get_matches(self):
        status, body = self._put(VALID_BODY)
        self.assertEqual(status, 200)
        self.assertEqual(body, VALID_BODY)
        status, body = self._get()
        self.assertEqual(status, 200)
        self.assertEqual(body, VALID_BODY)

    def test_put_unknown_wallet_returns_404(self):
        status, _ = self._put(VALID_BODY, wallet_id="ghost")
        self.assertEqual(status, 404)
        status, _ = self._get("ghost")
        self.assertEqual(status, 404)

    def test_bad_mode(self):
        for mode in ("cold-ish", "", 1, True, None, ["hot"]):
            body = dict(VALID_BODY, mode=mode)
            self.assertEqual(self._put(body)[0], 400, body)

    def test_bad_max_delta(self):
        for value in (0, -1, 1.5, "10", True, None, [10]):
            body = dict(VALID_BODY, max_delta=value)
            self.assertEqual(self._put(body)[0], 400, body)

    def test_bad_allowed_assets(self):
        bad_lists = [
            [],
            None,
            "btc",
            ["btc", "btc"],
            ["btc", "eth", "btc"],
            ["BTC", "bad asset"],
            ["BTC", "bad$"],
            [""],
            [1],
            [True],
            [None],
            ["x" * 129],
        ]
        for assets in bad_lists:
            body = dict(VALID_BODY, allowed_assets=assets)
            self.assertEqual(self._put(body)[0], 400, body)

    def test_valid_asset_boundary_lengths(self):
        body = dict(VALID_BODY, allowed_assets=["a", "Z" * 128, "0_-"])
        self.assertEqual(self._put(body)[0], 200)

    def test_failed_validation_persists_nothing(self):
        self._put(dict(VALID_BODY, mode="warm"))
        self._put(dict(VALID_BODY, allowed_assets=[]))
        self.assertEqual(self._get()[0], 404)
        events = self.srv.request(
            "GET", "/v1/wallets/w1/audit-events"
        )[1]["events"]
        self.assertEqual(events, [])


class TransactionPolicyEventTest(unittest.TestCase):
    """事件原子性、同值更新、重启持久化与 seq 连续。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

    def _events(self, svc, wallet_id="w1"):
        return svc.request("GET", f"/v1/wallets/{wallet_id}/audit-events")[1][
            "events"
        ]

    def test_event_emitted_with_three_details_fields(self):
        with http_server(self.tmpdir) as srv:
            srv.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
            status, _ = srv.request(
                "PUT",
                "/v1/wallets/w1/transaction-policy",
                {"mode": "cold", "max_delta": 5, "allowed_assets": ["BTC"]},
            )
            self.assertEqual(status, 200)
            events = self._events(srv)
            self.assertEqual(len(events), 1)
            event = events[0]
            self.assertEqual(event["type"], "transaction_policy_updated")
            self.assertEqual(event["seq"], 1)
            self.assertEqual(
                event["details"],
                {
                    "mode": "cold",
                    "max_delta": 5,
                    "allowed_assets": ["BTC"],
                },
            )
            self.assertIsNone(event["request_id"])
            self.assertIsNone(event["actor_id"])
            self.assertIsNone(event["reason"])

    def test_same_value_update_also_recorded(self):
        with http_server(self.tmpdir) as srv:
            srv.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
            body = {"mode": "hot", "max_delta": 7, "allowed_assets": ["btc"]}
            for _ in range(3):
                self.assertEqual(
                    srv.request(
                        "PUT", "/v1/wallets/w1/transaction-policy", body
                    )[0],
                    200,
                )
            events = self._events(srv)
            self.assertEqual(
                [e["type"] for e in events],
                ["transaction_policy_updated"] * 3,
            )
            self.assertEqual([e["seq"] for e in events], [1, 2, 3])

    def test_policy_and_events_survive_restart(self):
        with http_server(self.tmpdir) as srv:
            srv.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
            srv.request(
                "PUT",
                "/v1/wallets/w1/transaction-policy",
                VALID_BODY,
            )
        with http_server(self.tmpdir) as srv:
            status, body = srv.request(
                "GET", "/v1/wallets/w1/transaction-policy"
            )
            self.assertEqual(status, 200)
            self.assertEqual(body, VALID_BODY)
            events = self._events(srv)
            self.assertEqual([e["seq"] for e in events], [1])
            self.assertEqual(events[0]["type"], "transaction_policy_updated")
            # 重启后再次同值更新，seq 接续不重号
            srv.request("PUT", "/v1/wallets/w1/transaction-policy", VALID_BODY)
            events = self._events(srv)
            self.assertEqual([e["seq"] for e in events], [1, 2])

    def test_event_failure_rolls_back_policy(self):
        """事件落盘失败：策略状态回滚（首设删除、更新恢复旧值），无 seq 缺口。"""
        harness = make_harness(self.tmpdir)
        svc = harness.service
        svc.create_wallet("w1", 2)
        original_append = svc._audit.append_event

        def boom(wallet_id, event):
            raise OSError("audit disk unavailable")

        # 首设时事件失败：策略不得留下
        svc._audit.append_event = boom
        with self.assertRaises(OSError):
            svc.put_transaction_policy("w1", "hot", 10, ["btc"])
        svc._audit.append_event = original_append
        self.assertIsNone(svc._store.get_transaction_policy("w1"))

        # 成功首设
        svc.put_transaction_policy("w1", "hot", 10, ["btc"])
        # 更新时事件失败：恢复为旧策略
        svc._audit.append_event = boom
        with self.assertRaises(OSError):
            svc.put_transaction_policy("w1", "cold", 1, ["eth"])
        svc._audit.append_event = original_append
        self.assertEqual(
            svc._store.get_transaction_policy("w1"),
            {"mode": "hot", "max_delta": 10, "allowed_assets": ["btc"]},
        )
        # 仅一条事件、一个 seq：失败从未分配/留下 seq
        events = svc.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in events], [1])

    def test_policy_file_has_no_private_material(self):
        with http_server(self.tmpdir) as srv:
            srv.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
            srv.request(
                "PUT",
                "/v1/wallets/w1/transaction-policy",
                VALID_BODY,
            )
        path = os.path.join(
            self.tmpdir, "transaction-policies", "w1.json"
        )
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
        data = json.loads(raw)
        self.assertEqual(
            set(data.keys()), {"mode", "max_delta", "allowed_assets"}
        )
        self.assertNotIn("private", raw.lower())


class AssetPolicyEnforcementTest(unittest.TestCase):
    """有策略时 pending 首提的白名单/上限校验与不变量。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.harness = make_harness(self.tmpdir)
        self.svc = self.harness.service
        self.svc.create_wallet("w1", 2)
        self.svc.put_transaction_policy("w1", "hot", 10, ["btc", "eth"])

    def _create(self, op_id, asset_id, delta):
        return self.svc.create_asset_operation("w1", op_id, asset_id, delta)

    def _events(self):
        return self.svc.get_audit_events("w1")["events"]

    def _business_events(self):
        """除设置策略本身的 transaction_policy_updated 之外的事件。"""
        return [
            e
            for e in self._events()
            if e["type"] != "transaction_policy_updated"
        ]

    def test_allowed_asset_within_delta_201(self):
        status, record = self._create("op1", "btc", 10)
        self.assertEqual(status, 201)
        self.assertEqual(record["state"], "pending")
        status, record = self._create("op2", "eth", -10)
        self.assertEqual(status, 201)

    def test_disallowed_asset_409_and_no_side_effects(self):
        with self.assertRaises(ServiceError) as cm:
            self._create("op1", "doge", 1)
        self.assertEqual(cm.exception.status, 409)
        # 账本、审计不变
        with self.assertRaises(ServiceError) as cm2:
            self.svc.get_asset("w1", "doge")
        self.assertEqual(cm2.exception.status, 404)
        self.assertEqual(self._business_events(), [])
        # 幂等结果不变：该 operation_id 未被占用，之后合法首提仍 201
        status, _ = self._create("op1", "btc", 1)
        self.assertEqual(status, 201)

    def test_delta_over_max_409_uses_abs(self):
        for delta in (11, -11):
            with self.assertRaises(ServiceError) as cm:
                self._create(f"op-{delta}", "btc", delta)
            self.assertEqual(cm.exception.status, 409)
        # 边界值允许
        self.assertEqual(self._create("op-edge", "btc", 10)[0], 201)
        self.assertEqual(self._business_events(), [])

    def test_failed_create_does_not_consume_version(self):
        with self.assertRaises(ServiceError):
            self._create("op1", "doge", 100)
        self._create("op2", "btc", 5)
        status, _ = self.svc.commit_asset_operation("w1", "op2")
        self.assertEqual(status, 201)
        asset = self.svc.get_asset("w1", "btc")
        self.assertEqual(asset, {"asset_id": "btc", "balance": 5, "version": 1})

    def test_replay_not_rechecked_against_new_policy(self):
        status, first = self._create("op1", "btc", 10)
        self.assertEqual(status, 201)
        # 策略更新：btc 落出白名单、上限收紧
        self.svc.put_transaction_policy("w1", "hot", 1, ["eth"])
        # 既有 pending 不受影响：重放 200 同体，不按新策略复查
        status, replay = self._create("op1", "btc", 10)
        self.assertEqual(status, 200)
        self.assertEqual(replay, first)
        # 但新的首提按新策略被拒
        with self.assertRaises(ServiceError) as cm:
            self._create("op2", "btc", 1)
        self.assertEqual(cm.exception.status, 409)
        # 既有 pending 仍可正常提交（更新不影响 pending）
        status, committed = self.svc.commit_asset_operation("w1", "op1")
        self.assertEqual(status, 201)
        self.assertEqual(committed["state"], "committed")
        # committed 重放 200 同体，不再校验
        status, replay_committed = self._create("op1", "btc", 10)
        self.assertEqual(status, 200)
        self.assertEqual(replay_committed, committed)

    def test_no_policy_behavior_unchanged(self):
        self.svc.create_wallet("w2", 2)
        status, _ = self.svc.create_asset_operation(
            "w2", "op1", "anything", 123456
        )
        self.assertEqual(status, 201)


class ColdModeSigningTest(unittest.TestCase):
    """cold 首签的审批单要求与重放；hot 沿用旧规则。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.harness = make_harness(self.tmpdir)
        self.svc = self.harness.service
        self.svc.create_wallet("w1", 2)

    def _sigs(self, rid, message):
        return self.harness.two_signatures("w1", rid, message)

    def _sign(self, rid="r1", message="hello", sigs=None):
        return self.svc.sign(
            "w1", rid, message, sigs if sigs is not None else self._sigs(rid, message)
        )

    def test_cold_without_approval_policy_409(self):
        self.svc.put_transaction_policy("w1", "cold", 10, ["btc"])
        with self.assertRaises(ServiceError) as cm:
            self._sign()
        self.assertEqual(cm.exception.status, 409)
        # 失败不落签名、不记业务事件（设置交易策略自身的事件除外）
        self.assertIsNone(self.svc._store.get_signature("w1", "r1"))
        self.assertEqual(
            [
                e
                for e in self.svc.get_audit_events("w1")["events"]
                if e["type"] != "transaction_policy_updated"
            ],
            [],
        )

    def test_cold_without_request_409(self):
        self.svc.put_transaction_policy("w1", "cold", 10, ["btc"])
        self.svc.put_policy("w1", 1, 3600)
        with self.assertRaises(ServiceError) as cm:
            self._sign()
        self.assertEqual(cm.exception.status, 409)

    def test_cold_pending_request_409(self):
        self.svc.put_transaction_policy("w1", "cold", 10, ["btc"])
        self.svc.put_policy("w1", 1, 3600)
        self.svc.create_sign_request("w1", "r1", "hello")
        with self.assertRaises(ServiceError) as cm:
            self._sign()
        self.assertEqual(cm.exception.status, 409)

    def test_cold_rejected_request_409(self):
        self.svc.put_transaction_policy("w1", "cold", 10, ["btc"])
        self.svc.put_policy("w1", 1, 3600)
        self.svc.create_sign_request("w1", "r1", "hello")
        self.svc.reject("w1", "r1", "ops-1")
        with self.assertRaises(ServiceError) as cm:
            self._sign()
        self.assertEqual(cm.exception.status, 409)

    def test_cold_message_mismatch_409(self):
        self.svc.put_transaction_policy("w1", "cold", 10, ["btc"])
        self.svc.put_policy("w1", 1, 3600)
        self.svc.create_sign_request("w1", "r1", "hello")
        self.svc.approve("w1", "r1", "ops-1")
        with self.assertRaises(ServiceError) as cm:
            self._sign(message="different")
        self.assertEqual(cm.exception.status, 409)
        self.assertIsNone(self.svc._store.get_signature("w1", "r1"))

    def test_cold_approved_first_sign_201_replay_200(self):
        self.svc.put_transaction_policy("w1", "cold", 10, ["btc"])
        self.svc.put_policy("w1", 1, 3600)
        self.svc.create_sign_request("w1", "r1", "hello")
        self.svc.approve("w1", "r1", "ops-1")
        status, body = self._sign()
        self.assertEqual(status, 201)
        self.assertEqual(len(bytes.fromhex(body["signature"])), 128)
        # 重放 200：即使策略后来变化，也不再校验
        self.svc.put_transaction_policy("w1", "cold", 1, ["eth"])
        status, replay = self._sign()
        self.assertEqual(status, 200)
        self.assertEqual(replay, body)
        # 仅一条 request_signed 事件
        signed = [
            e
            for e in self.svc.get_audit_events("w1")["events"]
            if e["type"] == "request_signed"
        ]
        self.assertEqual(len(signed), 1)

    def test_hot_without_approval_policy_allows_sign(self):
        # hot 且未配置审批策略：行为与未引入交易策略前一致
        self.svc.put_transaction_policy("w1", "hot", 10, ["btc"])
        status, _ = self._sign()
        self.assertEqual(status, 201)

    def test_hot_with_approval_policy_keeps_legacy_rules(self):
        self.svc.put_transaction_policy("w1", "hot", 10, ["btc"])
        self.svc.put_policy("w1", 1, 3600)
        # 无审批单：沿用旧规则 -> 404
        with self.assertRaises(ServiceError) as cm:
            self._sign()
        self.assertEqual(cm.exception.status, 404)
        self.svc.create_sign_request("w1", "r1", "hello")
        with self.assertRaises(ServiceError) as cm:
            self._sign()
        self.assertEqual(cm.exception.status, 409)
        self.svc.approve("w1", "r1", "ops-1")
        self.assertEqual(self._sign()[0], 201)

    def test_switching_mode_only_affects_new_first_signs(self):
        # hot 下首签完成；切到 cold 不影响重放
        self.svc.put_transaction_policy("w1", "hot", 10, ["btc"])
        self.assertEqual(self._sign()[0], 201)
        self.svc.put_transaction_policy("w1", "cold", 10, ["btc"])
        self.assertEqual(self._sign()[0], 200)


class ShareSignRecoveryTest(unittest.TestCase):
    """share-sign 经 WalletService 钱包锁先懒恢复；失败输出 JSON 并非零退出。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _run_share_sign(self, wallet_id="w1"):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli_main(
                [
                    "share-sign",
                    "--data-dir", self.tmp,
                    "--wallet-id", wallet_id,
                    "--share-id", "share-1",
                    "--signing-request-id", "r1",
                    "--message", "m",
                ]
            )
        return code, out.getvalue().strip(), err.getvalue().strip()

    def test_share_sign_ok_after_rotation_heal(self):
        # 构造一个 prepared 轮换（暂存完整）：share-sign 持锁自愈应安全通过，
        # 并用当前在用份额 share-1 成功签名
        svc = WalletService(WalletStore(self.tmp))
        svc.create_wallet("w1", 2)
        svc.create_share_rotation("w1", "rot-1")
        code, out, err = self._run_share_sign()
        self.assertEqual(code, 0, err)
        body = json.loads(out)
        self.assertEqual(body["share_id"], "share-1")
        self.assertEqual(len(bytes.fromhex(body["signature"])), 64)

    def test_share_sign_recovery_failure_json_nonzero(self):
        # 摆出无法安全回滚的激活现场：新建 WalletService 即 RecoveryError，
        # share-sign 必须输出单行 JSON 错误并非零退出
        from tests.test_recovery_strict import _plant_unrecoverable_activation, _prepare_rotation

        _prepare_rotation(self.tmp)
        _plant_unrecoverable_activation(self.tmp)
        code, out, err = self._run_share_sign()
        self.assertNotEqual(code, 0)
        self.assertEqual(out, "")
        payload = json.loads(err)
        self.assertIn("error", payload)
        # 错误输出不含私钥
        self.assertNotIn("private_key", err)


if __name__ == "__main__":
    unittest.main()
