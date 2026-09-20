"""冷热钱包交易策略测试。

覆盖：
- PUT/GET /v1/wallets/{id}/transaction-policy 的全部状态码：成功 200 同体、
  钱包 404、mode/max_delta/allowed_assets 的类型/空值/重复/非法资产 400、
  GET 未配置 404；
- 策略与 transaction_policy_updated 事件锁内原子持久化：同值更新也记、
  details 恰为三项、事件追加失败回滚策略、seq 跨重启连续、重启后策略保持；
- 资产门控：无策略行为不变；有策略时 pending 首提按白名单与
  abs(delta)<=max_delta 检查，失败 409 且账本/version/状态/审计/幂等结果
  不变；committed 重放 200；策略更新不影响已存在 pending；
- 签名冷热门控：hot 沿用审批规则；cold 首签必须有同 id、同 message 且
  approved 的审批单，无审批策略/无单/未 approved 均 409，重放 200；
- share-sign 经 WalletService 钱包锁先懒恢复再读份额，恢复失败 fail-closed。
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest

from tests.helpers import http_server, make_harness
from threshold_wallet import crypto
from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import RecoveryError, WalletStore

VALID_BODY = {"mode": "hot", "max_delta": 100, "allowed_assets": ["btc", "eth"]}


class TransactionPolicyHttpTest(unittest.TestCase):
    """PUT/GET 接口的状态码与响应体。"""

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

    def _put(self, body, wallet_id="w1"):
        return self.srv.request(
            "PUT",
            f"/v1/wallets/{wallet_id}/transaction-policy",
            body,
        )

    def _get(self, wallet_id="w1"):
        return self.srv.request(
            "GET", f"/v1/wallets/{wallet_id}/transaction-policy"
        )

    def test_put_success_200_same_body(self):
        status, body = self._put(VALID_BODY)
        self.assertEqual(status, 200)
        self.assertEqual(body, VALID_BODY)

    def test_get_configured_200(self):
        self._put(VALID_BODY)
        status, body = self._get()
        self.assertEqual(status, 200)
        self.assertEqual(body, VALID_BODY)

    def test_get_unconfigured_404(self):
        status, body = self._get()
        self.assertEqual(status, 404)
        self.assertIn("error", body)

    def test_put_missing_wallet_404(self):
        status, _ = self._put(VALID_BODY, wallet_id="nope")
        self.assertEqual(status, 404)

    def test_get_missing_wallet_404(self):
        status, _ = self._get(wallet_id="nope")
        self.assertEqual(status, 404)

    def test_bad_mode_400(self):
        for bad in ("cold ", "WARM", "", None, 1, True, [], {}):
            with self.subTest(mode=bad):
                status, _ = self._put(
                    {
                        "mode": bad,
                        "max_delta": 1,
                        "allowed_assets": ["btc"],
                    }
                )
                self.assertEqual(status, 400)

    def test_bad_max_delta_400(self):
        for bad in (0, -1, True, False, 1.0, 1.5, "10", None, [], {}):
            with self.subTest(max_delta=bad):
                status, _ = self._put(
                    {"mode": "hot", "max_delta": bad,
                     "allowed_assets": ["btc"]}
                )
                self.assertEqual(status, 400)

    def test_bad_allowed_assets_400(self):
        bad_lists = [
            [],
            None,
            "btc",
            1,
            {},
            [""],
            ["has space"],
            ["slash/x"],
            ["dot.name"],
            ["x" * 129],
            ["中文"],
            [1],
            [None],
            [True],
            [["btc"]],
            [{"a": 1}],
            ["btc", "eth", "btc"],  # 重复
        ]
        for bad in bad_lists:
            with self.subTest(allowed_assets=bad):
                status, _ = self._put(
                    {"mode": "hot", "max_delta": 1, "allowed_assets": bad}
                )
                self.assertEqual(status, 400)

    def test_boundary_asset_id_accepted(self):
        status, _ = self._put(
            {"mode": "cold", "max_delta": 1, "allowed_assets": ["x" * 128]}
        )
        self.assertEqual(status, 200)

    def test_missing_fields_400(self):
        self.assertEqual(self._put({"max_delta": 1,
                                   "allowed_assets": ["a"]})[0], 400)
        self.assertEqual(self._put({"mode": "hot",
                                   "allowed_assets": ["a"]})[0], 400)
        self.assertEqual(self._put({"mode": "hot", "max_delta": 1})[0], 400)

    def test_update_overwrites_and_get_returns_latest(self):
        self._put({"mode": "hot", "max_delta": 10, "allowed_assets": ["btc"]})
        status, body = self._put(
            {"mode": "cold", "max_delta": 5, "allowed_assets": ["eth", "x"]}
        )
        self.assertEqual(status, 200)
        status, body = self._get()
        self.assertEqual(
            body,
            {"mode": "cold", "max_delta": 5, "allowed_assets": ["eth", "x"]},
        )

    def test_response_has_exactly_three_fields(self):
        _, body = self._put(VALID_BODY)
        self.assertEqual(
            set(body), {"mode", "max_delta", "allowed_assets"}
        )


class TransactionPolicyAuditTest(unittest.TestCase):
    """策略事件：同值更新也记、details 三项、seq 连续、回滚原子。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.harness = make_harness(self.tmpdir)
        self.service = self.harness.service
        self.service.create_wallet("w1", 2)

    def _events(self):
        return self.service.get_audit_events("w1")["events"]

    def test_first_put_records_event_with_three_details(self):
        policy = self.service.put_transaction_policy("w1", "hot", 10, ["btc"])
        events = self._events()
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["seq"], 1)
        self.assertEqual(event["type"], "transaction_policy_updated")
        self.assertIsNone(event["request_id"])
        self.assertIsNone(event["actor_id"])
        self.assertIsNone(event["reason"])
        self.assertEqual(
            event["details"],
            {"mode": "hot", "max_delta": 10, "allowed_assets": ["btc"]},
        )
        self.assertEqual(set(event["details"]),
                         {"mode", "max_delta", "allowed_assets"})
        self.assertEqual(event["details"], policy)

    def test_same_value_update_still_records(self):
        self.service.put_transaction_policy("w1", "hot", 10, ["btc"])
        self.service.put_transaction_policy("w1", "hot", 10, ["btc"])
        self.service.put_transaction_policy("w1", "hot", 10, ["btc"])
        events = self._events()
        self.assertEqual(len(events), 3)
        self.assertEqual([e["seq"] for e in events], [1, 2, 3])
        self.assertTrue(
            all(e["type"] == "transaction_policy_updated" for e in events)
        )

    def test_seq_continuous_across_other_events(self):
        self.service.put_policy("w1", 1, 60)
        self.service.put_transaction_policy("w1", "cold", 5, ["btc"])
        self.service.create_asset_operation("w1", "op1", "btc", 5)
        self.service.commit_asset_operation("w1", "op1")
        self.service.put_transaction_policy("w1", "cold", 9, ["btc"])
        events = self._events()
        self.assertEqual([e["seq"] for e in events], [1, 2, 3, 4])
        self.assertEqual(
            [e["type"] for e in events],
            [
                "policy_updated",
                "transaction_policy_updated",
                "asset_operation_committed",
                "transaction_policy_updated",
            ],
        )

    def test_event_append_failure_rolls_back_policy(self):
        real_append = self.service._audit.append_event

        def boom(wallet_id, event):
            raise OSError("audit disk full")

        self.service._audit.append_event = boom
        with self.assertRaises(OSError):
            self.service.put_transaction_policy("w1", "hot", 10, ["btc"])
        self.service._audit.append_event = real_append
        # 策略未留下：GET 表现为未配置，且无事件、无 seq 缺口
        with self.assertRaises(ServiceError) as ctx:
            self.service.get_transaction_policy("w1")
        self.assertEqual(ctx.exception.status, 404)
        self.assertEqual(self._events(), [])

        # 更新失败时回滚为旧值
        self.service.put_transaction_policy("w1", "hot", 10, ["btc"])

        def boom2(wallet_id, event):
            raise OSError("audit disk full")

        self.service._audit.append_event = boom2
        with self.assertRaises(OSError):
            self.service.put_transaction_policy("w1", "cold", 1, ["eth"])
        self.service._audit.append_event = real_append
        policy = self.service.get_transaction_policy("w1")
        self.assertEqual(
            policy, {"mode": "hot", "max_delta": 10, "allowed_assets": ["btc"]}
        )
        events = self._events()
        self.assertEqual(len(events), 1)


class TransactionPolicyPersistenceTest(unittest.TestCase):
    """重启保持与审计 seq 接续。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

    def _restart(self):
        self.harness = make_harness(self.tmpdir)
        self.service = self.harness.service
        return self.service

    def test_policy_survives_restart(self):
        service = self._restart()
        service.create_wallet("w1", 2)
        service.put_transaction_policy("w1", "cold", 42, ["btc", "eth"])

        service = self._restart()
        self.assertEqual(
            service.get_transaction_policy("w1"),
            {"mode": "cold", "max_delta": 42, "allowed_assets": ["btc", "eth"]},
        )
        # 未配置策略的钱包重启后仍 404
        service.create_wallet("w2", 2)
        with self.assertRaises(ServiceError) as ctx:
            service.get_transaction_policy("w2")
        self.assertEqual(ctx.exception.status, 404)
        # 重启后同值更新：事件 seq 接续
        service.put_transaction_policy("w1", "cold", 42, ["btc", "eth"])
        events = service.get_audit_events("w1")["events"]
        self.assertEqual([e["seq"] for e in events], [1, 2])

    def test_policy_file_contains_no_private_material(self):
        service = self._restart()
        service.create_wallet("w1", 2)
        service.put_transaction_policy("w1", "hot", 1, ["btc"])
        store = WalletStore(self.tmpdir)
        priv_hexes = [
            store.get_share("w1", sid)["private_key"]
            for sid in ("share-1", "share-2")
        ]
        path = os.path.join(self.tmpdir, "transaction-policies", "w1.json")
        with open(path, encoding="utf-8") as f:
            raw = f.read()
        self.assertNotIn("private", raw)
        for priv_hex in priv_hexes:
            self.assertNotIn(priv_hex, raw)


class AssetPolicyGateTest(unittest.TestCase):
    """pending 首提的白名单与 max_delta 门控（409 无副作用）。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.harness = make_harness(self.tmpdir)
        self.service = self.harness.service
        self.store = self.harness.store
        self.service.create_wallet("w1", 2)

    def _events(self):
        return self.service.get_audit_events("w1")["events"]

    def test_no_policy_behavior_unchanged(self):
        # 任意资产、任意 delta 均可创建
        status, _ = self.service.create_asset_operation(
            "w1", "op1", "anything", 10 ** 9
        )
        self.assertEqual(status, 201)

    def test_non_whitelisted_asset_409_with_no_side_effects(self):
        self.service.put_transaction_policy("w1", "hot", 100, ["btc"])
        with self.assertRaises(ServiceError) as ctx:
            self.service.create_asset_operation("w1", "op1", "eth", 10)
        self.assertEqual(ctx.exception.status, 409)
        # 账本无该操作、无该资产
        self.assertIsNone(self.store.get_asset_operation("w1", "op1"))
        self.assertIsNone(self.store.get_asset("w1", "eth"))
        # 无审计事件
        self.assertEqual(
            [e["type"] for e in self._events()],
            ["transaction_policy_updated"],
        )
        # 幂等结果未被占用：同一 operation_id 合法首提 201
        status, body = self.service.create_asset_operation(
            "w1", "op1", "btc", 10
        )
        self.assertEqual(status, 201)
        self.assertEqual(body["state"], "pending")

    def test_abs_delta_over_limit_409_for_both_signs(self):
        self.service.put_transaction_policy("w1", "hot", 100, ["btc"])
        for bad in (101, -101, 1000, -1000):
            with self.subTest(delta=bad):
                with self.assertRaises(ServiceError) as ctx:
                    self.service.create_asset_operation(
                        "w1", f"op-{bad}", "btc", bad
                    )
                self.assertEqual(ctx.exception.status, 409)
        # 边界 abs(delta)==max_delta 双向放行
        for ok in (100, -100):
            status, _ = self.service.create_asset_operation(
                "w1", f"ok-{ok}", "btc", ok
            )
            self.assertEqual(status, 201)

    def test_failure_does_not_change_version_or_ledger(self):
        self.service.put_transaction_policy("w1", "hot", 100, ["btc"])
        self.service.create_asset_operation("w1", "op0", "btc", 100)
        self.service.commit_asset_operation("w1", "op0")
        # 多次非法首提
        for oid, asset, delta in (
            ("bad1", "eth", 1),
            ("bad2", "btc", 101),
            ("bad3", "eth", 101),
        ):
            with self.assertRaises(ServiceError):
                self.service.create_asset_operation("w1", oid, asset, delta)
        asset = self.service.get_asset("w1", "btc")
        self.assertEqual((asset["balance"], asset["version"]), (100, 1))
        # 只有策略事件 + 一次 committed 事件
        self.assertEqual(
            [e["type"] for e in self._events()],
            ["transaction_policy_updated", "asset_operation_committed"],
        )

    def test_policy_update_does_not_affect_existing_pending(self):
        # 无策略时创建 pending
        status, first = self.service.create_asset_operation(
            "w1", "op1", "eth", 1000
        )
        self.assertEqual(status, 201)
        # 之后设置一个会拒绝该操作的策略
        self.service.put_transaction_policy("w1", "hot", 5, ["btc"])
        # 同参重放 200 同体，不再按新策略校验
        status, replay = self.service.create_asset_operation(
            "w1", "op1", "eth", 1000
        )
        self.assertEqual(status, 200)
        self.assertEqual(replay, first)
        # 异参重放仍 409（幂等冲突，而非策略拒绝）
        with self.assertRaises(ServiceError) as ctx:
            self.service.create_asset_operation("w1", "op1", "eth", 999)
        self.assertEqual(ctx.exception.status, 409)
        # pending 仍可提交（提交只查余额，资产创建时的策略不追溯）
        status, committed = self.service.commit_asset_operation("w1", "op1")
        self.assertEqual(status, 201)
        self.assertEqual(committed["balance"], 1000)

    def test_committed_replay_200_not_rechecked(self):
        self.service.put_transaction_policy("w1", "hot", 100, ["btc"])
        self.service.create_asset_operation("w1", "op1", "btc", 100)
        self.service.commit_asset_operation("w1", "op1")
        # 策略收紧到拒绝历史参数
        self.service.put_transaction_policy("w1", "hot", 1, ["btc"])
        # committed 重放 200 同体，不重新校验
        status, replay = self.service.create_asset_operation(
            "w1", "op1", "btc", 100
        )
        self.assertEqual(status, 200)
        self.assertEqual(replay["state"], "committed")
        status, replay_commit = self.service.commit_asset_operation("w1", "op1")
        self.assertEqual(status, 200)
        self.assertEqual(replay_commit["balance"], 100)
        self.assertEqual(replay_commit["version"], 1)

    def test_policy_gate_works_after_restart(self):
        self.service.put_transaction_policy("w1", "cold", 10, ["btc"])
        service = make_harness(self.tmpdir).service
        with self.assertRaises(ServiceError) as ctx:
            service.create_asset_operation("w1", "op1", "eth", 1)
        self.assertEqual(ctx.exception.status, 409)
        status, _ = service.create_asset_operation("w1", "op2", "btc", 10)
        self.assertEqual(status, 201)


def _two_share_signatures(store, wallet_id, request_id, message):
    out = []
    for sid in ("share-1", "share-2"):
        share = store.get_share(wallet_id, sid)
        payload = crypto.build_payload(request_id, message)
        out.append(
            {
                "share_id": sid,
                "signature": crypto.sign_share(
                    bytes.fromhex(share["private_key"]), payload
                ).hex(),
            }
        )
    return out


class SignModeGateTest(unittest.TestCase):
    """sign 在 hot/cold 模式下的审批门控。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.harness = make_harness(self.tmpdir)
        self.service = self.harness.service
        self.store = self.harness.store
        self.service.create_wallet("w1", 2)

    def _sign(self, request_id="r1", message="m", wallet_id="w1"):
        return self.service.sign(
            wallet_id,
            request_id,
            message,
            _two_share_signatures(self.store, wallet_id, request_id, message),
        )

    def _events(self, wallet_id="w1"):
        return self.service.get_audit_events(wallet_id)["events"]

    # ---- cold -------------------------------------------------------------

    def test_cold_without_approval_policy_409(self):
        self.service.put_transaction_policy("w1", "cold", 100, ["btc"])
        with self.assertRaises(ServiceError) as ctx:
            self._sign()
        self.assertEqual(ctx.exception.status, 409)
        # 失败不留签名、不记事件
        self.assertIsNone(self.store.get_signature("w1", "r1"))
        self.assertEqual(
            [e["type"] for e in self._events()],
            ["transaction_policy_updated"],
        )

    def test_cold_no_request_409(self):
        self.service.put_transaction_policy("w1", "cold", 100, ["btc"])
        self.service.put_policy("w1", 1, 3600)
        with self.assertRaises(ServiceError) as ctx:
            self._sign()
        self.assertEqual(ctx.exception.status, 409)

    def test_cold_pending_or_rejected_or_expired_409(self):
        self.service.put_transaction_policy("w1", "cold", 100, ["btc"])
        self.service.put_policy("w1", 1, 3600)
        self.service.create_sign_request("w1", "r1", "m")
        with self.assertRaises(ServiceError) as ctx:
            self._sign()
        self.assertEqual(ctx.exception.status, 409)
        # pending 单状态不变、无签名事件
        view = self.service.get_sign_request("w1", "r1")
        self.assertEqual(view["state"], "pending")
        self.service.reject("w1", "r1", "ops-1")
        with self.assertRaises(ServiceError):
            self._sign()

    def test_cold_message_mismatch_409(self):
        self.service.put_transaction_policy("w1", "cold", 100, ["btc"])
        self.service.put_policy("w1", 1, 3600)
        self.service.create_sign_request("w1", "r1", "m")
        self.service.approve("w1", "r1", "ops-1")
        with self.assertRaises(ServiceError) as ctx:
            self._sign(message="different")
        self.assertEqual(ctx.exception.status, 409)
        # 审批单不因失败推进
        view = self.service.get_sign_request("w1", "r1")
        self.assertEqual(view["state"], "approved")

    def test_cold_approved_201_then_replay_200(self):
        self.service.put_transaction_policy("w1", "cold", 100, ["btc"])
        self.service.put_policy("w1", 1, 3600)
        self.service.create_sign_request("w1", "r1", "m")
        self.service.approve("w1", "r1", "ops-1")
        status, body = self._sign()
        self.assertEqual(status, 201)
        self.assertEqual(len(bytes.fromhex(body["signature"])), 128)
        # 审批单推进 signed
        self.assertEqual(
            self.service.get_sign_request("w1", "r1")["state"], "signed"
        )
        # 重放 200 同体，不再校验（即使审批策略/交易策略随后变化）
        self.service.put_policy("w1", 2, 3600)
        status, replay = self._sign()
        self.assertEqual(status, 200)
        self.assertEqual(replay["signature"], body["signature"])
        # request_signed 只记一次
        signed = [e for e in self._events() if e["type"] == "request_signed"]
        self.assertEqual(len(signed), 1)

    def test_switching_hot_to_cold_tightens_signing(self):
        self.service.put_transaction_policy("w1", "hot", 100, ["btc"])
        # hot 无审批策略：首签 201
        status, _ = self._sign(request_id="hot-req")
        self.assertEqual(status, 201)
        # 切 cold 且无审批策略：新请求 409
        self.service.put_transaction_policy("w1", "cold", 100, ["btc"])
        with self.assertRaises(ServiceError) as ctx:
            self._sign(request_id="cold-req")
        self.assertEqual(ctx.exception.status, 409)

    # ---- hot --------------------------------------------------------------

    def test_hot_without_approval_policy_unchanged_201(self):
        self.service.put_transaction_policy("w1", "hot", 100, ["btc"])
        status, body = self._sign(request_id="r9")
        self.assertEqual(status, 201)
        status, body2 = self._sign(request_id="r9")
        self.assertEqual(status, 200)
        self.assertEqual(body2["signature"], body["signature"])

    def test_hot_with_approval_policy_follows_existing_rules(self):
        self.service.put_transaction_policy("w1", "hot", 100, ["btc"])
        self.service.put_policy("w1", 1, 3600)
        # 无审批单：hot 沿用原规则 404（区别于 cold 的 409）
        with self.assertRaises(ServiceError) as ctx:
            self._sign(request_id="ghost")
        self.assertEqual(ctx.exception.status, 404)
        # pending：409
        self.service.create_sign_request("w1", "r1", "m")
        with self.assertRaises(ServiceError) as ctx:
            self._sign()
        self.assertEqual(ctx.exception.status, 409)
        # approved：201
        self.service.approve("w1", "r1", "ops-1")
        status, _ = self._sign()
        self.assertEqual(status, 201)


class ShareSignLazyRecoveryTest(unittest.TestCase):
    """share-sign 必须经钱包锁先懒恢复再读份额。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        # 先建钱包并准备好轮换
        self.first = make_harness(self.tmpdir)
        self.first.service.create_wallet("w1", 2)
        self.wallet_before = self.first.store.get_wallet("w1")
        _, prepared = self.first.service.create_share_rotation("w1", "rot-1")
        self.prepared = prepared

    def _plant_crashed_activation_with_backup(self):
        """他进程激活到一半（换入已发生、事件未落盘），备份仍在。"""
        store = WalletStore(self.tmpdir)
        record = store.get_rotation("w1", "rot-1")
        wallet = store.get_wallet("w1")
        old_shares = [
            store.get_share("w1", s["share_id"]) for s in wallet["shares"]
        ]
        activating = dict(record)
        activating["state"] = "activating"
        activating["previous_public_key"] = wallet["public_key"]
        store.update_rotation("w1", "rot-1", activating)
        store.save_activation_backups("w1", "rot-1", old_shares, wallet)
        new_records = [
            store.get_staging_share("w1", "rot-1", sid)
            for sid in record["share_ids"]
        ]
        for share_record in new_records:
            store.save_share("w1", share_record)
        new_meta = dict(wallet)
        new_meta["shares"] = [
            {"share_id": r["share_id"], "public_key": r["public_key"]}
            for r in new_records
        ]
        new_meta["public_key"] = record["public_key"]
        store.save_wallet_meta("w1", new_meta)
        for share_record in old_shares:
            store.delete_share("w1", share_record["share_id"])

    def test_get_share_for_signing_lazy_heals(self):
        # 常驻服务（健康时构造），随后他进程留下崩溃现场
        service = self.first.service
        self._plant_crashed_activation_with_backup()
        # 读份额在钱包锁内先自愈：回滚后读到的是旧份额
        share = service.get_share_for_signing("w1", "share-1")
        self.assertEqual(share["share_id"], "share-1")
        wallet = service.get_wallet("w1")
        self.assertEqual(wallet["public_key"], self.wallet_before["public_key"])
        # 用读到的份额签名，服务端按旧公钥校验通过
        payload = crypto.build_payload("r1", "m")
        sig1 = crypto.sign_share(bytes.fromhex(share["private_key"]), payload)
        share2 = service.get_share_for_signing("w1", "share-2")
        sig2 = crypto.sign_share(
            bytes.fromhex(share2["private_key"]), payload
        )
        status, body = service.sign(
            "w1",
            "r1",
            "m",
            [
                {"share_id": "share-1", "signature": sig1.hex()},
                {"share_id": "share-2", "signature": sig2.hex()},
            ],
        )
        self.assertEqual(status, 201, body)

    def test_get_share_for_signing_missing_wallet_or_share_404(self):
        service = self.first.service
        with self.assertRaises(ServiceError) as ctx:
            service.get_share_for_signing("nope", "share-1")
        self.assertEqual(ctx.exception.status, 404)
        with self.assertRaises(ServiceError) as ctx:
            service.get_share_for_signing("w1", "share-9")
        self.assertEqual(ctx.exception.status, 404)

    def test_get_share_for_signing_unrecoverable_scene_raises(self):
        # 不可恢复现场：新服务构造即 fail-closed
        self._plant_unrecoverable()
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmpdir))

    def _plant_unrecoverable(self):
        self._plant_crashed_activation_with_backup()
        staging = os.path.join(
            self.tmpdir, "rotation-staging", "w1", "rot-1"
        )
        for name in os.listdir(staging):
            if name.endswith(".bak.json"):
                os.unlink(os.path.join(staging, name))

    def test_cli_share_sign_outputs_json_and_nonzero_on_failure(self):
        from threshold_wallet import cli

        # 未知份额：单行 JSON 到 stderr，退出码 1
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(
                [
                    "share-sign",
                    "--data-dir", self.tmpdir,
                    "--wallet-id", "w1",
                    "--share-id", "share-9",
                    "--signing-request-id", "r",
                    "--message", "m",
                ]
            )
        self.assertEqual(code, 1)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(len(err.getvalue().strip().splitlines()), 1)
        self.assertIn("error", json.loads(err.getvalue()))

    def test_cli_share_sign_lazy_heals_and_succeeds(self):
        from threshold_wallet import cli

        # 他进程崩溃现场（可回滚）；CLI 新构造服务先恢复再读份额
        self._plant_crashed_activation_with_backup()
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(
                [
                    "share-sign",
                    "--data-dir", self.tmpdir,
                    "--wallet-id", "w1",
                    "--share-id", "share-1",
                    "--signing-request-id", "r1",
                    "--message", "m",
                ]
            )
        self.assertEqual(code, 0, err.getvalue())
        body = json.loads(out.getvalue())
        self.assertEqual(body["share_id"], "share-1")
        self.assertEqual(len(bytes.fromhex(body["signature"])), 64)

    def test_cli_share_sign_unrecoverable_exit_nonzero_json(self):
        from threshold_wallet import cli

        self._plant_unrecoverable()
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(
                [
                    "share-sign",
                    "--data-dir", self.tmpdir,
                    "--wallet-id", "w1",
                    "--share-id", "share-1",
                    "--signing-request-id", "r",
                    "--message", "m",
                ]
            )
        self.assertNotEqual(code, 0)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(len(err.getvalue().strip().splitlines()), 1)
        self.assertIn("error", json.loads(err.getvalue()))


if __name__ == "__main__":
    unittest.main()
