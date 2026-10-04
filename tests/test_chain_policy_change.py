"""双人变更控制接入单资产跨链确认策略（target=chain-policy）测试。

覆盖：
- POST policy-changes target=chain-policy 额外要求 asset_id（仅此 target），
  原七类 target 夹带 asset_id 一律 400；asset_id 沿用安全标识、不要求已有
  余额记录；
- before 取该资产当前公开策略（未配置 null），after 沿用 PUT chain 规则；
- 审批 message 在 target 后插入 asset_id，嵌套策略用 PUT 公开视图字段序；
- 首提 201 含 seq（视图含 asset_id）、同参重放 200 不复查期限/配置/不记
  事件，换资产/改参数 409；
- 开关开启后合法 PUT chain 返回 409 change control required 且零写入；
  关闭时行为不变；
- 钱包/目标资产冻结时新变更与重放 409，查询仍可用；
- chain_policy 与 chain-policy 变更事件按 seq 混合折叠，GET 与后续跨链
  操作取该资产最近配置；派发后确认/结算沿用派发前策略；
- 重启保留结果、不补记事件。
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
from threshold_wallet import drbackup


def _chain_change_message(change_id, asset_id, before, after):
    """chain-policy 审批单 message：target 后插入 asset_id 的五键紧凑 JSON。"""
    return json.dumps(
        {
            "change_id": change_id,
            "target": "chain-policy",
            "asset_id": asset_id,
            "before": before,
            "after": after,
        },
        ensure_ascii=True,
        separators=(",", ":"),
    )


Q1 = {
    "chain_id": "eth",
    "enabled": True,
    "required_confirmations": 3,
    "reorg_window": 5,
}
Q2 = {
    "chain_id": "eth",
    "enabled": True,
    "required_confirmations": 6,
    "reorg_window": 2,
}


class ChainPolicyChangeServiceTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 2, 3600)

    def _events(self, event_type, svc=None):
        svc = svc or self.svc
        return [
            e
            for e in svc.get_audit_events("w1")["events"]
            if e["type"] == event_type
        ]

    def _approve(self, rid, message):
        code, _ = self.svc.create_sign_request("w1", rid, message)
        self.assertEqual(code, 201)
        self.svc.approve("w1", rid, "alice")
        self.svc.approve("w1", rid, "bob")

    def _enable(self):
        self._approve(
            "r-cc",
            json.dumps(
                {
                    "change_id": "cc-on",
                    "target": "change-control",
                    "before": {"enabled": False},
                    "after": {"enabled": True},
                },
                ensure_ascii=True,
                separators=(",", ":"),
            ),
        )
        code, view = self.svc.post_policy_change(
            "w1", "cc-on", "change-control",
            {"enabled": False}, {"enabled": True}, "r-cc",
        )
        self.assertEqual(code, 201)
        return view

    def _apply(self, change_id, asset_id, before, after, rid):
        self._approve(rid, _chain_change_message(
            change_id, asset_id, before, after
        ))
        return self.svc.post_policy_change(
            "w1", change_id, "chain-policy", before, after, rid,
            asset_id=asset_id,
        )

    # ---- 请求/响应形状 ---------------------------------------------------

    def test_first_config_before_null_201_view(self):
        # 资产无需已有余额记录；未配置时 before=null。
        code, view = self._apply("c1", "gold", None, Q1, "r1")
        self.assertEqual(code, 201)
        self.assertEqual(
            list(view),
            ["change_id", "target", "asset_id", "before", "after",
             "approval_request_id", "seq"],
        )
        self.assertEqual(view["change_id"], "c1")
        self.assertEqual(view["target"], "chain-policy")
        self.assertEqual(view["asset_id"], "gold")
        self.assertIsNone(view["before"])
        self.assertEqual(view["after"], Q1)
        self.assertEqual(view["approval_request_id"], "r1")
        self.assertIsInstance(view["seq"], int)
        # GET chain 公开视图取变更后的配置。
        self.assertEqual(self.svc.get_chain_policy("w1", "gold"), Q1)

    def test_event_details_six_keys_in_order(self):
        self._apply("c1", "gold", None, Q1, "r1")
        (event,) = self._events("policy_change_applied")
        self.assertEqual(event["request_id"], "c1")
        self.assertEqual(event["actor_id"], "r1")
        self.assertIsNone(event["reason"])
        self.assertEqual(
            list(event["details"]),
            ["change_id", "target", "asset_id", "before", "after",
             "approval_request_id"],
        )
        self.assertEqual(event["details"]["asset_id"], "gold")
        self.assertEqual(event["details"]["after"], Q1)

    def test_get_policy_change_returns_asset_id(self):
        code, view = self._apply("c1", "gold", None, Q1, "r1")
        self.assertEqual(code, 201)
        self.assertEqual(
            self.svc.get_policy_change("w1", "c1"), view
        )

    # ---- 400 / 404 -------------------------------------------------------

    def test_asset_id_required_for_chain_policy(self):
        self._enable()
        self._approve("r1", _chain_change_message("c1", "gold", None, Q1))
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "chain-policy", None, Q1, "r1",
                asset_id=None,
            )
        self.assertEqual(ctx.exception.status, 400)

    def test_asset_id_smuggled_on_other_target_400(self):
        for target, before, after in (
            ("change-control", {"enabled": False}, {"enabled": True}),
            ("nodes", None,
             {"nodes": {"n1": {"key": "aa" * 32, "state": "up"}}}),
        ):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.post_policy_change(
                    "w1", "cx", target, before, after, "r1",
                    asset_id="gold",
                )
            self.assertEqual(ctx.exception.status, 400, target)

    def test_invalid_asset_id_400(self):
        for bad in ("", "bad id!", 123, None, "x" * 129):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.post_policy_change(
                    "w1", "c1", "chain-policy", None, Q1, "r1",
                    asset_id=bad,
                )
            self.assertEqual(ctx.exception.status, 400, bad)

    def test_invalid_chain_config_400(self):
        bad_cases = [
            None,
            {},
            {"chain_id": "eth", "enabled": True,
             "required_confirmations": 3},  # 缺 reorg_window
            {"chain_id": "eth", "enabled": True,
             "required_confirmations": 0, "reorg_window": 1},
            {"chain_id": "eth", "enabled": True,
             "required_confirmations": 3, "reorg_window": -1},
            {"chain_id": "eth", "enabled": "yes",
             "required_confirmations": 3, "reorg_window": 1},
            {"chain_id": "bad id", "enabled": True,
             "required_confirmations": 3, "reorg_window": 1},
            {"chain_id": "eth", "enabled": False,
             "required_confirmations": 3, "reorg_window": 1, "extra": 1},
        ]
        for after in bad_cases:
            with self.assertRaises(ServiceError) as ctx:
                self.svc.post_policy_change(
                    "w1", "c1", "chain-policy", None, after, "r1",
                    asset_id="gold",
                )
            self.assertEqual(ctx.exception.status, 400, after)

    def test_after_null_400(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "chain-policy", None, None, "r1",
                asset_id="gold",
            )
        self.assertEqual(ctx.exception.status, 400)

    def test_unknown_approval_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "chain-policy", None, Q1, "ghost",
                asset_id="gold",
            )
        self.assertEqual(ctx.exception.status, 404)

    # ---- 审批 / 冲突 -----------------------------------------------------

    def test_message_must_include_asset_id(self):
        # 审批 message 缺少 asset_id（四键旧形）→ 409。
        self.svc.create_sign_request("w1", "r1", json.dumps(
            {"change_id": "c1", "target": "chain-policy",
             "before": None, "after": Q1},
            ensure_ascii=True, separators=(",", ":"),
        ))
        self.svc.approve("w1", "r1", "alice")
        self.svc.approve("w1", "r1", "bob")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "chain-policy", None, Q1, "r1",
                asset_id="gold",
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_before_drift_409(self):
        self._apply("c1", "gold", None, Q1, "r1")
        # 当前是 Q1，却声称 before=null。
        with self.assertRaises(ServiceError) as ctx:
            self._apply("c2", "gold", None, Q2, "r2")
        self.assertEqual(ctx.exception.status, 409)

    def test_other_asset_change_does_not_affect_before(self):
        self._apply("c1", "gold", None, Q1, "r1")
        # silver 的首配 before 仍为 null，不受 gold 变更影响。
        code, _ = self._apply("c2", "silver", None, Q2, "r2")
        self.assertEqual(code, 201)
        self.assertEqual(self.svc.get_chain_policy("w1", "gold"), Q1)
        self.assertEqual(self.svc.get_chain_policy("w1", "silver"), Q2)

    def test_replay_200_then_change_asset_or_params_409(self):
        code, view = self._apply("c1", "gold", None, Q1, "r1")
        self.assertEqual(code, 201)
        events_before = len(self._events("policy_change_applied"))
        # 同参重放 200 同体，不记事件。
        code, replay = self.svc.post_policy_change(
            "w1", "c1", "chain-policy", None, Q1, "r1", asset_id="gold",
        )
        self.assertEqual((code, replay), (200, view))
        self.assertEqual(
            len(self._events("policy_change_applied")), events_before
        )
        # 换资产 409
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "chain-policy", None, Q1, "r1",
                asset_id="silver",
            )
        self.assertEqual(ctx.exception.status, 409)
        # 改参数 409
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "chain-policy", None, Q2, "r1",
                asset_id="gold",
            )
        self.assertEqual(ctx.exception.status, 409)

    # ---- 开关 PUT 闸门 ----------------------------------------------------

    def test_put_chain_gated_when_enabled_but_free_when_disabled(self):
        # 关闭时 PUT chain 行为不变。
        self.svc.put_chain_policy(
            "w1", "gold", "eth", True, 3, 5
        )
        self._enable()
        # 开启后合法 PUT 409 change control required，且零写入。
        with self.assertRaises(ServiceError) as ctx:
            self.svc.put_chain_policy("w1", "gold", "eth", False, 9, 1)
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(ctx.exception.message, "change control required")
        self.assertEqual(
            self.svc.get_chain_policy("w1", "gold"),
            {"chain_id": "eth", "enabled": True,
             "required_confirmations": 3, "reorg_window": 5},
        )
        self.assertEqual(self._events("chain_policy")[0]["details"], Q1)

    def test_change_overwrites_legacy_put_by_seq(self):
        # 关闭时 PUT 建策略，开启后经统一入口覆盖：GET 取后者。
        self.svc.put_chain_policy("w1", "gold", "eth", True, 3, 5)
        self._enable()
        code, _ = self._apply("c1", "gold", Q1, Q2, "r1")
        self.assertEqual(code, 201)
        self.assertEqual(self.svc.get_chain_policy("w1", "gold"), Q2)
        # 再经统一入口更新 before 为 Q2。
        code, _ = self._apply(
            "c2", "gold", Q2,
            {"chain_id": "eth", "enabled": False,
             "required_confirmations": 6, "reorg_window": 2},
            "r2",
        )
        self.assertEqual(code, 201)

    # ---- 冻结闸门 ---------------------------------------------------------

    def _commit_asset(self, asset_id, operation_id):
        self.svc.create_asset_operation(
            "w1", operation_id, asset_id, 10
        )
        self.svc.commit_asset_operation("w1", operation_id)

    def test_wallet_frozen_new_change_and_replay_409(self):
        self._apply("c1", "gold", None, Q1, "r1")
        self.svc.freeze_wallet("w1", "incident")
        # 新变更 409
        with self.assertRaises(ServiceError) as ctx:
            self._apply("c2", "gold", Q1, Q2, "r2")
        self.assertEqual(ctx.exception.status, 409)
        # 同参重放也 409
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "chain-policy", None, Q1, "r1",
                asset_id="gold",
            )
        self.assertEqual(ctx.exception.status, 409)
        # 查询仍可用
        self.assertEqual(
            self.svc.get_policy_change("w1", "c1")["asset_id"], "gold"
        )
        self.assertEqual(self.svc.get_chain_policy("w1", "gold"), Q1)

    def test_asset_frozen_new_change_and_replay_409(self):
        # 资产冻结要求该资产有已提交余额。
        self._commit_asset("gold", "op-1")
        self._apply("c1", "gold", None, Q1, "r1")
        self.svc.freeze_asset("w1", "gold", "asset incident")
        with self.assertRaises(ServiceError) as ctx:
            self._apply("c2", "gold", Q1, Q2, "r2")
        self.assertEqual(ctx.exception.status, 409)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "chain-policy", None, Q1, "r1",
                asset_id="gold",
            )
        self.assertEqual(ctx.exception.status, 409)
        # 另一资产不受影响。
        code, _ = self._apply("c3", "silver", None, Q2, "r3")
        self.assertEqual(code, 201)
        # 查询仍可用
        self.assertEqual(self.svc.get_chain_policy("w1", "gold"), Q1)

    # ---- 派发前策略固定 ---------------------------------------------------

    def test_post_dispatch_confirm_uses_pre_dispatch_policy(self):
        # 关闭状态经 PUT 配置策略（3 确认、reorg_window 2）。
        self.svc.create_asset_operation("w1", "op1", "BTC", 100)
        self.svc.put_chain_policy("w1", "BTC", "chain-1", True, 3, 2)
        message = json.dumps(
            {"operation_id": "op1", "dispatch_id": "dp1",
             "adapter_id": "ad1", "chain_id": "chain-1"},
            ensure_ascii=False, separators=(",", ":"),
        )
        code, _ = self.svc.create_sign_request("w1", "ap1", message)
        self.assertEqual(code, 201)
        self.svc.approve("w1", "ap1", "boss")
        self.svc.approve("w1", "ap1", "ceo")
        code, _ = self.svc.post_chain_dispatch(
            "w1", "op1", "dp1", "ad1", "ap1"
        )
        self.assertEqual(code, 201)
        code, _ = self.svc.post_chain_dispatch_result(
            "w1", "dp1", "ad1", "broadcasted", "ab" * 32
        )
        self.assertEqual(code, 201)

        # 派发后开启变更控制并把策略改为 9 确认、reorg_window 0。
        self._enable()
        old_q = {
            "chain_id": "chain-1", "enabled": True,
            "required_confirmations": 3, "reorg_window": 2,
        }
        new_q = {
            "chain_id": "chain-1", "enabled": True,
            "required_confirmations": 9, "reorg_window": 0,
        }
        code, _ = self._apply("c1", "BTC", old_q, new_q, "r1")
        self.assertEqual(code, 201)
        # GET 取最近配置（9 确认）。
        self.assertEqual(
            self.svc.get_chain_policy("w1", "BTC"), new_q
        )

        # 派发后的确认仍沿用派发前策略：3 确认即 finalized，且旧窗口 2
        # 允许高度回退。先报高度 10、确认 3。
        code, view = self.svc.post_chain_dispatch_confirmation(
            "w1", "dp1", "ad1", "ab" * 32, 10, "01" * 32, 3
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "finalized")
        # 结算成功（操作 pending，finalized）。
        code, settled = self.svc.settle_chain_dispatch("w1", "dp1")
        self.assertEqual(code, 201)
        self.assertEqual(settled["state"], "committed")

    # ---- 损坏 fail-closed / 灾备 -----------------------------------------

    def test_tampered_chain_policy_change_fail_closed(self):
        self._apply("c1", "gold", None, Q1, "r1")
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for event in log["events"]:
            if (
                event["type"] == "policy_change_applied"
                and event["details"].get("target") == "chain-policy"
            ):
                # 破坏 after 配置（required_confirmations 非法）。
                event["details"]["after"]["required_confirmations"] = 0
                break
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises((RecoveryError, CorruptDataError)):
            WalletService(WalletStore(self.d))

    def test_backup_restore_preserves_chain_policy_change(self):
        self._enable()
        code, view = self._apply("c1", "gold", None, Q1, "r1")
        self.assertEqual(code, 201)
        out_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, out_dir, ignore_errors=True)
        out = os.path.join(out_dir, "snap.tar")
        body = drbackup.backup(self.d, "w1", "snap1", out)
        self.assertEqual(body["status"], 201)
        dst = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, dst, ignore_errors=True)
        status, restored = drbackup.restore(dst, "w1", out)
        self.assertEqual(status, 201)
        svc2 = WalletService(WalletStore(dst))
        self.assertEqual(svc2.get_chain_policy("w1", "gold"), Q1)
        self.assertEqual(
            svc2.get_policy_change("w1", "c1"), view
        )
        self.assertEqual(svc2.get_change_control("w1"),
                         {"enabled": True})

    # ---- 重启 -------------------------------------------------------------

    def test_concurrent_distinct_changes_same_before_one_wins(self):
        # 两个不同变更都以 before=null 修改同一资产首配：先成功者 201，
        # 另一方 before 漂移 409。
        for rid, cid in (("r1", "c1"), ("r2", "c2")):
            self._approve(
                rid, _chain_change_message(cid, "gold", None, Q1)
            )
        results = []

        def fire(cid, rid):
            try:
                results.append(
                    self.svc.post_policy_change(
                        "w1", cid, "chain-policy", None, Q1, rid,
                        asset_id="gold",
                    )
                )
            except ServiceError as exc:
                results.append((exc.status, exc.message))

        threads = [
            threading.Thread(target=fire, args=("c1", "r1")),
            threading.Thread(target=fire, args=("c2", "r2")),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        statuses = sorted(r[0] for r in results)
        self.assertEqual(statuses, [201, 409])
        self.assertEqual(self.svc.get_chain_policy("w1", "gold"), Q1)
        self.assertEqual(
            len(self._events("policy_change_applied")), 1
        )

    def test_restart_preserves_and_replays_without_extra_event(self):
        code, view = self._apply("c1", "gold", None, Q1, "r1")
        self.assertEqual(code, 201)
        svc2 = WalletService(WalletStore(self.d))
        self.assertEqual(svc2.get_chain_policy("w1", "gold"), Q1)
        before = len(svc2.get_audit_events("w1")["events"])
        code, replay = svc2.post_policy_change(
            "w1", "c1", "chain-policy", None, Q1, "r1", asset_id="gold",
        )
        self.assertEqual(code, 200)
        self.assertEqual(replay, view)
        self.assertEqual(
            len(svc2.get_audit_events("w1")["events"]), before
        )


class ChainPolicyChangeHttpTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def test_http_asset_id_key_rules_and_gating(self):
        with http_server(self.d) as srv:
            self.assertEqual(
                srv.request(
                    "POST", "/v1/wallets",
                    {"wallet_id": "w1", "shares": 2},
                )[0],
                201,
            )
            self.assertEqual(
                srv.request(
                    "PUT", "/v1/wallets/w1/approval-policy",
                    {"required_approvals": 2, "timeout_seconds": 3600},
                )[0],
                200,
            )

            def approve(rid, message):
                self.assertEqual(
                    srv.request(
                        "POST", "/v1/wallets/w1/sign-requests",
                        {"id": rid, "message": message},
                    )[0],
                    201,
                )
                for who in ("alice", "bob"):
                    self.assertEqual(
                        srv.request(
                            "POST",
                            f"/v1/wallets/w1/sign-requests/{rid}/approve",
                            {"approver_id": who},
                        )[0],
                        200,
                    )

            # 开启变更控制
            approve("rcc", json.dumps(
                {"change_id": "cc", "target": "change-control",
                 "before": {"enabled": False}, "after": {"enabled": True}},
                ensure_ascii=True, separators=(",", ":"),
            ))
            code, _ = srv.request(
                "POST", "/v1/wallets/w1/policy-changes",
                {"change_id": "cc", "target": "change-control",
                 "before": {"enabled": False}, "after": {"enabled": True},
                 "approval_request_id": "rcc"},
            )
            self.assertEqual(code, 201)

            # 开启后 PUT chain 409
            code, _ = srv.request(
                "PUT", "/v1/wallets/w1/chain/gold", Q1
            )
            self.assertEqual(code, 409)

            # chain-policy 缺 asset_id 键 → 400
            approve("r1", _chain_change_message("c1", "gold", None, Q1))
            code, _ = srv.request(
                "POST", "/v1/wallets/w1/policy-changes",
                {"change_id": "c1", "target": "chain-policy",
                 "before": None, "after": Q1,
                 "approval_request_id": "r1"},
            )
            self.assertEqual(code, 400)

            # 合法六键首提 201
            code, body = srv.request(
                "POST", "/v1/wallets/w1/policy-changes",
                {"change_id": "c1", "target": "chain-policy",
                 "asset_id": "gold", "before": None, "after": Q1,
                 "approval_request_id": "r1"},
            )
            self.assertEqual(code, 201)
            self.assertEqual(body["asset_id"], "gold")
            self.assertIsNone(body["before"])
            self.assertEqual(body["after"], Q1)

            # 原七类 target 夹带 asset_id → 400
            code, _ = srv.request(
                "POST", "/v1/wallets/w1/policy-changes",
                {"change_id": "cx", "target": "change-control",
                 "asset_id": "gold",
                 "before": {"enabled": True}, "after": {"enabled": False},
                 "approval_request_id": "r1"},
            )
            self.assertEqual(code, 400)

            # GET 变更视图与 GET chain 都返回新配置
            code, got = srv.request(
                "GET", "/v1/wallets/w1/policy-changes/c1"
            )
            self.assertEqual((code, got), (200, body))
            code, chain = srv.request(
                "GET", "/v1/wallets/w1/chain/gold"
            )
            self.assertEqual((code, chain), (200, Q1))


if __name__ == "__main__":
    unittest.main()
