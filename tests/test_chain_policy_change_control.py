"""跨链确认策略纳入双人变更控制（target=chain-policy）测试。

覆盖：
- POST /v1/wallets/{W}/policy-changes 的 chain-policy 目标：请求体在原五键
  之外恰增 asset_id（原七类目标夹带 asset_id 400，chain-policy 缺
  asset_id 400）；before 取该资产当前公开策略（未配置 null）、after 恒
  非空，两者沿用原跨链策略四键与取值规则；
- 审批 message 为 target 后插入 asset_id 的 ASCII 紧凑 JSON，嵌套策略
  沿用 PUT 公开视图字段序；首次应用要求逐字匹配、approved、两位不同
  审批人且未到期，否则 409；before 漂移 409（其他资产变动不影响）；
- 首次 201 返回含 asset_id 与 seq 的视图，GET 变更查询同形；同参重放
  200 同体不复查审批期限与当前配置、不追加事件；换资产或改参数 409；
  并发同参只有一个 201，并发异参修改同一旧配置只有一个成功；
- 开关开启后原跨链 PUT 409 change control required 且零副作用，关闭时
  保留既有行为；钱包或目标资产冻结时新变更与重放 409、查询仍可用；
- 每次成功变更只追加一条 policy_change_applied（details 六键固定序含
  asset_id）；新旧策略写入混合时 GET 与后续跨链操作按 seq 取最近配置；
  重启保留结果且不补记事件；事件被篡改 fail-closed。
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

POLICY = {
    "chain_id": "bitcoin",
    "enabled": True,
    "required_confirmations": 3,
    "reorg_window": 2,
}
POLICY2 = {
    "chain_id": "bitcoin",
    "enabled": True,
    "required_confirmations": 5,
    "reorg_window": 2,
}
POLICY_ETH = {
    "chain_id": "ethereum",
    "enabled": False,
    "required_confirmations": 12,
    "reorg_window": 0,
}

TX = "aa" * 32
HASH1 = "bb" * 32


def _chain_message(change_id, asset_id, before, after):
    """chain-policy 审批单 message 的契约 ASCII 紧凑 JSON（恰五键、固定
    序，asset_id 在 target 之后）。"""
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


def _change_message(change_id, target, before, after):
    """原七类目标审批单 message 的契约 ASCII 紧凑 JSON（恰四键）。"""
    return json.dumps(
        {
            "change_id": change_id,
            "target": target,
            "before": before,
            "after": after,
        },
        ensure_ascii=True,
        separators=(",", ":"),
    )


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

    def _approved_request(self, rid, message, svc=None):
        svc = svc or self.svc
        code, _ = svc.create_sign_request("w1", rid, message)
        self.assertEqual(code, 201)
        svc.approve("w1", rid, "alice")
        svc.approve("w1", rid, "bob")

    def _apply(self, change_id, asset_id, before, after, rid, *, svc=None):
        svc = svc or self.svc
        message = _chain_message(change_id, asset_id, before, after)
        self._approved_request(rid, message, svc=svc)
        return svc.post_policy_change(
            "w1", change_id, "chain-policy", before, after, rid,
            asset_id=asset_id,
        )

    def _enable_change_control(self, change_id="cc-on", rid="r-cc"):
        message = _change_message(
            change_id, "change-control",
            {"enabled": False}, {"enabled": True},
        )
        self._approved_request(rid, message)
        code, _ = self.svc.post_policy_change(
            "w1", change_id, "change-control",
            {"enabled": False}, {"enabled": True}, rid,
        )
        self.assertEqual(code, 201)

    # ---- 首提 / 视图 / 事件 ----------------------------------------------

    def test_first_apply_201_view_get_and_policy(self):
        # 资产无需已有余额记录；未配置时 before 为 null。
        code, view = self._apply("c1", "btc", None, POLICY, "r1")
        self.assertEqual(code, 201)
        self.assertEqual(
            list(view),
            ["change_id", "target", "asset_id", "before", "after",
             "approval_request_id", "seq"],
        )
        self.assertEqual(
            view,
            {
                "change_id": "c1",
                "target": "chain-policy",
                "asset_id": "btc",
                "before": None,
                "after": POLICY,
                "approval_request_id": "r1",
                "seq": view["seq"],
            },
        )
        self.assertIsInstance(view["seq"], int)
        # 变更查询返回同一视图（含 asset_id）
        self.assertEqual(self.svc.get_policy_change("w1", "c1"), view)
        # GET 链策略即变更后配置
        self.assertEqual(self.svc.get_chain_policy("w1", "btc"), POLICY)
        # 其他资产仍未配置
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_chain_policy("w1", "eth")
        self.assertEqual(ctx.exception.status, 404)

    def test_event_shape_and_on_disk_key_order(self):
        self._apply("c1", "btc", None, POLICY, "r1")
        (event,) = self._events("policy_change_applied")
        self.assertEqual(event["request_id"], "c1")
        self.assertEqual(event["actor_id"], "r1")
        self.assertIsNone(event["reason"])
        self.assertEqual(
            list(event["details"]),
            ["change_id", "target", "asset_id", "before", "after",
             "approval_request_id"],
        )
        self.assertEqual(event["details"]["asset_id"], "btc")
        # 落盘 JSON details 六键固定序（asset_id 在 target 之后）
        with open(os.path.join(self.d, "audit", "w1.json"),
                  encoding="utf-8") as f:
            raw = f.read()
        self.assertIn(
            '"change_id": "c1",\n'
            '        "target": "chain-policy",\n'
            '        "asset_id": "btc",\n'
            '        "before": null,',
            raw,
        )

    def test_only_one_event_per_successful_change(self):
        self._apply("c1", "btc", None, POLICY, "r1")
        self._apply("c2", "btc", POLICY, POLICY2, "r2")
        events = self._events("policy_change_applied")
        self.assertEqual(len(events), 2)
        self.assertEqual(
            [e["details"]["asset_id"] for e in events], ["btc", "btc"]
        )
        # 无 legacy chain_policy 事件（变更控制路径只写 policy_change_applied）
        self.assertEqual(self._events("chain_policy"), [])

    # ---- 审批 message 契约 -------------------------------------------------

    def test_message_is_five_key_compact_json(self):
        message = _chain_message("c1", "btc", None, POLICY)
        self.assertEqual(
            message,
            '{"change_id":"c1","target":"chain-policy","asset_id":"btc",'
            '"before":null,"after":{"chain_id":"bitcoin","enabled":true,'
            '"required_confirmations":3,"reorg_window":2}}',
        )
        self._approved_request("r1", message)
        code, _ = self.svc.post_policy_change(
            "w1", "c1", "chain-policy", None, POLICY, "r1", asset_id="btc"
        )
        self.assertEqual(code, 201)

    def test_message_without_asset_id_409(self):
        # 审批 message 沿用原四键（缺 asset_id）→ 不逐字匹配，409。
        message = _change_message("c1", "chain-policy", None, POLICY)
        self._approved_request("r1", message)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "chain-policy", None, POLICY, "r1",
                asset_id="btc",
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_message_other_asset_409(self):
        # 审批 message 绑定其他资产 → 409。
        message = _chain_message("c1", "eth", None, POLICY)
        self._approved_request("r1", message)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "chain-policy", None, POLICY, "r1",
                asset_id="btc",
            )
        self.assertEqual(ctx.exception.status, 409)

    # ---- 审批门控 ----------------------------------------------------------

    def test_approval_gates(self):
        message = _chain_message("c1", "btc", None, POLICY)
        # pending（未批准）→ 409
        code, _ = self.svc.create_sign_request("w1", "r1", message)
        self.assertEqual(code, 201)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "chain-policy", None, POLICY, "r1",
                asset_id="btc",
            )
        self.assertEqual(ctx.exception.status, 409)
        # 仅一位审批人 → 409
        self.svc.approve("w1", "r1", "alice")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "chain-policy", None, POLICY, "r1",
                asset_id="btc",
            )
        self.assertEqual(ctx.exception.status, 409)
        # 两位不同审批人 → 201
        self.svc.approve("w1", "r1", "bob")
        code, _ = self.svc.post_policy_change(
            "w1", "c1", "chain-policy", None, POLICY, "r1", asset_id="btc"
        )
        self.assertEqual(code, 201)

    def test_rejected_approval_409(self):
        message = _chain_message("c1", "btc", None, POLICY)
        self.svc.create_sign_request("w1", "r1", message)
        self.svc.reject("w1", "r1", "alice")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "chain-policy", None, POLICY, "r1",
                asset_id="btc",
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_expired_approval_409(self):
        message = _chain_message("c1", "btc", None, POLICY)
        self._approved_request("r1", message)
        record = self.h.store.get_request("w1", "r1")
        record["t1"] = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat().replace("+00:00", "Z")
        self.h.store.update_request("w1", "r1", record)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "chain-policy", None, POLICY, "r1",
                asset_id="btc",
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_unknown_approval_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "chain-policy", None, POLICY, "ghost",
                asset_id="btc",
            )
        self.assertEqual(ctx.exception.status, 404)

    # ---- 重放 / 冲突 --------------------------------------------------------

    def test_replay_200_no_recheck_no_extra_event(self):
        code, view = self._apply("c1", "btc", None, POLICY, "r1")
        self.assertEqual(code, 201)
        # 再应用一笔同资产变更，使当前配置与 c1 的 after 不同
        self._apply("c2", "btc", POLICY, POLICY2, "r2")
        # 审批单回拨为已过期：重放不复查审批期限
        record = self.h.store.get_request("w1", "r1")
        record["t1"] = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat().replace("+00:00", "Z")
        self.h.store.update_request("w1", "r1", record)
        events_before = len(self._events("policy_change_applied"))
        code, replay = self.svc.post_policy_change(
            "w1", "c1", "chain-policy", None, POLICY, "r1", asset_id="btc"
        )
        self.assertEqual(code, 200)
        self.assertEqual(replay, view)
        self.assertEqual(
            len(self._events("policy_change_applied")), events_before
        )

    def test_same_change_id_different_asset_409(self):
        self._apply("c1", "btc", None, POLICY, "r1")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "chain-policy", None, POLICY, "r1",
                asset_id="eth",
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_same_change_id_different_params_409(self):
        self._apply("c1", "btc", None, POLICY, "r1")
        for before, after, rid in (
            (None, POLICY2, "r1"),  # 改 after
            (POLICY_ETH, POLICY, "r1"),  # 改 before
            (None, POLICY, "r9"),  # 改审批单
        ):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.post_policy_change(
                    "w1", "c1", "chain-policy", before, after, rid,
                    asset_id="btc",
                )
            self.assertEqual(ctx.exception.status, 409, (before, after, rid))

    def test_before_drift_409(self):
        self._apply("c1", "btc", None, POLICY, "r1")
        # before 声称 null 但该资产已配置 → 409
        message = _chain_message("c2", "btc", None, POLICY2)
        self._approved_request("r2", message)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c2", "chain-policy", None, POLICY2, "r2",
                asset_id="btc",
            )
        self.assertEqual(ctx.exception.status, 409)
        # before 与当前配置一致 → 201
        self._apply("c3", "btc", POLICY, POLICY2, "r3")

    def test_other_asset_change_does_not_affect_before(self):
        self._apply("c1", "btc", None, POLICY, "r1")
        # 其他资产（eth）的变更不影响 btc 的 before 比较
        self._apply("c2", "eth", None, POLICY_ETH, "r2")
        self._apply("c3", "btc", POLICY, POLICY2, "r3")
        self.assertEqual(self.svc.get_chain_policy("w1", "btc"), POLICY2)
        self.assertEqual(self.svc.get_chain_policy("w1", "eth"), POLICY_ETH)

    # ---- 400 / 404 ---------------------------------------------------------

    def test_asset_id_required_for_chain_policy_400(self):
        for bad in (None, "", "bad id!", 123, "x" * 129):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.post_policy_change(
                    "w1", "c1", "chain-policy", None, POLICY, "r1",
                    asset_id=bad,
                )
            self.assertEqual(ctx.exception.status, 400, bad)

    def test_asset_id_rejected_for_other_targets_400(self):
        for target, before, after in (
            ("change-control", {"enabled": False}, {"enabled": True}),
            ("approval-policy",
             {"required_approvals": 2, "timeout_seconds": 3600},
             {"required_approvals": 1, "timeout_seconds": 60}),
            ("approval-roster",
             {"allowed_approvers": []}, {"allowed_approvers": ["a"]}),
            ("transaction-policy", None,
             {"mode": "hot", "max_delta": 5, "allowed_assets": ["a"]}),
            ("dkg-failover-policy", {"enabled": False}, {"enabled": True}),
            ("nodes", None, {"nodes": {"n1": {"key": TX, "state": "up"}}}),
            ("chain-adapters", None, {"adapters": {"a1": "up"}}),
        ):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.post_policy_change(
                    "w1", "c1", target, before, after, "r1",
                    asset_id="btc",
                )
            self.assertEqual(ctx.exception.status, 400, target)

    def test_invalid_config_400(self):
        cases = [
            {},  # 缺键
            {**POLICY, "extra": 1},  # 夹带键
            {**POLICY, "chain_id": "bad id!"},
            {**POLICY, "chain_id": 1},
            {**POLICY, "enabled": "yes"},
            {**POLICY, "enabled": 1},
            {**POLICY, "required_confirmations": 0},
            {**POLICY, "required_confirmations": -1},
            {**POLICY, "required_confirmations": True},
            {**POLICY, "required_confirmations": 1.5},
            {**POLICY, "reorg_window": -1},
            {**POLICY, "reorg_window": False},
            {**POLICY, "reorg_window": 1.5},
            "not-a-dict",
        ]
        for after in cases:
            with self.assertRaises(ServiceError) as ctx:
                self.svc.post_policy_change(
                    "w1", "c1", "chain-policy", None, after, "r1",
                    asset_id="btc",
                )
            self.assertEqual(ctx.exception.status, 400, after)

    def test_after_null_400_before_nullable(self):
        # after 恒非空
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "chain-policy", None, None, "r1",
                asset_id="btc",
            )
        self.assertEqual(ctx.exception.status, 400)
        # before 非 null 时同样须为合法配置
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "chain-policy", {"bad": 1}, POLICY, "r1",
                asset_id="btc",
            )
        self.assertEqual(ctx.exception.status, 400)

    def test_unknown_wallet_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "nope", "c1", "chain-policy", None, POLICY, "r1",
                asset_id="btc",
            )
        self.assertEqual(ctx.exception.status, 404)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_policy_change("nope", "c1")
        self.assertEqual(ctx.exception.status, 404)

    def test_get_unknown_change_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_policy_change("w1", "ghost")
        self.assertEqual(ctx.exception.status, 404)

    # ---- 开关对原 PUT 的闸门 -------------------------------------------------

    def test_put_gated_when_change_control_enabled(self):
        self._enable_change_control()
        with self.assertRaises(ServiceError) as ctx:
            self.svc.put_chain_policy(
                "w1", "btc",
                POLICY["chain_id"], POLICY["enabled"],
                POLICY["required_confirmations"], POLICY["reorg_window"],
            )
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(ctx.exception.message, "change control required")
        # 零副作用：无 chain_policy 事件、策略仍未配置
        self.assertEqual(self._events("chain_policy"), [])
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_chain_policy("w1", "btc")
        self.assertEqual(ctx.exception.status, 404)

    def test_put_compatible_when_change_control_disabled(self):
        # 默认关闭：原 PUT 行为不变
        result = self.svc.put_chain_policy(
            "w1", "btc",
            POLICY["chain_id"], POLICY["enabled"],
            POLICY["required_confirmations"], POLICY["reorg_window"],
        )
        self.assertEqual(result, POLICY)
        self.assertEqual(self.svc.get_chain_policy("w1", "btc"), POLICY)
        self.assertEqual(len(self._events("chain_policy")), 1)

    # ---- 冻结闸门 ------------------------------------------------------------

    def test_wallet_frozen_blocks_new_and_replay_409(self):
        _, view = self._apply("c1", "btc", None, POLICY, "r1")
        self.svc.freeze_wallet("w1", "incident")
        # 新变更 409
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c2", "chain-policy", POLICY, POLICY2, "r2",
                asset_id="btc",
            )
        self.assertEqual(ctx.exception.status, 409)
        # 重放也 409
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "chain-policy", None, POLICY, "r1",
                asset_id="btc",
            )
        self.assertEqual(ctx.exception.status, 409)
        # 查询仍可用
        self.assertEqual(self.svc.get_policy_change("w1", "c1"), view)
        self.assertEqual(self.svc.get_chain_policy("w1", "btc"), POLICY)

    def test_asset_frozen_blocks_new_and_replay_409(self):
        # 资产冻结要求已有已提交操作：先落账（未配置链策略时可人工提交）
        code, _ = self.svc.create_asset_operation("w1", "op1", "btc", 100)
        self.assertEqual(code, 201)
        code, _ = self.svc.commit_asset_operation("w1", "op1")
        self.assertEqual(code, 201)
        _, view = self._apply("c1", "btc", None, POLICY, "r1")
        code, _ = self.svc.freeze_asset("w1", "btc", "incident")
        self.assertEqual(code, 201)
        # 新变更 409
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c2", "chain-policy", POLICY, POLICY2, "r2",
                asset_id="btc",
            )
        self.assertEqual(ctx.exception.status, 409)
        # 重放也 409
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "chain-policy", None, POLICY, "r1",
                asset_id="btc",
            )
        self.assertEqual(ctx.exception.status, 409)
        # 其他资产的变更不受影响
        self._apply("c3", "eth", None, POLICY_ETH, "r3")
        # 查询仍可用
        self.assertEqual(self.svc.get_policy_change("w1", "c1"), view)
        self.assertEqual(self.svc.get_chain_policy("w1", "btc"), POLICY)

    # ---- 混合写入按 seq 折叠 ---------------------------------------------------

    def test_mixed_legacy_and_change_fold_by_seq(self):
        # 先经原 PUT 配置（开关关闭），再经变更入口覆盖：GET 与后续跨链
        # 操作都按 seq 取最近配置。
        self.svc.put_chain_policy(
            "w1", "btc",
            POLICY["chain_id"], POLICY["enabled"],
            POLICY["required_confirmations"], POLICY["reorg_window"],
        )
        self._enable_change_control()
        code, view = self._apply("c2", "btc", POLICY, POLICY2, "r2")
        self.assertEqual(code, 201)
        self.assertEqual(view["before"], POLICY)
        self.assertEqual(self.svc.get_chain_policy("w1", "btc"), POLICY2)
        # 后续跨链操作按新策略（required_confirmations=5）门控：
        # 确认数 4 未达新门槛不提交，达 5 才自动提交。
        code, _ = self.svc.create_asset_operation("w1", "op1", "btc", 100)
        self.assertEqual(code, 201)
        code, _ = self.svc.post_chain_report(
            "w1", "op1", "bitcoin", TX, 100, HASH1, 4
        )
        self.assertEqual(code, 201)
        self.assertEqual(
            self.h.store.get_asset_operation("w1", "op1")["state"],
            "pending",
        )
        code, _ = self.svc.post_chain_report(
            "w1", "op1", "bitcoin", TX, 100, HASH1, 5
        )
        self.assertEqual(code, 201)
        self.assertEqual(
            self.h.store.get_asset_operation("w1", "op1")["state"],
            "committed",
        )

    def test_change_then_disable_control_put_reads_folded_state(self):
        # 变更入口写入后关闭开关，原 PUT 恢复可用且 before 折叠自合并流。
        self._enable_change_control()
        self._apply("c1", "btc", None, POLICY, "r1")
        message = _change_message(
            "c-off", "change-control",
            {"enabled": True}, {"enabled": False},
        )
        self._approved_request("r-off", message)
        code, _ = self.svc.post_policy_change(
            "w1", "c-off", "change-control",
            {"enabled": True}, {"enabled": False}, "r-off",
        )
        self.assertEqual(code, 201)
        # 原 PUT 恢复：同值更新也记 chain_policy 事件
        result = self.svc.put_chain_policy(
            "w1", "btc",
            POLICY2["chain_id"], POLICY2["enabled"],
            POLICY2["required_confirmations"], POLICY2["reorg_window"],
        )
        self.assertEqual(result, POLICY2)
        self.assertEqual(self.svc.get_chain_policy("w1", "btc"), POLICY2)

    # ---- 并发 / 重启 / 故障闭合 ----------------------------------------------

    def test_concurrent_same_params_single_201(self):
        message = _chain_message("c1", "btc", None, POLICY)
        self._approved_request("r1", message)
        results = []

        def fire():
            results.append(
                self.svc.post_policy_change(
                    "w1", "c1", "chain-policy", None, POLICY, "r1",
                    asset_id="btc",
                )
            )

        threads = [threading.Thread(target=fire) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        statuses = sorted(code for code, _ in results)
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(200), 7)
        self.assertEqual(len({v["seq"] for _, v in results}), 1)
        self.assertEqual(len(self._events("policy_change_applied")), 1)

    def test_concurrent_conflicting_changes_single_winner(self):
        # 两个不同变更（不同 change_id、不同 after）都以 before=null 修改
        # 同一资产的同一旧配置：只有一个首提成功，另一方 409。
        for change_id, rid, after in (
            ("c1", "r1", POLICY), ("c2", "r2", POLICY2)
        ):
            self._approved_request(
                rid, _chain_message(change_id, "btc", None, after)
            )
        outcomes = {"c1": [], "c2": []}

        def fire(change_id, rid, after):
            try:
                outcomes[change_id].append(
                    self.svc.post_policy_change(
                        "w1", change_id, "chain-policy", None, after, rid,
                        asset_id="btc",
                    )[0]
                )
            except ServiceError as exc:
                outcomes[change_id].append(exc.status)

        threads = [
            threading.Thread(target=fire, args=("c1", "r1", POLICY)),
            threading.Thread(target=fire, args=("c2", "r2", POLICY2)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        winners = [
            cid for cid, codes in outcomes.items() if 201 in codes
        ]
        self.assertEqual(len(winners), 1)
        loser = "c2" if winners[0] == "c1" else "c1"
        self.assertEqual(outcomes[loser], [409])
        self.assertEqual(len(self._events("policy_change_applied")), 1)

    def test_restart_preserves_results_no_extra_events(self):
        _, view = self._apply("c1", "btc", None, POLICY, "r1")
        svc2 = WalletService(WalletStore(self.d))
        # 结果保留：GET 变更视图与链策略一致，事件不补记
        self.assertEqual(svc2.get_policy_change("w1", "c1"), view)
        self.assertEqual(svc2.get_chain_policy("w1", "btc"), POLICY)
        events_before = len(self._events("policy_change_applied", svc=svc2))
        code, replay = svc2.post_policy_change(
            "w1", "c1", "chain-policy", None, POLICY, "r1", asset_id="btc"
        )
        self.assertEqual(code, 200)
        self.assertEqual(replay, view)
        self.assertEqual(
            len(self._events("policy_change_applied", svc=svc2)),
            events_before,
        )

    def test_dr_backup_restore_preserves_results(self):
        from threshold_wallet import drbackup

        _, view = self._apply("c1", "btc", None, POLICY, "r1")
        out_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, out_dir, ignore_errors=True)
        pack = os.path.join(out_dir, "snap.tar")
        body = drbackup.backup(self.d, "w1", "SNAP1", pack)
        self.assertEqual(body["status"], 201)
        dst = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, dst, ignore_errors=True)
        status, _ = drbackup.restore(dst, "w1", pack)
        self.assertEqual(status, 201)
        svc2 = WalletService(WalletStore(dst))
        # 灾备恢复后结果保留、不补记事件
        self.assertEqual(svc2.get_policy_change("w1", "c1"), view)
        self.assertEqual(svc2.get_chain_policy("w1", "btc"), POLICY)
        self.assertEqual(
            len(self._events("policy_change_applied", svc=svc2)), 1
        )
        code, replay = svc2.post_policy_change(
            "w1", "c1", "chain-policy", None, POLICY, "r1", asset_id="btc"
        )
        self.assertEqual(code, 200)
        self.assertEqual(replay, view)

    def test_tampered_event_fail_closed(self):
        self._apply("c1", "btc", None, POLICY, "r1")
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for event in log["events"]:
            if event["type"] == "policy_change_applied":
                # 篡改 details：after 换成别的策略（与审批 message 不符）
                event["details"]["after"] = POLICY2
                break
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises((RecoveryError, CorruptDataError)):
            WalletService(WalletStore(self.d))

    def test_tampered_details_key_order_fail_closed(self):
        self._apply("c1", "btc", None, POLICY, "r1")
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for event in log["events"]:
            if event["type"] == "policy_change_applied":
                # 重排 details 键序（asset_id 挪到末位）即不可对账现场
                details = event["details"]
                event["details"] = {
                    "change_id": details["change_id"],
                    "target": details["target"],
                    "before": details["before"],
                    "after": details["after"],
                    "approval_request_id": details["approval_request_id"],
                    "asset_id": details["asset_id"],
                }
                break
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises((RecoveryError, CorruptDataError)):
            WalletService(WalletStore(self.d))


class ChainPolicyChangeHttpTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def _create_wallet_and_policy(self, srv):
        self.assertEqual(
            srv.request(
                "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
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

    def _approve(self, srv, rid, message):
        self.assertEqual(
            srv.request(
                "POST", "/v1/wallets/w1/sign-requests",
                {"id": rid, "message": message},
            )[0],
            201,
        )
        for approver in ("alice", "bob"):
            self.assertEqual(
                srv.request(
                    "POST",
                    f"/v1/wallets/w1/sign-requests/{rid}/approve",
                    {"approver_id": approver},
                )[0],
                200,
            )

    def test_http_full_flow(self):
        with http_server(self.d) as srv:
            self._create_wallet_and_policy(srv)
            message = _chain_message("c1", "btc", None, POLICY)
            self._approve(srv, "r1", message)
            payload = {
                "change_id": "c1",
                "target": "chain-policy",
                "asset_id": "btc",
                "before": None,
                "after": POLICY,
                "approval_request_id": "r1",
            }
            code, body = srv.request(
                "POST", "/v1/wallets/w1/policy-changes", payload
            )
            self.assertEqual(code, 201)
            self.assertEqual(body["asset_id"], "btc")
            self.assertEqual(body["after"], POLICY)
            self.assertIn("seq", body)
            # 重放 200 同体
            code, replay = srv.request(
                "POST", "/v1/wallets/w1/policy-changes", payload
            )
            self.assertEqual(code, 200)
            self.assertEqual(replay, body)
            # GET 变更视图含 asset_id
            code, got = srv.request(
                "GET", "/v1/wallets/w1/policy-changes/c1"
            )
            self.assertEqual((code, got), (200, body))
            # GET 链策略即变更后配置
            code, policy = srv.request("GET", "/v1/wallets/w1/chain/btc")
            self.assertEqual((code, policy), (200, POLICY))

    def test_http_body_key_rules(self):
        with http_server(self.d) as srv:
            self._create_wallet_and_policy(srv)
            base = {
                "change_id": "c1",
                "target": "chain-policy",
                "before": None,
                "after": POLICY,
                "approval_request_id": "r1",
            }
            # chain-policy 缺 asset_id → 400
            code, _ = srv.request(
                "POST", "/v1/wallets/w1/policy-changes", base
            )
            self.assertEqual(code, 400)
            # 原七类目标夹带 asset_id → 400
            legacy = {
                "change_id": "c1",
                "target": "change-control",
                "asset_id": "btc",
                "before": {"enabled": False},
                "after": {"enabled": True},
                "approval_request_id": "r1",
            }
            code, _ = srv.request(
                "POST", "/v1/wallets/w1/policy-changes", legacy
            )
            self.assertEqual(code, 400)
            # 夹带未知键 → 400
            code, _ = srv.request(
                "POST", "/v1/wallets/w1/policy-changes",
                {**base, "asset_id": "btc", "extra": 1},
            )
            self.assertEqual(code, 400)


if __name__ == "__main__":
    unittest.main()
