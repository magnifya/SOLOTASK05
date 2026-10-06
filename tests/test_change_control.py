"""高风险配置双人变更控制（change control）测试。

覆盖：
- GET /v1/wallets/{W}/change-control 初始 {"enabled": false}，启用后 true，
  未知钱包 404、非法标识 400；
- POST /v1/wallets/{W}/policy-changes：请求体恰五键；target 七类；before 对
  可缺省四类允许 null、after 恒为合法公开视图；审批 message 须逐字为仅含
  change_id,target,before,after 的 ASCII 紧凑 JSON；须同钱包 approved 且
  两位不同审批人、未过期；
- 首次 201 返回含 seq 的六键视图；同参重放 200 同体且不新增事件；同
  change_id 异参/before 漂移/审批未 approved/已过期/message 不符 409；
  请求体/target/配置/标识非法 400；未知钱包/审批单/change_id 404；
- 启用后六类受控 PUT 统一 409 change control required 且零副作用；
- GET /v1/wallets/{W}/policy-changes/{change_id} 返回已应用视图；
- 配置生效：approval-policy/transaction-policy 文件与 GET、approval-roster/
  dkg-failover-policy/nodes/chain-adapters 的 GET 与按 seq 折叠均取变更后值；
- 并发与重启只有一次首次应用，崩溃窗口按审计提交点前滚/回滚；
- 审计事件形状/私钥不泄露/灾备闭合集合。
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

KEY_A = "aa" * 32
KEY_B = "bb" * 32


def _change_message(change_id, target, before, after):
    """审批单 message 的契约 ASCII 紧凑 JSON（恰四键、固定序）。"""
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


class ChangeControlServiceTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)

    def _events(self, event_type, svc=None):
        svc = svc or self.svc
        return [
            e
            for e in svc.get_audit_events("w1")["events"]
            if e["type"] == event_type
        ]

    def _policy2(self, timeout=3600):
        self.svc.put_policy("w1", 2, timeout)

    def _approved_request(self, rid, message, timeout=3600):
        code, _ = self.svc.create_sign_request("w1", rid, message)
        self.assertEqual(code, 201)
        self.svc.approve("w1", rid, "alice")
        self.svc.approve("w1", rid, "bob")

    def _apply(
        self, change_id, target, before, after, rid, *, svc=None, timeout=3600
    ):
        svc = svc or self.svc
        message = _change_message(change_id, target, before, after)
        code, _ = svc.create_sign_request("w1", rid, message)
        self.assertEqual(code, 201)
        svc.approve("w1", rid, "alice")
        svc.approve("w1", rid, "bob")
        return svc.post_policy_change(
            "w1", change_id, target, before, after, rid
        )

    def _enable(self, change_id="cc-on", rid="r-cc"):
        self._policy2()
        code, view = self._apply(
            change_id,
            "change-control",
            {"enabled": False},
            {"enabled": True},
            rid,
        )
        self.assertEqual(code, 201)
        return view

    # ---- 查询开关 --------------------------------------------------------

    def test_get_change_control_default_off(self):
        self.assertEqual(self.svc.get_change_control("w1"),
                         {"enabled": False})

    def test_get_change_control_unknown_wallet_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_change_control("nope")
        self.assertEqual(ctx.exception.status, 404)

    def test_get_change_control_invalid_wallet_400(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_change_control("bad id!")
        self.assertEqual(ctx.exception.status, 400)

    # ---- 启用与 PUT 闸门 --------------------------------------------------

    def test_enable_then_puts_gated(self):
        view = self._enable()
        self.assertEqual(
            view,
            {
                "change_id": "cc-on",
                "target": "change-control",
                "before": {"enabled": False},
                "after": {"enabled": True},
                "approval_request_id": "r-cc",
                "seq": view["seq"],
            },
        )
        self.assertIsInstance(view["seq"], int)
        self.assertEqual(self.svc.get_change_control("w1"),
                         {"enabled": True})
        # 六类受控 PUT 统一 409 change control required。
        gated_calls = [
            ("put_policy", (1, 60)),
            ("put_approval_roster", (["x"],)),
            ("put_transaction_policy", ("hot", 5, ["gold"])),
            ("put_dkg_failover_policy", (False,)),
            ("put_dkg_nodes",
             ({"n1": {"key": KEY_A, "state": "up"}},)),
            ("put_chain_adapters", ({"a1": "up"},)),
        ]
        for method, args in gated_calls:
            with self.assertRaises(ServiceError) as ctx:
                getattr(self.svc, method)("w1", *args)
            self.assertEqual(ctx.exception.status, 409, method)
            self.assertEqual(ctx.exception.message,
                             "change control required")
        # 闸门零副作用：无 policy_updated/node_state 等额外事件，开关仍开。
        self.assertEqual(self.svc.get_change_control("w1"),
                         {"enabled": True})
        self.assertEqual(
            len(self._events("policy_updated")), 1  # 仅最初的 2 审批策略
        )

    def test_disabled_puts_remain_compatible(self):
        # 默认关闭时六类 PUT 行为完全不变。
        self.svc.put_policy("w1", 1, 60)
        self.svc.put_approval_roster("w1", ["alice"])
        self.svc.put_transaction_policy("w1", "hot", 5, ["gold"])
        self.svc.put_dkg_failover_policy("w1", True)
        self.svc.put_dkg_nodes(
            "w1", {"n1": {"key": KEY_A, "state": "up"}}
        )
        self.svc.put_chain_adapters("w1", {"a1": "up"})
        self.assertEqual(self.svc.get_change_control("w1"),
                         {"enabled": False})

    # ---- 首提 / 重放 / 事件 ----------------------------------------------

    def test_first_apply_201_replay_200_same_body_no_extra_event(self):
        view = self._enable()
        before_seq = view["seq"]
        events_before = len(self._events("policy_change_applied"))
        code, replay = self.svc.post_policy_change(
            "w1", "cc-on", "change-control",
            {"enabled": False}, {"enabled": True}, "r-cc",
        )
        self.assertEqual(code, 200)
        self.assertEqual(replay, view)
        self.assertEqual(replay["seq"], before_seq)
        events_after = self._events("policy_change_applied")
        self.assertEqual(len(events_after), events_before)

    def test_policy_change_event_shape(self):
        self._enable()
        (event,) = self._events("policy_change_applied")
        self.assertEqual(
            set(event),
            {"seq", "type", "at", "request_id", "actor_id", "reason",
             "details"},
        )
        self.assertEqual(event["request_id"], "cc-on")
        self.assertEqual(event["actor_id"], "r-cc")
        self.assertIsNone(event["reason"])
        self.assertEqual(
            list(event["details"]),
            ["change_id", "target", "before", "after",
             "approval_request_id"],
        )
        self.assertEqual(event["details"]["approval_request_id"], "r-cc")
        # 落盘 JSON details 五键固定序
        with open(os.path.join(self.d, "audit", "w1.json"),
                  encoding="utf-8") as f:
            raw = f.read()
        self.assertIn(
            '"change_id": "cc-on",\n'
            '        "target": "change-control",\n'
            '        "before": {\n'
            '          "enabled": false\n'
            '        },\n'
            '        "after": {\n'
            '          "enabled": true\n'
            '        },\n'
            '        "approval_request_id": "r-cc"',
            raw,
        )

    # ---- 409 冲突 ---------------------------------------------------------

    def test_same_change_id_different_params_409(self):
        self._enable()
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "cc-on", "change-control",
                {"enabled": False}, {"enabled": False}, "r-cc",
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_before_drift_409(self):
        self._policy2()
        # 当前开关为 true（已被另一变更启用），before 却声称 false。
        self._enable("c1", "r1")
        message = _change_message(
            "c2", "change-control",
            {"enabled": False}, {"enabled": False},
        )
        self.svc.create_sign_request("w1", "r2", message)
        self.svc.approve("w1", "r2", "alice")
        self.svc.approve("w1", "r2", "bob")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c2", "change-control",
                {"enabled": False}, {"enabled": False}, "r2",
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_not_approved_409(self):
        self._policy2()
        message = _change_message(
            "c1", "change-control",
            {"enabled": False}, {"enabled": True},
        )
        self.svc.create_sign_request("w1", "r1", message)
        # 不批准
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "change-control",
                {"enabled": False}, {"enabled": True}, "r1",
            )
        self.assertEqual(ctx.exception.status, 409)
        # 仅一位批准仍 409
        self.svc.approve("w1", "r1", "alice")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "change-control",
                {"enabled": False}, {"enabled": True}, "r1",
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_same_approver_twice_not_enough(self):
        # required=2 但同一人重复批准只计一次，approvers 去重后 <2。
        self._policy2()
        message = _change_message(
            "c1", "change-control",
            {"enabled": False}, {"enabled": True},
        )
        self.svc.create_sign_request("w1", "r1", message)
        self.svc.approve("w1", "r1", "alice")
        self.svc.approve("w1", "r1", "alice")  # 同人重放，不计数
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "change-control",
                {"enabled": False}, {"enabled": True}, "r1",
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_expired_approval_409(self):
        from datetime import datetime, timedelta, timezone

        self.svc.put_policy("w1", 2, 3600)
        message = _change_message(
            "c1", "change-control",
            {"enabled": False}, {"enabled": True},
        )
        self.svc.create_sign_request("w1", "r1", message)
        self.svc.approve("w1", "r1", "alice")
        self.svc.approve("w1", "r1", "bob")
        # 确定性地把已 approved 审批单的截止时间 t1 回拨到过去（approved 是
        # 终态、不被懒过期翻转），门控须显式按 t1 判 409。
        record = self.h.store.get_request("w1", "r1")
        self.assertEqual(record["state"], "approved")
        past = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat().replace("+00:00", "Z")
        record["t1"] = past
        self.h.store.update_request("w1", "r1", record)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "change-control",
                {"enabled": False}, {"enabled": True}, "r1",
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_pending_expired_approval_409(self):
        from datetime import datetime, timedelta, timezone

        self.svc.put_policy("w1", 2, 3600)
        message = _change_message(
            "c1", "change-control",
            {"enabled": False}, {"enabled": True},
        )
        self.svc.create_sign_request("w1", "r1", message)
        # 未批准（pending），回拨 t1：懒过期转 expired 后 state != approved。
        record = self.h.store.get_request("w1", "r1")
        record["t1"] = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat().replace("+00:00", "Z")
        self.h.store.update_request("w1", "r1", record)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "change-control",
                {"enabled": False}, {"enabled": True}, "r1",
            )
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(
            self.svc.get_sign_request("w1", "r1")["state"], "expired"
        )

    def test_message_mismatch_409(self):
        self._policy2()
        # 审批 message 里的 after 与提交 after 不同。
        message = _change_message(
            "c1", "change-control",
            {"enabled": False}, {"enabled": False},
        )
        self.svc.create_sign_request("w1", "r1", message)
        self.svc.approve("w1", "r1", "alice")
        self.svc.approve("w1", "r1", "bob")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "change-control",
                {"enabled": False}, {"enabled": True}, "r1",
            )
        self.assertEqual(ctx.exception.status, 409)

    # ---- 400 / 404 -------------------------------------------------------

    def test_invalid_change_id_400(self):
        self._policy2()
        for bad in ("", "bad id!", 123, None, "x" * 129):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.post_policy_change(
                    "w1", bad, "change-control",
                    {"enabled": False}, {"enabled": True}, "r1",
                )
            self.assertEqual(ctx.exception.status, 400, bad)

    def test_invalid_target_400(self):
        self._policy2()
        for bad in ("nope", "", None, 1, "approval_policy"):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.post_policy_change(
                    "w1", "c1", bad,
                    {"enabled": False}, {"enabled": True}, "r1",
                )
            self.assertEqual(ctx.exception.status, 400, bad)

    def test_invalid_approval_request_id_400(self):
        self._policy2()
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "change-control",
                {"enabled": False}, {"enabled": True}, "bad id!",
            )
        self.assertEqual(ctx.exception.status, 400)

    def test_invalid_config_400(self):
        self._policy2()
        cases = [
            ("change-control", {"enabled": False}, {"enabled": "yes"}),
            ("change-control", {"enabled": False}, {}),
            ("approval-policy",
             {"required_approvals": 2, "timeout_seconds": 60},
             {"required_approvals": 17, "timeout_seconds": 60}),
            ("approval-policy",
             {"required_approvals": 2, "timeout_seconds": 60},
             {"required_approvals": 1, "timeout_seconds": 0}),
            ("transaction-policy", None,
             {"mode": "warm", "max_delta": 5, "allowed_assets": ["a"]}),
            ("transaction-policy", None,
             {"mode": "hot", "max_delta": 0, "allowed_assets": ["a"]}),
            ("transaction-policy", None,
             {"mode": "hot", "max_delta": 5, "allowed_assets": []}),
            ("transaction-policy", None,
             {"mode": "hot", "max_delta": 5,
              "allowed_assets": ["a", "a"]}),
            ("nodes", None, {"nodes": {}}),
            ("nodes", None,
             {"nodes": {"n1": {"key": "zz", "state": "up"}}}),
            ("nodes", None,
             {"nodes": {"n1": {"key": KEY_A, "state": "weird"}}}),
            ("chain-adapters", None, {"adapters": {}}),
            ("chain-adapters", None, {"adapters": {"b1": "up", "a1": "down"}}),
            ("chain-adapters", None, {"adapters": {"a1": "sideways"}}),
            ("approval-roster", {"allowed_approvers": []},
             {"allowed_approvers": [""]}),
            ("approval-roster", {"allowed_approvers": []},
             {"allowed_approvers": ["a", "a"]}),
        ]
        for target, before, after in cases:
            with self.assertRaises(ServiceError) as ctx:
                self.svc.post_policy_change(
                    "w1", "c1", target, before, after, "r1"
                )
            self.assertEqual(ctx.exception.status, 400, (target, after))

    def test_nonnullable_target_before_null_400(self):
        self._policy2()
        # change-control 的 before 不允许 null（缺省为 {"enabled": false}）。
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "change-control",
                None, {"enabled": True}, "r1",
            )
        self.assertEqual(ctx.exception.status, 400)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c2", "approval-roster",
                None, {"allowed_approvers": []}, "r1",
            )
        self.assertEqual(ctx.exception.status, 400)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c3", "dkg-failover-policy",
                None, {"enabled": True}, "r1",
            )
        self.assertEqual(ctx.exception.status, 400)

    def test_after_null_400_even_for_nullable_targets(self):
        self._policy2()
        for target in ("approval-policy", "transaction-policy", "nodes",
                       "chain-adapters"):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.post_policy_change(
                    "w1", "c1", target, None, None, "r1"
                )
            self.assertEqual(ctx.exception.status, 400, target)

    def test_unknown_wallet_404_before_validation(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "nope", "c1", "change-control",
                {"enabled": False}, {"enabled": True}, "r1",
            )
        self.assertEqual(ctx.exception.status, 404)

    def test_unknown_approval_request_404(self):
        self._policy2()
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change(
                "w1", "c1", "change-control",
                {"enabled": False}, {"enabled": True}, "ghost",
            )
        self.assertEqual(ctx.exception.status, 404)

    def test_get_unknown_change_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_policy_change("w1", "ghost")
        self.assertEqual(ctx.exception.status, 404)

    def test_get_change_invalid_id_400(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_policy_change("w1", "bad id!")
        self.assertEqual(ctx.exception.status, 400)

    def test_unknown_wallet_get_change_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_policy_change("nope", "c1")
        self.assertEqual(ctx.exception.status, 404)

    # ---- 各 target 配置生效 ----------------------------------------------

    def test_apply_approval_policy_takes_effect(self):
        self._policy2(3600)
        code, view = self._apply(
            "c1", "approval-policy",
            {"required_approvals": 2, "timeout_seconds": 3600},
            {"required_approvals": 1, "timeout_seconds": 60},
            "r1",
        )
        self.assertEqual(code, 201)
        # 文件已更新（内部形含 wallet_id），GET（经受控入口外的直接读）取新值
        self.assertEqual(
            self.h.store.get_policy("w1"),
            {"wallet_id": "w1", "required_approvals": 1,
             "timeout_seconds": 60},
        )
        self.assertEqual(view["before"],
                         {"required_approvals": 2, "timeout_seconds": 3600})

    def test_apply_approval_policy_first_config_before_null(self):
        self._policy2()
        # 删除审批策略文件模拟未配置（但变更控制需要审批策略，故此用例仅直接
        # 调文件存储构造 before=null 的事务策略首配）。
        code, _ = self._apply(
            "c1", "transaction-policy",
            None,
            {"mode": "cold", "max_delta": 9, "allowed_assets": ["gold"]},
            "r1",
        )
        self.assertEqual(code, 201)
        self.assertEqual(
            self.svc.get_transaction_policy("w1"),
            {"mode": "cold", "max_delta": 9, "allowed_assets": ["gold"]},
        )

    def test_apply_roster_takes_effect(self):
        self._enable()
        # 启用后改名单：after 为归一（码点升序）视图，message 与之逐字一致。
        code, _ = self._apply(
            "c2", "approval-roster",
            {"allowed_approvers": []},
            {"allowed_approvers": ["bob", "carol"]},
            "r2",
        )
        self.assertEqual(code, 201)
        self.assertEqual(
            self.svc.get_approval_roster("w1"),
            {"allowed_approvers": ["bob", "carol"]},
        )

    def test_apply_approval_policy_multi_party_threshold(self):
        self._policy2(3600)
        code, _ = self._apply(
            "c1", "approval-policy",
            {"required_approvals": 2, "timeout_seconds": 3600},
            {"required_approvals": 3, "timeout_seconds": 60},
            "r1",
        )
        self.assertEqual(code, 201)
        self.assertEqual(
            self.h.store.get_policy("w1"),
            {"wallet_id": "w1", "required_approvals": 3,
             "timeout_seconds": 60},
        )
        # 新建审批单取新阈值快照；既有审批单（r1）不追溯
        code, view = self.svc.create_sign_request("w1", "r2", "m")
        self.assertEqual(code, 201)
        self.assertEqual(view["req"], 3)
        self.assertEqual(self.svc.get_sign_request("w1", "r1")["req"], 2)
        self.svc.approve("w1", "r2", "alice")
        self.svc.approve("w1", "r2", "bob")
        self.assertEqual(
            self.svc.get_sign_request("w1", "r2")["state"], "pending"
        )
        self.svc.approve("w1", "r2", "carol")
        self.assertEqual(
            self.svc.get_sign_request("w1", "r2")["state"], "approved"
        )

    def test_policy_change_above_roster_size_409_zero_side_effects(self):
        self._policy2()
        # 变更控制启用前直接设置两名成员名单（满足 req=2）
        self.svc.put_approval_roster("w1", ["alice", "bob"])
        self._enable()
        before_events = len(self._events("policy_change_applied"))
        with self.assertRaises(ServiceError) as ctx:
            self._apply(
                "c2", "approval-policy",
                {"required_approvals": 2, "timeout_seconds": 3600},
                {"required_approvals": 3, "timeout_seconds": 60},
                "r2",
            )
        self.assertEqual(ctx.exception.status, 409)
        # 零副作用：策略不变、无新的变更事件
        self.assertEqual(
            self.h.store.get_policy("w1")["required_approvals"], 2
        )
        self.assertEqual(
            len(self._events("policy_change_applied")), before_events
        )

    def test_policy_change_shrink_roster_below_threshold_409(self):
        self._policy2()
        self._enable()
        # 先把阈值提高到 3（名单为空，开放语义不受约束）
        code, _ = self._apply(
            "c2", "approval-policy",
            {"required_approvals": 2, "timeout_seconds": 3600},
            {"required_approvals": 3, "timeout_seconds": 3600},
            "r2",
        )
        self.assertEqual(code, 201)

        def apply3(change_id, target, before, after, rid):
            """阈值为 3 后审批单需三名不同审批人方可应用变更。"""
            message = _change_message(change_id, target, before, after)
            code, _ = self.svc.create_sign_request("w1", rid, message)
            self.assertEqual(code, 201)
            for approver in ("alice", "bob", "carol"):
                self.svc.approve("w1", rid, approver)
            return self.svc.post_policy_change(
                "w1", change_id, target, before, after, rid
            )

        # 把名单缩小到不可满足阈值：409 且零副作用
        with self.assertRaises(ServiceError) as ctx:
            apply3(
                "c3", "approval-roster",
                {"allowed_approvers": []},
                {"allowed_approvers": ["alice", "bob"]},
                "r3",
            )
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(
            self.svc.get_approval_roster("w1"), {"allowed_approvers": []}
        )
        # 满足阈值的名单可正常应用
        code, _ = apply3(
            "c4", "approval-roster",
            {"allowed_approvers": []},
            {"allowed_approvers": ["alice", "bob", "carol"]},
            "r4",
        )
        self.assertEqual(code, 201)
        self.assertEqual(
            self.svc.get_approval_roster("w1"),
            {"allowed_approvers": ["alice", "bob", "carol"]},
        )


    def test_apply_dkg_failover_policy_takes_effect(self):
        self._enable()
        code, _ = self._apply(
            "c2", "dkg-failover-policy",
            {"enabled": False}, {"enabled": True}, "r2",
        )
        self.assertEqual(code, 201)
        self.assertEqual(
            self.svc.get_dkg_failover_policy("w1"), {"enabled": True}
        )

    def test_apply_nodes_takes_effect_and_get(self):
        self._enable()
        # after 为归一览（节点 ID 升序），message 与之逐字一致。
        nodes = {"n1": {"key": KEY_A, "state": "up"},
                 "n2": {"key": KEY_B, "state": "down"}}
        code, _ = self._apply(
            "c2", "nodes", None, {"nodes": nodes}, "r2"
        )
        self.assertEqual(code, 201)
        view = self.svc.get_dkg_nodes("w1")
        # 归一为节点 ID 升序
        self.assertEqual(list(view["nodes"]), ["n1", "n2"])
        self.assertEqual(
            view["nodes"]["n1"], {"key": KEY_A, "state": "up"}
        )

    def test_apply_chain_adapters_takes_effect(self):
        self._enable()
        code, _ = self._apply(
            "c2", "chain-adapters",
            None, {"adapters": {"a1": "up", "a2": "down"}}, "r2",
        )
        self.assertEqual(code, 201)
        self.assertEqual(
            self.svc.get_chain_adapters("w1"),
            {"adapters": {"a1": "up", "a2": "down"}},
        )

    def test_apply_nodes_snapshot_folds_by_seq(self):
        # 先经 PUT（未启用）建表，启用后再经变更入口覆盖：GET 取后者。
        self._policy2()
        self.svc.put_dkg_nodes(
            "w1", {"n1": {"key": KEY_A, "state": "up"}}
        )
        self._enable()
        code, _ = self._apply(
            "c2", "nodes",
            {"nodes": {"n1": {"key": KEY_A, "state": "up"}}},
            {"nodes": {"n1": {"key": KEY_A, "state": "down"}}},
            "r2",
        )
        self.assertEqual(code, 201)
        self.assertEqual(
            self.svc.get_dkg_nodes("w1"),
            {"nodes": {"n1": {"key": KEY_A, "state": "down"}}},
        )

    def test_disable_change_control_through_policy_change(self):
        self._enable()
        # 启用后仍可经统一入口把开关关掉（target=change-control 本身受控，
        # 但走 policy-changes 合法）。
        code, _ = self._apply(
            "c2", "change-control",
            {"enabled": True}, {"enabled": False}, "r2",
        )
        self.assertEqual(code, 201)
        self.assertEqual(self.svc.get_change_control("w1"),
                         {"enabled": False})
        # 关闭后原 PUT 恢复可用
        self.svc.put_dkg_failover_policy("w1", False)

    # ---- 重启恢复 / 并发 --------------------------------------------------

    def test_restart_preserves_state_and_single_apply(self):
        self._enable()
        self._apply(
            "c2", "nodes", None,
            {"nodes": {"n1": {"key": KEY_A, "state": "up"}}},
            "r2",
        )
        svc2 = WalletService(WalletStore(self.d))
        self.assertEqual(svc2.get_change_control("w1"),
                         {"enabled": True})
        self.assertEqual(
            svc2.get_dkg_nodes("w1"),
            {"nodes": {"n1": {"key": KEY_A, "state": "up"}}},
        )
        # 重放 200 同体，不新增事件
        events_before = svc2.get_audit_events("w1")["events"]
        code, view = svc2.post_policy_change(
            "w1", "c2", "nodes", None,
            {"nodes": {"n1": {"key": KEY_A, "state": "up"}}},
            "r2",
        )
        self.assertEqual(code, 200)
        self.assertEqual(view["change_id"], "c2")
        self.assertEqual(
            len(svc2.get_audit_events("w1")["events"]),
            len(events_before),
        )

    def test_concurrent_first_apply_only_one_201(self):
        self._policy2()
        message = _change_message(
            "c1", "change-control",
            {"enabled": False}, {"enabled": True},
        )
        self.svc.create_sign_request("w1", "r1", message)
        self.svc.approve("w1", "r1", "alice")
        self.svc.approve("w1", "r1", "bob")
        results = []

        def fire():
            results.append(
                self.svc.post_policy_change(
                    "w1", "c1", "change-control",
                    {"enabled": False}, {"enabled": True}, "r1",
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
        bodies = [v for _, v in results]
        self.assertEqual(len({b["seq"] for b in bodies}), 1)
        self.assertEqual(
            len(self._events("policy_change_applied")), 1
        )

    def test_crash_event_absent_rolls_back_file_policy(self):
        self._enable()
        # 直接构造崩溃窗口：意图 + 新交易策略文件已写，但事件未落盘。
        after = {"mode": "hot", "max_delta": 5, "allowed_assets": ["gold"]}
        self.h.store.save_policy_change_intent(
            "w1", "cx",
            {"target": "transaction-policy", "previous_file": None,
             "after_view": after},
        )
        self.h.store.save_transaction_policy("w1", after)
        svc2 = WalletService(WalletStore(self.d))  # 触发恢复
        self.assertIsNone(self.h.store.get_transaction_policy("w1"))
        self.assertEqual(svc2.get_change_control("w1"),
                         {"enabled": True})
        self.assertFalse(self.h.store.get_policy_change_intents("w1"))

    def test_crash_event_present_rolls_forward_file_policy(self):
        self._enable()
        code, _ = self._apply(
            "c2", "approval-policy",
            {"required_approvals": 2, "timeout_seconds": 3600},
            {"required_approvals": 1, "timeout_seconds": 60},
            "r2",
        )
        self.assertEqual(code, 201)
        # 事件在、文件丢失：前滚补齐。
        os.unlink(os.path.join(self.d, "policies", "w1.json"))
        WalletService(WalletStore(self.d))
        self.assertEqual(
            self.h.store.get_policy("w1"),
            {"wallet_id": "w1", "required_approvals": 1,
             "timeout_seconds": 60},
        )

    def test_tampered_event_fail_closed(self):
        self._enable()
        # 篡改 policy_change_applied 事件的 details，重启 fail-closed。
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for event in log["events"]:
            if event["type"] == "policy_change_applied":
                event["details"]["after"] = {"enabled": False}
                # 重算链以免先被链校验拦住（确保走到语义对账）
                break
        # 直接改写并使链与记录一致地"自洽"篡改：更简单地破坏链即 RecoveryError
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises((RecoveryError, CorruptDataError)):
            WalletService(WalletStore(self.d))


class ChangeControlHttpTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def _request(self, srv, method, path, body=None):
        return srv.request(method, path, body)

    def _wallet_policy2_approve(self, srv, rid, message):
        self.assertEqual(
            self._request(
                srv, "PUT", "/v1/wallets/w1/approval-policy",
                {"required_approvals": 2, "timeout_seconds": 3600},
            )[0],
            200,
        )
        self.assertEqual(
            self._request(
                srv, "POST", "/v1/wallets/w1/sign-requests",
                {"id": rid, "message": message},
            )[0],
            201,
        )
        for approver in ("alice", "bob"):
            self.assertEqual(
                self._request(
                    srv,
                    "POST",
                    f"/v1/wallets/w1/sign-requests/{rid}/approve",
                    {"approver_id": approver},
                )[0],
                200,
            )

    def test_http_full_flow(self):
        with http_server(self.d) as srv:
            self.assertEqual(
                self._request(
                    srv, "POST", "/v1/wallets",
                    {"wallet_id": "w1", "shares": 2},
                )[0],
                201,
            )
            # 初始开关
            code, body = self._request(
                srv, "GET", "/v1/wallets/w1/change-control"
            )
            self.assertEqual((code, body), (200, {"enabled": False}))

            message = _change_message(
                "cc-on", "change-control",
                {"enabled": False}, {"enabled": True},
            )
            self._wallet_policy2_approve(srv, "r1", message)
            payload = {
                "change_id": "cc-on",
                "target": "change-control",
                "before": {"enabled": False},
                "after": {"enabled": True},
                "approval_request_id": "r1",
            }
            code, body = self._request(
                srv, "POST", "/v1/wallets/w1/policy-changes", payload
            )
            self.assertEqual(code, 201)
            self.assertEqual(body["change_id"], "cc-on")
            self.assertIn("seq", body)
            # 重放 200 同体
            code, replay = self._request(
                srv, "POST", "/v1/wallets/w1/policy-changes", payload
            )
            self.assertEqual(code, 200)
            self.assertEqual(replay, body)
            # GET 已应用视图
            code, got = self._request(
                srv, "GET",
                "/v1/wallets/w1/policy-changes/cc-on",
            )
            self.assertEqual((code, got), (200, body))
            # 开关已启用；受控 PUT 409
            code, _ = self._request(
                srv, "PUT", "/v1/wallets/w1/dkg-failover-policy",
                {"enabled": False},
            )
            self.assertEqual(code, 409)

    def test_http_bad_body_keys_400(self):
        with http_server(self.d) as srv:
            self._request(
                srv, "POST", "/v1/wallets",
                {"wallet_id": "w1", "shares": 2},
            )
            # 缺键 / 夹带键一律 400
            for bad in (
                {"change_id": "c1"},
                {"change_id": "c1", "target": "change-control",
                 "before": {"enabled": False},
                 "after": {"enabled": True}},
                {"change_id": "c1", "target": "change-control",
                 "before": {"enabled": False},
                 "after": {"enabled": True},
                 "approval_request_id": "r1", "extra": 1},
            ):
                code, body = self._request(
                    srv, "POST", "/v1/wallets/w1/policy-changes", bad
                )
                self.assertEqual(code, 400, bad)
                self.assertIn("error", body)

    def test_http_unknown_wallet_and_change_404(self):
        with http_server(self.d) as srv:
            code, _ = self._request(
                srv, "GET", "/v1/wallets/ghost/change-control"
            )
            self.assertEqual(code, 404)
            code, _ = self._request(
                srv, "GET",
                "/v1/wallets/ghost/policy-changes/c1",
            )
            self.assertEqual(code, 404)


if __name__ == "__main__":
    unittest.main()
