"""高风险配置双人变更控制（change-control / policy-changes）测试。

覆盖：
- GET change-control 缺省 {"enabled": false}，仅经统一入口启停；
- POST policy-changes 请求体恰为
  {change_id,target,before,after,approval_request_id}，target 七选一，
  after 为公开视图配置、before 等于应用前配置（未配置 null）；
- 审批 message 须逐字为仅含 change_id/target/before/after 的 ASCII
  紧凑 JSON，须两位**不同**审批人批准且未过期；
- 首提 201 并原子追加唯一 policy_change_applied（事件型目标与既有
  快照事件同批落盘），同参重放 200 同体不新增事件，异参 409；
- 启用后六个受控 PUT 一律 409 change control required 且零副作用，
  停用后原 PUT 恢复；GET policy-changes/{id} 返回已应用视图；
- 非法 target/配置/标识 400，未知钱包/审批单/change_id 404；
- 并发/重启只产生一次首次应用；矛盾/篡改现场 fail-closed。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import time
import unittest

from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import RecoveryError, WalletStore

from tests.helpers import http_server, make_harness

KEY_A = "aa" * 32


def _change_message(change_id, target, before, after):
    """审批单 message 契约：仅四键的 ASCII 紧凑 JSON。"""
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


def _call(fn, *args):
    try:
        return fn(*args)
    except ServiceError as exc:
        return exc.status, {"error": exc.message}


class ChangeControlServiceTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)

    def _events(self, event_type=None, svc=None):
        svc = svc or self.svc
        events = svc.get_audit_events("w1")["events"]
        if event_type is None:
            return events
        return [e for e in events if e["type"] == event_type]

    def _set_two_approval_policy(self, timeout=3600):
        self.svc.put_policy("w1", 2, timeout)

    def _approved_request(
        self,
        change_id,
        target,
        before,
        after,
        request_id,
        approvers=("alice", "bob"),
    ):
        """建单并由给定审批人批准（不提交变更）。"""
        message = _change_message(change_id, target, before, after)
        code, _ = self.svc.create_sign_request(
            "w1", request_id, message
        )
        self.assertEqual(code, 201, (change_id, target))
        for approver in approvers:
            self.svc.approve("w1", request_id, approver)

    def _change_body(self, change_id, target, before, after, request_id):
        return {
            "change_id": change_id,
            "target": target,
            "before": before,
            "after": after,
            "approval_request_id": request_id,
        }

    def _apply_approved(
        self, change_id, target, before, after, request_id,
        approvers=("alice", "bob"),
    ):
        self._approved_request(
            change_id, target, before, after, request_id, approvers
        )
        body = self._change_body(
            change_id, target, before, after, request_id
        )
        return self.svc.post_policy_change("w1", body), body

    def _enable(self, change_id="cc-on", rid="req-cc-on"):
        self._set_two_approval_policy()
        (result, body) = self._apply_approved(
            change_id, "change-control",
            {"enabled": False}, {"enabled": True}, rid,
        )
        self.assertEqual(result[0], 201)
        return body

    # ---- 缺省 / 查询 -----------------------------------------------------

    def test_default_disabled(self):
        self.assertEqual(
            self.svc.get_change_control("w1"), {"enabled": False}
        )

    def test_get_unknown_wallet_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_change_control("ghost")
        self.assertEqual(ctx.exception.status, 404)

    def test_get_invalid_wallet_400(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_change_control("bad id!")
        self.assertEqual(ctx.exception.status, 400)

    # ---- 启用 ------------------------------------------------------------

    def test_enable_201_applies_switch_with_single_event(self):
        self._set_two_approval_policy()
        before_cc = len(self._events("policy_change_applied"))
        (code, view), _ = self._apply_approved(
            "cc-on", "change-control",
            {"enabled": False}, {"enabled": True}, "req-cc-on",
        )
        self.assertEqual(code, 201)
        self.assertEqual(
            self.svc.get_change_control("w1"), {"enabled": True}
        )
        # 恰好新增一条 policy_change_applied（无旁路开关事件）
        new = self._events("policy_change_applied")[before_cc:]
        self.assertEqual(len(new), 1)
        self.assertEqual(new[0]["request_id"], "cc-on")
        self.assertEqual(new[0]["actor_id"], "req-cc-on")
        self.assertIsNone(new[0]["reason"])
        self.assertEqual(
            list(new[0]["details"]),
            ["change_id", "target", "before", "after"],
        )

    def test_enable_requires_explicit_false_before(self):
        # change-control 始终有缺省 false，null before 不匹配 → 409
        self._set_two_approval_policy()
        self._approved_request(
            "x", "change-control", None, {"enabled": True}, "rx"
        )
        body = self._change_body(
            "x", "change-control", None, {"enabled": True}, "rx"
        )
        self.assertEqual(
            _call(self.svc.post_policy_change, "w1", body)[0], 409
        )

    # ---- 受控 PUT 闸门 ---------------------------------------------------

    def test_gated_puts_409_and_no_side_effects(self):
        self._enable()
        cases = [
            ("put_policy", ("w1", 1, 60)),
            ("put_approval_roster", ("w1", ["x"])),
            ("put_transaction_policy", ("w1", "hot", 1, ["a"])),
            ("put_dkg_failover_policy", ("w1", True)),
            ("put_dkg_nodes",
             ("w1", {"n1": {"key": KEY_A, "state": "up"}})),
            ("put_chain_adapters", ("w1", {"a": "up"})),
        ]
        before_events = self._events()
        for method, args in cases:
            result = _call(getattr(self.svc, method), *args)
            self.assertEqual(result[0], 409, method)
            self.assertEqual(result[1]["error"], "change control required")
        # 零副作用：无新增事件；nodes/adapters 仍未配置
        self.assertEqual(self._events(), before_events)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_dkg_nodes("w1")
        self.assertEqual(ctx.exception.status, 404)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_chain_adapters("w1")
        self.assertEqual(ctx.exception.status, 404)

    def test_gate_then_disable_restores_put(self):
        self._enable()
        self.assertEqual(
            _call(self.svc.put_dkg_failover_policy, "w1", True)[0], 409
        )
        (code, _), _ = self._apply_approved(
            "cc-off", "change-control",
            {"enabled": True}, {"enabled": False}, "req-cc-off",
        )
        self.assertEqual(code, 201)
        self.assertEqual(
            self.svc.put_dkg_failover_policy("w1", True), {"enabled": True}
        )

    # ---- target/配置/标识 400 ---------------------------------------------

    def test_invalid_target_config_and_ids_400(self):
        self._enable()
        good_after = {"nodes": {"n1": {"key": KEY_A, "state": "up"}}}

        def post(change_id="c", target="nodes", before=None,
                 after=good_after, rid="r"):
            body = self._change_body(change_id, target, before, after, rid)
            return _call(self.svc.post_policy_change, "w1", body)

        self.assertEqual(post(change_id="bad id")[0], 400)
        self.assertEqual(post(rid=7)[0], 400)
        self.assertEqual(post(target="nope")[0], 400)
        # 非法 after
        self.assertEqual(post(after={"nodes": {}})[0], 400)
        self.assertEqual(
            post(after={"nodes": {"n1": {"key": "short", "state": "up"}}})[0],
            400,
        )
        # 未规范序的 nodes 表 → 400（服务端不替客户端重排）
        self.assertEqual(
            post(after={"nodes": {
                "z": {"key": KEY_A, "state": "up"},
                "a": {"key": KEY_A, "state": "up"},
            }})[0],
            400,
        )
        # 非法 before
        self.assertEqual(post(before={"nodes": {}})[0], 400)

    def test_body_not_object_400(self):
        self._enable()
        self.assertEqual(
            _call(self.svc.post_policy_change, "w1", [])[0], 400
        )
        self.assertEqual(
            _call(self.svc.post_policy_change, "w1", "x")[0], 400
        )

    def test_unknown_wallet_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_policy_change("ghost", {})
        self.assertEqual(ctx.exception.status, 404)

    # ---- 审批门控 --------------------------------------------------------

    def _pending_body(self, change_id="c1", target="nodes",
                      before=None, after=None, rid="r9"):
        after = after or {"nodes": {"n1": {"key": KEY_A, "state": "up"}}}
        return (
            self._change_body(change_id, target, before, after, rid),
            _change_message(change_id, target, before, after),
        )

    def test_unknown_approval_request_404(self):
        self._enable()
        body, _ = self._pending_body()
        self.assertEqual(
            _call(self.svc.post_policy_change, "w1", body)[0], 404
        )

    def test_pending_single_and_duplicate_approver_409(self):
        self._enable()  # 审批策略 req=2，开关启用
        body, message = self._pending_body(rid="rp")
        # 未建单 → 404
        self.assertEqual(
            _call(self.svc.post_policy_change, "w1", body)[0], 404
        )
        self.assertEqual(
            self.svc.create_sign_request("w1", "rp", message)[0], 201
        )
        # 无人批准：pending → 409
        self.assertEqual(
            _call(self.svc.post_policy_change, "w1", body)[0], 409
        )
        # 一位审批：仍 pending → 409
        self.svc.approve("w1", "rp", "alice")
        self.assertEqual(
            _call(self.svc.post_policy_change, "w1", body)[0], 409
        )
        # 同一审批人重复批准不计数：仍 pending → 409
        self.svc.approve("w1", "rp", "alice")
        self.assertEqual(
            _call(self.svc.post_policy_change, "w1", body)[0], 409
        )
        # 第二位**不同**审批人后 approved → 201
        self.svc.approve("w1", "rp", "bob")
        self.assertEqual(self.svc.post_policy_change("w1", body)[0], 201)

    def test_rejected_and_expired_409(self):
        # 统一入口在开关关闭时同样可用（启停本身也经此入口），审批门控与
        # 开关状态无关：rejected / expired 审批单一律 409。
        self._set_two_approval_policy()
        body, message = self._pending_body(change_id="cr", rid="rr")
        self.svc.create_sign_request("w1", "rr", message)
        self.svc.reject("w1", "rr", "alice")
        self.assertEqual(
            _call(self.svc.post_policy_change, "w1", body)[0], 409
        )

        # 过期：1 秒超时的审批策略；pending 单到点由变更操作懒过期为
        # expired（仅一位批准、未达 req=2，故仍是 pending）。
        self.svc.put_policy("w1", 2, 1)
        body2, message2 = self._pending_body(change_id="ce", rid="re")
        self.svc.create_sign_request("w1", "re", message2)
        self.svc.approve("w1", "re", "alice")
        time.sleep(1.3)
        self.assertEqual(
            _call(self.svc.post_policy_change, "w1", body2)[0], 409
        )
        self.assertEqual(
            self.svc.get_sign_request("w1", "re")["state"], "expired"
        )

    def test_message_mismatch_409(self):
        self._enable()
        good_after = {"nodes": {"n1": {"key": KEY_A, "state": "up"}}}
        message = _change_message(
            "cm", "nodes", None,
            {"nodes": {"n1": {"key": "bb" * 32, "state": "up"}}},
        )
        self.svc.create_sign_request("w1", "rm", message)
        self.svc.approve("w1", "rm", "alice")
        self.svc.approve("w1", "rm", "bob")
        body = self._change_body("cm", "nodes", None, good_after, "rm")
        self.assertEqual(
            _call(self.svc.post_policy_change, "w1", body)[0], 409
        )

    def test_message_must_be_canonical_compact_ascii(self):
        self._enable()
        good_after = {"nodes": {"n1": {"key": KEY_A, "state": "up"}}}
        weird = json.dumps(
            {
                "after": good_after,
                "before": None,
                "target": "nodes",
                "change_id": "cw",
            }
        )
        self.svc.create_sign_request("w1", "rw", weird)
        self.svc.approve("w1", "rw", "alice")
        self.svc.approve("w1", "rw", "bob")
        body = self._change_body("cw", "nodes", None, good_after, "rw")
        self.assertEqual(
            _call(self.svc.post_policy_change, "w1", body)[0], 409
        )

    def test_message_is_verbatim_ascii_compact(self):
        self._enable()
        after = {"nodes": {"n1": {"key": KEY_A, "state": "up"}}}
        self._approved_request("cv", "nodes", None, after, "rv")
        request = self.svc.get_sign_request("w1", "rv")
        self.assertEqual(
            request["message"],
            '{"change_id":"cv","target":"nodes","before":null,'
            '"after":{"nodes":{"n1":{"key":"' + KEY_A + '","state":"up"}}}}',
        )
        body = self._change_body("cv", "nodes", None, after, "rv")
        self.assertEqual(self.svc.post_policy_change("w1", body)[0], 201)

    def test_before_mismatch_409(self):
        self._enable()
        existing = {"nodes": {"n1": {"key": KEY_A, "state": "up"}}}
        self._approved_request("cb", "nodes", existing, existing, "rcb")
        body = self._change_body("cb", "nodes", existing, existing, "rcb")
        self.assertEqual(
            _call(self.svc.post_policy_change, "w1", body)[0], 409
        )

    # ---- 幂等 / 冲突 / 查询 ----------------------------------------------

    def test_first_201_replay_200_same_body_no_new_event(self):
        self._enable()
        after = {"nodes": {"n1": {"key": KEY_A, "state": "up"}}}
        (code, view) = self._apply_approved(
            "c1", "nodes", None, after, "req-c1"
        )[0]
        self.assertEqual(code, 201)
        self.assertIsNone(view["before"])
        self.assertEqual(view["after"], after)
        self.assertEqual(view["approval_request_id"], "req-c1")
        n_after_first = len(self._events())
        body = self._change_body("c1", "nodes", None, after, "req-c1")
        code, view2 = self.svc.post_policy_change("w1", dict(body))
        self.assertEqual(code, 200)
        self.assertEqual(view2, view)
        self.assertEqual(len(self._events()), n_after_first)
        self.assertEqual(self.svc.get_policy_change("w1", "c1"), view)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_policy_change("w1", "ghost")
        self.assertEqual(ctx.exception.status, 404)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_policy_change("w1", "bad id")
        self.assertEqual(ctx.exception.status, 400)

    def test_same_change_id_different_params_409(self):
        self._enable()
        after = {"nodes": {"n1": {"key": KEY_A, "state": "up"}}}
        self._approved_request("c1", "nodes", None, after, "req-c1")
        body = self._change_body("c1", "nodes", None, after, "req-c1")
        self.assertEqual(self.svc.post_policy_change("w1", body)[0], 201)
        # 换 target → 409（即便 after 不适配新 target，也按异参 409，
        # 幂等判定先于 target/配置校验）
        other = dict(body)
        other["target"] = "chain-adapters"
        self.assertEqual(
            _call(self.svc.post_policy_change, "w1", other)[0], 409
        )
        # 换审批单 → 409
        other = dict(body)
        other["approval_request_id"] = "req-cc-on"
        self.assertEqual(
            _call(self.svc.post_policy_change, "w1", other)[0], 409
        )
        # 只产生一次首提
        self.assertEqual(len(self._events("policy_change_applied")), 2)

    def test_replay_preempts_without_recheck(self):
        self._enable()
        after = {"nodes": {"n1": {"key": KEY_A, "state": "up"}}}
        self._approved_request("c1", "nodes", None, after, "req-c1")
        body = self._change_body("c1", "nodes", None, after, "req-c1")
        code, view = self.svc.post_policy_change("w1", body)
        self.assertEqual(code, 201)
        # 同参重放 200 同体、不复查现场（不依赖审批单现状）。
        code, view2 = self.svc.post_policy_change("w1", dict(body))
        self.assertEqual(code, 200)
        self.assertEqual(view2, view)

    # ---- 七个 target 的应用与落盘形状 ------------------------------------

    def test_all_targets_apply_with_correct_views(self):
        self._set_two_approval_policy()

        def apply(cid, target, before, after):
            (code, view), _ = self._apply_approved(
                cid, target, before, after, "req-" + cid
            )
            self.assertEqual(code, 201, (cid, target))
            return view

        # 先启用双人变更控制（开关本身也经统一入口）；其后所有受控配置都
        # 只能走该入口，最后再停用。
        apply(
            "eon", "change-control",
            {"enabled": False}, {"enabled": True},
        )
        # approval-policy（已存在 → 非 null before）：文件型，仅一条提交
        # 事件。保持 required_approvals=2，使其后各变更仍可双人批准。
        ev_before = len(self._events("policy_change_applied"))
        apply(
            "p1", "approval-policy",
            {"required_approvals": 2, "timeout_seconds": 3600},
            {"required_approvals": 2, "timeout_seconds": 7200},
        )
        self.assertEqual(
            len(self._events("policy_change_applied")) - ev_before, 1
        )
        self.assertEqual(
            WalletStore(self.d).get_policy("w1")["timeout_seconds"], 7200
        )
        # approval-roster（缺省空名单）：事件型，同批两条
        view = apply(
            "r1", "approval-roster",
            {"allowed_approvers": []},
            {"allowed_approvers": ["alice", "bob"]},
        )
        self.assertEqual(
            self.svc.get_approval_roster("w1"),
            {"allowed_approvers": ["alice", "bob"]},
        )
        self.assertEqual(self._events()[-2]["type"],
                         "approval_roster_updated")
        self.assertEqual(view["seq"] - 1, self._events()[-2]["seq"])
        # transaction-policy 首建 before=null：文件型，仅一条提交事件
        ev_before = len(self._events("policy_change_applied"))
        txn = {"mode": "cold", "max_delta": 9, "allowed_assets": ["gold"]}
        apply("t1", "transaction-policy", None, txn)
        self.assertEqual(
            len(self._events("policy_change_applied")) - ev_before, 1
        )
        self.assertEqual(self.svc.get_transaction_policy("w1"), txn)
        # dkg-failover-policy（缺省 false）：同批两条
        view = apply(
            "d1", "dkg-failover-policy",
            {"enabled": False}, {"enabled": True},
        )
        self.assertEqual(
            self.svc.get_dkg_failover_policy("w1"), {"enabled": True}
        )
        self.assertEqual(self._events()[-2]["type"],
                         "dkg_failover_policy_updated")
        self.assertEqual(view["seq"] - 1, self._events()[-2]["seq"])
        # nodes 首建 before=null，同批快照
        nodes = {"nodes": {"n1": {"key": KEY_A, "state": "up"}}}
        apply("n1", "nodes", None, nodes)
        self.assertEqual(self.svc.get_dkg_nodes("w1"), nodes)
        # chain-adapters 首建 before=null，同批快照
        adapters = {"adapters": {"a1": "up", "b2": "down"}}
        apply("c1b", "chain-adapters", None, adapters)
        self.assertEqual(self.svc.get_chain_adapters("w1"), adapters)
        # change-control 停用（开关型，仅一条）
        apply(
            "off", "change-control",
            {"enabled": True}, {"enabled": False},
        )
        self.assertEqual(
            self.svc.get_change_control("w1"), {"enabled": False}
        )
        seqs = [e["seq"] for e in self._events()]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))

    def test_frozen_wallet_change_409(self):
        self._enable()
        # 审批单在冻结前建好并批准
        self._approved_request(
            "f1", "dkg-failover-policy",
            {"enabled": False}, {"enabled": True}, "req-f1",
        )
        self.svc.freeze_wallet("w1", "incident")
        body = self._change_body(
            "f1", "dkg-failover-policy",
            {"enabled": False}, {"enabled": True}, "req-f1",
        )
        self.assertEqual(
            _call(self.svc.post_policy_change, "w1", body)[0], 409
        )

    # ---- 并发 / 重启 / 篡改 ----------------------------------------------

    def test_concurrent_single_201(self):
        self._enable()
        after = {"nodes": {"n1": {"key": KEY_A, "state": "up"}}}
        self._approved_request("cc", "nodes", None, after, "req-cc")
        body = self._change_body("cc", "nodes", None, after, "req-cc")
        codes = []
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            codes.append(
                self.svc.post_policy_change("w1", dict(body))[0]
            )

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(codes), [200] * 7 + [201])
        # cc-on + cc 共两条提交事件
        self.assertEqual(
            len(self._events("policy_change_applied")), 2
        )

    def test_restart_preserves_state_and_adds_no_events(self):
        self._enable()
        after = {"nodes": {"n1": {"key": KEY_A, "state": "down"}}}
        self._approved_request("n1", "nodes", None, after, "req-n1")
        body = self._change_body("n1", "nodes", None, after, "req-n1")
        self.assertEqual(self.svc.post_policy_change("w1", body)[0], 201)
        before = self.svc.get_audit_events("w1")["events"]
        svc2 = WalletService(self.h.store)
        self.assertEqual(svc2.get_change_control("w1"), {"enabled": True})
        self.assertEqual(svc2.get_dkg_nodes("w1"), after)
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)

    def test_restart_file_backed_policy(self):
        self._enable()
        txn = {"mode": "hot", "max_delta": 3, "allowed_assets": ["x"]}
        self._approved_request("tp", "transaction-policy", None, txn, "rq")
        body = self._change_body("tp", "transaction-policy", None, txn, "rq")
        self.assertEqual(self.svc.post_policy_change("w1", body)[0], 201)
        svc2 = WalletService(self.h.store)
        self.assertEqual(svc2.get_transaction_policy("w1"), txn)

    def test_tampered_or_duplicate_change_is_fail_closed(self):
        self._enable()
        after = {"nodes": {"n1": {"key": KEY_A, "state": "up"}}}
        self._approved_request("t1", "nodes", None, after, "req-t1")
        body = self._change_body("t1", "nodes", None, after, "req-t1")
        self.assertEqual(self.svc.post_policy_change("w1", body)[0], 201)
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        original = None
        for event in log["events"]:
            if (
                event.get("type") == "policy_change_applied"
                and event.get("request_id") == "t1"
            ):
                original = event
        self.assertIsNotNone(original)
        # 篡改既有提交事件的 after（形状仍合法，但与配对快照不符）→ 矛盾
        original["details"]["after"] = {
            "nodes": {"n1": {"key": KEY_A, "state": "down"}}
        }
        from threshold_wallet import audit as audit_mod

        count, head = audit_mod.compute_chain_head(log["events"])
        log["chain"] = {
            "algorithm": audit_mod.CHAIN_ALGORITHM,
            "head": head,
            "count": count,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_approver_tamper_after_commit_is_fail_closed(self):
        self._set_two_approval_policy()
        self._approved_request(
            "e1", "change-control",
            {"enabled": False}, {"enabled": True}, "req-e1",
        )
        body = self._change_body(
            "e1", "change-control",
            {"enabled": False}, {"enabled": True}, "req-e1",
        )
        self.assertEqual(self.svc.post_policy_change("w1", body)[0], 201)
        # 提交后把审批单改成仅一名审批人：恢复复核两位不同审批人即失败
        path = os.path.join(self.d, "requests", "w1.json")
        with open(path, encoding="utf-8") as f:
            requests = json.load(f)
        requests["req-e1"]["approvers"] = ["alice"]
        requests["req-e1"]["count"] = 1
        with open(path, "w", encoding="utf-8") as f:
            json.dump(requests, f)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_unpaired_snapshot_is_fail_closed(self):
        # 删掉与提交事件同批的快照（node_state）：恢复判定缺少成对快照
        self._enable()
        after = {"nodes": {"n1": {"key": KEY_A, "state": "up"}}}
        self._approved_request("n1", "nodes", None, after, "req-n1")
        body = self._change_body("n1", "nodes", None, after, "req-n1")
        self.assertEqual(self.svc.post_policy_change("w1", body)[0], 201)
        from threshold_wallet import audit as audit_mod

        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        log["events"] = [
            e for e in log["events"] if e["type"] != "node_state"
        ]
        for i, event in enumerate(log["events"], 1):
            event["seq"] = i
        count, head = audit_mod.compute_chain_head(log["events"])
        log["next_seq"] = len(log["events"]) + 1
        log["chain"] = {
            "algorithm": audit_mod.CHAIN_ALGORITHM,
            "head": head,
            "count": count,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)


class ChangeControlHttpTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def _enable(self, srv):
        req = srv.request
        req("PUT", "/v1/wallets/w1/approval-policy",
            {"required_approvals": 2, "timeout_seconds": 3600})
        message = _change_message(
            "on", "change-control",
            {"enabled": False}, {"enabled": True},
        )
        req("POST", "/v1/wallets/w1/sign-requests",
            {"id": "ron", "message": message})
        req("POST", "/v1/wallets/w1/sign-requests/ron/approve",
            {"approver_id": "alice"})
        req("POST", "/v1/wallets/w1/sign-requests/ron/approve",
            {"approver_id": "bob"})
        body = {
            "change_id": "on",
            "target": "change-control",
            "before": {"enabled": False},
            "after": {"enabled": True},
            "approval_request_id": "ron",
        }
        return req("POST", "/v1/wallets/w1/policy-changes", body), body

    def test_http_full_flow(self):
        with http_server(self.d) as srv:
            req = srv.request
            self.assertEqual(
                req("POST", "/v1/wallets",
                    {"wallet_id": "w1", "shares": 2})[0],
                201,
            )
            self.assertEqual(
                req("GET", "/v1/wallets/w1/change-control"),
                (200, {"enabled": False}),
            )
            (code, view), body = self._enable(srv)
            self.assertEqual(code, 201)
            self.assertEqual(view["seq"], 5)
            # 同参重放 200 同体
            self.assertEqual(
                req("POST", "/v1/wallets/w1/policy-changes", body),
                (200, view),
            )
            # GET 已应用视图
            self.assertEqual(
                req("GET", "/v1/wallets/w1/policy-changes/on"),
                (200, view),
            )
            # 受控 PUT 一律 409（即便请求体非法，闸门在读体之前）
            self.assertEqual(
                req("PUT", "/v1/wallets/w1/approval-policy",
                    {"bad": 1})[0],
                409,
            )
            self.assertEqual(
                req("PUT", "/v1/wallets/w1/nodes",
                    {"nodes": {"n": {"key": "x", "state": "up"}}})[0],
                409,
            )
            code, err = req(
                "PUT", "/v1/wallets/w1/chain-adapters", {"adapters": {}}
            )
            self.assertEqual(code, 409)
            self.assertEqual(err["error"], "change control required")
            # 受控 PUT 未知钱包 404（先于请求体）
            self.assertEqual(
                req("PUT", "/v1/wallets/ghost/nodes", {"nodes": {}})[0],
                404,
            )
            # POST 键集错误 400
            self.assertEqual(
                req("POST", "/v1/wallets/w1/policy-changes",
                    {"change_id": "x"})[0],
                400,
            )
            # 未知 change_id 404
            self.assertEqual(
                req("GET", "/v1/wallets/w1/policy-changes/nope")[0], 404
            )
            # 读接口仍可用（nodes 未配置 404）
            self.assertEqual(
                req("GET", "/v1/wallets/w1/nodes")[0], 404
            )

    def test_http_gate_drains_body_for_keepalive(self):
        import http.client

        with http_server(self.d) as srv:
            port = int(srv.base_url.rsplit(":", 1)[1])

            def raw(method, path, payload=None, ctype=None):
                conn = http.client.HTTPConnection("127.0.0.1", port)
                headers = {"Content-Type": ctype} if ctype else {}
                conn.request(method, path, body=payload, headers=headers)
                resp = conn.getresponse()
                data = resp.read()
                conn.close()
                return resp.status, data

            raw("POST", "/v1/wallets",
                json.dumps({"wallet_id": "w1", "shares": 2}).encode(),
                "application/json")
            self._enable(srv)
            # 启用后：带非法 JSON 体的受控 PUT 仍 409 并排空 body
            status, _ = raw(
                "PUT", "/v1/wallets/w1/nodes",
                b"{broken json body", "application/json",
            )
            self.assertEqual(status, 409)
            # 紧随其后的正常 GET 不被残留字节污染
            status, data = raw(
                "GET", "/v1/wallets/w1/change-control"
            )
            self.assertEqual(status, 200)
            self.assertEqual(
                json.loads(data.decode("utf-8")), {"enabled": True}
            )


if __name__ == "__main__":
    unittest.main()
