"""DKG 故障轮次 reinstate 动作与 node_rejoined 审计读取键序测试。

覆盖：
- reinstate：请求体恰为 K=(round,action,node,replacement,key) 加
  approval_request_id 六键；沿用 replace 契约（commit|share 轮、node
  在用、replacement 空闲、换槽回 commit），另须 replacement 为已提交
  node_rejoined 对应的当前 up 空闲节点；approval_request_id 须为同钱包
  approved 审批单且 message 逐字为以 dkg_id 后接 K 的紧凑 JSON——审批
  开关不豁免；否则 409（缺/非法 approval_request_id 为 400）；
- 仅六字段全同重放 200，更换审批单或任一值 409；
- dkg_failover 事件：request_id=<id>/<轮次>、actor_id=审批单标识（仅
  reinstate 非 null，abort/replace 仍为 null）、reason=null、details
  键序 id,round,action,node,replacement,key,state（state=commit）；
- 恢复按 actor_id 复核审批（同钱包、message 逐字、approved/signed）并
  核验 replacement 对应事前已提交的 node_rejoined，矛盾 fail-closed；
- 审计读取在归一化前校验 node_rejoined details 的 README 键序：错序抛
  RecoveryError，坏 JSON 抛 CorruptDataError。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import CorruptDataError, RecoveryError, WalletStore

from tests.helpers import http_server, make_harness

KEY_A = "aa" * 32
KEY_B = "bb" * 32
KEY_C = "cc" * 32
KEY_D = "dd" * 32
HASH_A = "11" * 32
HASH_B = "22" * 32

HEALTH = {
    "n1": {"key": KEY_A, "state": "up"},
    "n2": {"key": KEY_B, "state": "up"},
    "n3": {"key": KEY_C, "state": "down"},
    "n4": {"key": KEY_D, "state": "up"},
}


def _failover_message(did, round_no, action, node, replacement, key):
    """审批单 message 的契约紧凑 JSON：dkg_id 后接有序 K。"""
    return json.dumps(
        {
            "dkg_id": did,
            "round": round_no,
            "action": action,
            "node": node,
            "replacement": replacement,
            "key": key,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _rejoin_message(rejoin_id, dkg_id, round_no, node, key):
    return json.dumps(
        {
            "rejoin_id": rejoin_id,
            "dkg_id": dkg_id,
            "round": round_no,
            "node": node,
            "key": key,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _call(fn, *args):
    """把 ServiceError 归一为 (status, {"error": ...})，便于断言状态码。"""
    try:
        return fn(*args)
    except ServiceError as exc:
        return exc.status, {"error": exc.message}


class ReinstateServiceTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 3600)
        self.svc.put_dkg_nodes("w1", HEALTH)
        for op, node, key, hsh in (
            ("register", "n1", KEY_A, None),
            ("register", "n2", KEY_B, None),
            ("commit", "n1", None, HASH_A),
            ("commit", "n2", None, HASH_B),
        ):
            code, _ = self.svc.post_dkg_stage(
                "w1", "d1", op, node, key, hsh, None
            )
            self.assertEqual(code, 201)

    # ---- 构造辅助 ------------------------------------------------------

    def _approve(self, rid, message):
        code, _ = self.svc.create_sign_request("w1", rid, message)
        self.assertEqual(code, 201)
        self.svc.approve("w1", rid, "boss")

    def _rejoin_n3(self):
        """把 n3 经 rejoin 置为 up（当前轮为基线轮 1、处 share 阶段）。"""
        self._approve(
            "ap1", _rejoin_message("rj1", "d1", 1, "n3", KEY_C)
        )
        code, view = _call(
            self.svc.post_node_rejoin,
            "w1", "n3", "rj1", "d1", 1, KEY_C, "ap1",
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "up")

    def _approve_reinstate(self, rid="r1", did="d1", round_no=2,
                           node="n2", replacement="n3", key=KEY_C):
        self._approve(
            rid,
            _failover_message(did, round_no, "reinstate",
                              node, replacement, key),
        )

    def _reinstate(self, round_no=2, node="n2", replacement="n3",
                   key=KEY_C, approval="r1"):
        return _call(
            self.svc.post_dkg_failover,
            "w1", "d1", round_no, "reinstate", node, replacement, key,
            approval,
        )

    def _events(self, event_type, svc=None):
        svc = svc or self.svc
        return [
            e
            for e in svc.get_audit_events("w1")["events"]
            if e["type"] == event_type
        ]

    def _audit_path(self):
        return os.path.join(self.d, "audit", "w1.json")

    # ---- 首提 201 / 事件形状 -------------------------------------------

    def test_first_reinstate_201_and_event_shape(self):
        self._rejoin_n3()
        self._approve_reinstate()
        code, view = self._reinstate()
        self.assertEqual(code, 201)
        self.assertEqual(view["round"], 2)
        self.assertEqual(view["state"], "commit")
        self.assertEqual(view["nodes"], ["n1", "n3"])
        self.assertEqual(view["committed"], [])
        self.assertEqual(view["shared"], [])
        (event,) = self._events("dkg_failover")
        self.assertEqual(event["request_id"], "d1/2")
        # 仅 reinstate 的 actor_id 非 null（审批单标识），reason 为 null
        self.assertEqual(event["actor_id"], "r1")
        self.assertIsNone(event["reason"])
        # details 键序 id,K,state（K 原位展开），state=commit
        self.assertEqual(
            list(event["details"]),
            ["id", "round", "action", "node", "replacement", "key",
             "state"],
        )
        self.assertEqual(
            event["details"],
            {
                "id": "d1",
                "round": 2,
                "action": "reinstate",
                "node": "n2",
                "replacement": "n3",
                "key": KEY_C,
                "state": "commit",
            },
        )

    def test_abort_and_replace_actor_id_stay_null(self):
        # 手工 replace（开关关闭，五键）
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", "n4", KEY_D,
        )
        self.assertEqual(code, 201)
        # abort 第 3 轮
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 3, "abort", None, None, None,
        )
        self.assertEqual(code, 201)
        events = self._events("dkg_failover")
        self.assertEqual(len(events), 2)
        for event in events:
            self.assertIsNone(event["actor_id"])
            self.assertIsNone(event["reason"])

    # ---- 审批门控（开关不豁免） -----------------------------------------

    def test_approval_required_even_when_toggle_disabled(self):
        self._rejoin_n3()
        # 开关缺省关闭：无审批单仍 409（不豁免）
        code, _ = self._reinstate(approval="ghost")
        self.assertEqual(code, 409)
        # pending 单 409
        message = _failover_message("d1", 2, "reinstate", "n2", "n3", KEY_C)
        code, _ = self.svc.create_sign_request("w1", "r1", message)
        self.assertEqual(code, 201)
        code, _ = self._reinstate()
        self.assertEqual(code, 409)
        # 拒绝单 409
        self.svc.reject("w1", "r1", "boss")
        code, _ = self._reinstate()
        self.assertEqual(code, 409)
        self.assertEqual(self._events("dkg_failover"), [])

    def test_missing_or_invalid_approval_id_400(self):
        self._rejoin_n3()
        # 缺 approval_request_id（五键）
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "reinstate", "n2", "n3", KEY_C,
        )
        self.assertEqual(code, 400)
        # 显式 None / 非法标识
        code, _ = self._reinstate(approval=None)
        self.assertEqual(code, 400)
        code, _ = self._reinstate(approval="bad id!")
        self.assertEqual(code, 400)

    def test_message_must_be_verbatim_compact_json(self):
        self._rejoin_n3()
        self._approve_reinstate()
        request = self.svc.get_sign_request("w1", "r1")
        self.assertEqual(
            request["message"],
            '{"dkg_id":"d1","round":2,"action":"reinstate","node":"n2",'
            '"replacement":"n3","key":"' + KEY_C + '"}',
        )
        # message 不符（key 不同）409
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "reinstate", "n2", "n3", KEY_D, "r1",
        )
        self.assertEqual(code, 409)
        # 逐字一致则 201（开关关闭也强制审批通过即可）
        code, view = self._reinstate()
        self.assertEqual(code, 201)
        self.assertEqual(view["nodes"], ["n1", "n3"])

    def test_reinstate_also_works_when_toggle_enabled(self):
        self._rejoin_n3()
        self.svc.put_dkg_failover_policy("w1", True)
        self._approve_reinstate()
        code, view = self._reinstate()
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "commit")

    # ---- replacement 须为已提交 rejoin 的当前 up 空闲节点 -----------------

    def test_replacement_must_be_rejoined_and_up(self):
        # n3 仍 down（未 rejoin）：409
        self._approve_reinstate()
        code, _ = self._reinstate()
        self.assertEqual(code, 409)
        # n4 当前 up 但从未 rejoin：409
        self._approve(
            "r2", _failover_message("d1", 2, "reinstate", "n2", "n4", KEY_D)
        )
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "reinstate", "n2", "n4", KEY_D, "r2",
        )
        self.assertEqual(code, 409)
        self.assertEqual(self._events("dkg_failover"), [])

    def test_replacement_rejoined_but_down_again_409(self):
        self._rejoin_n3()
        # 新快照把 n3 重新置为 down：生效健康表中非 up
        self.svc.put_dkg_nodes("w1", HEALTH)
        self._approve_reinstate()
        code, _ = self._reinstate()
        self.assertEqual(code, 409)

    def test_replace_contract_still_applies(self):
        self._rejoin_n3()
        # 非当前轮 +1：409
        self._approve_reinstate(round_no=3)
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 3, "reinstate", "n2", "n3", KEY_C, "r1",
        )
        self.assertEqual(code, 409)
        # node 不在用：409
        self._approve(
            "r3", _failover_message("d1", 2, "reinstate", "n3", "n1", KEY_A)
        )
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "reinstate", "n3", "n1", KEY_A, "r3",
        )
        self.assertEqual(code, 409)
        # replacement 占用槽位（n1 在用）：同上一条即覆盖；非法值 400
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "reinstate", "n2", None, KEY_C, "r1",
        )
        self.assertEqual(code, 400)
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "reinstate", "n2", "n3", "ZZ" * 32, "r1",
        )
        self.assertEqual(code, 400)

    # ---- 重放：仅六字段全同 200 ------------------------------------------

    def test_replay_only_identical_six_fields_200(self):
        self._rejoin_n3()
        self._approve_reinstate()
        code, view = self._reinstate()
        self.assertEqual(code, 201)
        # 六字段全同：200 同视图
        code, view2 = self._reinstate()
        self.assertEqual(code, 200)
        self.assertEqual(view2, view)
        # 更换审批单：409（即便该单也存在且 approved）
        self._approve_reinstate(rid="r9")
        code, _ = self._reinstate(approval="r9")
        self.assertEqual(code, 409)
        # 更换任一值：409
        code, _ = self._reinstate(node="n1")
        self.assertEqual(code, 409)
        code, _ = self._reinstate(key=KEY_D)
        self.assertEqual(code, 409)
        code, _ = self._reinstate(replacement="n4")
        self.assertEqual(code, 409)
        # 缺 approval_request_id（五键）：409
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "reinstate", "n2", "n3", KEY_C,
        )
        self.assertEqual(code, 409)
        # 仍恰一条故障事件
        self.assertEqual(len(self._events("dkg_failover")), 1)

    # ---- 恢复 ------------------------------------------------------------

    def test_restart_recovers_round_and_actor(self):
        self._rejoin_n3()
        self._approve_reinstate()
        code, _ = self._reinstate()
        self.assertEqual(code, 201)
        before = self.svc.get_audit_events("w1")["events"]
        svc2 = WalletService(self.h.store)
        # 恢复不新增事件、不改 seq
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)
        view = svc2.get_dkg_session("w1", "d1", "2")
        self.assertEqual(view["nodes"], ["n1", "n3"])
        self.assertEqual(view["state"], "commit")
        (event,) = self._events("dkg_failover", svc=svc2)
        self.assertEqual(event["actor_id"], "r1")
        # 重启后同六字段重放仍 200
        code, _ = _call(
            svc2.post_dkg_failover,
            "w1", "d1", 2, "reinstate", "n2", "n3", KEY_C, "r1",
        )
        self.assertEqual(code, 200)

    def _tamper_failover_event(self, mutate):
        path = self._audit_path()
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for event in log["events"]:
            if event["type"] == "dkg_failover":
                mutate(event)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)

    def test_recovery_tampered_actor_id_fail_closed(self):
        self._rejoin_n3()
        self._approve_reinstate()
        code, _ = self._reinstate()
        self.assertEqual(code, 201)
        # actor_id 置 null：reinstate 事件必须携带审批单标识
        self._tamper_failover_event(lambda e: e.update(actor_id=None))
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)
        with self.assertRaises(RecoveryError):
            self.svc.get_dkg_session("w1", "d1")

    def test_recovery_unknown_approval_fail_closed(self):
        self._rejoin_n3()
        self._approve_reinstate()
        code, _ = self._reinstate()
        self.assertEqual(code, 201)
        # actor_id 指向未知审批单
        self._tamper_failover_event(lambda e: e.update(actor_id="ghost"))
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_recovery_tampered_approval_message_fail_closed(self):
        self._rejoin_n3()
        self._approve_reinstate()
        code, _ = self._reinstate()
        self.assertEqual(code, 201)
        # 篡改审批单 message：恢复按 actor_id 复核审批时逐字不符
        record = self.h.store.get_request("w1", "r1")
        record["message"] = "tampered"
        self.h.store.update_request("w1", "r1", record)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_recovery_replace_with_actor_fail_closed(self):
        # abort/replace 事件的 actor_id 仍必须为 null
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", "n4", KEY_D,
        )
        self.assertEqual(code, 201)
        self._tamper_failover_event(lambda e: e.update(actor_id="r1"))
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    # ---- 审计读取：node_rejoined details 键序（归一化前） ------------------

    def test_audit_read_rejects_reordered_rejoin_details(self):
        self._rejoin_n3()
        path = self._audit_path()
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for event in log["events"]:
            if event["type"] == "node_rejoined":
                details = event["details"]
                # 同键集、错序（state 提前）
                event["details"] = {
                    "state": details["state"],
                    "rejoin_id": details["rejoin_id"],
                    "dkg_id": details["dkg_id"],
                    "round": details["round"],
                    "node": details["node"],
                    "key": details["key"],
                }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        # 归一化前校验：错序抛 RecoveryError（启动拒绝就绪、常驻 fail-closed）
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)
        with self.assertRaises(RecoveryError):
            self.svc.get_audit_events("w1")

    def test_audit_read_corrupt_json_raises_corrupt_data(self):
        self._rejoin_n3()
        with open(self._audit_path(), "w", encoding="utf-8") as f:
            f.write("{not json")
        with self.assertRaises(CorruptDataError):
            self.svc.get_audit_events("w1")


class ReinstateHttpTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def test_http_reinstate_flow(self):
        with http_server(self.d) as srv:
            srv.request(
                "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
            )
            code, _ = srv.request(
                "PUT", "/v1/wallets/w1/approval-policy",
                {"required_approvals": 1, "timeout_seconds": 3600},
            )
            self.assertEqual(code, 200)
            code, _ = srv.request(
                "PUT", "/v1/wallets/w1/nodes", {"nodes": HEALTH}
            )
            self.assertEqual(code, 200)
            for op, node, key, hsh in (
                ("register", "n1", KEY_A, None),
                ("register", "n2", KEY_B, None),
                ("commit", "n1", None, HASH_A),
                ("commit", "n2", None, HASH_B),
            ):
                code, _ = srv.request(
                    "POST", "/v1/dkg/w1/d1",
                    {"op": op, "node": node, "key": key,
                     "hash": hsh, "peer": None},
                )
                self.assertEqual(code, 201)
            # rejoin n3
            message = _rejoin_message("rj1", "d1", 1, "n3", KEY_C)
            srv.request(
                "POST", "/v1/wallets/w1/sign-requests",
                {"id": "ap1", "message": message},
            )
            srv.request(
                "POST", "/v1/wallets/w1/sign-requests/ap1/approve",
                {"approver_id": "boss"},
            )
            code, _ = srv.request(
                "POST", "/v1/wallets/w1/nodes/n3/rejoin",
                {"rejoin_id": "rj1", "dkg_id": "d1", "round": 1,
                 "key": KEY_C, "approval_request_id": "ap1"},
            )
            self.assertEqual(code, 201)
            # 五键 reinstate：400（体仅含 K+approval_request_id 六键）
            five = {"round": 2, "action": "reinstate", "node": "n2",
                    "replacement": "n3", "key": KEY_C}
            code, _ = srv.request(
                "POST", "/v1/dkg/w1/d1/failover", five
            )
            self.assertEqual(code, 400)
            # 审批单 + 批准
            message = _failover_message("d1", 2, "reinstate",
                                        "n2", "n3", KEY_C)
            srv.request(
                "POST", "/v1/wallets/w1/sign-requests",
                {"id": "r1", "message": message},
            )
            srv.request(
                "POST", "/v1/wallets/w1/sign-requests/r1/approve",
                {"approver_id": "boss"},
            )
            # 六键首提 201
            code, view = srv.request(
                "POST", "/v1/dkg/w1/d1/failover",
                {**five, "approval_request_id": "r1"},
            )
            self.assertEqual(code, 201)
            self.assertEqual(view["nodes"], ["n1", "n3"])
            self.assertEqual(view["state"], "commit")
            # 六字段全同重放 200
            code, _ = srv.request(
                "POST", "/v1/dkg/w1/d1/failover",
                {**five, "approval_request_id": "r1"},
            )
            self.assertEqual(code, 200)
            # 更换审批单 409
            code, _ = srv.request(
                "POST", "/v1/dkg/w1/d1/failover",
                {**five, "approval_request_id": "ap1"},
            )
            self.assertEqual(code, 409)
            # 审计事件：actor_id 为审批单标识、reason 为 null
            code, body = srv.request("GET", "/v1/wallets/w1/audit-events")
            self.assertEqual(code, 200)
            failovers = [
                e for e in body["events"] if e["type"] == "dkg_failover"
            ]
            self.assertEqual(len(failovers), 1)
            self.assertEqual(failovers[0]["actor_id"], "r1")
            self.assertIsNone(failovers[0]["reason"])
            self.assertEqual(failovers[0]["request_id"], "d1/2")


if __name__ == "__main__":
    unittest.main()
