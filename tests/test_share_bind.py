"""DKG 复职节点份额槽位绑定（share-bind）测试。

覆盖：
- POST /v1/wallets/{W}/share-bind：体恰含 id,rotation,dkg,round,node,slot,
  approval 七键；round 为正整数、slot 为 1|2（均拒布尔），键集/类型/值错
  400；
- 未知轮换/DKG/节点/审批及跨钱包审批一律 404；
- 轮换非 prepared、round 非当前 done、node 非该轮 reinstate 换入的 up
  节点、审批非 approved、message 非 B 去 approval 后紧凑 JSON、槽占用均
  409；
- 返回 V={id,node,slot,share_id}（share_id=prepared 轮换 share_ids
  [slot-1]）；首提 201、同 id 同参 200、异参 409；
- share_participant_reinstated 是唯一提交点（request_id=id、
  actor_id=approval、reason=null、details=V）；锁内并发一 201，重启恢复；
- 激活后绑定仅约束签名会话/shares：被绑定份额体恰含
  {node,share_id,signature}，node 不匹配 409、键集/签名错 400；未绑定
  份额、/sign、share-sign 不变；
- 损坏/矛盾现场 fail-closed（RecoveryError → 503），details 键序在归一化
  之前校验。
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
KEY_C = "cc" * 32
HASH_A = "11" * 32
HASH_B = "22" * 32
HASH_C = "33" * 32

HEALTH = {
    "n1": {"key": KEY_A, "state": "up"},
    "n2": {"key": KEY_B, "state": "up"},
    "n3": {"key": KEY_C, "state": "down"},
}


def _bind_message(
    bind_id="b1", rotation="rot1", dkg="d1", round=2, node="n3", slot=2
):
    return json.dumps(
        {
            "id": bind_id,
            "rotation": rotation,
            "dkg": dkg,
            "round": round,
            "node": node,
            "slot": slot,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _call(fn, *args):
    try:
        return fn(*args)
    except ServiceError as exc:
        return exc.status, {"error": exc.message}


class ShareBindServiceTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 600)
        self.svc.put_dkg_nodes("w1", HEALTH)
        # 基线轮：n1/n2 注册并 commit（share 阶段，非 done）
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
        # n3 经 rejoin 审批恢复为 up（轮外待命）
        rj_msg = json.dumps(
            {
                "rejoin_id": "rj1",
                "dkg_id": "d1",
                "round": 1,
                "node": "n3",
                "key": KEY_C,
            },
            separators=(",", ":"),
        )
        self.svc.create_sign_request("w1", "apR", rj_msg)
        self.svc.approve("w1", "apR", "boss")
        code, _ = self.svc.post_node_rejoin(
            "w1", "n3", "rj1", "d1", 1, KEY_C, "apR"
        )
        self.assertEqual(code, 201)
        # reinstate：第 2 轮把 n3 换入 n2 的槽位
        ri_msg = json.dumps(
            {
                "dkg_id": "d1",
                "round": 2,
                "action": "reinstate",
                "node": "n2",
                "replacement": "n3",
                "key": KEY_C,
            },
            separators=(",", ":"),
        )
        self.svc.create_sign_request("w1", "ap2", ri_msg)
        self.svc.approve("w1", "ap2", "boss")
        code, _ = self.svc.post_dkg_failover(
            "w1", "d1", 2, "reinstate", "n2", "n3", KEY_C, "ap2"
        )
        self.assertEqual(code, 201)
        # 第 2 轮推进到 done
        for node, hsh in (("n1", HASH_A), ("n3", HASH_C)):
            code, _ = self.svc.post_dkg_stage(
                "w1", "d1", "commit", node, None, hsh, None, "2"
            )
            self.assertEqual(code, 201)
        for node, peer in (("n1", "n3"), ("n3", "n1")):
            code, _ = self.svc.post_dkg_stage(
                "w1",
                "d1",
                "share",
                node,
                None,
                {"n1": HASH_A, "n3": HASH_C}[peer],
                peer,
                "2",
            )
            self.assertEqual(code, 201)
        self.assertEqual(
            self.svc.get_dkg_session("w1", "d1", "2")["state"], "done"
        )
        # prepared 轮换
        code, _ = self.svc.create_share_rotation("w1", "rot1")
        self.assertEqual(code, 201)

    def _approve_bind(self, rid="apB", message=None):
        msg = message if message is not None else _bind_message()
        code, _ = self.svc.create_sign_request("w1", rid, msg)
        self.assertEqual(code, 201)
        self.svc.approve("w1", rid, "boss")

    def _bind(self, bind_id="b1", rotation="rot1", dkg="d1", round=2,
              node="n3", slot=2, approval="apB"):
        return _call(
            self.svc.post_share_bind,
            "w1", bind_id, rotation, dkg, round, node, slot, approval,
        )

    def _bind_events(self, svc=None):
        svc = svc or self.svc
        return [
            e
            for e in svc.get_audit_events("w1")["events"]
            if e["type"] == "share_participant_reinstated"
        ]

    # ---- 201 / V / 事件 ----------------------------------------------------

    def test_bind_201_returns_view(self):
        self._approve_bind()
        code, view = self._bind()
        self.assertEqual(code, 201)
        self.assertEqual(
            view,
            {"id": "b1", "node": "n3", "slot": 2, "share_id": "rot1-share-2"},
        )
        self.assertEqual(list(view), ["id", "node", "slot", "share_id"])

    def test_bind_slot1_share_id(self):
        self._approve_bind(message=_bind_message(slot=1))
        code, view = self._bind(slot=1)
        self.assertEqual(code, 201)
        self.assertEqual(view["share_id"], "rot1-share-1")

    def test_commit_event_shape(self):
        self._approve_bind()
        code, _ = self._bind()
        self.assertEqual(code, 201)
        events = self._bind_events()
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(
            list(event),
            ["actor_id", "at", "details", "reason", "request_id", "seq", "type"],
        )
        self.assertEqual(event["request_id"], "b1")
        self.assertEqual(event["actor_id"], "apB")
        self.assertIsNone(event["reason"])
        self.assertEqual(
            event["details"],
            {"id": "b1", "node": "n3", "slot": 2, "share_id": "rot1-share-2"},
        )
        self.assertEqual(
            list(event["details"]), ["id", "node", "slot", "share_id"]
        )

    def test_replay_same_params_200(self):
        self._approve_bind()
        code, view = self._bind()
        self.assertEqual(code, 201)
        code, view2 = self._bind()
        self.assertEqual(code, 200)
        self.assertEqual(view2, view)
        # 重放不记事件
        self.assertEqual(len(self._bind_events()), 1)

    def test_replay_wins_over_state_change(self):
        self._approve_bind()
        code, view = self._bind()
        self.assertEqual(code, 201)
        # 事后节点下线、轮换激活、审批推进都不影响幂等重放
        self.svc.put_dkg_nodes(
            "w1",
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "up"},
                "n3": {"key": KEY_C, "state": "down"},
            },
        )
        self.svc.activate_share_rotation("w1", "rot1")
        code, view2 = self._bind()
        self.assertEqual(code, 200)
        self.assertEqual(view2, view)

    def test_same_id_different_params_409(self):
        self._approve_bind()
        code, _ = self._bind()
        self.assertEqual(code, 201)
        # 更换 slot
        code, _ = self._bind(slot=1)
        self.assertEqual(code, 409)
        # 更换 node
        code, _ = self._bind(node="n1")
        self.assertEqual(code, 409)
        # 更换 rotation
        code, _ = self._bind(rotation="rot2")
        self.assertEqual(code, 409)
        # 更换审批单
        code, _ = self._bind(approval="apOther")
        self.assertEqual(code, 409)

    # ---- 400 ---------------------------------------------------------------

    def test_400_bad_types(self):
        self._approve_bind()
        for slot in (True, False, 0, 3, 2.0, "2", None):
            code, _ = self._bind(slot=slot)
            self.assertEqual(code, 400, slot)
        for round_ in (True, False, 0, -1, 2.0, "2", None):
            code, _ = self._bind(round=round_)
            self.assertEqual(code, 400, round_)
        for bad in ("", "a b", None, 5, "x" * 129):
            code, _ = self._bind(bind_id=bad)
            self.assertEqual(code, 400, bad)
            code, _ = self._bind(node=bad)
            self.assertEqual(code, 400, bad)
            code, _ = self._bind(approval=bad)
            self.assertEqual(code, 400, bad)

    # ---- 404 ---------------------------------------------------------------

    def test_404_unknowns(self):
        self._approve_bind()
        code, _ = self._bind(rotation="nope")
        self.assertEqual(code, 404)
        code, _ = self._bind(dkg="nope")
        self.assertEqual(code, 404)
        code, _ = self._bind(node="nope")
        self.assertEqual(code, 404)
        code, _ = self._bind(approval="nope")
        self.assertEqual(code, 404)

    def test_404_cross_wallet_approval(self):
        # 审批单存在于另一钱包：对本钱包仍是未知审批
        self.svc.create_wallet("w2", 2)
        self.svc.put_policy("w2", 1, 600)
        self.svc.create_sign_request("w2", "apW", _bind_message())
        self.svc.approve("w2", "apW", "boss")
        code, _ = self._bind(approval="apW")
        self.assertEqual(code, 404)

    # ---- 409 ---------------------------------------------------------------

    def test_409_rotation_not_prepared(self):
        self._approve_bind()
        code, _ = self._bind()
        self.assertEqual(code, 201)
        self.svc.activate_share_rotation("w1", "rot1")
        self._approve_bind(rid="apC", message=_bind_message(bind_id="b2", slot=1))
        code, _ = self._bind(bind_id="b2", slot=1, approval="apC")
        self.assertEqual(code, 409)

    def test_409_round_not_current(self):
        self._approve_bind(rid="apY", message=_bind_message(bind_id="bY", round=1, slot=1))
        code, _ = self._bind(bind_id="bY", round=1, slot=1, approval="apY")
        self.assertEqual(code, 409)

    def test_409_round_not_done(self):
        # d2 停在 commit 阶段（非 done）
        for op, node, key, hsh in (
            ("register", "n1", KEY_A, None),
            ("register", "n2", KEY_B, None),
            ("commit", "n1", None, HASH_A),
        ):
            code, _ = self.svc.post_dkg_stage("w1", "d2", op, node, key, hsh, None)
            self.assertEqual(code, 201)
        msg = json.dumps(
            {"id": "bN", "rotation": "rot1", "dkg": "d2", "round": 1,
             "node": "n1", "slot": 1},
            separators=(",", ":"),
        )
        self._approve_bind(rid="apN", message=msg)
        code, _ = self._bind(bind_id="bN", dkg="d2", round=1, node="n1",
                             slot=1, approval="apN")
        self.assertEqual(code, 409)

    def test_409_node_not_reinstated(self):
        # n1 是当前轮节点但不是 reinstate 换入者
        self._approve_bind(
            rid="apX",
            message=_bind_message(bind_id="bX", node="n1", slot=1),
        )
        code, _ = self._bind(bind_id="bX", node="n1", slot=1, approval="apX")
        self.assertEqual(code, 409)

    def test_409_node_not_up(self):
        self._approve_bind()
        self.svc.put_dkg_nodes(
            "w1",
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "up"},
                "n3": {"key": KEY_C, "state": "down"},
            },
        )
        code, _ = self._bind()
        self.assertEqual(code, 409)

    def test_409_approval_not_approved(self):
        code, _ = self.svc.create_sign_request("w1", "apP", _bind_message())
        self.assertEqual(code, 201)
        # pending
        code, _ = self._bind(approval="apP")
        self.assertEqual(code, 409)
        # rejected
        self.svc.reject("w1", "apP", "boss")
        code, _ = self._bind(approval="apP")
        self.assertEqual(code, 409)

    def test_409_message_mismatch(self):
        # message 与 B 去 approval 的紧凑 JSON 不符
        self._approve_bind(
            rid="apM",
            message=_bind_message(slot=1),
        )
        code, _ = self._bind(approval="apM")
        self.assertEqual(code, 409)
        # 非紧凑（带空格）
        self._approve_bind(
            rid="apM2",
            message=json.dumps(
                {"id": "b1", "rotation": "rot1", "dkg": "d1", "round": 2,
                 "node": "n3", "slot": 2}
            ),
        )
        code, _ = self._bind(approval="apM2")
        self.assertEqual(code, 409)

    def test_409_slot_occupied(self):
        self._approve_bind()
        code, _ = self._bind()
        self.assertEqual(code, 201)
        self._approve_bind(rid="apC", message=_bind_message(bind_id="b2"))
        code, _ = self._bind(bind_id="b2", approval="apC")
        self.assertEqual(code, 409)

    # ---- 并发 ---------------------------------------------------------------

    def test_concurrent_same_id_one_201(self):
        self._approve_bind()
        results = []

        def fire():
            code, _ = self._bind()
            results.append(code)

        threads = [threading.Thread(target=fire) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count(201), 1)
        self.assertEqual(results.count(200), 7)
        self.assertEqual(len(self._bind_events()), 1)

    # ---- 重启恢复 ------------------------------------------------------------

    def test_restart_recovers_binding(self):
        self._approve_bind()
        code, view = self._bind()
        self.assertEqual(code, 201)
        svc2 = WalletService(WalletStore(self.d))
        events = self._bind_events(svc2)
        self.assertEqual(len(events), 1)
        # 重启后幂等重放仍 200
        code, view2 = _call(
            svc2.post_share_bind, "w1", "b1", "rot1", "d1", 2, "n3", 2, "apB"
        )
        self.assertEqual(code, 200)
        self.assertEqual(view2, view)

    def test_recovery_rejects_tampered_event(self):
        self._approve_bind()
        code, _ = self._bind()
        self.assertEqual(code, 201)
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for event in data["events"]:
            if event["type"] == "share_participant_reinstated":
                event["details"]["node"] = "n1"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.d))

    def test_recovery_rejects_reordered_details(self):
        self._approve_bind()
        code, _ = self._bind()
        self.assertEqual(code, 201)
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for event in data["events"]:
            if event["type"] == "share_participant_reinstated":
                d = event["details"]
                event["details"] = {
                    "share_id": d["share_id"],
                    "slot": d["slot"],
                    "node": d["node"],
                    "id": d["id"],
                }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.d))

    def test_recovery_rejects_corrupt_audit_json(self):
        self._approve_bind()
        code, _ = self._bind()
        self.assertEqual(code, 201)
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write("{not json")
        with self.assertRaises((CorruptDataError, RecoveryError)):
            WalletService(WalletStore(self.d))


class ShareBindSessionEnforcementTest(unittest.TestCase):
    """激活后绑定仅约束签名会话/shares；未绑定份额、/sign、share-sign 不变。"""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 600)
        self.svc.put_dkg_nodes("w1", HEALTH)
        for op, node, key, hsh in (
            ("register", "n1", KEY_A, None),
            ("register", "n2", KEY_B, None),
            ("commit", "n1", None, HASH_A),
            ("commit", "n2", None, HASH_B),
        ):
            self.svc.post_dkg_stage("w1", "d1", op, node, key, hsh, None)
        rj_msg = json.dumps(
            {"rejoin_id": "rj1", "dkg_id": "d1", "round": 1, "node": "n3",
             "key": KEY_C},
            separators=(",", ":"),
        )
        self.svc.create_sign_request("w1", "apR", rj_msg)
        self.svc.approve("w1", "apR", "boss")
        self.svc.post_node_rejoin("w1", "n3", "rj1", "d1", 1, KEY_C, "apR")
        ri_msg = json.dumps(
            {"dkg_id": "d1", "round": 2, "action": "reinstate", "node": "n2",
             "replacement": "n3", "key": KEY_C},
            separators=(",", ":"),
        )
        self.svc.create_sign_request("w1", "ap2", ri_msg)
        self.svc.approve("w1", "ap2", "boss")
        self.svc.post_dkg_failover(
            "w1", "d1", 2, "reinstate", "n2", "n3", KEY_C, "ap2"
        )
        for node, hsh in (("n1", HASH_A), ("n3", HASH_C)):
            self.svc.post_dkg_stage(
                "w1", "d1", "commit", node, None, hsh, None, "2"
            )
        for node, peer in (("n1", "n3"), ("n3", "n1")):
            self.svc.post_dkg_stage(
                "w1", "d1", "share", node, None,
                {"n1": HASH_A, "n3": HASH_C}[peer], peer, "2",
            )
        self.svc.create_share_rotation("w1", "rot1")
        self.svc.create_sign_request("w1", "apB", _bind_message())
        self.svc.approve("w1", "apB", "boss")
        code, _ = self.svc.post_share_bind(
            "w1", "b1", "rot1", "d1", 2, "n3", 2, "apB"
        )
        self.assertEqual(code, 201)

    def _sig(self, share_id, sid, msg):
        return self.h.share_signature("w1", share_id, sid, msg)

    def test_pre_activation_no_constraint(self):
        # 绑定存在但轮换未激活：被绑定份额尚非在用，不约束
        self.svc.create_sign_session("w1", "s1", "m", 600)
        sig = self._sig("share-1", "s1", "m")
        code, _ = self.svc.submit_sign_session_share("w1", "s1", "share-1", sig)
        self.assertEqual(code, 201)

    def test_unbound_share_stray_node_400(self):
        self.svc.create_sign_session("w1", "s1", "m", 600)
        sig = self._sig("share-2", "s1", "m")
        code, _ = _call(
            self.svc.submit_sign_session_share,
            "w1", "s1", "share-2", sig, "n3",
        )
        self.assertEqual(code, 400)

    def test_post_activation_bound_share_needs_node(self):
        self.svc.activate_share_rotation("w1", "rot1")
        self.svc.create_sign_session("w1", "s2", "m2", 600)
        bsig = self._sig("rot1-share-2", "s2", "m2")
        # 缺 node -> 400
        code, _ = _call(
            self.svc.submit_sign_session_share,
            "w1", "s2", "rot1-share-2", bsig,
        )
        self.assertEqual(code, 400)
        # node 类型错 -> 400
        code, _ = _call(
            self.svc.submit_sign_session_share,
            "w1", "s2", "rot1-share-2", bsig, True,
        )
        self.assertEqual(code, 400)
        # node 不匹配 -> 409
        code, _ = _call(
            self.svc.submit_sign_session_share,
            "w1", "s2", "rot1-share-2", bsig, "n1",
        )
        self.assertEqual(code, 409)
        # 正确 node -> 201
        code, _ = self.svc.submit_sign_session_share(
            "w1", "s2", "rot1-share-2", bsig, "n3"
        )
        self.assertEqual(code, 201)

    def test_post_activation_unbound_share_unchanged(self):
        self.svc.activate_share_rotation("w1", "rot1")
        self.svc.create_sign_session("w1", "s2", "m2", 600)
        usig = self._sig("rot1-share-1", "s2", "m2")
        code, _ = self.svc.submit_sign_session_share(
            "w1", "s2", "rot1-share-1", usig
        )
        self.assertEqual(code, 201)
        # 未绑定份额夹带 node -> 400
        code, _ = _call(
            self.svc.submit_sign_session_share,
            "w1", "s2", "rot1-share-1", usig, "n3",
        )
        self.assertEqual(code, 400)

    def test_signed_session_replay_survives_later_rotation(self):
        # 会话用被绑定份额签成 signed 并冻结；之后再轮换把该份额轮换出去，
        # 同值三键体重放仍 200（绑定随份额身份存在）。
        self.svc.activate_share_rotation("w1", "rot1")
        # 会话聚合需同 id 同 message 的 approved 审批单（钱包配了审批策略）
        self.svc.create_sign_request("w1", "s2", "m2")
        self.svc.approve("w1", "s2", "boss")
        self.svc.create_sign_session("w1", "s2", "m2", 600)
        bsig = self._sig("rot1-share-2", "s2", "m2")
        usig = self._sig("rot1-share-1", "s2", "m2")
        code, _ = self.svc.submit_sign_session_share(
            "w1", "s2", "rot1-share-2", bsig, "n3"
        )
        self.assertEqual(code, 201)
        code, _ = self.svc.submit_sign_session_share(
            "w1", "s2", "rot1-share-1", usig
        )
        self.assertEqual(code, 201)
        self.assertEqual(
            self.svc.get_sign_session("w1", "s2")["state"], "signed"
        )
        # 再做一笔轮换（需要新 DKG done；这里直接用一笔不带绑定的轮换即可，
        # 轮换 prepared 前先保证没有其他 prepared）。
        code, _ = self.svc.create_share_rotation("w1", "rot2")
        self.assertEqual(code, 201)
        self.svc.activate_share_rotation("w1", "rot2")
        # 冻结会话的被绑定份额同值三键重放仍 200
        code, _ = self.svc.submit_sign_session_share(
            "w1", "s2", "rot1-share-2", bsig, "n3"
        )
        self.assertEqual(code, 200)
        # 缺 node 仍 400（该份额身份带绑定）
        code, _ = _call(
            self.svc.submit_sign_session_share,
            "w1", "s2", "rot1-share-2", bsig,
        )
        self.assertEqual(code, 400)

    def test_sign_and_share_sign_unchanged(self):
        self.svc.activate_share_rotation("w1", "rot1")
        self.svc.create_sign_request("w1", "pay", "msg1")
        self.svc.approve("w1", "pay", "boss")
        sigs = [
            {"share_id": "rot1-share-1",
             "signature": self._sig("rot1-share-1", "pay", "msg1")},
            {"share_id": "rot1-share-2",
             "signature": self._sig("rot1-share-2", "pay", "msg1")},
        ]
        code, _ = self.svc.sign("w1", "pay", "msg1", sigs)
        self.assertEqual(code, 201)
        # share-sign 本地命令不经绑定约束
        out = self.svc.share_sign("w1", "rot1-share-2", "pay2", "m")
        self.assertIn("signature", out)


class ShareBindHttpTest(unittest.TestCase):
    """HTTP 层键集/路由测试。"""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def test_key_set_enforcement(self):
        with http_server(self.d) as R:
            R.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
            body = {
                "id": "b1", "rotation": "rot1", "dkg": "d1", "round": 2,
                "node": "n3", "slot": 2, "approval": "apB",
            }
            # 缺键
            missing = {k: v for k, v in body.items() if k != "slot"}
            code, _ = R.request("POST", "/v1/wallets/w1/share-bind", missing)
            self.assertEqual(code, 400)
            # 多键
            code, _ = R.request(
                "POST", "/v1/wallets/w1/share-bind", body | {"z": 1}
            )
            self.assertEqual(code, 400)
            # 未知钱包
            code, _ = R.request("POST", "/v1/wallets/nope/share-bind", body)
            self.assertEqual(code, 404)
            # 非对象体
            code, _ = R.request("POST", "/v1/wallets/w1/share-bind", [1, 2])
            self.assertEqual(code, 400)


if __name__ == "__main__":
    unittest.main()
