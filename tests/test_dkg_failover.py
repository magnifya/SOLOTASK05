"""DKG 故障轮次（/v1/dkg/{W}/{D}/failover）测试。

覆盖：
- replace：限两方 commit|share，换槽、清空 committed/shared 回到 commit；
- abort：限非终态，派生 aborted 空轮（三空数组）；
- 首提 201、同参重放 200 优先、异参 409、钱包/会话未知 404、非法 400；
- 故障后轮次参照：P 缺参/旧轮 409、未知轮 404、非法 400，GET 200；
  aborted 轮一律 409，派生轮 register 409，commit/share 旧约；
- dkg_failover/dkg_stage 事件 request_id 为 <id>/<轮次>，details 键序
  既定，重放不记；重启/灾备保轮次与 seq；矛盾现场 fail-closed。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from threshold_wallet import drbackup
from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import RecoveryError, WalletStore

from tests.helpers import http_server, make_harness

KEY_A = "aa" * 32
KEY_B = "bb" * 32
KEY_C = "cc" * 32
KEY_D = "dd" * 32
HASH_A = "11" * 32
HASH_B = "22" * 32
HASH_C = "33" * 32

VIEW_KEYS = ["id", "round", "state", "nodes", "committed", "shared",
             "public_key"]


def _call(fn, *args):
    """把 ServiceError 归一为 (status, {"error": ...})，便于断言状态码。"""
    try:
        return fn(*args)
    except ServiceError as exc:
        return exc.status, {"error": exc.message}


class DkgFailoverServiceTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)

    def _post(self, did, op, node, key=None, hash=None, peer=None,
              round=None):
        return _call(
            self.svc.post_dkg_stage,
            "w1", did, op, node, key, hash, peer, round,
        )

    def _get(self, did, wallet="w1", round=None):
        try:
            return 200, self.svc.get_dkg_session(wallet, did, round)
        except ServiceError as exc:
            return exc.status, {"error": exc.message}

    def _failover(self, did, round, action, node=None, replacement=None,
                  key=None, wallet="w1"):
        return _call(
            self.svc.post_dkg_failover,
            wallet, did, round, action, node, replacement, key,
        )

    def _register_pair(self, did="d1"):
        code, _ = self._post(did, "register", "n1", key=KEY_A)
        self.assertEqual(code, 201)
        code, _ = self._post(did, "register", "n2", key=KEY_B)
        self.assertEqual(code, 201)

    def _commit_pair(self, did="d1", round=None, n1="n1", n2="n2"):
        code, _ = self._post(did, "commit", n1, hash=HASH_A, round=round)
        self.assertEqual(code, 201)
        code, _ = self._post(did, "commit", n2, hash=HASH_B, round=round)
        self.assertEqual(code, 201)

    def _complete(self, did="d1"):
        self._register_pair(did)
        self._commit_pair(did)
        code, _ = self._post(did, "share", "n1", hash=HASH_B, peer="n2")
        self.assertEqual(code, 201)
        code, view = self._post(did, "share", "n2", hash=HASH_A, peer="n1")
        self.assertEqual(code, 201)
        return view

    def _events(self, event_type, svc=None):
        svc = svc or self.svc
        return [
            e for e in svc.get_audit_events("w1")["events"]
            if e["type"] == event_type
        ]

    # ---- replace 故障轮次 -------------------------------------------------

    def test_replace_happy_path(self):
        self._register_pair()
        self._commit_pair()
        code, view = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 201)
        self.assertEqual(list(view), VIEW_KEYS)
        self.assertEqual(view["id"], "d1")
        self.assertEqual(view["round"], 2)
        self.assertEqual(view["state"], "commit")
        # 换槽：n3 顶替 n2 的槽位；后两数组清空
        self.assertEqual(view["nodes"], ["n1", "n3"])
        self.assertEqual(view["committed"], [])
        self.assertEqual(view["shared"], [])
        self.assertIsNone(view["public_key"])

    def test_replace_from_share_stage(self):
        self._register_pair()
        self._commit_pair()
        code, _ = self._post("d1", "share", "n1", hash=HASH_B, peer="n2")
        self.assertEqual(code, 201)
        code, view = self._failover(
            "d1", 2, "replace", node="n1", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "commit")
        self.assertEqual(view["nodes"], ["n3", "n2"])

    def test_replace_then_complete_derived_round(self):
        self._register_pair()
        self._commit_pair()
        code, _ = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 201)
        # 派生轮 commit/share 旧约（须带 ?round=2）
        self._commit_pair(round="2", n1="n1", n2="n3")
        code, _ = self._post(
            "d1", "share", "n1", hash=HASH_B, peer="n3", round="2"
        )
        self.assertEqual(code, 201)
        code, view = self._post(
            "d1", "share", "n3", hash=HASH_A, peer="n1", round="2"
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "done")
        # 完成公钥为派生轮注册序拼接
        self.assertEqual(view["public_key"], KEY_A + KEY_C)
        code, view = self._get("d1", round="2")
        self.assertEqual(code, 200)
        self.assertEqual(view["state"], "done")

    def test_sequential_failovers(self):
        self._register_pair()
        self._commit_pair()
        code, _ = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 201)
        self._commit_pair(round="2", n1="n1", n2="n3")
        # 后续故障基于当前轮（第 2 轮）
        code, view = self._failover(
            "d1", 3, "replace", node="n1", replacement="n4", key=KEY_D
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["round"], 3)
        self.assertEqual(view["nodes"], ["n4", "n3"])
        self.assertEqual(view["state"], "commit")

    # ---- abort 故障轮次 ---------------------------------------------------

    def test_abort_happy_path(self):
        self._register_pair()
        code, view = self._failover("d1", 2, "abort")
        self.assertEqual(code, 201)
        self.assertEqual(list(view), VIEW_KEYS)
        self.assertEqual(view["round"], 2)
        self.assertEqual(view["state"], "aborted")
        self.assertEqual(view["nodes"], [])
        self.assertEqual(view["committed"], [])
        self.assertEqual(view["shared"], [])
        self.assertIsNone(view["public_key"])

    def test_abort_terminal_round_409(self):
        self._complete()
        code, _ = self._failover("d1", 2, "abort")
        self.assertEqual(code, 409)
        # aborted 轮也是终态：不能再故障
        self._register_pair("d2")
        code, _ = self._failover("d2", 2, "abort")
        self.assertEqual(code, 201)
        code, _ = self._failover("d2", 3, "abort")
        self.assertEqual(code, 409)
        code, _ = self._failover(
            "d2", 3, "replace", node="n1", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 409)

    def test_replace_wrong_stage_409(self):
        # register 阶段（不足两方）不能 replace
        code, _ = self._post("d1", "register", "n1", key=KEY_A)
        self.assertEqual(code, 201)
        code, _ = self._failover(
            "d1", 2, "replace", node="n1", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 409)
        # done 后不能 replace
        self._complete("d2")
        code, _ = self._failover(
            "d2", 2, "replace", node="n1", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 409)

    def test_replace_membership_409(self):
        self._register_pair()
        self._commit_pair()
        # node 不在用
        code, _ = self._failover(
            "d1", 2, "replace", node="n9", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 409)
        # replacement 不空闲（含 replacement == node）
        code, _ = self._failover(
            "d1", 2, "replace", node="n1", replacement="n2", key=KEY_C
        )
        self.assertEqual(code, 409)
        code, _ = self._failover(
            "d1", 2, "replace", node="n1", replacement="n1", key=KEY_C
        )
        self.assertEqual(code, 409)

    # ---- 幂等与轮次序号 -----------------------------------------------------

    def test_replay_200_preempts(self):
        self._register_pair()
        self._commit_pair()
        code, view = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 201)
        # 同参重放 200 同体优先
        code, view2 = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 200)
        self.assertEqual(view2, view)
        # 异参 409
        code, _ = self._failover(
            "d1", 2, "replace", node="n1", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 409)
        code, _ = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_D
        )
        self.assertEqual(code, 409)
        code, _ = self._failover("d1", 2, "abort")
        self.assertEqual(code, 409)
        # 重放不记事件：仍恰 1 条 dkg_failover
        self.assertEqual(len(self._events("dkg_failover")), 1)

    def test_round_sequence_409(self):
        self._register_pair()
        # 首轮故障必须基于基线轮：round 必须恰为 2
        code, _ = self._failover("d1", 1, "abort")
        self.assertEqual(code, 409)
        code, _ = self._failover("d1", 3, "abort")
        self.assertEqual(code, 409)
        code, _ = self._failover("d1", 2, "abort")
        self.assertEqual(code, 201)
        # 终态后无后续轮次
        code, _ = self._failover("d1", 3, "abort")
        self.assertEqual(code, 409)

    # ---- 400 / 404 ----------------------------------------------------------

    def test_invalid_params_400(self):
        self._register_pair()
        bad = [
            # round 类型非法
            ("d1", "2", "abort", None, None, None),
            ("d1", 2.0, "abort", None, None, None),
            ("d1", True, "abort", None, None, None),
            ("d1", 0, "abort", None, None, None),
            ("d1", -1, "abort", None, None, None),
            ("d1", None, "abort", None, None, None),
            # action 未知
            ("d1", 2, "noop", None, None, None),
            ("d1", 2, None, None, None, None),
            # abort 夹带非 null 值
            ("d1", 2, "abort", "n1", None, None),
            ("d1", 2, "abort", None, "n3", None),
            ("d1", 2, "abort", None, None, KEY_C),
            # replace：node/replacement 非法、key 非法
            ("d1", 2, "replace", "bad node!", "n3", KEY_C),
            ("d1", 2, "replace", None, "n3", KEY_C),
            ("d1", 2, "replace", "n1", "bad node!", KEY_C),
            ("d1", 2, "replace", "n1", None, KEY_C),
            ("d1", 2, "replace", "n1", "n3", "CC" * 32),
            ("d1", 2, "replace", "n1", "n3", "cc" * 31),
            ("d1", 2, "replace", "n1", "n3", None),
        ]
        for did, round, action, node, repl, key in bad:
            code, _ = self._failover(
                did, round, action, node=node, replacement=repl, key=key
            )
            self.assertEqual(
                code, 400, (did, round, action, node, repl, key)
            )
        # 非法 dkg id
        code, _ = self._failover("bad id!", 2, "abort")
        self.assertEqual(code, 400)

    def test_unknown_wallet_or_session_404(self):
        code, _ = self._failover("d1", 2, "abort", wallet="nope")
        self.assertEqual(code, 404)
        code, _ = self._failover("d1", 2, "abort")
        self.assertEqual(code, 404)

    # ---- 故障后的 P（?round=） ---------------------------------------------

    def test_p_requires_current_round_after_failover(self):
        self._register_pair()
        self._commit_pair()
        code, _ = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 201)
        # 缺参 409（GET/POST 同样）
        code, _ = self._get("d1")
        self.assertEqual(code, 409)
        code, _ = self._post("d1", "commit", "n1", hash=HASH_A)
        self.assertEqual(code, 409)
        # 旧轮 409
        code, _ = self._get("d1", round="1")
        self.assertEqual(code, 409)
        code, _ = self._post(
            "d1", "commit", "n1", hash=HASH_A, round="1"
        )
        self.assertEqual(code, 409)
        # 未知轮 404
        code, _ = self._get("d1", round="9")
        self.assertEqual(code, 404)
        code, _ = self._post(
            "d1", "commit", "n1", hash=HASH_A, round="9"
        )
        self.assertEqual(code, 404)
        # 非法 R 400
        for bad in ("x", "1.5", "01", "-1", "0", ""):
            code, _ = self._get("d1", round=bad)
            self.assertEqual(code, 400, bad)
        # 当前轮 GET 200
        code, view = self._get("d1", round="2")
        self.assertEqual(code, 200)
        self.assertEqual(view["round"], 2)
        self.assertEqual(view["nodes"], ["n1", "n3"])

    def test_derived_round_register_409(self):
        self._register_pair()
        self._commit_pair()
        code, _ = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 201)
        code, _ = self._post("d1", "register", "n4", key=KEY_D, round="2")
        self.assertEqual(code, 409)
        # 旧节点再 register 也 409
        code, _ = self._post("d1", "register", "n1", key=KEY_A, round="2")
        self.assertEqual(code, 409)

    def test_aborted_round_all_409(self):
        self._register_pair()
        code, _ = self._failover("d1", 2, "abort")
        self.assertEqual(code, 201)
        code, _ = self._get("d1", round="2")
        self.assertEqual(code, 409)
        code, _ = self._post("d1", "register", "n1", key=KEY_A, round="2")
        self.assertEqual(code, 409)
        code, _ = self._post("d1", "commit", "n1", hash=HASH_A, round="2")
        self.assertEqual(code, 409)
        code, _ = self._post(
            "d1", "share", "n1", hash=HASH_B, peer="n2", round="2"
        )
        self.assertEqual(code, 409)

    def test_p_without_failover_keeps_old_behavior(self):
        # 无故障轮次：P 无需参照轮次；显式 ?round=1 亦接受
        code, view = self._post("d1", "register", "n1", key=KEY_A)
        self.assertEqual(code, 201)
        self.assertEqual(view["round"], 1)
        code, view = self._post(
            "d1", "register", "n2", key=KEY_B, round="1"
        )
        self.assertEqual(code, 201)
        code, view = self._get("d1")
        self.assertEqual(code, 200)
        self.assertEqual(view["round"], 1)
        code, view = self._get("d1", round="1")
        self.assertEqual(code, 200)
        # 未知轮 404
        code, _ = self._get("d1", round="2")
        self.assertEqual(code, 404)

    # ---- 事件与持久化 -------------------------------------------------------

    def test_failover_event_shape_and_order(self):
        self._register_pair()
        self._commit_pair()
        code, _ = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 201)
        events = self._events("dkg_failover")
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(
            set(event),
            {"seq", "type", "at", "request_id", "actor_id", "reason",
             "details"},
        )
        self.assertEqual(event["request_id"], "d1/2")
        self.assertIsNone(event["actor_id"])
        self.assertIsNone(event["reason"])
        # 公开审计查询的外层键序为契约序 seq,type,at,request_id,
        # actor_id,reason,details（不同于落盘 sort_keys 序）
        self.assertEqual(
            list(event),
            ["seq", "type", "at", "request_id", "actor_id", "reason",
             "details"],
        )
        self.assertEqual(
            list(event["details"]),
            ["id", "round", "action", "node", "replacement", "key",
             "state"],
        )
        self.assertEqual(
            event["details"],
            {"id": "d1", "round": 2, "action": "replace", "node": "n2",
             "replacement": "n3", "key": KEY_C, "state": "commit"},
        )
        # 落盘键序一致
        with open(
            os.path.join(self.d, "audit", "w1.json"), encoding="utf-8"
        ) as f:
            log = json.load(f)
        for e in log["events"]:
            if e["type"] == "dkg_failover":
                # 落盘外层七字段仍是 sort_keys 序，公开键序仅在查询副本
                # 上重排（查询不写盘）
                self.assertEqual(
                    list(e),
                    ["actor_id", "at", "details", "reason", "request_id",
                     "seq", "type"],
                )
                self.assertEqual(
                    list(e["details"]),
                    ["id", "round", "action", "node", "replacement",
                     "key", "state"],
                )
        # 同次查询中的其余事件类型仍保持落盘 sort_keys 外层序（其余契约
        # 不变）；重复查询结果一致且为独立副本（查询不写盘、不改现场）。
        stages = self._events("dkg_stage")
        self.assertTrue(stages)
        self.assertEqual(
            list(stages[0]),
            ["actor_id", "at", "details", "reason", "request_id", "seq",
             "type"],
        )
        again = self._events("dkg_failover")
        self.assertEqual([dict(e) for e in again], [dict(e) for e in events])
        self.assertIsNot(again[0], events[0])

    def test_abort_event_details(self):
        self._register_pair()
        code, _ = self._failover("d1", 2, "abort")
        self.assertEqual(code, 201)
        (event,) = self._events("dkg_failover")
        self.assertEqual(event["request_id"], "d1/2")
        self.assertEqual(
            event["details"],
            {"id": "d1", "round": 2, "action": "abort", "node": None,
             "replacement": None, "key": None, "state": "aborted"},
        )

    def test_derived_round_stage_events(self):
        self._register_pair()
        self._commit_pair()
        code, _ = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 201)
        code, _ = self._post(
            "d1", "commit", "n1", hash=HASH_A, round="2"
        )
        self.assertEqual(code, 201)
        stages = self._events("dkg_stage")
        # 基线轮 4 条（request_id 为 d1）+ 派生轮 1 条（request_id 为 d1/2）
        self.assertEqual(len(stages), 5)
        derived = [e for e in stages if e["request_id"] == "d1/2"]
        self.assertEqual(len(derived), 1)
        self.assertEqual(
            list(derived[0]["details"]),
            ["id", "op", "node", "key", "hash", "peer", "state"],
        )
        self.assertEqual(
            derived[0]["details"],
            {"id": "d1", "op": "commit", "node": "n1", "key": None,
             "hash": HASH_A, "peer": None, "state": "commit"},
        )

    def test_restart_keeps_rounds_and_seq(self):
        self._register_pair()
        self._commit_pair()
        code, _ = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 201)
        before = self.svc.get_audit_events("w1")["events"]
        svc2 = WalletService(self.h.store)
        # 恢复不新增审计事件，seq 连续
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)
        view = svc2.get_dkg_session("w1", "d1", "2")
        self.assertEqual(view["round"], 2)
        self.assertEqual(view["nodes"], ["n1", "n3"])
        # 重启后续作派生轮
        code, view = svc2.post_dkg_stage(
            "w1", "d1", "commit", "n1", None, HASH_A, None, "2"
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "commit")
        seqs = [e["seq"] for e in svc2.get_audit_events("w1")["events"]]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))

    def test_tampered_failover_event_is_fail_closed(self):
        self._register_pair()
        self._commit_pair()
        code, _ = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 201)
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for event in log["events"]:
            if event["type"] == "dkg_failover":
                # 篡改：故障动作与落盘状态自相矛盾
                event["details"]["state"] = "done"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_failover_event_outer_fields_reordered_is_fail_closed(self):
        # 落盘外层七字段错序（规范序为 actor_id,at,details,reason,
        # request_id,seq,type）：审计加载在归一化之前即 RecoveryError，
        # 拒绝就绪、绝不写盘
        self._register_pair()
        self._commit_pair()
        code, _ = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 201)
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for event in log["events"]:
            if event["type"] == "dkg_failover":
                # 同键集、外层错序（公开契约序而非落盘规范序）
                reordered = {
                    "seq": event["seq"],
                    "type": event["type"],
                    "at": event["at"],
                    "request_id": event["request_id"],
                    "actor_id": event["actor_id"],
                    "reason": event["reason"],
                    "details": event["details"],
                }
                event.clear()
                event.update(reordered)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        raw_before = open(path, "rb").read()
        # 读取即 RecoveryError，且不被归一化静默修正
        with self.assertRaises(RecoveryError):
            self.svc._audit.dkg_failover_events("w1")
        # 追加写盘前的加载同样 fail-closed：错序现场绝不写盘
        with self.assertRaises(RecoveryError):
            self.svc._audit.append_event(
                "w1",
                {
                    "type": "dkg_stage",
                    "at": "2026-01-01T00:00:00Z",
                    "request_id": "d1",
                    "actor_id": None,
                    "reason": None,
                    "details": {},
                },
            )
        self.assertEqual(open(path, "rb").read(), raw_before)
        # 启动恢复拒绝就绪
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_missing_failover_event_is_fail_closed(self):
        self._register_pair()
        self._commit_pair()
        code, _ = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 201)
        code, _ = self._post(
            "d1", "commit", "n1", hash=HASH_A, round="2"
        )
        self.assertEqual(code, 201)
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        # 删除故障事件：派生轮的 dkg_stage 失去派生依据
        events = [
            e for e in log["events"] if e["type"] != "dkg_failover"
        ]
        for i, event in enumerate(events, 1):
            event["seq"] = i
        log["events"] = events
        log["next_seq"] = len(events) + 1
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_concurrent_failover_single_201(self):
        # 跨线程并发同一故障：恰一个 201，其余幂等 200，事件只记一次
        self._register_pair()
        self._commit_pair()
        import threading

        codes = []
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            code, _ = self._failover(
                "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C
            )
            codes.append(code)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(codes), [200] * 7 + [201])
        self.assertEqual(len(self._events("dkg_failover")), 1)
        seqs = [e["seq"] for e in self.svc.get_audit_events("w1")["events"]]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))

    # ---- 灾备 ---------------------------------------------------------------

    def test_backup_restore_keeps_rounds_and_seq(self):
        self._register_pair()
        self._commit_pair()
        code, _ = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 201)
        self._commit_pair(round="2", n1="n1", n2="n3")
        out = os.path.join(tempfile.mkdtemp(), "snap.tar")
        self.addCleanup(shutil.rmtree, os.path.dirname(out),
                        ignore_errors=True)
        body = drbackup.backup(self.d, "w1", "S1", out)
        self.assertEqual(body["status"], 201)
        dst = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, dst, ignore_errors=True)
        status, _ = drbackup.restore(dst, "w1", out)
        self.assertEqual(status, 201)
        svc2 = WalletService(WalletStore(dst))
        before = self.svc.get_audit_events("w1")["events"]
        after = svc2.get_audit_events("w1")["events"]
        self.assertEqual(before, after)
        view = svc2.get_dkg_session("w1", "d1", "2")
        self.assertEqual(view["state"], "share")
        self.assertEqual(view["nodes"], ["n1", "n3"])
        # 恢复后同参重放仍 200，不记事件
        code, _ = svc2.post_dkg_failover(
            "w1", "d1", 2, "replace", "n2", "n3", KEY_C
        )
        self.assertEqual(code, 200)
        self.assertEqual(
            svc2.get_audit_events("w1")["events"], after
        )


class DkgFailoverHttpTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def test_http_failover_flow(self):
        with http_server(self.d) as srv:
            code, _ = srv.request(
                "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
            )
            self.assertEqual(code, 201)
            body = {"op": "register", "node": "n1", "key": KEY_A,
                    "hash": None, "peer": None}
            code, _ = srv.request("POST", "/v1/dkg/w1/d1", body)
            self.assertEqual(code, 201)
            body = {"op": "register", "node": "n2", "key": KEY_B,
                    "hash": None, "peer": None}
            code, _ = srv.request("POST", "/v1/dkg/w1/d1", body)
            self.assertEqual(code, 201)
            # 请求体缺键/多键一律 400
            code, _ = srv.request(
                "POST", "/v1/dkg/w1/d1/failover",
                {"round": 2, "action": "abort"},
            )
            self.assertEqual(code, 400)
            code, _ = srv.request(
                "POST", "/v1/dkg/w1/d1/failover",
                {"round": 2, "action": "abort", "node": None,
                 "replacement": None, "key": None, "extra": 1},
            )
            self.assertEqual(code, 400)
            # abort 201，视图含轮次
            code, view = srv.request(
                "POST", "/v1/dkg/w1/d1/failover",
                {"round": 2, "action": "abort", "node": None,
                 "replacement": None, "key": None},
            )
            self.assertEqual(code, 201)
            self.assertEqual(
                list(view),
                ["id", "round", "state", "nodes", "committed", "shared",
                 "public_key"],
            )
            self.assertEqual(view["state"], "aborted")
            # 同参重放 200
            code, _ = srv.request(
                "POST", "/v1/dkg/w1/d1/failover",
                {"round": 2, "action": "abort", "node": None,
                 "replacement": None, "key": None},
            )
            self.assertEqual(code, 200)
            # aborted 轮一律 409；缺参 409
            code, _ = srv.request("GET", "/v1/dkg/w1/d1?round=2")
            self.assertEqual(code, 409)
            code, _ = srv.request("GET", "/v1/dkg/w1/d1")
            self.assertEqual(code, 409)
            # failover 仅 POST：GET 404
            code, _ = srv.request("GET", "/v1/dkg/w1/d1/failover")
            self.assertEqual(code, 404)

    def test_http_round_query_param(self):
        with http_server(self.d) as srv:
            srv.request(
                "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
            )
            for node, key in (("n1", KEY_A), ("n2", KEY_B)):
                srv.request(
                    "POST", "/v1/dkg/w1/d1",
                    {"op": "register", "node": node, "key": key,
                     "hash": None, "peer": None},
                )
            code, _ = srv.request(
                "POST", "/v1/dkg/w1/d1/failover",
                {"round": 2, "action": "replace", "node": "n2",
                 "replacement": "n3", "key": KEY_C},
            )
            self.assertEqual(code, 201)
            # 带当前轮的 GET 200
            code, view = srv.request("GET", "/v1/dkg/w1/d1?round=2")
            self.assertEqual(code, 200)
            self.assertEqual(view["nodes"], ["n1", "n3"])
            # 带当前轮的 POST 推进派生轮
            code, view = srv.request(
                "POST", "/v1/dkg/w1/d1?round=2",
                {"op": "commit", "node": "n1", "key": None,
                 "hash": HASH_A, "peer": None},
            )
            self.assertEqual(code, 201)
            self.assertEqual(view["committed"], ["n1"])
            # 旧轮/未知轮/非法轮
            code, _ = srv.request("GET", "/v1/dkg/w1/d1?round=1")
            self.assertEqual(code, 409)
            code, _ = srv.request("GET", "/v1/dkg/w1/d1?round=7")
            self.assertEqual(code, 404)
            code, _ = srv.request("GET", "/v1/dkg/w1/d1?round=x")
            self.assertEqual(code, 400)


if __name__ == "__main__":
    unittest.main()
