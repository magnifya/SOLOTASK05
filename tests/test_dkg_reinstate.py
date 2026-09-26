"""DKG 故障节点复职（reinstate）与 node_rejoined details 归一化前键序测试。

覆盖：
- POST /v1/dkg/{W}/{D}/failover 的 action="reinstate"：体恰含
  round,action,node,replacement,key,approval_request_id 六键；
  reinstate 沿用 replace 的换槽派生，但 replacement 额外须为已提交
  node_rejoined 对应的当前 up 空闲节点、key 与健康表一致；
- 审批开关不豁免：开关关闭时仍强制 approval_request_id（五键 400）；
  审批单须同钱包 approved，message 逐字为 dkg_id 后接 K 的紧凑 JSON；
- 首提 201；六字段全同重放 200；更换审批单或任一值 409；
- 唯一 dkg_failover 事件：request_id=D/round、actor_id=审批单（非
  null）、reason=null、details 七键 id,K,state（K 原位展开）、
  state=commit；abort/replace 的 actor_id 仍为 null；
- 恢复按 actor_id 复核审批单与事前生效健康表/更早 rejoin，矛盾
  fail-closed（RecoveryError/CorruptDataError/OSError → 503）；
- 审计读取在归一化之前校验 node_rejoined.details 的 README 键序：
  错序 RecoveryError，坏 JSON CorruptDataError。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import unittest

from threshold_wallet import drbackup
from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import CorruptDataError, RecoveryError, WalletStore

from tests.helpers import http_server, make_harness

KEY_A = "aa" * 32
KEY_B = "bb" * 32
KEY_C = "cc" * 32
KEY_D = "dd" * 32
HASH_A = "11" * 32
HASH_B = "22" * 32
HASH_C = "33" * 32

HEALTH = {
    "n1": {"key": KEY_A, "state": "up"},
    "n2": {"key": KEY_B, "state": "up"},
    "n3": {"key": KEY_C, "state": "down"},
}


def _rejoin_message(node="n3", key=KEY_C, round=1, dkg_id="d1",
                    rejoin_id="rj1"):
    return json.dumps(
        {
            "rejoin_id": rejoin_id,
            "dkg_id": dkg_id,
            "round": round,
            "node": node,
            "key": key,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _reinstate_message(round=2, node="n2", replacement="n3", key=KEY_C,
                       dkg_id="d1", action="reinstate"):
    return json.dumps(
        {
            "dkg_id": dkg_id,
            "round": round,
            "action": action,
            "node": node,
            "replacement": replacement,
            "key": key,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _call(fn, *args):
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
        self.svc.put_policy("w1", 1, 600)
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
        # 把 n3 经 rejoin 审批恢复为 up（轮外待命）。
        self.svc.create_sign_request("w1", "apR", _rejoin_message())
        self.svc.approve("w1", "apR", "boss")
        code, _ = self.svc.post_node_rejoin(
            "w1", "n3", "rj1", "d1", 1, KEY_C, "apR"
        )
        self.assertEqual(code, 201)

    def _approve_failover(self, rid="ap2", message=None):
        msg = message if message is not None else _reinstate_message()
        code, _ = self.svc.create_sign_request("w1", rid, msg)
        self.assertEqual(code, 201)
        self.svc.approve("w1", rid, "boss")

    def _reinstate(self, round=2, node="n2", replacement="n3", key=KEY_C,
                   approval="ap2"):
        return _call(
            self.svc.post_dkg_failover,
            "w1", "d1", round, "reinstate", node, replacement, key,
            approval,
        )

    def _failover_events(self, svc=None):
        svc = svc or self.svc
        return [
            e for e in svc.get_audit_events("w1")["events"]
            if e["type"] == "dkg_failover"
        ]

    # ---- 201 / 派生轮 / 续作 ----------------------------------------------

    def test_reinstate_201_swaps_slot(self):
        self._approve_failover()
        code, view = self._reinstate()
        self.assertEqual(code, 201)
        self.assertEqual(view["id"], "d1")
        self.assertEqual(view["round"], 2)
        self.assertEqual(view["state"], "commit")
        self.assertEqual(view["nodes"], ["n1", "n3"])
        self.assertEqual(view["committed"], [])
        self.assertEqual(view["shared"], [])
        self.assertIsNone(view["public_key"])

    def test_derived_round_continues_with_reinstated_node(self):
        self._approve_failover()
        code, _ = self._reinstate()
        self.assertEqual(code, 201)
        # 派生轮由 n1/n3 继续 commit/share（须带 ?round=2）
        for node, hsh in (("n1", HASH_A), ("n3", HASH_C)):
            code, _ = self.svc.post_dkg_stage(
                "w1", "d1", "commit", node, None, hsh, None, "2"
            )
            self.assertEqual(code, 201)
        code, _ = self.svc.post_dkg_stage(
            "w1", "d1", "share", "n1", None, HASH_C, "n3", "2"
        )
        self.assertEqual(code, 201)
        code, view = self.svc.post_dkg_stage(
            "w1", "d1", "share", "n3", None, HASH_A, "n1", "2"
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "done")
        self.assertEqual(view["public_key"], KEY_A + KEY_C)

    # ---- 审批开关不豁免 ---------------------------------------------------

    def test_switch_off_still_requires_approval_key(self):
        # 开关缺省关闭：五键提交 reinstate 一律 400
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "reinstate", "n2", "n3", KEY_C,
        )
        self.assertEqual(code, 400)

    def test_switch_on_also_gated(self):
        self.svc.put_dkg_failover_policy("w1", True)
        # 开开关但不带审批单：400
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "reinstate", "n2", "n3", KEY_C,
        )
        self.assertEqual(code, 400)
        # 带同钱包 approved 单仍 201
        self._approve_failover()
        code, view = self._reinstate()
        self.assertEqual(code, 201)
        self.assertEqual(view["nodes"], ["n1", "n3"])

    # ---- 400 --------------------------------------------------------------

    def test_invalid_params_400(self):
        bad = [
            (2, None, "n3", KEY_C),          # node 非字符串
            (2, "n2", None, KEY_C),          # replacement 非字符串
            (2, "n2", "n3", None),           # key 非字符串
            (2, "bad id!", "n3", KEY_C),
            (2, "n2", "bad id!", KEY_C),
            (2, "n2", "n3", "CC" * 32),
            (2, "n2", "n3", "cc" * 31),
            ("2", "n2", "n3", KEY_C),        # round 非 int
            (0, "n2", "n3", KEY_C),
        ]
        for round_no, node, repl, key in bad:
            code, _ = _call(
                self.svc.post_dkg_failover,
                "w1", "d1", round_no, "reinstate", node, repl, key, "ap2",
            )
            self.assertEqual(code, 400, (round_no, node, repl, key))

    # ---- 409 前置 ---------------------------------------------------------

    def test_no_rejoin_event_409(self):
        # n4 在健康表中一直 up，但从未 rejoin：不能复职
        self.svc.put_dkg_nodes(
            "w1",
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "up"},
                "n3": {"key": KEY_C, "state": "up"},
                "n4": {"key": KEY_D, "state": "up"},
            },
        )
        self._approve_failover(
            message=_reinstate_message(replacement="n4", key=KEY_D)
        )
        code, _ = self._reinstate(replacement="n4", key=KEY_D)
        self.assertEqual(code, 409)
        self.assertEqual(self._failover_events(), [])

    def test_replacement_no_longer_up_409(self):
        # rejoin 后又把 n3 翻回 down：复职要求当前 up
        self.svc.put_dkg_nodes(
            "w1",
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "up"},
                "n3": {"key": KEY_C, "state": "down"},
            },
        )
        self._approve_failover()
        code, _ = self._reinstate()
        self.assertEqual(code, 409)

    def test_key_mismatch_409(self):
        self._approve_failover(message=_reinstate_message(key=KEY_C))
        # 提交 key 与健康表 n3 的 key 不符（审批单按 KEY_C，故这里先以
        # 未建单的 KEY_D 直送——审批单 message 也不符，仍 409；再单独
        # 构造一张 KEY_D 审批单确认是前置 key 不符而非 message 不符）。
        self._approve_failover("apD", _reinstate_message(key=KEY_D))
        code, _ = self._reinstate(approval="apD", key=KEY_D)
        self.assertEqual(code, 409)

    def test_node_not_active_409(self):
        self._approve_failover(message=_reinstate_message(node="n3"))
        # n3 当前 up 且不占槽，作为被换出 node 非法（不在用）
        code, _ = self._reinstate(node="n3")
        self.assertEqual(code, 409)

    def test_replacement_not_free_409(self):
        self._approve_failover(
            message=_reinstate_message(node="n1", replacement="n2",
                                       key=KEY_B)
        )
        code, _ = self._reinstate(node="n1", replacement="n2", key=KEY_B)
        self.assertEqual(code, 409)

    def test_done_round_409(self):
        # rejoin（在 share 阶段）后把基线轮推进到 done，再复职 409
        for node, hsh, peer in (
            ("n1", HASH_B, "n2"),
            ("n2", HASH_A, "n1"),
        ):
            code, _ = self.svc.post_dkg_stage(
                "w1", "d1", "share", node, None, hsh, peer
            )
            self.assertEqual(code, 201)
        self._approve_failover()
        code, _ = self._reinstate()
        self.assertEqual(code, 409)

    def test_wrong_round_409(self):
        self._approve_failover(message=_reinstate_message(round=3))
        code, _ = self._reinstate(round=3)
        self.assertEqual(code, 409)

    def test_unknown_wallet_or_session_404(self):
        self._approve_failover()
        code, _ = _call(
            self.svc.post_dkg_failover,
            "zz", "d1", 2, "reinstate", "n2", "n3", KEY_C, "ap2",
        )
        self.assertEqual(code, 404)
        code, _ = self._reinstate()  # 占位（同 dkg 正常），下面改 dkg id
        self.assertEqual(code, 201)
        # 已提交轮后用未知会话
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "zzz", 2, "reinstate", "n2", "n3", KEY_C, "ap2",
        )
        self.assertEqual(code, 404)

    # ---- 审批门控 409 -----------------------------------------------------

    def test_unknown_approval_409_and_unchanged(self):
        code, _ = self._reinstate(approval="ghost")
        self.assertEqual(code, 409)
        self.assertEqual(self._failover_events(), [])
        self.assertEqual(self.svc.get_dkg_session("w1", "d1")["round"], 1)

    def test_pending_approval_409(self):
        self.svc.create_sign_request("w1", "ap2", _reinstate_message())
        code, _ = self._reinstate()
        self.assertEqual(code, 409)

    def test_rejected_approval_409(self):
        self.svc.create_sign_request("w1", "ap2", _reinstate_message())
        self.svc.reject("w1", "ap2", "boss")
        code, _ = self._reinstate()
        self.assertEqual(code, 409)

    def test_wrong_message_409(self):
        # 审批 message 键序/内容与提交不符
        self.svc.create_sign_request(
            "w1", "ap2",
            json.dumps(
                {
                    "key": KEY_C, "replacement": "n3", "node": "n2",
                    "action": "reinstate", "round": 2, "dkg_id": "d1",
                }
            ),
        )
        self.svc.approve("w1", "ap2", "boss")
        code, _ = self._reinstate()
        self.assertEqual(code, 409)

    # ---- 重放 -------------------------------------------------------------

    def test_six_field_replay_200(self):
        self._approve_failover()
        code, v1 = self._reinstate()
        self.assertEqual(code, 201)
        code, v2 = self._reinstate()
        self.assertEqual(code, 200)
        self.assertEqual(v2, v1)
        self.assertEqual(len(self._failover_events()), 1)

    def test_change_approval_409(self):
        self._approve_failover()
        self.assertEqual(self._reinstate()[0], 201)
        # 换一张同形已批准审批单：409
        self._approve_failover("ap3")
        code, _ = self._reinstate(approval="ap3")
        self.assertEqual(code, 409)
        # 未知审批单同样 409
        code, _ = self._reinstate(approval="ghost")
        self.assertEqual(code, 409)
        # 不带审批单（五键）在 service 层走六字段重放比对：approval 哨兵
        # 不等于已提交审批单 → 409（HTTP 层的五键 400 由 HttpTest 覆盖）
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "reinstate", "n2", "n3", KEY_C,
        )
        self.assertEqual(code, 409)
        self.assertEqual(len(self._failover_events()), 1)

    def test_change_any_value_409(self):
        self._approve_failover()
        self.assertEqual(self._reinstate()[0], 201)
        # 异 node（审批单也按异参批准，确保比对的是六字段而非仅 message）
        self._approve_failover("a1", _reinstate_message(node="n1"))
        code, _ = self._reinstate(approval="a1", node="n1")
        self.assertEqual(code, 409)
        # 异 replacement/key
        self.svc.put_dkg_nodes(
            "w1",
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "up"},
                "n3": {"key": KEY_C, "state": "up"},
                "n4": {"key": KEY_D, "state": "up"},
            },
        )
        # n4 未 rejoin，即便审批单匹配也会 409（重放优先，异参即 409）
        self._approve_failover(
            "a2", _reinstate_message(replacement="n4", key=KEY_D)
        )
        code, _ = self._reinstate(approval="a2", replacement="n4", key=KEY_D)
        self.assertEqual(code, 409)
        # 异 round
        self._approve_failover("a3", _reinstate_message(round=3))
        code, _ = self._reinstate(approval="a3", round=3)
        self.assertEqual(code, 409)
        self.assertEqual(len(self._failover_events()), 1)

    def test_replay_200_after_policy_toggle(self):
        self._approve_failover()
        code, v1 = self._reinstate()
        self.assertEqual(code, 201)
        # 事后切换故障审批开关：六字段全同重放优先 200、不复查开关现状，
        # 也不重复记事件（恢复对 reinstate 的审批复核只读审批单本身，
        # 与开关无关）。
        self.svc.put_dkg_failover_policy("w1", True)
        code, v2 = self._reinstate()
        self.assertEqual(code, 200)
        self.assertEqual(v2, v1)
        self.svc.put_dkg_failover_policy("w1", False)
        code, v3 = self._reinstate()
        self.assertEqual(code, 200)
        self.assertEqual(v3, v1)
        self.assertEqual(len(self._failover_events()), 1)

    # ---- 事件形状 / 并发 --------------------------------------------------

    def test_event_shape_unique_commit_point(self):
        self._approve_failover()
        self.assertEqual(self._reinstate()[0], 201)
        (event,) = self._failover_events()
        self.assertEqual(event["type"], "dkg_failover")
        self.assertEqual(event["request_id"], "d1/2")
        self.assertEqual(event["actor_id"], "ap2")
        self.assertIsNone(event["reason"])
        self.assertEqual(
            list(event["details"]),
            ["id", "round", "action", "node", "replacement", "key",
             "state"],
        )
        self.assertEqual(
            event["details"],
            {"id": "d1", "round": 2, "action": "reinstate", "node": "n2",
             "replacement": "n3", "key": KEY_C, "state": "commit"},
        )
        # 落盘外层规范序、details 键序
        log = json.load(
            open(os.path.join(self.d, "audit", "w1.json"), encoding="utf-8")
        )
        stored = [e for e in log["events"]
                  if e["type"] == "dkg_failover"][0]
        self.assertEqual(
            list(stored),
            ["actor_id", "at", "details", "reason", "request_id", "seq",
             "type"],
        )
        self.assertEqual(
            list(stored["details"]),
            ["id", "round", "action", "node", "replacement", "key",
             "state"],
        )
        self.assertEqual(stored["actor_id"], "ap2")

    def test_abort_and_replace_actor_remains_null(self):
        # 同一钱包另一会话：replace/abort 的 actor_id 仍为 null
        self._approve_failover()
        self.assertEqual(self._reinstate()[0], 201)
        for node, key in (("n1", KEY_A), ("n2", KEY_B)):
            code, _ = self.svc.post_dkg_stage(
                "w1", "d2", "register", node, key, None, None
            )
            self.assertEqual(code, 201)
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d2", 2, "abort", None, None, None,
        )
        self.assertEqual(code, 201)
        abort_event = [
            e for e in self._failover_events()
            if e["details"]["id"] == "d2"
        ][0]
        self.assertIsNone(abort_event["actor_id"])
        reinstate_event = [
            e for e in self._failover_events()
            if e["details"]["id"] == "d1"
        ][0]
        self.assertEqual(reinstate_event["actor_id"], "ap2")

    def test_concurrent_single_201(self):
        self._approve_failover()
        codes = []
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            codes.append(self._reinstate()[0])

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(codes), [200] * 7 + [201])
        self.assertEqual(len(self._failover_events()), 1)


class ReinstateRecoveryTest(unittest.TestCase):
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
        self.svc.create_sign_request("w1", "apR", _rejoin_message())
        self.svc.approve("w1", "apR", "boss")
        self.assertEqual(
            self.svc.post_node_rejoin(
                "w1", "n3", "rj1", "d1", 1, KEY_C, "apR"
            )[0],
            201,
        )
        self.svc.create_sign_request("w1", "ap2", _reinstate_message())
        self.svc.approve("w1", "ap2", "boss")
        code, self.view = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "reinstate", "n2", "n3", KEY_C, "ap2",
        )
        self.assertEqual(code, 201)

    def _audit_path(self):
        return os.path.join(self.d, "audit", "w1.json")

    def _rewrite(self, mutate):
        path = self._audit_path()
        log = json.load(open(path, encoding="utf-8"))
        mutate(log)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)

    def _assert_refuses_ready(self):
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_restart_keeps_round_seq_and_replays(self):
        before = self.svc.get_audit_events("w1")["events"]
        svc2 = WalletService(self.h.store)
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)
        view = svc2.get_dkg_session("w1", "d1", "2")
        self.assertEqual(view["nodes"], ["n1", "n3"])
        self.assertEqual(view["state"], "commit")
        # 六字段全同重放 200，不记事件
        code, v2 = _call(
            svc2.post_dkg_failover,
            "w1", "d1", 2, "reinstate", "n2", "n3", KEY_C, "ap2",
        )
        self.assertEqual(code, 200)
        self.assertEqual(v2, self.view)
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)
        seqs = [e["seq"] for e in before]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))

    def test_backup_restore_keeps_reinstate(self):
        out = os.path.join(tempfile.mkdtemp(), "snap.tar")
        self.addCleanup(shutil.rmtree, os.path.dirname(out),
                        ignore_errors=True)
        self.assertEqual(
            drbackup.backup(self.d, "w1", "S1", out)["status"], 201
        )
        dst = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, dst, ignore_errors=True)
        status, _ = drbackup.restore(dst, "w1", out)
        self.assertEqual(status, 201)
        svc2 = WalletService(WalletStore(dst))
        self.assertEqual(
            svc2.get_dkg_session("w1", "d1", "2")["nodes"], ["n1", "n3"]
        )
        code, _ = _call(
            svc2.post_dkg_failover,
            "w1", "d1", 2, "reinstate", "n2", "n3", KEY_C, "ap2",
        )
        self.assertEqual(code, 200)

    def test_actor_nulled_fail_closed(self):
        def mutate(log):
            for e in log["events"]:
                if e["type"] == "dkg_failover":
                    e["actor_id"] = None
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_actor_malformed_fail_closed(self):
        def mutate(log):
            for e in log["events"]:
                if e["type"] == "dkg_failover":
                    e["actor_id"] = "bad id!"
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_forged_actor_on_abort_fail_closed(self):
        # 在另一会话提交一个 abort（actor 为 null），再伪造非 null actor：
        # abort 的 actor_id 必须为 null，恢复 fail-closed。
        for node, key in (("n1", KEY_A), ("n2", KEY_B)):
            code, _ = self.svc.post_dkg_stage(
                "w1", "d2", "register", node, key, None, None
            )
            self.assertEqual(code, 201)
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d2", 2, "abort", None, None, None,
        )
        self.assertEqual(code, 201)

        def mutate(log):
            for e in log["events"]:
                if (
                    e["type"] == "dkg_failover"
                    and e["details"].get("id") == "d2"
                ):
                    e["actor_id"] = "mallory"
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_approval_message_tampered_fail_closed(self):
        req_path = os.path.join(self.d, "requests", "w1.json")
        requests = json.load(open(req_path, encoding="utf-8"))
        requests["ap2"]["message"] = _reinstate_message() + "x"
        with open(req_path, "w", encoding="utf-8") as f:
            json.dump(requests, f)
        self._assert_refuses_ready()

    def test_approval_state_pending_fail_closed(self):
        req_path = os.path.join(self.d, "requests", "w1.json")
        requests = json.load(open(req_path, encoding="utf-8"))
        requests["ap2"]["state"] = "pending"
        with open(req_path, "w", encoding="utf-8") as f:
            json.dump(requests, f)
        self._assert_refuses_ready()

    def test_approval_deleted_fail_closed(self):
        os.unlink(os.path.join(self.d, "requests", "w1.json"))
        self._assert_refuses_ready()

    def test_signed_approval_state_accepted(self):
        # 提交后审批单经 /sign 推进为 signed：恢复仍认可
        req_path = os.path.join(self.d, "requests", "w1.json")
        requests = json.load(open(req_path, encoding="utf-8"))
        requests["ap2"]["state"] = "signed"
        with open(req_path, "w", encoding="utf-8") as f:
            json.dump(requests, f)
        svc2 = WalletService(self.h.store, recover=False)
        with svc2._wallet_lock("w1"):
            svc2._recover_wallet("w1")  # 不应抛

    def test_delete_rejoin_event_fail_closed(self):
        def mutate(log):
            log["events"] = [
                e for e in log["events"]
                if e["type"] != "node_rejoined"
            ]
            for i, event in enumerate(log["events"], 1):
                event["seq"] = i
            log["next_seq"] = len(log["events"]) + 1
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_up_but_never_rejoined_before_failover_fail_closed(self):
        # 删除 rejoin 事件、并把事前快照 n3 改为一直 up：replacement 当时
        # 虽 up 却无更早 node_rejoined 对应，reinstate 不可对账。
        def mutate(log):
            log["events"] = [
                e for e in log["events"]
                if e["type"] != "node_rejoined"
            ]
            for e in log["events"]:
                if e["type"] == "node_state":
                    e["details"]["nodes"]["n3"]["state"] = "up"
            for i, event in enumerate(log["events"], 1):
                event["seq"] = i
            log["next_seq"] = len(log["events"]) + 1
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_replacement_down_before_failover_fail_closed(self):
        # 删除 rejoin、并把健康快照 n3 置 down：reinstate 事前生效表中
        # replacement 非 up，不可对账。
        def mutate(log):
            log["events"] = [
                e for e in log["events"]
                if e["type"] != "node_rejoined"
            ]
            for e in log["events"]:
                if e["type"] == "node_state":
                    e["details"]["nodes"]["n3"]["state"] = "down"
            for i, event in enumerate(log["events"], 1):
                event["seq"] = i
            log["next_seq"] = len(log["events"]) + 1
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_later_down_snapshot_does_not_invalidate(self):
        # 事后把 n3 翻 down：reinstate 复核只看提交前现场，历史有效
        self.svc.put_dkg_nodes(
            "w1",
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "up"},
                "n3": {"key": KEY_C, "state": "down"},
            },
        )
        svc2 = WalletService(self.h.store)  # 不抛
        self.assertEqual(
            svc2.get_dkg_session("w1", "d1", "2")["nodes"], ["n1", "n3"]
        )

    def test_corrupt_audit_json_is_503(self):
        with open(self._audit_path(), "wb") as f:
            f.write(b"{not json")
        with self.assertRaises(CorruptDataError):
            self.h.service._audit.dkg_failover_events("w1")
        self._assert_refuses_ready()


class NodeRejoinedStrictDetailsOrderTest(unittest.TestCase):
    """node_rejoined.details 必须在审计归一化之前校验 README 键序。"""

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
        self.svc.create_sign_request("w1", "ap1", _rejoin_message())
        self.svc.approve("w1", "ap1", "boss")
        self.assertEqual(
            self.svc.post_node_rejoin(
                "w1", "n3", "rj1", "d1", 1, KEY_C, "ap1"
            )[0],
            201,
        )

    def _audit_path(self):
        return os.path.join(self.d, "audit", "w1.json")

    def _rewrite(self, mutate):
        path = self._audit_path()
        log = json.load(open(path, encoding="utf-8"))
        mutate(log)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)

    def test_details_reordered_before_normalization_fail_closed(self):
        def mutate(log):
            for e in log["events"]:
                if e["type"] == "node_rejoined":
                    d = e["details"]
                    # 同键集、错序（state 提前）
                    e["details"] = {
                        "state": d["state"],
                        "rejoin_id": d["rejoin_id"],
                        "dkg_id": d["dkg_id"],
                        "round": d["round"],
                        "node": d["node"],
                        "key": d["key"],
                    }
        self._rewrite(mutate)
        # 读取即 RecoveryError，且不被归一化静默修正
        with self.assertRaises(RecoveryError):
            self.svc._audit.node_rejoined_events("w1")
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_bad_json_is_corrupt_data(self):
        with open(self._audit_path(), "wb") as f:
            f.write(b"{broken")
        with self.assertRaises(CorruptDataError):
            self.svc._audit.node_rejoined_events("w1")

    def test_canonical_order_still_loads(self):
        # 正常落盘（既定六键序）可正常读取
        events = self.svc._audit.node_rejoined_events("w1")["rj1"]
        self.assertEqual(len(events), 1)
        self.assertEqual(
            list(events[0]["details"]),
            ["rejoin_id", "dkg_id", "round", "node", "key", "state"],
        )


class ReinstateHttpTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def _setup(self, srv):
        srv.request("POST", "/v1/wallets",
                    {"wallet_id": "w1", "shares": 2})
        srv.request(
            "PUT", "/v1/wallets/w1/approval-policy",
            {"required_approvals": 1, "timeout_seconds": 600},
        )
        srv.request("PUT", "/v1/wallets/w1/nodes",
                    {"nodes": HEALTH})
        for body in (
            {"op": "register", "node": "n1", "key": KEY_A,
             "hash": None, "peer": None},
            {"op": "register", "node": "n2", "key": KEY_B,
             "hash": None, "peer": None},
            {"op": "commit", "node": "n1", "key": None,
             "hash": HASH_A, "peer": None},
            {"op": "commit", "node": "n2", "key": None,
             "hash": HASH_B, "peer": None},
        ):
            self.assertEqual(
                srv.request("POST", "/v1/dkg/w1/d1", body)[0], 201
            )
        srv.request(
            "POST", "/v1/wallets/w1/sign-requests",
            {"id": "apR", "message": _rejoin_message()},
        )
        srv.request(
            "POST", "/v1/wallets/w1/sign-requests/apR/approve",
            {"approver_id": "boss"},
        )
        self.assertEqual(
            srv.request(
                "POST", "/v1/wallets/w1/nodes/n3/rejoin",
                {"rejoin_id": "rj1", "dkg_id": "d1", "round": 1,
                 "key": KEY_C, "approval_request_id": "apR"},
            )[0],
            201,
        )
        srv.request(
            "POST", "/v1/wallets/w1/sign-requests",
            {"id": "ap2", "message": _reinstate_message()},
        )
        srv.request(
            "POST", "/v1/wallets/w1/sign-requests/ap2/approve",
            {"approver_id": "boss"},
        )

    def test_http_reinstate_flow(self):
        with http_server(self.d) as srv:
            self._setup(srv)
            five = {"round": 2, "action": "reinstate", "node": "n2",
                    "replacement": "n3", "key": KEY_C}
            # 开关关闭：五键 400、第七键 400
            self.assertEqual(
                srv.request("POST", "/v1/dkg/w1/d1/failover", five)[0],
                400,
            )
            self.assertEqual(
                srv.request(
                    "POST", "/v1/dkg/w1/d1/failover",
                    {**five, "approval_request_id": "ap2", "x": 1},
                )[0],
                400,
            )
            # 六键首提 201
            code, view = srv.request(
                "POST", "/v1/dkg/w1/d1/failover",
                {**five, "approval_request_id": "ap2"},
            )
            self.assertEqual(code, 201)
            self.assertEqual(view["nodes"], ["n1", "n3"])
            # 六字段全同重放 200
            code, _ = srv.request(
                "POST", "/v1/dkg/w1/d1/failover",
                {**five, "approval_request_id": "ap2"},
            )
            self.assertEqual(code, 200)
            # 事件：actor 非 null、details 七键
            code, body = srv.request(
                "GET", "/v1/wallets/w1/audit-events"
            )
            self.assertEqual(code, 200)
            event = [e for e in body["events"]
                     if e["type"] == "dkg_failover"][0]
            self.assertEqual(event["request_id"], "d1/2")
            self.assertEqual(event["actor_id"], "ap2")
            self.assertIsNone(event["reason"])
            self.assertEqual(
                list(event["details"]),
                ["id", "round", "action", "node", "replacement", "key",
                 "state"],
            )

    def test_http_reinstate_503_on_corruption(self):
        with http_server(self.d) as srv:
            self._setup(srv)
            five = {"round": 2, "action": "reinstate", "node": "n2",
                    "replacement": "n3", "key": KEY_C}
            self.assertEqual(
                srv.request(
                    "POST", "/v1/dkg/w1/d1/failover",
                    {**five, "approval_request_id": "ap2"},
                )[0],
                201,
            )
            # 篡改 rejoin details 键序：下一次 failover 读审计即 503
            path = os.path.join(self.d, "audit", "w1.json")
            log = json.load(open(path, encoding="utf-8"))
            for e in log["events"]:
                if e["type"] == "node_rejoined":
                    d = e["details"]
                    e["details"] = {
                        "state": d["state"], "key": d["key"],
                        "node": d["node"], "round": d["round"],
                        "dkg_id": d["dkg_id"],
                        "rejoin_id": d["rejoin_id"],
                    }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(log, f)
            code, body = srv.request(
                "POST", "/v1/dkg/w1/d1/failover",
                {**five, "approval_request_id": "ap2"},
            )
            self.assertEqual(code, 503)
            self.assertEqual(
                body, {"error": "service temporarily unavailable"}
            )


if __name__ == "__main__":
    unittest.main()
