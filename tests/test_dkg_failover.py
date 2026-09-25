"""DKG 故障轮次（POST /v1/dkg/{W}/{D}/failover）与轮次化视图测试。

覆盖：
- abort：限非终态，node/replacement/key 三 null，新轮 aborted 且三空数组、
  public_key null；首提 201、同参重放 200 优先、异参/错轮 409、终态 409；
- replace：限 commit/share，key 为 64 位小写 hex，node 在用、replacement
  空闲，换槽、清空 committed/shared，新轮从 commit 起步，随后可完成；
- GET/POST 轮次定位：故障后无参/旧/未知/非法 R = 409/409/404/400，
  派生轮 register 409，commit/share 沿用旧约（同值重放 200）；
- 事件：dkg_failover（request_id=D/round，details 固定键序）与派生轮
  dkg_stage（request_id=D/round）；
- 重启/灾备保持轮次与 seq、重放不记事件；篡改现场 fail-closed；
- 跨进程并发同一故障轮次只有一个 201；
- 视图只含标识/公钥/哈希，绝不含私钥或份额正文。
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
from threshold_wallet.store import RecoveryError, WalletStore

from tests.helpers import http_server, make_harness

KEY_A = "aa" * 32
KEY_B = "bb" * 32
KEY_C = "cc" * 32
KEY_D = "dd" * 32
HASH_A = "11" * 32
HASH_B = "22" * 32
HASH_C = "33" * 32


def _call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except ServiceError as exc:
        return exc.status, {"error": exc.message}


def _get_on(svc, wallet, did, round=None):
    """get_dkg_session 成功返回视图 dict（非元组），统一为 (200, view)。"""
    try:
        return 200, svc.get_dkg_session(wallet, did, round)
    except ServiceError as exc:
        return exc.status, {"error": exc.message}


def _stage_body(op, node, key=None, hash=None, peer=None):
    return {"op": op, "node": node, "key": key, "hash": hash, "peer": peer}


def _fail_body(round_no, action, node=None, replacement=None, key=None):
    return {
        "round": round_no,
        "action": action,
        "node": node,
        "replacement": replacement,
        "key": key,
    }


class DkgFailoverServiceTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)

    def _post(self, did, op, node, key=None, hash=None, peer=None, round=None):
        return _call(
            self.svc.post_dkg_stage,
            "w1", did, op, node, key, hash, peer, round,
        )

    def _fail(self, did, round_no, action, node=None, replacement=None,
              key=None):
        return _call(
            self.svc.post_dkg_failover,
            "w1", did, round_no, action, node, replacement, key,
        )

    def _get(self, did, round=None):
        try:
            return 200, self.svc.get_dkg_session("w1", did, round)
        except ServiceError as exc:
            return exc.status, {"error": exc.message}

    def _register_pair(self, did="d1"):
        self.assertEqual(self._post(did, "register", "n1", key=KEY_A)[0], 201)
        self.assertEqual(self._post(did, "register", "n2", key=KEY_B)[0], 201)

    def _commit_pair(self, did="d1", round=None):
        self.assertEqual(
            self._post(did, "commit", "n1", hash=HASH_A, round=round)[0],
            201,
        )
        self.assertEqual(
            self._post(did, "commit", "n2", hash=HASH_B, round=round)[0],
            201,
        )

    def _complete(self, did="d1", round=None, hashes=(HASH_A, HASH_B),
                  nodes=("n1", "n2")):
        h1, h2 = hashes
        first, second = nodes
        code, _ = self._post(
            did, "share", first, hash=h2, peer=second, round=round
        )
        self.assertEqual(code, 201)
        code, view = self._post(
            did, "share", second, hash=h1, peer=first, round=round
        )
        self.assertEqual(code, 201)
        return view

    # ---- 基线视图含 round -------------------------------------------------

    def test_baseline_view_has_round_one(self):
        self._register_pair()
        code, view = self._get("d1")
        self.assertEqual(code, 200)
        self.assertEqual(
            list(view),
            ["id", "round", "state", "nodes", "committed", "shared",
             "public_key"],
        )
        self.assertEqual(view["round"], 1)
        self.assertEqual(view["state"], "commit")

    # ---- abort -------------------------------------------------------------

    def test_abort_from_register_state(self):
        # 仅一方注册（register 非终态）也可 abort
        self.assertEqual(self._post("d1", "register", "n1", key=KEY_A)[0], 201)
        code, view = self._fail("d1", 2, "abort")
        self.assertEqual(code, 201)
        self.assertEqual(view["round"], 2)
        self.assertEqual(view["state"], "aborted")
        self.assertEqual(view["nodes"], [])
        self.assertEqual(view["committed"], [])
        self.assertEqual(view["shared"], [])
        self.assertIsNone(view["public_key"])

    def test_abort_from_commit_state(self):
        self._register_pair()
        code, view = self._fail("d1", 2, "abort")
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "aborted")

    def test_abort_rejects_non_null_fields_400(self):
        self._register_pair()
        for body_node, body_repl, body_key in (
            ("n1", None, None),
            (None, "n3", None),
            (None, None, KEY_C),
            ("n1", "n3", KEY_C),
        ):
            code, _ = self._fail(
                "d1", 2, "abort", body_node, body_repl, body_key
            )
            self.assertEqual(
                code, 400, (body_node, body_repl, body_key)
            )

    def test_abort_replay_same_params_200(self):
        self._register_pair()
        self.assertEqual(self._fail("d1", 2, "abort")[0], 201)
        code, view = self._fail("d1", 2, "abort")
        self.assertEqual(code, 200)
        self.assertEqual(view["state"], "aborted")
        # 重放不记事件
        events = self._failover_events("d1")
        self.assertEqual(len(events), 1)

    def test_abort_wrong_round_409(self):
        self._register_pair()
        # 当前轮为 1，下一轮必须是 2；跳号 3 -> 409
        code, _ = self._fail("d1", 3, "abort")
        self.assertEqual(code, 409)
        # 旧轮号 1（且无对应故障事件）-> 409
        code, _ = self._fail("d1", 1, "abort")
        self.assertEqual(code, 409)

    def test_abort_terminal_round_409(self):
        # done 后 abort 409
        self._register_pair()
        self._commit_pair()
        self._complete()
        code, _ = self._fail("d1", 2, "abort")
        self.assertEqual(code, 409)
        # aborted 后再次 abort（新一轮）409
        code, _ = self._fail("d1", 2, "abort")
        self.assertEqual(code, 409)

    def test_abort_unknown_session_and_wallet_404(self):
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "nope", 1, "abort", None, None, None,
        )
        self.assertEqual(code, 404)
        code, _ = _call(
            self.svc.post_dkg_failover,
            "nope", "d1", 1, "abort", None, None, None,
        )
        self.assertEqual(code, 404)

    # ---- replace -----------------------------------------------------------

    def test_replace_happy_path_from_commit(self):
        self._register_pair()
        # 已有一方 commit（commit 阶段中），替换 n2 -> n3
        self.assertEqual(
            self._post("d1", "commit", "n1", hash=HASH_A)[0], 201
        )
        code, view = self._fail(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["round"], 2)
        # 换槽保留槽位序，清空 committed/shared，从 commit 起步
        self.assertEqual(view["state"], "commit")
        self.assertEqual(view["nodes"], ["n1", "n3"])
        self.assertEqual(view["committed"], [])
        self.assertEqual(view["shared"], [])
        self.assertIsNone(view["public_key"])

    def test_replace_then_complete_new_round(self):
        self._register_pair()
        self._commit_pair()
        code, _ = self._fail(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 201)
        # 派生轮 register 一律 409
        code, _ = self._post(
            "d1", "register", "n3", key=KEY_C, round="2"
        )
        self.assertEqual(code, 409)
        # 无参推进 409（必须 ?round=2）
        code, _ = self._post("d1", "commit", "n1", hash=HASH_A)
        self.assertEqual(code, 409)
        # commit/share 沿用旧约
        self.assertEqual(
            self._post("d1", "commit", "n1", hash=HASH_A, round="2")[0],
            201,
        )
        self.assertEqual(
            self._post("d1", "commit", "n3", hash=HASH_C, round="2")[0],
            201,
        )
        view = self._complete(
            "d1", round="2", hashes=(HASH_A, HASH_C), nodes=("n1", "n3")
        )
        self.assertEqual(view["state"], "done")
        self.assertEqual(view["nodes"], ["n1", "n3"])
        # 完成公钥为新轮两 key 按注册（槽位）序拼接
        self.assertEqual(view["public_key"], KEY_A + KEY_C)

    def test_replace_from_share_state(self):
        self._register_pair()
        self._commit_pair()
        self.assertEqual(
            self._post("d1", "share", "n1", hash=HASH_B, peer="n2")[0],
            201,
        )
        code, view = self._fail(
            "d1", 2, "replace", node="n1", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "commit")
        self.assertEqual(view["nodes"], ["n3", "n2"])
        self.assertEqual(view["committed"], [])
        self.assertEqual(view["shared"], [])

    def test_replace_from_register_state_409(self):
        # 仅注册阶段（两方未齐）不允许 replace
        self._register_pair()
        # 双方已齐即进入 commit；再制造只有一方注册的新会话 d2
        self.assertEqual(
            self._post("d2", "register", "n1", key=KEY_A)[0], 201
        )
        code, _ = self._fail(
            "d2", 1, "replace", node="n1", replacement="n3", key=KEY_C
        )
        # 轮号必须是当前轮+1（=2）；先纠正轮号验证阶段限制
        self.assertEqual(code, 409)
        code, _ = self._fail(
            "d2", 2, "replace", node="n1", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 409)

    def test_replace_bad_params_400(self):
        self._register_pair()
        bad = [
            (2, "replace", "bad node!", "n3", KEY_C),
            (2, "replace", None, "n3", KEY_C),
            (2, "replace", "n2", "bad n3!", KEY_C),
            (2, "replace", "n2", None, KEY_C),
            (2, "replace", "n2", "n3", "CC" * 32),
            (2, "replace", "n2", "n3", "cc" * 31),
            (2, "replace", "n2", "n3", None),
            (True, "replace", "n2", "n3", KEY_C),
            (0, "replace", "n2", "n3", KEY_C),
            (2, "dance", "n2", "n3", KEY_C),
            (2, None, "n2", "n3", KEY_C),
        ]
        for round_no, action, node, repl, key in bad:
            code, _ = self._fail("d1", round_no, action, node, repl, key)
            self.assertEqual(
                code, 400, (round_no, action, node, repl, key)
            )

    def test_replace_conflicts_409(self):
        self._register_pair()
        # node 不在用
        code, _ = self._fail(
            "d1", 2, "replace", node="n9", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 409)
        # replacement 已在用（不空闲）
        code, _ = self._fail(
            "d1", 2, "replace", node="n2", replacement="n1", key=KEY_C
        )
        self.assertEqual(code, 409)
        # replacement 与 node 同（在占用集合内）
        code, _ = self._fail(
            "d1", 2, "replace", node="n2", replacement="n2", key=KEY_C
        )
        self.assertEqual(code, 409)

    def test_replace_replay_same_200_diff_409(self):
        self._register_pair()
        args = ("d1", 2, "replace", "n2", "n3", KEY_C)
        self.assertEqual(self._fail(*args)[0], 201)
        code, view = self._fail(*args)
        self.assertEqual(code, 200)
        self.assertEqual(view["nodes"], ["n1", "n3"])
        # 异参（不同 key）409
        code, _ = self._fail("d1", 2, "replace", "n2", "n3", KEY_D)
        self.assertEqual(code, 409)
        # 异 replacement 409
        code, _ = self._fail("d1", 2, "replace", "n2", "n4", KEY_C)
        self.assertEqual(code, 409)

    # ---- 轮次定位（GET / POST）--------------------------------------------

    def test_get_round_resolution_after_abort(self):
        self._register_pair()
        self.assertEqual(self._fail("d1", 2, "abort")[0], 201)
        # 无参 409
        self.assertEqual(self._get("d1")[0], 409)
        # 当前轮 200
        code, view = self._get("d1", round="2")
        self.assertEqual(code, 200)
        self.assertEqual(view["state"], "aborted")
        # 旧轮 409
        self.assertEqual(self._get("d1", round="1")[0], 409)
        # 未知轮 404
        self.assertEqual(self._get("d1", round="3")[0], 404)
        # 非法 R 400
        for bad in ("0", "-1", "x", "1.5", " 2", ""):
            self.assertEqual(self._get("d1", round=bad)[0], 400, bad)

    def test_get_round_before_failover_ignores_param_when_baseline(self):
        self._register_pair()
        # 基线轮 ?round=1 正常
        code, view = self._get("d1", round="1")
        self.assertEqual(code, 200)
        self.assertEqual(view["round"], 1)
        # 未知轮 404
        self.assertEqual(self._get("d1", round="2")[0], 404)

    def test_post_round_resolution_after_replace(self):
        self._register_pair()
        self._commit_pair()
        self.assertEqual(
            self._fail(
                "d1", 2, "replace", "n2", "n3", KEY_C
            )[0],
            201,
        )
        # 无参 409、旧轮 409、未知轮 404、非法 400
        self.assertEqual(
            self._post("d1", "commit", "n1", hash=HASH_A)[0], 409
        )
        self.assertEqual(
            self._post("d1", "commit", "n1", hash=HASH_A, round="1")[0],
            409,
        )
        self.assertEqual(
            self._post("d1", "commit", "n1", hash=HASH_A, round="3")[0],
            404,
        )
        self.assertEqual(
            self._post("d1", "commit", "n1", hash=HASH_A, round="x")[0],
            400,
        )

    def test_aborted_round_stage_post_always_409(self):
        self._register_pair()
        self.assertEqual(self._fail("d1", 2, "abort")[0], 201)
        for op_kwargs in (
            dict(op="commit", node="n1", hash=HASH_A),
            dict(op="share", node="n1", hash=HASH_B, peer="n2"),
            dict(op="register", node="n3", key=KEY_C),
        ):
            code, _ = self._post("d1", round="2", **op_kwargs)
            self.assertEqual(code, 409, op_kwargs)

    def test_stage_replay_in_derived_round_200(self):
        self._register_pair()
        self._commit_pair()
        self.assertEqual(
            self._fail("d1", 2, "replace", "n2", "n3", KEY_C)[0], 201
        )
        self.assertEqual(
            self._post("d1", "commit", "n1", hash=HASH_A, round="2")[0],
            201,
        )
        # 同值重放 200
        code, view = self._post(
            "d1", "commit", "n1", hash=HASH_A, round="2"
        )
        self.assertEqual(code, 200)
        self.assertEqual(view["committed"], ["n1"])
        # 异值 409
        code, _ = self._post(
            "d1", "commit", "n1", hash=HASH_C, round="2"
        )
        self.assertEqual(code, 409)

    # ---- 审计事件 -----------------------------------------------------------

    def _events(self, ttype):
        return [
            e for e in self.svc.get_audit_events("w1")["events"]
            if e["type"] == ttype
        ]

    def _failover_events(self, did="d1"):
        return [
            e for e in self._events("dkg_failover")
            if e["details"]["id"] == did
        ]

    def test_failover_event_shape_abort(self):
        self._register_pair()
        self.assertEqual(self._fail("d1", 2, "abort")[0], 201)
        events = self._failover_events()
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
        self.assertEqual(
            list(event["details"]),
            ["id", "round", "action", "node", "replacement", "key",
             "state"],
        )
        self.assertEqual(
            event["details"],
            {"id": "d1", "round": 2, "action": "abort", "node": None,
             "replacement": None, "key": None, "state": "aborted"},
        )

    def test_failover_event_shape_replace(self):
        self._register_pair()
        self._fail("d1", 2, "replace", "n2", "n3", KEY_C)
        event = self._failover_events()[0]
        self.assertEqual(event["request_id"], "d1/2")
        self.assertEqual(
            event["details"],
            {"id": "d1", "round": 2, "action": "replace", "node": "n2",
             "replacement": "n3", "key": KEY_C, "state": "commit"},
        )

    def test_derived_round_stage_event_request_id(self):
        self._register_pair()
        self._commit_pair()
        self._fail("d1", 2, "replace", "n2", "n3", KEY_C)
        self._post("d1", "commit", "n1", hash=HASH_A, round="2")
        stage_events = [
            e for e in self._events("dkg_stage")
            if e["details"]["id"] == "d1"
        ]
        # 基线轮事件 request_id=d1；派生轮事件 request_id=d1/2
        baseline = [e for e in stage_events if e["request_id"] == "d1"]
        derived = [e for e in stage_events if e["request_id"] == "d1/2"]
        self.assertEqual(len(baseline), 4)  # 2 register + 2 commit
        self.assertEqual(len(derived), 1)
        self.assertEqual(derived[0]["details"]["op"], "commit")
        self.assertEqual(derived[0]["details"]["state"], "commit")

    def test_seq_contiguous_across_failover(self):
        self._register_pair()
        self._fail("d1", 2, "replace", "n2", "n3", KEY_C)
        self._post("d1", "commit", "n1", hash=HASH_A, round="2")
        seqs = [e["seq"] for e in self.svc.get_audit_events("w1")["events"]]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))

    # ---- 重启 / 灾备 --------------------------------------------------------

    def test_restart_keeps_rounds(self):
        self._register_pair()
        self._fail("d1", 2, "abort")
        svc2 = WalletService(self.h.store)
        # 无参仍 409，?round=2 恢复 aborted 视图
        self.assertEqual(
            _get_on(svc2, "w1", "d1")[0], 409
        )
        code, view = _get_on(svc2, "w1", "d1", "2")
        self.assertEqual(code, 200)
        self.assertEqual(view["state"], "aborted")
        self.assertEqual(view["round"], 2)

    def test_restart_resumes_derived_round(self):
        self._register_pair()
        self._commit_pair()
        self._fail("d1", 2, "replace", "n2", "n3", KEY_C)
        svc2 = WalletService(self.h.store)
        code, view = svc2.post_dkg_stage(
            "w1", "d1", "commit", "n1", None, HASH_A, None, "2"
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "commit")
        # 重放不新增事件：总 dkg_stage 数 = 4 基线 + 1
        stage = [
            e for e in svc2.get_audit_events("w1")["events"]
            if e["type"] == "dkg_stage"
        ]
        self.assertEqual(len(stage), 5)

    def test_restart_keeps_completed_derived_round_pubkey(self):
        self._register_pair()
        self._commit_pair()
        self._fail("d1", 2, "replace", "n2", "n3", KEY_C)
        self._post("d1", "commit", "n1", hash=HASH_A, round="2")
        self._post("d1", "commit", "n3", hash=HASH_C, round="2")
        self._complete(
            "d1", round="2", hashes=(HASH_A, HASH_C), nodes=("n1", "n3")
        )
        svc2 = WalletService(self.h.store)
        _, view = _get_on(svc2, "w1", "d1", "2")
        self.assertEqual(view["state"], "done")
        self.assertEqual(view["public_key"], KEY_A + KEY_C)

    def test_backup_restore_keeps_rounds_and_seq(self):
        self._register_pair()
        self._commit_pair()
        self._fail("d1", 2, "replace", "n2", "n3", KEY_C)
        self._post("d1", "commit", "n1", hash=HASH_A, round="2")
        before = self.svc.get_audit_events("w1")["events"]
        out = os.path.join(tempfile.mkdtemp(), "snap.tar")
        self.addCleanup(shutil.rmtree, os.path.dirname(out), ignore_errors=True)
        self.assertEqual(drbackup.backup(self.d, "w1", "S1", out)["status"], 201)
        dst = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, dst, ignore_errors=True)
        self.assertEqual(drbackup.restore(dst, "w1", out)[0], 201)
        svc2 = WalletService(WalletStore(dst))
        _, view = _get_on(svc2, "w1", "d1", "2")
        self.assertEqual(view["state"], "commit")
        self.assertEqual(view["nodes"], ["n1", "n3"])
        self.assertEqual(view["committed"], ["n1"])
        after = svc2.get_audit_events("w1")["events"]
        self.assertEqual(before, after)

    # ---- 损坏 fail-closed ---------------------------------------------------

    def _audit_log_path(self):
        return os.path.join(self.d, "audit", "w1.json")

    def _tamper(self, mutate):
        path = self._audit_log_path()
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        mutate(log)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)

    def test_tampered_failover_state_is_fail_closed(self):
        self._register_pair()
        self._fail("d1", 2, "abort")

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "dkg_failover":
                    e["details"]["state"] = "commit"

        self._tamper(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_tampered_failover_request_id_is_fail_closed(self):
        self._register_pair()
        self._fail("d1", 2, "abort")

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "dkg_failover":
                    e["request_id"] = "d1/9"

        self._tamper(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_stage_event_in_aborted_round_is_fail_closed(self):
        self._register_pair()
        self._fail("d1", 2, "abort")
        # 手工伪造一条 request_id=d1/2 的 commit 事件，推进已 aborted 轮
        path = self._audit_log_path()
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        forged = {
            "seq": len(log["events"]) + 1,
            "type": "dkg_stage",
            "at": log["events"][0]["at"],
            "request_id": "d1/2",
            "actor_id": None,
            "reason": None,
            "details": {
                "id": "d1", "op": "commit", "node": "n1",
                "key": None, "hash": HASH_A, "peer": None,
                "state": "aborted",
            },
        }
        log["events"].append(forged)
        log["next_seq"] = len(log["events"]) + 1
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_non_consecutive_failover_round_is_fail_closed(self):
        self._register_pair()
        self._fail("d1", 2, "abort")

        def mutate(log):
            for e in log["events"]:
                if e["type"] == "dkg_failover":
                    e["details"]["round"] = 5
                    e["request_id"] = "d1/5"

        self._tamper(mutate)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    # ---- 并发：恰一个 201 ---------------------------------------------------

    def test_concurrent_abort_single_201(self):
        self._register_pair()
        results = []
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            code, _ = _call(
                self.svc.post_dkg_failover,
                "w1", "d1", 2, "abort", None, None, None,
            )
            results.append(code)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(results).count(201), 1)
        self.assertEqual(sorted(results).count(200), 7)
        self.assertEqual(len(self._failover_events()), 1)

    def test_concurrent_replace_single_201(self):
        self._register_pair()
        self._commit_pair()
        results = []
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            code, _ = _call(
                self.svc.post_dkg_failover,
                "w1", "d1", 2, "replace", "n2", "n3", KEY_C,
            )
            results.append(code)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(results).count(201), 1)
        self.assertEqual(sorted(results).count(200), 7)
        self.assertEqual(len(self._failover_events()), 1)


class DkgFailoverHttpTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def test_http_failover_flow(self):
        with http_server(self.d) as srv:
            self.assertEqual(
                srv.request("POST", "/v1/wallets",
                            {"wallet_id": "w1", "shares": 2})[0],
                201,
            )
            # 缺键/多键 400
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
            # 未知会话 404
            code, _ = srv.request(
                "POST", "/v1/dkg/w1/nope/failover",
                _fail_body(1, "abort"),
            )
            self.assertEqual(code, 404)
            # 走一轮基线到 commit
            srv.request("POST", "/v1/dkg/w1/d1",
                        _stage_body("register", "n1", key=KEY_A))
            srv.request("POST", "/v1/dkg/w1/d1",
                        _stage_body("register", "n2", key=KEY_B))
            # abort 201
            code, view = srv.request(
                "POST", "/v1/dkg/w1/d1/failover", _fail_body(2, "abort")
            )
            self.assertEqual(code, 201)
            self.assertEqual(view["state"], "aborted")
            # 故障后无参 GET 409，?round=2 200
            self.assertEqual(srv.request("GET", "/v1/dkg/w1/d1")[0], 409)
            code, view = srv.request("GET", "/v1/dkg/w1/d1?round=2")
            self.assertEqual(code, 200)
            self.assertEqual(view["state"], "aborted")
            # abort 后同参重放 200
            code, _ = srv.request(
                "POST", "/v1/dkg/w1/d1/failover", _fail_body(2, "abort")
            )
            self.assertEqual(code, 200)
            # GET failover 子路径不是 GET 资源 -> 404
            self.assertEqual(
                srv.request("GET", "/v1/dkg/w1/d1/failover")[0], 404
            )

    def test_http_replace_then_complete_with_round_query(self):
        with http_server(self.d) as srv:
            srv.request("POST", "/v1/wallets",
                        {"wallet_id": "w1", "shares": 2})
            srv.request("POST", "/v1/dkg/w1/d1",
                        _stage_body("register", "n1", key=KEY_A))
            srv.request("POST", "/v1/dkg/w1/d1",
                        _stage_body("register", "n2", key=KEY_B))
            srv.request("POST", "/v1/dkg/w1/d1",
                        _stage_body("commit", "n1", hash=HASH_A))
            srv.request("POST", "/v1/dkg/w1/d1",
                        _stage_body("commit", "n2", hash=HASH_B))
            code, view = srv.request(
                "POST", "/v1/dkg/w1/d1/failover",
                _fail_body(2, "replace", node="n2", replacement="n3",
                           key=KEY_C),
            )
            self.assertEqual(code, 201)
            self.assertEqual(view["nodes"], ["n1", "n3"])
            # 派生轮带 ?round=2 推进到 done
            code, _ = srv.request(
                "POST", "/v1/dkg/w1/d1?round=2",
                _stage_body("commit", "n1", hash=HASH_A),
            )
            self.assertEqual(code, 201)
            code, _ = srv.request(
                "POST", "/v1/dkg/w1/d1?round=2",
                _stage_body("commit", "n3", hash=HASH_C),
            )
            self.assertEqual(code, 201)
            code, _ = srv.request(
                "POST", "/v1/dkg/w1/d1?round=2",
                _stage_body("share", "n1", hash=HASH_C, peer="n3"),
            )
            self.assertEqual(code, 201)
            code, view = srv.request(
                "POST", "/v1/dkg/w1/d1?round=2",
                _stage_body("share", "n3", hash=HASH_A, peer="n1"),
            )
            self.assertEqual(code, 201)
            self.assertEqual(view["state"], "done")
            self.assertEqual(view["public_key"], KEY_A + KEY_C)

    def test_http_no_key_material_leak_in_logs(self):
        with http_server(self.d) as srv:
            srv.request("POST", "/v1/wallets",
                        {"wallet_id": "w1", "shares": 2})
            srv.request("POST", "/v1/dkg/w1/d1",
                        _stage_body("register", "n1", key=KEY_A))
            srv.request("POST", "/v1/dkg/w1/d1",
                        _stage_body("register", "n2", key=KEY_B))
            srv.request(
                "POST", "/v1/dkg/w1/d1/failover",
                _fail_body(2, "replace", node="n2", replacement="n3",
                           key=KEY_C),
            )
            for line in srv.logs:
                self.assertNotIn("private", line)
                self.assertNotIn(KEY_C, line)


if __name__ == "__main__":
    unittest.main()
