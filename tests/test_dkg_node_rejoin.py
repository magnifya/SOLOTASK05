"""DKG 故障节点重新加入（rejoin）与 node_state 恢复严格键序测试。

覆盖：
- P=POST /v1/wallets/{W}/nodes/{N}/rejoin：体恰含
  rejoin_id,dkg_id,round,key,approval_request_id；安全标识/64 位小写
  hex/非布尔正整数；键集/类型/值错 400；钱包、DKG、节点未知 404；
- 首提须 N 为 down|ban、key 匹配、round 为当前 commit|share 轮且 N 不占
  槽、同钱包 approved 审批单且 message 为按 rejoin_id,dkg_id,round,node,
  key 序的紧凑 JSON，否则 409 且不变；成功 N 置 up、201 返回 V；
- 同 rejoin_id 同参 200 同 V（含审批标识），异参 409；并发仅一 201；
- node_rejoined 为唯一提交点：request_id=rejoin_id、actor_id=
  approval_request_id、reason=null、details=V 且六键固定序；GET nodes
  折叠 rejoin 翻转；
- 恢复按事前健康表（折叠其后更早 rejoin）、DKG（seq 前缀）、审批单
  复核；重复 rejoin_id/坏形状/坏值/矛盾 fail-closed
  （RecoveryError/CorruptDataError/OSError → 503）；
- node_state 恢复严格校验外层/details/nodes/条目键序与节点 ID 升序。
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

HEALTH = {
    "n1": {"key": KEY_A, "state": "up"},
    "n2": {"key": KEY_B, "state": "up"},
    "n3": {"key": KEY_C, "state": "down"},
}


def _msg(rejoin_id="rj1", dkg_id="d1", round_no=1, node="n3", key=KEY_C):
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
    try:
        return fn(*args)
    except ServiceError as exc:
        return exc.status, {"error": exc.message}


class RejoinServiceTest(unittest.TestCase):
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

    def _rejoin(self, node="n3", rejoin_id="rj1", dkg_id="d1", round_no=1,
                key=KEY_C, approval="ap1", wallet="w1"):
        return _call(
            self.svc.post_node_rejoin,
            wallet, node, rejoin_id, dkg_id, round_no, key, approval,
        )

    def _approve(self, rid="ap1", rejoin_id="rj1", dkg_id="d1",
                 round_no=1, node="n3", key=KEY_C, message=None):
        msg = message if message is not None else _msg(
            rejoin_id, dkg_id, round_no, node, key
        )
        code, _ = self.svc.create_sign_request("w1", rid, msg)
        self.assertEqual(code, 201)
        self.svc.approve("w1", rid, "boss")

    def _rejoin_events(self, svc=None):
        svc = svc or self.svc
        return [
            e for e in svc.get_audit_events("w1")["events"]
            if e["type"] == "node_rejoined"
        ]

    # ---- 201 / 视图 / 健康表翻转 -----------------------------------------

    def test_first_rejoin_201_sets_node_up(self):
        self._approve()
        code, v = self._rejoin()
        self.assertEqual(code, 201)
        self.assertEqual(
            v,
            {
                "rejoin_id": "rj1",
                "dkg_id": "d1",
                "round": 1,
                "node": "n3",
                "key": KEY_C,
                "state": "up",
            },
        )
        self.assertEqual(
            list(v),
            ["rejoin_id", "dkg_id", "round", "node", "key", "state"],
        )
        nodes = self.svc.get_dkg_nodes("w1")["nodes"]
        self.assertEqual(nodes["n3"]["state"], "up")
        self.assertEqual(nodes["n3"]["key"], KEY_C)

    def test_banned_node_also_allowed(self):
        self.svc.put_dkg_nodes(
            "w1",
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "up"},
                "n3": {"key": KEY_C, "state": "ban"},
            },
        )
        self._approve()
        code, _ = self._rejoin()
        self.assertEqual(code, 201)
        self.assertEqual(
            self.svc.get_dkg_nodes("w1")["nodes"]["n3"]["state"], "up"
        )

    # ---- 400 ---------------------------------------------------------------

    def test_invalid_values_400(self):
        cases = [
            ("n3", "rj1", "d1", True, KEY_C, "ap1"),   # bool round
            ("n3", "rj1", "d1", 0, KEY_C, "ap1"),      # zero round
            ("n3", "rj1", "d1", -1, KEY_C, "ap1"),     # negative round
            ("n3", "rj1", "d1", 1.0, KEY_C, "ap1"),    # float round
            ("n3", "bad id!", "d1", 1, KEY_C, "ap1"),  # bad rejoin id
            ("n3", "rj1", "bad id!", 1, KEY_C, "ap1"),  # bad dkg id
            ("n3", "rj1", "d1", 1, KEY_C, "bad id!"),  # bad approval id
            ("n3", "rj1", "d1", 1, "ZZ" * 32, "ap1"),  # non-lower hex
            ("n3", "rj1", "d1", 1, KEY_C[:-1], "ap1"),  # short key
            ("n3", "rj1", "d1", 1, 123, "ap1"),        # non-string key
            ("n3", 123, "d1", 1, KEY_C, "ap1"),        # non-string rejoin
            (None, "rj1", "d1", 1, KEY_C, "ap1"),      # non-string node
        ]
        for args in cases:
            code, _ = self._rejoin(*args)
            self.assertEqual(code, 400, args)

    def test_invalid_wallet_id_400(self):
        code, _ = self._rejoin(wallet="bad id!")
        self.assertEqual(code, 400)

    # ---- 404 ---------------------------------------------------------------

    def test_unknown_wallet_404(self):
        code, _ = self._rejoin(wallet="zz")
        self.assertEqual(code, 404)

    def test_unknown_dkg_404(self):
        self._approve(rid="a1", dkg_id="zz")
        code, _ = self._rejoin(dkg_id="zz", approval="a1")
        self.assertEqual(code, 404)

    def test_unknown_node_404(self):
        self._approve(rid="a1", node="n9")
        code, _ = self._rejoin(node="n9", approval="a1")
        self.assertEqual(code, 404)

    # ---- 409 前置 ----------------------------------------------------------

    def test_up_node_conflicts_409(self):
        # n2 既 up 又占用槽位：409（且不区分先后，up 优先报冲突）
        self._approve(rid="a1", node="n2", key=KEY_B)
        code, _ = self._rejoin(node="n2", key=KEY_B, approval="a1")
        self.assertEqual(code, 409)
        self.assertEqual(self._rejoin_events(), [])

    def test_node_occupies_slot_409(self):
        # n1 up 且占槽：409
        self._approve(rid="a1", node="n1", key=KEY_A)
        code, _ = self._rejoin(node="n1", key=KEY_A, approval="a1")
        self.assertEqual(code, 409)

    def test_wrong_round_409(self):
        self._approve(rid="a1", round_no=2)
        code, _ = self._rejoin(round_no=2, approval="a1")
        self.assertEqual(code, 409)
        self.assertEqual(self._rejoin_events(), [])

    def test_key_mismatch_409(self):
        self._approve(rid="a1", key=KEY_D)
        code, _ = self._rejoin(key=KEY_D, approval="a1")
        self.assertEqual(code, 409)
        self.assertEqual(self._rejoin_events(), [])

    def test_done_round_conflicts_409(self):
        # 推进 round 1 到 done：n3 rejoin 409（非 commit|share）
        for op, node, hsh, peer in (
            ("share", "n1", HASH_B, "n2"),
            ("share", "n2", HASH_A, "n1"),
        ):
            code, _ = self.svc.post_dkg_stage(
                "w1", "d1", op, node, None, hsh, peer
            )
            self.assertEqual(code, 201)
        self._approve()
        code, _ = self._rejoin()
        self.assertEqual(code, 409)

    def test_approval_unknown_409(self):
        code, _ = self._rejoin(approval="ghost")
        self.assertEqual(code, 409)

    def test_approval_pending_409(self):
        msg = _msg()
        self.assertEqual(self.svc.create_sign_request("w1", "ap1", msg)[0], 201)
        code, _ = self._rejoin()
        self.assertEqual(code, 409)

    def test_approval_rejected_409(self):
        self.svc.create_sign_request("w1", "ap1", _msg())
        self.svc.reject("w1", "ap1", "boss")
        code, _ = self._rejoin()
        self.assertEqual(code, 409)

    def test_approval_wrong_message_409(self):
        # 非紧凑（尾随空格，仍是同一字符串内容之外的差异）
        self._approve(message=_msg() + " ")
        code, _ = self._rejoin()
        self.assertEqual(code, 409)

    # ---- 幂等 --------------------------------------------------------------

    def test_replay_same_params_200_same_v(self):
        self._approve()
        code, v1 = self._rejoin()
        self.assertEqual(code, 201)
        code, v2 = self._rejoin()
        self.assertEqual(code, 200)
        self.assertEqual(v2, v1)
        self.assertEqual(len(self._rejoin_events()), 1)

    def test_replay_different_params_409(self):
        self._approve()
        self.assertEqual(self._rejoin()[0], 201)
        # 异 key
        self.assertEqual(self._rejoin(key=KEY_D)[0], 409)
        # 异 dkg
        self.assertEqual(self._rejoin(dkg_id="d2")[0], 409)
        # 异 round
        self.assertEqual(self._rejoin(round_no=2)[0], 409)
        # 异 node
        self.assertEqual(self._rejoin(node="n4")[0], 409)
        # 异审批标识（同形审批单 a2 已批准）
        self._approve(rid="ap2")
        self.assertEqual(self._rejoin(approval="ap2")[0], 409)
        # 仍仅一条事件
        self.assertEqual(len(self._rejoin_events()), 1)

    def test_replay_200_ignores_later_changes(self):
        self._approve()
        code, v1 = self._rejoin()
        self.assertEqual(code, 201)
        # 事后把健康表翻回 down、审批单状态变化等：重放仍 200 同 V
        self.svc.put_dkg_nodes(
            "w1",
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "up"},
                "n3": {"key": KEY_C, "state": "down"},
            },
        )
        code, v2 = self._rejoin()
        self.assertEqual(code, 200)
        self.assertEqual(v2, v1)

    # ---- 事件形状 / 并发 ---------------------------------------------------

    def test_event_shape_is_commit_point(self):
        self._approve()
        self.assertEqual(self._rejoin()[0], 201)
        (event,) = self._rejoin_events()
        self.assertEqual(event["type"], "node_rejoined")
        self.assertEqual(event["request_id"], "rj1")
        self.assertEqual(event["actor_id"], "ap1")
        self.assertIsNone(event["reason"])
        self.assertEqual(
            list(event["details"]),
            ["rejoin_id", "dkg_id", "round", "node", "key", "state"],
        )
        self.assertEqual(event["details"]["state"], "up")
        # 落盘键序
        log = json.load(
            open(os.path.join(self.d, "audit", "w1.json"), encoding="utf-8")
        )
        stored = [e for e in log["events"] if e["type"] == "node_rejoined"][0]
        self.assertEqual(
            list(stored),
            ["actor_id", "at", "details", "reason", "request_id", "seq",
             "type"],
        )
        self.assertEqual(
            list(stored["details"]),
            ["rejoin_id", "dkg_id", "round", "node", "key", "state"],
        )

    def test_concurrent_single_201(self):
        self._approve()
        codes = []
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            codes.append(self._rejoin()[0])

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(codes), [200] * 7 + [201])
        self.assertEqual(len(self._rejoin_events()), 1)

    # ---- GET 折叠 / PUT 同值 ----------------------------------------------

    def test_get_folds_rejoin_and_put_same_value_no_event(self):
        self._approve()
        self.assertEqual(self._rejoin()[0], 201)
        nodes = self.svc.get_dkg_nodes("w1")["nodes"]
        self.assertEqual(nodes["n3"]["state"], "up")
        # 以生效表（n3 up）同值 PUT：不记 node_state
        before = [
            e for e in self.svc.get_audit_events("w1")["events"]
            if e["type"] == "node_state"
        ]
        self.svc.put_dkg_nodes("w1", nodes)
        after = [
            e for e in self.svc.get_audit_events("w1")["events"]
            if e["type"] == "node_state"
        ]
        self.assertEqual(len(before), len(after))

    def test_auto_failover_uses_rejoined_up_node_as_candidate(self):
        # n2 down、n3 down；先把 n3 rejoin 回 up，再 auto failover n2，
        # 候选应取已 rejoin 为 up 的 n3。
        self.svc.put_dkg_nodes(
            "w1",
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "down"},
                "n3": {"key": KEY_C, "state": "down"},
            },
        )
        self._approve(rid="ap1")
        self.assertEqual(self._rejoin()[0], 201)
        # 新 failover 轮：当前 round 1 为 share，n2 down，候选 n3 已 up
        code, view = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", None, None,
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["nodes"], ["n1", "n3"])


class RejoinRecoveryTest(unittest.TestCase):
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
        self.svc.create_sign_request("w1", "ap1", _msg())
        self.svc.approve("w1", "ap1", "boss")
        code, self.view = self.svc.post_node_rejoin(
            "w1", "n3", "rj1", "d1", 1, KEY_C, "ap1"
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

    def _rejoin_event(self, log):
        return next(e for e in log["events"] if e["type"] == "node_rejoined")

    def _assert_refuses_ready(self):
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_restart_keeps_state_and_logs_nothing(self):
        before = self.svc.get_audit_events("w1")["events"]
        svc2 = WalletService(self.h.store)
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)
        self.assertEqual(
            svc2.get_dkg_nodes("w1")["nodes"]["n3"]["state"], "up"
        )
        # 新进程同参重放仍 200 同 V，不记事件
        code, v = svc2.post_node_rejoin(
            "w1", "n3", "rj1", "d1", 1, KEY_C, "ap1"
        )
        self.assertEqual(code, 200)
        self.assertEqual(v, self.view)
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)

    def test_backup_restore_keeps_rejoin(self):
        out = os.path.join(tempfile.mkdtemp(), "snap.tar")
        self.addCleanup(shutil.rmtree, os.path.dirname(out), ignore_errors=True)
        self.assertEqual(drbackup.backup(self.d, "w1", "S1", out)["status"], 201)
        dst = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, dst, ignore_errors=True)
        status, _ = drbackup.restore(dst, "w1", out)
        self.assertEqual(status, 201)
        svc2 = WalletService(WalletStore(dst))
        self.assertEqual(
            svc2.get_dkg_nodes("w1")["nodes"]["n3"]["state"], "up"
        )
        code, v = svc2.post_node_rejoin(
            "w1", "n3", "rj1", "d1", 1, KEY_C, "ap1"
        )
        self.assertEqual(code, 200)
        self.assertEqual(v, self.view)

    def test_tampered_key_fail_closed(self):
        def mutate(log):
            self._rejoin_event(log)["details"]["key"] = KEY_D
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_tampered_node_fail_closed(self):
        def mutate(log):
            ev = self._rejoin_event(log)
            ev["details"]["node"] = "n9"
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_tampered_round_fail_closed(self):
        def mutate(log):
            self._rejoin_event(log)["details"]["round"] = 2
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_tampered_dkg_fail_closed(self):
        def mutate(log):
            self._rejoin_event(log)["details"]["dkg_id"] = "zz"
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_state_not_up_fail_closed(self):
        def mutate(log):
            self._rejoin_event(log)["details"]["state"] = "down"
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_request_id_mismatch_fail_closed(self):
        def mutate(log):
            self._rejoin_event(log)["request_id"] = "other"
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_actor_missing_fail_closed(self):
        def mutate(log):
            self._rejoin_event(log)["actor_id"] = None
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_reason_set_fail_closed(self):
        def mutate(log):
            self._rejoin_event(log)["reason"] = "why"
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_duplicate_rejoin_id_fail_closed(self):
        def mutate(log):
            ev = dict(self._rejoin_event(log))
            ev["seq"] = len(log["events"]) + 1
            log["events"].append(ev)
            log["next_seq"] = len(log["events"]) + 1
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_approval_record_deleted_fail_closed(self):
        os.unlink(os.path.join(self.d, "requests", "w1.json"))
        self._assert_refuses_ready()

    def test_approval_message_tampered_fail_closed(self):
        req_path = os.path.join(self.d, "requests", "w1.json")
        requests = json.load(open(req_path, encoding="utf-8"))
        requests["ap1"]["message"] = _msg() + "x"
        with open(req_path, "w", encoding="utf-8") as f:
            json.dump(requests, f)
        self._assert_refuses_ready()

    def test_approval_state_pending_fail_closed(self):
        req_path = os.path.join(self.d, "requests", "w1.json")
        requests = json.load(open(req_path, encoding="utf-8"))
        requests["ap1"]["state"] = "pending"
        with open(req_path, "w", encoding="utf-8") as f:
            json.dump(requests, f)
        self._assert_refuses_ready()

    def test_signed_approval_state_accepted(self):
        # 提交后审批单经 /sign 推进为 signed：恢复仍应认可。
        sigs = self.h.two_signatures("w1", "ap1", _msg())
        # 用一个独立 message 走 /sign 需要同 id 审批单——这里直接把审批单
        # 状态改为 signed（事件链由恢复按请求文件对账，signed 是合法终态）。
        req_path = os.path.join(self.d, "requests", "w1.json")
        requests = json.load(open(req_path, encoding="utf-8"))
        requests["ap1"]["state"] = "signed"
        with open(req_path, "w", encoding="utf-8") as f:
            json.dump(requests, f)
        # 仅改请求文件而无 request_signed 事件会被灾备严格校验拦，但线上
        # _recover_wallet 的 rejoin 复核只读请求状态；这里验证的是 rejoin
        # 复核认可 signed，故直接调用复核方法。
        svc2 = WalletService(self.h.store, recover=False)
        with svc2._wallet_lock("w1"):
            svc2._reconcile_node_rejoins("w1")  # 不应抛

    def test_node_healthy_in_prior_snapshot_fail_closed(self):
        # 把事前健康表中 n3 改为 up：rejoin 当时 N 未故障。
        def mutate(log):
            for event in log["events"]:
                if event["type"] == "node_state":
                    event["details"]["nodes"]["n3"]["state"] = "up"
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_no_prior_snapshot_fail_closed(self):
        def mutate(log):
            log["events"] = [
                e for e in log["events"] if e["type"] != "node_state"
            ]
            for i, event in enumerate(log["events"], 1):
                event["seq"] = i
            log["next_seq"] = len(log["events"]) + 1
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_later_snapshot_flip_does_not_invalidate(self):
        # 事后追加一条把 n3 翻 down 的快照：恢复核验只看 rejoin 事前快照，
        # 但生效表以最后快照为准（GET 反映 down），历史 rejoin 仍有效。
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
            svc2.get_dkg_nodes("w1")["nodes"]["n3"]["state"], "down"
        )

    def test_corrupt_audit_json_is_503_boundary(self):
        with open(self._audit_path(), "wb") as f:
            f.write(b"{not json")
        with self.assertRaises(CorruptDataError):
            self.h.service._audit.node_rejoined_events("w1")
        self._assert_refuses_ready()


class NodeStateStrictOrderTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.put_dkg_nodes("w1", HEALTH)

    def _audit_path(self):
        return os.path.join(self.d, "audit", "w1.json")

    def _rewrite(self, mutate):
        path = self._audit_path()
        log = json.load(open(path, encoding="utf-8"))
        mutate(log)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)

    def _assert_refuses(self):
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)
        with self.assertRaises(RecoveryError):
            self.svc.get_dkg_nodes("w1")

    def test_outer_field_reorder_fail_closed(self):
        def mutate(log):
            for e in log["events"]:
                if e["type"] == "node_state":
                    items = list(e.items())
                    items = [items[-1]] + items[:-1]
                    e.clear()
                    e.update(items)
        self._rewrite(mutate)
        self._assert_refuses()

    def test_entry_key_reorder_fail_closed(self):
        def mutate(log):
            for e in log["events"]:
                if e["type"] == "node_state":
                    for nid, v in e["details"]["nodes"].items():
                        e["details"]["nodes"][nid] = {
                            "state": v["state"],
                            "key": v["key"],
                        }
        self._rewrite(mutate)
        self._assert_refuses()

    def test_node_ids_descending_fail_closed(self):
        def mutate(log):
            for e in log["events"]:
                if e["type"] == "node_state":
                    nodes = e["details"]["nodes"]
                    e["details"]["nodes"] = {
                        k: nodes[k] for k in sorted(nodes, reverse=True)
                    }
        self._rewrite(mutate)
        self._assert_refuses()

    def test_details_extra_key_fail_closed(self):
        def mutate(log):
            for e in log["events"]:
                if e["type"] == "node_state":
                    e["details"]["extra"] = 1
        self._rewrite(mutate)
        self._assert_refuses()

    def test_bad_value_fail_closed(self):
        def mutate(log):
            for e in log["events"]:
                if e["type"] == "node_state":
                    e["details"]["nodes"]["n1"]["state"] = "gone"
        self._rewrite(mutate)
        self._assert_refuses()


class RejoinHttpTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def _setup(self, srv):
        srv.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
        srv.request(
            "PUT", "/v1/wallets/w1/approval-policy",
            {"required_approvals": 1, "timeout_seconds": 600},
        )
        srv.request("PUT", "/v1/wallets/w1/nodes", {"nodes": HEALTH})
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
            code, _ = srv.request("POST", "/v1/dkg/w1/d1", body)
            self.assertEqual(code, 201)
        srv.request(
            "POST", "/v1/wallets/w1/sign-requests",
            {"id": "ap1", "message": _msg()},
        )
        srv.request(
            "POST", "/v1/wallets/w1/sign-requests/ap1/approve",
            {"approver_id": "boss"},
        )

    def _body(self, **over):
        body = {
            "rejoin_id": "rj1",
            "dkg_id": "d1",
            "round": 1,
            "key": KEY_C,
            "approval_request_id": "ap1",
        }
        body.update(over)
        return body

    def test_http_rejoin_flow(self):
        with http_server(self.d) as srv:
            self._setup(srv)
            # 多键/缺键 400
            code, _ = srv.request(
                "POST", "/v1/wallets/w1/nodes/n3/rejoin", self._body(x=1)
            )
            self.assertEqual(code, 400)
            code, _ = srv.request(
                "POST", "/v1/wallets/w1/nodes/n3/rejoin", {"rejoin_id": "rj1"}
            )
            self.assertEqual(code, 400)
            # bool round 400
            code, _ = srv.request(
                "POST", "/v1/wallets/w1/nodes/n3/rejoin",
                self._body(round=True),
            )
            self.assertEqual(code, 400)
            # 未知钱包 404 / 未知节点 404
            code, _ = srv.request(
                "POST", "/v1/wallets/zz/nodes/n3/rejoin", self._body()
            )
            self.assertEqual(code, 404)
            code, _ = srv.request(
                "POST", "/v1/wallets/w1/nodes/n9/rejoin", self._body()
            )
            self.assertEqual(code, 404)
            # 首提 201
            code, v = srv.request(
                "POST", "/v1/wallets/w1/nodes/n3/rejoin", self._body()
            )
            self.assertEqual(code, 201)
            self.assertEqual(v["state"], "up")
            # 重放 200 同体
            code, v2 = srv.request(
                "POST", "/v1/wallets/w1/nodes/n3/rejoin", self._body()
            )
            self.assertEqual(code, 200)
            self.assertEqual(v2, v)
            # GET nodes n3 up
            code, body = srv.request("GET", "/v1/wallets/w1/nodes")
            self.assertEqual(code, 200)
            self.assertEqual(body["nodes"]["n3"]["state"], "up")

    def test_http_corrupt_scene_is_503(self):
        with http_server(self.d) as srv:
            self._setup(srv)
            code, _ = srv.request(
                "POST", "/v1/wallets/w1/nodes/n3/rejoin", self._body()
            )
            self.assertEqual(code, 201)
            path = os.path.join(self.d, "audit", "w1.json")
            log = json.load(open(path, encoding="utf-8"))
            for event in log["events"]:
                if event["type"] == "node_rejoined":
                    event["details"]["key"] = KEY_D
            with open(path, "w", encoding="utf-8") as f:
                json.dump(log, f)
            code, body = srv.request(
                "POST", "/v1/wallets/w1/nodes/n3/rejoin", self._body()
            )
            self.assertEqual(code, 503)
            self.assertEqual(
                body, {"error": "service temporarily unavailable"}
            )


if __name__ == "__main__":
    unittest.main()
