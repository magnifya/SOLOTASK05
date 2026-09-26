"""DKG 节点重新入群（rejoin）测试。

覆盖：
- P=POST /v1/wallets/{W}/nodes/{N}/rejoin：B 恰含
  rejoin_id,dkg_id,round,key,approval_request_id；ID 安全、key 为 64 位
  小写 hex、round 非布尔正整数，键集/类型/值错 400；钱包/DKG/节点未知
  404；
- 首提须 N 为 down|ban、key 匹配，round 为当前 commit|share 轮且 N 不占
  槽；审批单同钱包 approved，message 为按 rejoin_id,dkg_id,round,node,
  key 序的紧凑 JSON，否则 409 且健康表/DKG/审批不变；
- 成功 N 置 up，201 返回 V={rejoin_id,dkg_id,round,node,key,state}；同
  rejoin_id 同参 200 同 V，异参 409；
- node_rejoined 为唯一提交点（request_id=rejoin_id、
  actor_id=approval_request_id、reason=null、details=V），与翻 up 的
  node_state 同批原子落盘；并发仅一 201；
- 恢复按事前健康表、DKG、审批复核；损坏/I/O/矛盾 fail-closed，重启/灾备
  后视图与 seq 不变。
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
HASH_A = "11" * 32
HASH_B = "22" * 32


def _call(fn, *args):
    try:
        return fn(*args)
    except ServiceError as exc:
        return exc.status, {"error": exc.message}


def _rejoin_message(rejoin_id, dkg_id, round_no, node, key):
    return json.dumps(
        {
            "rejoin_id": rejoin_id,
            "dkg_id": dkg_id,
            "round": round_no,
            "node": node,
            "key": key,
        },
        separators=(",", ":"),
    )


class RejoinServiceTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        # n1 up / n2 down / n3 up；基线轮 n1,n2 注册+commit 后手工故障
        # 替换 n2->n3，当前轮（第 2 轮）槽位为 n1,n3、阶段 commit。
        self.svc.put_dkg_nodes(
            "w1",
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "down"},
                "n3": {"key": KEY_C, "state": "up"},
            },
        )
        for op, node, key, hsh, peer in [
            ("register", "n1", KEY_A, None, None),
            ("register", "n2", KEY_B, None, None),
            ("commit", "n1", None, HASH_A, None),
            ("commit", "n2", None, HASH_B, None),
        ]:
            code, _ = self.svc.post_dkg_stage(
                "w1", "d1", op, node, key, hsh, peer, None
            )
            self.assertEqual(code, 201)
        code, view = self.svc.post_dkg_failover(
            "w1", "d1", 2, "replace", "n2", "n3", KEY_C
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["nodes"], ["n1", "n3"])
        self.svc.put_policy("w1", 1, 1000)

    def _approved_request(self, rid, message):
        code, _ = self.svc.create_sign_request("w1", rid, message)
        self.assertEqual(code, 201)
        self.svc.approve("w1", rid, "boss", None)

    def _rejoin(
        self, node="n2", rejoin_id="rj1", dkg_id="d1", round_no=2,
        key=KEY_B, approval="ar1", wallet="w1",
    ):
        return _call(
            self.svc.rejoin_node,
            wallet, node, rejoin_id, dkg_id, round_no, key, approval,
        )

    def _events(self, event_type):
        return [
            e
            for e in self.svc.get_audit_events("w1")["events"]
            if e["type"] == event_type
        ]

    # ---- 201 / 200 / 健康表翻转 -------------------------------------------

    def test_first_rejoin_201_returns_V_and_flips_up(self):
        self._approved_request(
            "ar1", _rejoin_message("rj1", "d1", 2, "n2", KEY_B)
        )
        code, body = self._rejoin()
        self.assertEqual(code, 201)
        self.assertEqual(
            body,
            {
                "rejoin_id": "rj1",
                "dkg_id": "d1",
                "round": 2,
                "node": "n2",
                "key": KEY_B,
                "state": "up",
            },
        )
        self.assertEqual(list(body), [
            "rejoin_id", "dkg_id", "round", "node", "key", "state"
        ])
        nodes = self.svc.get_dkg_nodes("w1")["nodes"]
        self.assertEqual(nodes["n2"]["state"], "up")
        # 其余条目逐项不变
        self.assertEqual(nodes["n1"], {"key": KEY_A, "state": "up"})
        self.assertEqual(nodes["n3"], {"key": KEY_C, "state": "up"})

    def test_same_replay_200_same_V_no_new_events(self):
        self._approved_request(
            "ar1", _rejoin_message("rj1", "d1", 2, "n2", KEY_B)
        )
        code, first = self._rejoin()
        self.assertEqual(code, 201)
        before = self.svc.get_audit_events("w1")["events"]
        code, second = self._rejoin()
        self.assertEqual(code, 200)
        self.assertEqual(second, first)
        self.assertEqual(
            self.svc.get_audit_events("w1")["events"], before
        )

    def test_replay_ignores_later_health_and_dkg_changes(self):
        self._approved_request(
            "ar1", _rejoin_message("rj1", "d1", 2, "n2", KEY_B)
        )
        self.assertEqual(self._rejoin()[0], 201)
        # 事后健康翻转、轮次推进：同参重放仍 200 同 V
        self.svc.put_dkg_nodes(
            "w1",
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "ban"},
                "n3": {"key": KEY_C, "state": "up"},
            },
        )
        self.assertEqual(
            self.svc.post_dkg_stage(
                "w1", "d1", "commit", "n1", None, HASH_A, None, "2"
            )[0],
            201,
        )
        code, body = self._rejoin()
        self.assertEqual(code, 200)
        self.assertEqual(body["state"], "up")

    def test_same_rejoin_id_different_params_409(self):
        self._approved_request(
            "ar1", _rejoin_message("rj1", "d1", 2, "n2", KEY_B)
        )
        self.assertEqual(self._rejoin()[0], 201)
        # 异 key
        code, _ = self._rejoin(key=KEY_C)
        self.assertEqual(code, 409)
        # 异审批单
        code, _ = self._rejoin(approval="arX")
        self.assertEqual(code, 409)
        # 异轮
        code, _ = self._rejoin(round_no=1)
        self.assertEqual(code, 409)

    # ---- 400 ---------------------------------------------------------------

    def test_invalid_bodies_400(self):
        bad = [
            dict(node="n2", rejoin_id="bad!", dkg_id="d1", round_no=2,
                 key=KEY_B, approval="ar1"),
            dict(node="n2", rejoin_id="rj1", dkg_id="d1", round_no=True,
                 key=KEY_B, approval="ar1"),
            dict(node="n2", rejoin_id="rj1", dkg_id="d1", round_no=0,
                 key=KEY_B, approval="ar1"),
            dict(node="n2", rejoin_id="rj1", dkg_id="d1", round_no=1.5,
                 key=KEY_B, approval="ar1"),
            dict(node="n2", rejoin_id="rj1", dkg_id="d1", round_no="2",
                 key=KEY_B, approval="ar1"),
            dict(node="n2", rejoin_id="rj1", dkg_id="d1", round_no=2,
                 key="ZZ" * 32, approval="ar1"),
            dict(node="n2", rejoin_id="rj1", dkg_id="d1", round_no=2,
                 key=KEY_B[:-1], approval="ar1"),
            dict(node="n2", rejoin_id="rj1", dkg_id="d1", round_no=2,
                 key=KEY_B, approval="bad!"),
            dict(node=1, rejoin_id="rj1", dkg_id="d1", round_no=2,
                 key=KEY_B, approval="ar1"),
        ]
        for kwargs in bad:
            with self.subTest(kwargs=kwargs):
                code, _ = self._rejoin(**kwargs)
                self.assertEqual(code, 400)

    def test_unknown_wallet_404(self):
        code, _ = self._rejoin(wallet="nope")
        self.assertEqual(code, 404)

    def test_unknown_node_dkg_round_404(self):
        self._approved_request(
            "ar1", _rejoin_message("rj1", "d1", 2, "n2", KEY_B)
        )
        # 节点不在健康表
        code, _ = self._rejoin(node="n9")
        self.assertEqual(code, 404)
        # DKG 未知
        code, _ = self._rejoin(dkg_id="dX")
        self.assertEqual(code, 404)
        # 轮次超过当前轮
        code, _ = self._rejoin(round_no=9)
        self.assertEqual(code, 404)

    # ---- 409 前置 ----------------------------------------------------------

    def test_node_must_be_down_or_banned(self):
        self.svc.put_dkg_nodes(
            "w1",
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "up"},
                "n3": {"key": KEY_C, "state": "up"},
            },
        )
        self._approved_request(
            "ar1", _rejoin_message("rj1", "d1", 2, "n2", KEY_B)
        )
        code, _ = self._rejoin()
        self.assertEqual(code, 409)
        self.assertEqual(self._events("node_rejoined"), [])

    def test_key_must_match_health_table(self):
        self._approved_request(
            "ar1", _rejoin_message("rj1", "d1", 2, "n2", KEY_C)
        )
        # KEY_C 是合法 hex，但与 n2 在健康表中的 key（KEY_B）不符
        code, _ = self._rejoin(key=KEY_C, approval="ar1")
        self.assertEqual(code, 409)

    def test_round_must_be_current_and_commit_or_share(self):
        self._approved_request(
            "ar1", _rejoin_message("rj1", "d1", 2, "n2", KEY_B)
        )
        # 旧轮 1：409（轮 1 存在，故非 404）
        code, _ = self._rejoin(round_no=1)
        self.assertEqual(code, 409)
        # 把第 2 轮推进到 done 后再 rejoin：阶段不符 409
        for args in [
            ("commit", "n1", None, HASH_A, None),
            ("commit", "n3", None, HASH_B, None),
            ("share", "n1", None, HASH_B, "n3"),
            ("share", "n3", None, HASH_A, "n1"),
        ]:
            self.assertEqual(
                self.svc.post_dkg_stage(
                    "w1", "d1", args[0], args[1], args[2], args[3],
                    args[4], "2"
                )[0],
                201,
            )
        code, view = self._rejoin()
        self.assertEqual(code, 409)

    def test_node_must_not_occupy_slot(self):
        # n1 占着第 2 轮槽位：即使置 down 也不能 rejoin
        self.svc.put_dkg_nodes(
            "w1",
            {
                "n1": {"key": KEY_A, "state": "down"},
                "n2": {"key": KEY_B, "state": "down"},
                "n3": {"key": KEY_C, "state": "up"},
            },
        )
        self._approved_request(
            "ar1", _rejoin_message("rj1", "d1", 2, "n1", KEY_A)
        )
        code, _ = self._rejoin(node="n1", key=KEY_A)
        self.assertEqual(code, 409)

    def test_approval_gate_409_and_scene_unchanged(self):
        # 审批单未知
        code, _ = self._rejoin(approval="ghost")
        self.assertEqual(code, 409)
        # pending 单
        self.assertEqual(
            self.svc.create_sign_request(
                "w1",
                "arp",
                _rejoin_message("rj1", "d1", 2, "n2", KEY_B),
            )[0],
            201,
        )
        code, _ = self._rejoin(approval="arp")
        self.assertEqual(code, 409)
        # approved 但 message 不符
        self._approved_request("arb", "different message")
        code, _ = self._rejoin(approval="arb")
        self.assertEqual(code, 409)
        # 全部失败：健康表仍 down、无 node_rejoined 事件
        self.assertEqual(
            self.svc.get_dkg_nodes("w1")["nodes"]["n2"]["state"], "down"
        )
        self.assertEqual(self._events("node_rejoined"), [])

    # ---- 提交点事件 --------------------------------------------------------

    def test_node_rejoined_event_is_commit_point(self):
        self._approved_request(
            "ar1", _rejoin_message("rj1", "d1", 2, "n2", KEY_B)
        )
        self.assertEqual(self._rejoin()[0], 201)
        (event,) = self._events("node_rejoined")
        self.assertEqual(event["request_id"], "rj1")
        self.assertEqual(event["actor_id"], "ar1")
        self.assertIsNone(event["reason"])
        self.assertEqual(
            list(event["details"]),
            ["rejoin_id", "dkg_id", "round", "node", "key", "state"],
        )
        self.assertEqual(event["details"]["state"], "up")
        all_events = self.svc.get_audit_events("w1")["events"]
        index = next(
            i for i, e in enumerate(all_events)
            if e["type"] == "node_rejoined"
        )
        # 同批前一事件恰为把 n2 翻 up 的 node_state
        flip = all_events[index - 1]
        self.assertEqual(flip["type"], "node_state")
        self.assertEqual(flip["seq"], event["seq"] - 1)
        self.assertEqual(flip["details"]["nodes"]["n2"]["state"], "up")
        self.assertEqual(flip["details"]["nodes"]["n1"]["state"], "up")
        self.assertEqual(flip["details"]["nodes"]["n3"]["state"], "up")
        # 落盘 JSON 键序一致
        with open(os.path.join(self.d, "audit", "w1.json"),
                  encoding="utf-8") as f:
            log = json.load(f)
        stored = next(
            e for e in log["events"] if e["type"] == "node_rejoined"
        )
        self.assertEqual(
            list(stored["details"]),
            ["rejoin_id", "dkg_id", "round", "node", "key", "state"],
        )

    def test_concurrent_only_one_201(self):
        self._approved_request(
            "ar1", _rejoin_message("rj1", "d1", 2, "n2", KEY_B)
        )
        codes = []
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            code, _ = self._rejoin()
            codes.append(code)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(codes), [200] * 7 + [201])
        self.assertEqual(len(self._events("node_rejoined")), 1)

    # ---- 重启 / 灾备 -------------------------------------------------------

    def test_restart_replays_and_logs_nothing(self):
        self._approved_request(
            "ar1", _rejoin_message("rj1", "d1", 2, "n2", KEY_B)
        )
        self.assertEqual(self._rejoin()[0], 201)
        before = self.svc.get_audit_events("w1")["events"]
        svc2 = WalletService(self.h.store)
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)
        self.assertEqual(
            svc2.get_dkg_nodes("w1")["nodes"]["n2"]["state"], "up"
        )
        code, body = svc2.rejoin_node(
            "w1", "n2", "rj1", "d1", 2, KEY_B, "ar1"
        )
        self.assertEqual(code, 200)
        self.assertEqual(body["rejoin_id"], "rj1")
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)

    def test_backup_restore_keeps_rejoin(self):
        self._approved_request(
            "ar1", _rejoin_message("rj1", "d1", 2, "n2", KEY_B)
        )
        self.assertEqual(self._rejoin()[0], 201)
        before = self.svc.get_audit_events("w1")["events"]
        out = os.path.join(tempfile.mkdtemp(), "snap.tar")
        self.addCleanup(
            shutil.rmtree, os.path.dirname(out), ignore_errors=True
        )
        self.assertEqual(
            drbackup.backup(self.d, "w1", "S1", out)["status"], 201
        )
        dst = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, dst, ignore_errors=True)
        status, _ = drbackup.restore(dst, "w1", out)
        self.assertEqual(status, 201)
        svc2 = WalletService(WalletStore(dst))
        self.assertEqual(
            svc2.get_dkg_nodes("w1")["nodes"]["n2"]["state"], "up"
        )
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)
        code, _ = svc2.rejoin_node(
            "w1", "n2", "rj1", "d1", 2, KEY_B, "ar1"
        )
        self.assertEqual(code, 200)


class RejoinRecoveryStrictTest(unittest.TestCase):
    """恢复按事前健康表/DKG/审批复核 node_rejoined：矛盾 fail-closed。"""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.put_dkg_nodes(
            "w1",
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "down"},
                "n3": {"key": KEY_C, "state": "up"},
            },
        )
        for op, node, key, hsh, peer in [
            ("register", "n1", KEY_A, None, None),
            ("register", "n2", KEY_B, None, None),
            ("commit", "n1", None, HASH_A, None),
            ("commit", "n2", None, HASH_B, None),
        ]:
            self.assertEqual(
                self.svc.post_dkg_stage(
                    "w1", "d1", op, node, key, hsh, peer, None
                )[0],
                201,
            )
        self.assertEqual(
            self.svc.post_dkg_failover(
                "w1", "d1", 2, "replace", "n2", "n3", KEY_C
            )[0],
            201,
        )
        self.svc.put_policy("w1", 1, 1000)
        self.assertEqual(
            self.svc.create_sign_request(
                "w1",
                "ar1",
                _rejoin_message("rj1", "d1", 2, "n2", KEY_B),
            )[0],
            201,
        )
        self.svc.approve("w1", "ar1", "boss", None)
        self.assertEqual(
            self.svc.rejoin_node(
                "w1", "n2", "rj1", "d1", 2, KEY_B, "ar1"
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

    def _rejoin_event(self, log):
        return next(
            e for e in log["events"] if e["type"] == "node_rejoined"
        )

    def _assert_refuses_ready(self):
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_tampered_state_is_fail_closed(self):
        def mutate(log):
            self._rejoin_event(log)["details"]["state"] = "down"
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_tampered_round_is_fail_closed(self):
        def mutate(log):
            self._rejoin_event(log)["details"]["round"] = 1
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_tampered_node_is_fail_closed(self):
        def mutate(log):
            self._rejoin_event(log)["details"]["node"] = "n9"
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_flip_without_prior_snapshot_is_fail_closed(self):
        # 删除同批翻 up 之前的全部 node_state：无事前快照可核验。
        def mutate(log):
            target = self._rejoin_event(log)["seq"]
            log["events"] = [
                e
                for e in log["events"]
                if not (
                    e["type"] == "node_state" and e["seq"] < target - 1
                )
            ]
            for i, event in enumerate(log["events"], 1):
                event["seq"] = i
            log["next_seq"] = len(log["events"]) + 1
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_flip_changing_other_entries_is_fail_closed(self):
        # 同批 node_state 除翻 n2 外还改了 n1 状态：非"仅翻 N"。
        def mutate(log):
            target = self._rejoin_event(log)["seq"]
            for event in log["events"]:
                if (
                    event["seq"] == target - 1
                    and event["type"] == "node_state"
                ):
                    event["details"]["nodes"]["n1"]["state"] = "ban"
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_missing_adjacent_node_state_is_fail_closed(self):
        def mutate(log):
            target = self._rejoin_event(log)["seq"]
            log["events"] = [
                e for e in log["events"] if e["seq"] != target - 1
            ]
            for i, event in enumerate(log["events"], 1):
                event["seq"] = i
            log["next_seq"] = len(log["events"]) + 1
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_missing_approval_request_is_fail_closed(self):
        os.unlink(os.path.join(self.d, "requests", "w1.json"))
        self._assert_refuses_ready()

    def test_tampered_approval_message_is_fail_closed(self):
        path = os.path.join(self.d, "requests", "w1.json")
        records = json.load(open(path, encoding="utf-8"))
        records["ar1"]["message"] = "tampered"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(records, f)
        self._assert_refuses_ready()

    def test_approval_rejected_afterward_is_fail_closed(self):
        # 提交时刻 approved 的复核依据是 seq 前的审计事件：补一条 rejected
        # 放在 node_rejoined 之前会破坏 seq 连续性（CorruptDataError）；
        # 改为把审批单当前状态改回 rejected 不影响提交点（提交时已
        # approved 有 request_approved 事件佐证），故这里删除批准事件
        # 序列中的达门槛 approved，恢复应判提交时刻未 approved。
        def mutate(log):
            for event in log["events"]:
                if (
                    event["type"] == "request_approved"
                    and event.get("request_id") == "ar1"
                    and event.get("details", {}).get("state") == "approved"
                ):
                    event["details"]["state"] = "pending"
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_later_round_progress_does_not_invalidate_recovery(self):
        # 提交后把第 2 轮推进到 done：恢复按提交时刻（commit 阶段）核验，
        # 不受事后推进影响。
        for args in [
            ("commit", "n1", None, HASH_A, None),
            ("commit", "n3", None, HASH_B, None),
            ("share", "n1", None, HASH_B, "n3"),
            ("share", "n3", None, HASH_A, "n1"),
        ]:
            self.assertEqual(
                self.svc.post_dkg_stage(
                    "w1", "d1", args[0], args[1], args[2], args[3],
                    args[4], "2"
                )[0],
                201,
            )
        svc2 = WalletService(self.h.store)  # 不抛即通过
        self.assertEqual(
            svc2.get_dkg_nodes("w1")["nodes"]["n2"]["state"], "up"
        )

    def test_corrupt_audit_json_is_corrupt_then_503_online(self):
        # 损坏审计 JSON：在线持锁访问统一 fail-closed（RecoveryError）
        with open(self._audit_path(), "wb") as f:
            f.write(b"{not json")
        with self.assertRaises(Exception):
            self.svc.get_dkg_nodes("w1")


class RejoinHttpTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def test_http_rejoin_flow(self):
        with http_server(self.d) as srv:
            self.assertEqual(
                srv.request(
                    "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
                )[0],
                201,
            )
            self.assertEqual(
                srv.request(
                    "PUT",
                    "/v1/wallets/w1/nodes",
                    {"nodes": {
                        "n1": {"key": KEY_A, "state": "up"},
                        "n2": {"key": KEY_B, "state": "down"},
                        "n3": {"key": KEY_C, "state": "up"},
                    }},
                )[0],
                200,
            )
            for body in [
                {"op": "register", "node": "n1", "key": KEY_A,
                 "hash": None, "peer": None},
                {"op": "register", "node": "n2", "key": KEY_B,
                 "hash": None, "peer": None},
                {"op": "commit", "node": "n1", "key": None,
                 "hash": HASH_A, "peer": None},
                {"op": "commit", "node": "n2", "key": None,
                 "hash": HASH_B, "peer": None},
            ]:
                self.assertEqual(
                    srv.request("POST", "/v1/dkg/w1/d1", body)[0], 201
                )
            self.assertEqual(
                srv.request(
                    "POST", "/v1/dkg/w1/d1/failover",
                    {"round": 2, "action": "replace", "node": "n2",
                     "replacement": "n3", "key": KEY_C},
                )[0],
                201,
            )
            self.assertEqual(
                srv.request(
                    "PUT", "/v1/wallets/w1/approval-policy",
                    {"required_approvals": 1, "timeout_seconds": 1000},
                )[0],
                200,
            )
            message = _rejoin_message("rj1", "d1", 2, "n2", KEY_B)
            self.assertEqual(
                srv.request(
                    "POST", "/v1/wallets/w1/sign-requests",
                    {"id": "ar1", "message": message},
                )[0],
                201,
            )
            self.assertEqual(
                srv.request(
                    "POST",
                    "/v1/wallets/w1/sign-requests/ar1/approve",
                    {"approver_id": "boss"},
                )[0],
                200,
            )
            # 多/缺键 400
            code, _ = srv.request(
                "POST", "/v1/wallets/w1/nodes/n2/rejoin",
                {"rejoin_id": "rj1", "dkg_id": "d1", "round": 2,
                 "key": KEY_B, "approval_request_id": "ar1", "x": 1},
            )
            self.assertEqual(code, 400)
            code, _ = srv.request(
                "POST", "/v1/wallets/w1/nodes/n2/rejoin",
                {"rejoin_id": "rj1", "dkg_id": "d1", "round": 2,
                 "key": KEY_B},
            )
            self.assertEqual(code, 400)
            # 首提 201
            code, body = srv.request(
                "POST", "/v1/wallets/w1/nodes/n2/rejoin",
                {"rejoin_id": "rj1", "dkg_id": "d1", "round": 2,
                 "key": KEY_B, "approval_request_id": "ar1"},
            )
            self.assertEqual(code, 201)
            self.assertEqual(body["state"], "up")
            # 重放 200 同体
            code, body2 = srv.request(
                "POST", "/v1/wallets/w1/nodes/n2/rejoin",
                {"rejoin_id": "rj1", "dkg_id": "d1", "round": 2,
                 "key": KEY_B, "approval_request_id": "ar1"},
            )
            self.assertEqual(code, 200)
            self.assertEqual(body2, body)
            # GET rejoin 不存在
            code, _ = srv.request("GET", "/v1/wallets/w1/nodes/n2/rejoin")
            self.assertEqual(code, 404)


if __name__ == "__main__":
    unittest.main()
