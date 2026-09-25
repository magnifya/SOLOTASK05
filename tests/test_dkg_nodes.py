"""DKG 节点健康（/v1/wallets/{W}/nodes）与自动替补（auto failover）测试。

覆盖：
- 节点健康表：PUT 仅 Q={"nodes"}、GET/PUT 200 同体（节点按安全 ID 升序、
  值键序 key,state）、非法 400、钱包未知 404、未配置 404、PUT 可首建、
  同值不记/变更记 node_state（details=Q）、重启/灾备保健康表与 seq、
  矛盾事件 fail-closed；
- 自动替补：replace 双 null 即 auto（恰一项 null 400）；首提须审批关、
  轮次 commit|share、node 在用且 down|ban，取首个 up 非参与节点及其
  key；无候选/违例 409；首提 201、并发一 201；auto 事件 details 为旧
  七键末加 mode="auto" 且 replacement/key 写实值；
- auto 重放：同 round/action/node 且双 null 优先 200（审批事后开启
  亦同），其余 409；恢复以事件前最近 node_state 核验，矛盾 fail-closed。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import unittest

from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import RecoveryError

from tests.helpers import http_server, make_harness

KEY_A = "aa" * 32
KEY_B = "bb" * 32
KEY_C = "cc" * 32
KEY_D = "dd" * 32
HASH_A = "11" * 32
HASH_B = "22" * 32


def _call(fn, *args):
    """把 ServiceError 归一为 (status, {"error": ...})，便于断言状态码。"""
    try:
        result = fn(*args)
        if isinstance(result, tuple):
            return result
        return 200, result
    except ServiceError as exc:
        return exc.status, {"error": exc.message}


class DkgNodesServiceTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)

    def _put(self, nodes, wallet="w1"):
        return _call(self.svc.put_dkg_nodes, wallet, nodes)

    def _get(self, wallet="w1"):
        return _call(self.svc.get_dkg_nodes, wallet)

    def _events(self, event_type, svc=None):
        svc = svc or self.svc
        return [
            e for e in svc.get_audit_events("w1")["events"]
            if e["type"] == event_type
        ]

    def test_put_get_happy_and_ordering(self):
        code, body = self._put(
            {
                "n2": {"key": KEY_B, "state": "down"},
                "n1": {"state": "up", "key": KEY_A},
                "n3": {"key": KEY_C, "state": "ban"},
            }
        )
        self.assertEqual(code, 200)
        # 节点按安全 ID 升序，值键序 key,state
        self.assertEqual(list(body), ["nodes"])
        self.assertEqual(list(body["nodes"]), ["n1", "n2", "n3"])
        for entry in body["nodes"].values():
            self.assertEqual(list(entry), ["key", "state"])
        self.assertEqual(
            body["nodes"]["n1"], {"key": KEY_A, "state": "up"}
        )
        code, got = self._get()
        self.assertEqual(code, 200)
        self.assertEqual(got, body)

    def test_get_unconfigured_404(self):
        code, _ = self._get()
        self.assertEqual(code, 404)

    def test_unknown_wallet_404(self):
        code, _ = self._get(wallet="nope")
        self.assertEqual(code, 404)
        code, _ = self._put(
            {"n1": {"key": KEY_A, "state": "up"}}, wallet="nope"
        )
        self.assertEqual(code, 404)

    def test_put_invalid_400(self):
        bad = [
            {},  # 空表
            {"bad id": {"key": KEY_A, "state": "up"}},  # 非法安全 ID
            {"n1": "up"},  # 值非对象
            {"n1": {"key": KEY_A}},  # 缺 state
            {"n1": {"key": KEY_A, "state": "up", "x": 1}},  # 多键
            {"n1": {"key": "AA" * 32, "state": "up"}},  # 非小写 hex
            {"n1": {"key": "ab", "state": "up"}},  # 长度不足
            {"n1": {"key": KEY_A, "state": "weird"}},  # 非法 state
            {"n1": {"key": KEY_A, "state": True}},  # 非字符串 state
        ]
        for nodes in bad:
            with self.subTest(nodes=nodes):
                code, _ = self._put(nodes)
                self.assertEqual(code, 400)
        for nodes in ([], "x", 1, None, True):
            with self.subTest(nodes=nodes):
                code, _ = self._put(nodes)
                self.assertEqual(code, 400)
        # 全部拒绝后不产生事件、仍未配置
        self.assertEqual(self._events("node_state"), [])
        code, _ = self._get()
        self.assertEqual(code, 404)

    def test_same_value_not_recorded_change_recorded(self):
        nodes = {"n1": {"key": KEY_A, "state": "up"}}
        code, _ = self._put(nodes)
        self.assertEqual(code, 200)
        self.assertEqual(len(self._events("node_state")), 1)
        # 同值（即使键序不同）不记
        code, _ = self._put({"n1": {"state": "up", "key": KEY_A}})
        self.assertEqual(code, 200)
        self.assertEqual(len(self._events("node_state")), 1)
        # 变更才记，details 即 Q
        code, body = self._put(
            {"n1": {"key": KEY_A, "state": "down"},
             "n2": {"key": KEY_B, "state": "up"}}
        )
        self.assertEqual(code, 200)
        events = self._events("node_state")
        self.assertEqual(len(events), 2)
        self.assertEqual(events[-1]["details"], body)

    def test_event_shape(self):
        self._put({"n1": {"key": KEY_A, "state": "up"}})
        (event,) = self._events("node_state")
        self.assertEqual(
            set(event),
            {"seq", "type", "at", "request_id", "actor_id", "reason",
             "details"},
        )
        self.assertIsNone(event["request_id"])
        self.assertIsNone(event["actor_id"])
        self.assertIsNone(event["reason"])
        self.assertEqual(
            event["details"],
            {"nodes": {"n1": {"key": KEY_A, "state": "up"}}},
        )

    def test_restart_keeps_health_and_seq(self):
        self._put({"n1": {"key": KEY_A, "state": "up"}})
        before = self.svc.get_audit_events("w1")["events"]
        svc2 = WalletService(self.h.store)
        # 恢复不新增审计事件
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)
        code, body = _call(svc2.get_dkg_nodes, "w1")
        self.assertEqual(code, 200)
        self.assertEqual(
            body, {"nodes": {"n1": {"key": KEY_A, "state": "up"}}}
        )

    def test_corrupt_node_state_event_is_fail_closed(self):
        self._put({"n1": {"key": KEY_A, "state": "up"}})
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for event in log["events"]:
            if event["type"] == "node_state":
                event["details"]["nodes"]["n1"]["state"] = "weird"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        # serve 拒绝就绪
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_corrupt_audit_json_is_fail_closed(self):
        self._put({"n1": {"key": KEY_A, "state": "up"}})
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write("{not json")
        with self.assertRaises(Exception):
            WalletService(self.h.store)


class DkgAutoFailoverServiceTest(unittest.TestCase):
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

    def _stage(self, did, op, node, key=None, hash=None, peer=None,
               round=None):
        try:
            return self.svc.post_dkg_stage(
                "w1", did, op, node, key, hash, peer, round
            )
        except ServiceError as exc:
            return exc.status, {"error": exc.message}

    def _failover(self, did, round, action, node=None, replacement=None,
                  key=None, svc=None):
        svc = svc or self.svc
        try:
            return svc.post_dkg_failover(
                "w1", did, round, action, node, replacement, key
            )
        except ServiceError as exc:
            return exc.status, {"error": exc.message}

    def _register_pair(self, did="d1"):
        code, _ = self._stage(did, "register", "n1", key=KEY_A)
        self.assertEqual(code, 201)
        code, _ = self._stage(did, "register", "n2", key=KEY_B)
        self.assertEqual(code, 201)

    def _commit_pair(self, did="d1", round=None, n1="n1", n2="n2"):
        code, _ = self._stage(did, "commit", n1, hash=HASH_A, round=round)
        self.assertEqual(code, 201)
        code, _ = self._stage(did, "commit", n2, hash=HASH_B, round=round)
        self.assertEqual(code, 201)

    def _events(self, event_type, svc=None):
        svc = svc or self.svc
        return [
            e for e in svc.get_audit_events("w1")["events"]
            if e["type"] == event_type
        ]

    # ---- 自动替补首提 ------------------------------------------------------

    def test_auto_happy_path(self):
        self._register_pair()
        self._commit_pair()
        code, view = self._failover("d1", 2, "replace", node="n2")
        self.assertEqual(code, 201)
        self.assertEqual(view["round"], 2)
        self.assertEqual(view["state"], "commit")
        # 实选首个 up 非参与节点 n3 及其 key
        self.assertEqual(view["nodes"], ["n1", "n3"])
        self.assertEqual(view["committed"], [])
        self.assertEqual(view["shared"], [])
        # auto 事件：旧七键末加 mode，replacement/key 写实选值
        (event,) = self._events("dkg_failover")
        self.assertEqual(
            list(event["details"]),
            ["id", "round", "action", "node", "replacement", "key",
             "state", "mode"],
        )
        self.assertEqual(
            event["details"],
            {"id": "d1", "round": 2, "action": "replace", "node": "n2",
             "replacement": "n3", "key": KEY_C, "state": "commit",
             "mode": "auto"},
        )
        # 落盘键序一致（mode 为末键）
        with open(
            os.path.join(self.d, "audit", "w1.json"), encoding="utf-8"
        ) as f:
            log = json.load(f)
        for e in log["events"]:
            if e["type"] == "dkg_failover":
                self.assertEqual(
                    list(e["details"]),
                    ["id", "round", "action", "node", "replacement",
                     "key", "state", "mode"],
                )

    def test_auto_one_null_400(self):
        self._register_pair()
        self._commit_pair()
        code, _ = self._failover(
            "d1", 2, "replace", node="n2", key=KEY_C
        )
        self.assertEqual(code, 400)
        code, _ = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3"
        )
        self.assertEqual(code, 400)

    def test_auto_node_not_down_or_ban_409(self):
        self._register_pair()
        self._commit_pair()
        # n1 为 up：违例 409
        code, _ = self._failover("d1", 2, "replace", node="n1")
        self.assertEqual(code, 409)

    def test_auto_node_missing_from_health_409(self):
        # 健康表不含 n2：无法判定 down|ban，409
        self.svc.put_dkg_nodes(
            "w1",
            {"n1": {"key": KEY_A, "state": "up"},
             "n3": {"key": KEY_C, "state": "up"}},
        )
        self._register_pair()
        self._commit_pair()
        code, _ = self._failover("d1", 2, "replace", node="n2")
        self.assertEqual(code, 409)

    def test_auto_no_candidate_409(self):
        # 唯一非参与节点也 down：无候选
        self.svc.put_dkg_nodes(
            "w1",
            {"n1": {"key": KEY_A, "state": "up"},
             "n2": {"key": KEY_B, "state": "down"},
             "n3": {"key": KEY_C, "state": "down"}},
        )
        self._register_pair()
        self._commit_pair()
        code, _ = self._failover("d1", 2, "replace", node="n2")
        self.assertEqual(code, 409)

    def test_auto_no_health_configured_409(self):
        h = make_harness(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, h.tmpdir, ignore_errors=True)
        h.service.create_wallet("w1", 2)
        for op, node, key in (("register", "n1", KEY_A),
                              ("register", "n2", KEY_B)):
            code, _ = _call(
                h.service.post_dkg_stage,
                "w1", "d1", op, node, key, None, None, None,
            )
            self.assertEqual(code, 201)
        code, _ = _call(
            h.service.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", None, None,
        )
        self.assertEqual(code, 409)

    def test_auto_candidate_order_and_participant_skip(self):
        # 首个（安全 ID 升序）up 非参与节点中选；参与节点与 down 节点跳过
        self.svc.put_dkg_nodes(
            "w1",
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "ban"},
                "n4": {"key": KEY_D, "state": "up"},
                "n3": {"key": KEY_C, "state": "up"},
            },
        )
        self._register_pair()
        self._commit_pair()
        code, view = self._failover("d1", 2, "replace", node="n2")
        self.assertEqual(code, 201)
        self.assertEqual(view["nodes"], ["n1", "n3"])

    def test_auto_requires_approval_off_409(self):
        self._register_pair()
        self._commit_pair()
        self.svc.put_dkg_failover_policy("w1", True)
        code, _ = self._failover("d1", 2, "replace", node="n2")
        self.assertEqual(code, 409)
        # 违例不记事件、现场不变
        self.assertEqual(self._events("dkg_failover"), [])
        code, view = _call(self.svc.get_dkg_session, "w1", "d1", None)
        self.assertEqual(code, 200)
        self.assertEqual(view["round"], 1)

    def test_auto_wrong_stage_409(self):
        # register 阶段（未齐两份注册）不允许 replace
        code, _ = self._stage("d1", "register", "n1", key=KEY_A)
        self.assertEqual(code, 201)
        code, _ = self._failover("d1", 2, "replace", node="n2")
        self.assertEqual(code, 409)

    def test_auto_wrong_round_409(self):
        self._register_pair()
        self._commit_pair()
        code, _ = self._failover("d1", 3, "replace", node="n2")
        self.assertEqual(code, 409)

    # ---- auto 重放 ----------------------------------------------------------

    def test_auto_replay_double_null_200(self):
        self._register_pair()
        self._commit_pair()
        code, view = self._failover("d1", 2, "replace", node="n2")
        self.assertEqual(code, 201)
        # 双 null 重放 200 同视图，不记事件
        code, replay = self._failover("d1", 2, "replace", node="n2")
        self.assertEqual(code, 200)
        self.assertEqual(replay, view)
        self.assertEqual(len(self._events("dkg_failover")), 1)
        # 审批事后开启亦同
        self.svc.put_dkg_failover_policy("w1", True)
        code, replay = self._failover("d1", 2, "replace", node="n2")
        self.assertEqual(code, 200)
        self.assertEqual(replay, view)
        # 健康表事后变更亦同
        self.svc.put_dkg_nodes(
            "w1", {"n1": {"key": KEY_A, "state": "up"},
                   "n2": {"key": KEY_B, "state": "up"},
                   "n3": {"key": KEY_C, "state": "down"}}
        )
        code, _ = self._failover("d1", 2, "replace", node="n2")
        self.assertEqual(code, 200)

    def test_auto_replay_other_params_409(self):
        self._register_pair()
        self._commit_pair()
        code, _ = self._failover("d1", 2, "replace", node="n2")
        self.assertEqual(code, 201)
        # 实值重放（即使恰为实选值）409
        code, _ = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 409)
        # 异 node 409
        code, _ = self._failover("d1", 2, "replace", node="n1")
        self.assertEqual(code, 409)
        # 异 action 409
        code, _ = self._failover("d1", 2, "abort")
        self.assertEqual(code, 409)

    def test_manual_round_double_null_replay_409(self):
        # 手工轮次只按手工重放：双 null 重放 409
        self._register_pair()
        self._commit_pair()
        code, _ = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 201)
        code, _ = self._failover("d1", 2, "replace", node="n2")
        self.assertEqual(code, 409)
        # 手工同参重放仍 200
        code, _ = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C
        )
        self.assertEqual(code, 200)
        # 手工事件仍为旧七键（无 mode）
        (event,) = self._events("dkg_failover")
        self.assertEqual(
            list(event["details"]),
            ["id", "round", "action", "node", "replacement", "key",
             "state"],
        )

    def test_auto_concurrent_single_201(self):
        self._register_pair()
        self._commit_pair()
        codes = []
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            code, _ = self._failover("d1", 2, "replace", node="n2")
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

    # ---- 恢复核验 ------------------------------------------------------------

    def test_restart_recovers_auto_round(self):
        self._register_pair()
        self._commit_pair()
        code, view = self._failover("d1", 2, "replace", node="n2")
        self.assertEqual(code, 201)
        before = self.svc.get_audit_events("w1")["events"]
        svc2 = WalletService(self.h.store)
        # 恢复不新增审计事件，seq 连续
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)
        code, got = _call(svc2.get_dkg_session, "w1", "d1", "2")
        self.assertEqual(code, 200)
        self.assertEqual(got, view)
        # 重启后 auto 重放仍 200
        code, replay = self._failover("d1", 2, "replace", node="n2", svc=svc2)
        self.assertEqual(code, 200)
        self.assertEqual(replay, view)
        # 重启后续作派生轮
        code, view = _call(
            svc2.post_dkg_stage,
            "w1", "d1", "commit", "n1", None, HASH_A, None, "2",
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "commit")

    def test_recovery_uses_node_state_before_event(self):
        # 故障后再变更健康表：恢复按事件前最近 node_state 核验，不受影响
        self._register_pair()
        self._commit_pair()
        code, _ = self._failover("d1", 2, "replace", node="n2")
        self.assertEqual(code, 201)
        self.svc.put_dkg_nodes(
            "w1", {"n1": {"key": KEY_A, "state": "up"},
                   "n2": {"key": KEY_B, "state": "up"},
                   "n3": {"key": KEY_C, "state": "ban"}}
        )
        svc2 = WalletService(self.h.store)
        code, view = _call(svc2.get_dkg_session, "w1", "d1", "2")
        self.assertEqual(code, 200)
        self.assertEqual(view["nodes"], ["n1", "n3"])

    def test_tampered_auto_replacement_is_fail_closed(self):
        self._register_pair()
        self._commit_pair()
        code, _ = self._failover("d1", 2, "replace", node="n2")
        self.assertEqual(code, 201)
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for event in log["events"]:
            if event["type"] == "dkg_failover":
                # 篡改：实选值与事件前健康表重算不符
                event["details"]["replacement"] = "n9"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_tampered_auto_mode_is_fail_closed(self):
        self._register_pair()
        self._commit_pair()
        code, _ = self._failover("d1", 2, "replace", node="n2")
        self.assertEqual(code, 201)
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for event in log["events"]:
            if event["type"] == "dkg_failover":
                event["details"]["mode"] = "manual"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_tampered_earlier_node_state_is_fail_closed(self):
        # 篡改事件前的 node_state：实选值与重算不符
        self._register_pair()
        self._commit_pair()
        code, _ = self._failover("d1", 2, "replace", node="n2")
        self.assertEqual(code, 201)
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for event in log["events"]:
            if event["type"] == "node_state":
                event["details"]["nodes"]["n3"]["key"] = KEY_D
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)


class DkgNodesHttpTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def test_nodes_endpoint_over_http(self):
        with http_server(self.d) as srv:
            code, _ = srv.request("POST", "/v1/wallets", {
                "wallet_id": "w1", "shares": 2,
            })
            self.assertEqual(code, 201)
            # 未配置 404
            code, _ = srv.request("GET", "/v1/wallets/w1/nodes")
            self.assertEqual(code, 404)
            # 夹带其他键 400
            code, _ = srv.request("PUT", "/v1/wallets/w1/nodes", {
                "nodes": {"n1": {"key": KEY_A, "state": "up"}}, "x": 1,
            })
            self.assertEqual(code, 400)
            # 首建 200 同体
            code, body = srv.request("PUT", "/v1/wallets/w1/nodes", {
                "nodes": {
                    "n2": {"key": KEY_B, "state": "down"},
                    "n1": {"key": KEY_A, "state": "up"},
                },
            })
            self.assertEqual(code, 200)
            self.assertEqual(list(body["nodes"]), ["n1", "n2"])
            code, got = srv.request("GET", "/v1/wallets/w1/nodes")
            self.assertEqual(code, 200)
            self.assertEqual(got, body)
            # 钱包不存在 404
            code, _ = srv.request("GET", "/v1/wallets/nope/nodes")
            self.assertEqual(code, 404)
            code, _ = srv.request("PUT", "/v1/wallets/nope/nodes", {
                "nodes": {"n1": {"key": KEY_A, "state": "up"}},
            })
            self.assertEqual(code, 404)

    def test_auto_failover_over_http(self):
        with http_server(self.d) as srv:
            srv.request("POST", "/v1/wallets", {
                "wallet_id": "w1", "shares": 2,
            })
            srv.request("PUT", "/v1/wallets/w1/nodes", {
                "nodes": {
                    "n1": {"key": KEY_A, "state": "up"},
                    "n2": {"key": KEY_B, "state": "down"},
                    "n3": {"key": KEY_C, "state": "up"},
                },
            })
            for node, key in (("n1", KEY_A), ("n2", KEY_B)):
                code, _ = srv.request("POST", "/v1/dkg/w1/d1", {
                    "op": "register", "node": node, "key": key,
                    "hash": None, "peer": None,
                })
                self.assertEqual(code, 201)
            for node, h in (("n1", HASH_A), ("n2", HASH_B)):
                code, _ = srv.request("POST", "/v1/dkg/w1/d1", {
                    "op": "commit", "node": node, "key": None,
                    "hash": h, "peer": None,
                })
                self.assertEqual(code, 201)
            code, view = srv.request("POST", "/v1/dkg/w1/d1/failover", {
                "round": 2, "action": "replace", "node": "n2",
                "replacement": None, "key": None,
            })
            self.assertEqual(code, 201)
            self.assertEqual(view["nodes"], ["n1", "n3"])
            # 双 null 重放 200
            code, replay = srv.request("POST", "/v1/dkg/w1/d1/failover", {
                "round": 2, "action": "replace", "node": "n2",
                "replacement": None, "key": None,
            })
            self.assertEqual(code, 200)
            self.assertEqual(replay, view)

    def test_corrupt_node_state_http_503(self):
        with http_server(self.d) as srv:
            srv.request("POST", "/v1/wallets", {
                "wallet_id": "w1", "shares": 2,
            })
            code, _ = srv.request("PUT", "/v1/wallets/w1/nodes", {
                "nodes": {"n1": {"key": KEY_A, "state": "up"}},
            })
            self.assertEqual(code, 200)
            # 运行中篡改 node_state 事件：常驻请求一律 503
            path = os.path.join(self.d, "audit", "w1.json")
            with open(path, encoding="utf-8") as f:
                log = json.load(f)
            for event in log["events"]:
                if event["type"] == "node_state":
                    event["details"]["nodes"]["n1"]["state"] = "weird"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(log, f)
            code, body = srv.request("GET", "/v1/wallets/w1/nodes")
            self.assertEqual(code, 503)
            self.assertEqual(set(body), {"error"})


class DkgNodesBackupTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)

    def test_backup_restore_keeps_health_and_auto_round(self):
        from threshold_wallet import drbackup

        self.svc.put_dkg_nodes(
            "w1",
            {"n1": {"key": KEY_A, "state": "up"},
             "n2": {"key": KEY_B, "state": "down"},
             "n3": {"key": KEY_C, "state": "up"}},
        )
        for op, node, key in (("register", "n1", KEY_A),
                              ("register", "n2", KEY_B)):
            code, _ = _call(
                self.svc.post_dkg_stage,
                "w1", "d1", op, node, key, None, None, None,
            )
            self.assertEqual(code, 201)
        for node, h in (("n1", HASH_A), ("n2", HASH_B)):
            code, _ = _call(
                self.svc.post_dkg_stage,
                "w1", "d1", "commit", node, None, h, None, None,
            )
            self.assertEqual(code, 201)
        code, view = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", None, None,
        )
        self.assertEqual(code, 201)
        before = self.svc.get_audit_events("w1")["events"]
        out_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, out_dir, ignore_errors=True)
        out = os.path.join(out_dir, "snap.tar")
        body = drbackup.backup(self.d, "w1", "S1", out)
        self.assertEqual(body["status"], 201)
        dst = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, dst, ignore_errors=True)
        status, _ = drbackup.restore(dst, "w1", out)
        self.assertEqual(status, 201)
        svc2 = make_harness(dst).service
        # 灾备恢复后健康表、轮次与 seq 不变，auto 重放仍 200
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)
        self.assertEqual(
            svc2.get_dkg_nodes("w1"),
            {"nodes": {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "down"},
                "n3": {"key": KEY_C, "state": "up"},
            }},
        )
        code, got = _call(
            svc2.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", None, None,
        )
        self.assertEqual(code, 200)
        self.assertEqual(got, view)


if __name__ == "__main__":
    unittest.main()
