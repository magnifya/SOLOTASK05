"""DKG 节点健康表与 failover 自动替补（auto）测试。

覆盖：
- P=GET/PUT /v1/wallets/{W}/nodes：PUT 仅 Q={"nodes":...}；nodes 非空、
  键为安全标识（归一 ID 升序），每值恰含 key(64 位小写 hex)/state
  (up|down|ban) 且键序 key,state；非法 400、钱包 404、GET 未配 404、
  PUT 可首建；同值不记 node_state、变更记（details=Q，三 id 字段 null）；
  纯事件恢复，重启/灾备保持，损坏/矛盾 fail-closed；
- F=failover replace 自动替补：replacement/key 双 null 即 auto，一项
  null 400；首提须审批关、当前轮 commit|share、node 在用且 down|ban，
  取首个 up 非参与节点及 key；无表/node 未故障/无候选/审批开 409；
  首提 201、并发一 201；事件 details 八键末键 mode=auto 且写实值，
  手工事件为旧七键；
- auto 重放：同 round/action/node 双 null 优先 200，不查审批/健康/
  候选/阶段（事后开审批、翻健康、推进到 done 亦同），其余 409；
- 恢复以事件前最近 node_state 核验选择；矛盾/坏审计 JSON/审计 I/O →
  RecoveryError/CorruptDataError/OSError，HTTP 503、serve 拒绝就绪；
  恢复不记事件，不泄露私钥/份额正文。
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
KEY_E = "ee" * 32
HASH_A = "11" * 32
HASH_B = "22" * 32

NODES_UP = {
    "n1": {"key": KEY_A, "state": "up"},
    "n2": {"key": KEY_B, "state": "up"},
    "n3": {"key": KEY_C, "state": "up"},
}


def _call(fn, *args):
    try:
        return fn(*args)
    except ServiceError as exc:
        return exc.status, {"error": exc.message}


class NodeHealthServiceTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)

    def _events(self, event_type="node_state", svc=None):
        svc = svc or self.svc
        return [
            e
            for e in svc.get_audit_events("w1")["events"]
            if e["type"] == event_type
        ]

    # ---- 404 / 首建 / 同体 -------------------------------------------------

    def test_get_unconfigured_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_dkg_nodes("w1")
        self.assertEqual(ctx.exception.status, 404)

    def test_unknown_wallet_404(self):
        for method in ("get", "put"):
            with self.assertRaises(ServiceError) as ctx:
                if method == "get":
                    self.svc.get_dkg_nodes("nope")
                else:
                    self.svc.put_dkg_nodes("nope", NODES_UP)
            self.assertEqual(ctx.exception.status, 404, method)

    def test_put_first_then_get_same_body(self):
        # 乱序输入：归一为节点 ID 升序
        body = self.svc.put_dkg_nodes(
            "w1",
            {
                "n3": {"key": KEY_C, "state": "up"},
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "down"},
            },
        )
        self.assertEqual(list(body["nodes"]), ["n1", "n2", "n3"])
        self.assertEqual(body, self.svc.get_dkg_nodes("w1"))
        # 每个值键序固定 key,state
        for entry in body["nodes"].values():
            self.assertEqual(list(entry), ["key", "state"])

    # ---- 400 ---------------------------------------------------------------

    def test_invalid_bodies_400(self):
        bad_bodies = [
            {},  # 空表
            {"n1": {"key": "ZZ" * 32, "state": "up"}},  # 非小写 hex
            {"n1": {"key": KEY_C[:-1], "state": "up"}},  # 长度错
            {"n1": {"key": KEY_C, "state": "gone"}},  # state 非法
            {"n1": {"key": KEY_C, "state": "UP"}},
            {"n1": {"key": KEY_C}},  # 缺 state
            {"n1": {"state": "up"}},  # 缺 key
            {"n1": {"key": KEY_C, "state": "up", "x": 1}},  # 多键
            {"n1": {"key": KEY_C, "state": True}},  # state 非字符串
            {"n1": {"key": 123, "state": "up"}},  # key 非字符串
            {"bad id!": {"key": KEY_C, "state": "up"}},  # 键非法
            {1: {"key": KEY_C, "state": "up"}},  # 键非字符串
            [],  # 非对象
            None,
            "nope",
        ]
        for nodes in bad_bodies:
            with self.subTest(nodes=nodes):
                with self.assertRaises(ServiceError) as ctx:
                    self.svc.put_dkg_nodes("w1", nodes)
                self.assertEqual(ctx.exception.status, 400)

    def test_invalid_wallet_400(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_dkg_nodes("bad id!")
        self.assertEqual(ctx.exception.status, 400)

    # ---- 事件：同值不记、变更记 --------------------------------------------

    def test_same_value_does_not_log_change_logs(self):
        table = {
            "n1": {"key": KEY_A, "state": "up"},
            "n2": {"key": KEY_B, "state": "down"},
        }
        self.svc.put_dkg_nodes("w1", table)
        # 首建记一条
        self.assertEqual(len(self._events()), 1)
        # 同值（即便输入乱序、归一后相等）不记
        self.svc.put_dkg_nodes(
            "w1",
            {
                "n2": {"state": "down", "key": KEY_B},
                "n1": {"state": "up", "key": KEY_A},
            },
        )
        self.assertEqual(len(self._events()), 1)
        # 任何差异（state/key/成员）记一条
        changed = {
            "n1": {"key": KEY_A, "state": "ban"},
            "n2": {"key": KEY_B, "state": "down"},
        }
        self.svc.put_dkg_nodes("w1", changed)
        self.assertEqual(len(self._events()), 2)

    def test_event_shape_is_Q_with_null_ids(self):
        self.svc.put_dkg_nodes("w1", NODES_UP)
        (event,) = self._events()
        self.assertEqual(
            set(event),
            {"seq", "type", "at", "request_id", "actor_id", "reason",
             "details"},
        )
        self.assertEqual(event["type"], "node_state")
        self.assertIsNone(event["request_id"])
        self.assertIsNone(event["actor_id"])
        self.assertIsNone(event["reason"])
        self.assertEqual(
            event["details"],
            {"nodes": NODES_UP},
        )
        self.assertEqual(list(event["details"]), ["nodes"])
        # 落盘 JSON 键序一致
        with open(os.path.join(self.d, "audit", "w1.json"),
                  encoding="utf-8") as f:
            log = json.load(f)
        (stored,) = [e for e in log["events"] if e["type"] == "node_state"]
        self.assertEqual(list(stored["details"]), ["nodes"])
        self.assertEqual(
            list(next(iter(stored["details"]["nodes"].values()))),
            ["key", "state"],
        )

    # ---- 重启 / 灾备 / 损坏 ------------------------------------------------

    def test_restart_takes_last_event_and_logs_nothing(self):
        self.svc.put_dkg_nodes("w1", NODES_UP)
        self.svc.put_dkg_nodes(
            "w1", {**NODES_UP, "n2": {"key": KEY_B, "state": "ban"}}
        )
        before = self.svc.get_audit_events("w1")["events"]
        svc2 = WalletService(self.h.store)
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)
        body = svc2.get_dkg_nodes("w1")
        self.assertEqual(body["nodes"]["n2"]["state"], "ban")

    def test_tampered_event_is_fail_closed(self):
        self.svc.put_dkg_nodes("w1", NODES_UP)
        path = os.path.join(self.d, "audit", "w1.json")
        log = json.load(open(path, encoding="utf-8"))
        for event in log["events"]:
            if event["type"] == "node_state":
                event["details"]["nodes"]["n1"]["state"] = "gone"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        # 启动拒绝就绪
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)
        # 常驻请求同样 fail-closed
        with self.assertRaises(RecoveryError):
            self.svc.get_dkg_nodes("w1")

    def test_event_with_actor_is_fail_closed(self):
        self.svc.put_dkg_nodes("w1", NODES_UP)
        path = os.path.join(self.d, "audit", "w1.json")
        log = json.load(open(path, encoding="utf-8"))
        for event in log["events"]:
            if event["type"] == "node_state":
                event["actor_id"] = "mallory"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_backup_restore_keeps_health_and_seq(self):
        self.svc.put_dkg_nodes("w1", NODES_UP)
        before = self.svc.get_audit_events("w1")["events"]
        out = os.path.join(tempfile.mkdtemp(), "snap.tar")
        self.addCleanup(shutil.rmtree, os.path.dirname(out),
                        ignore_errors=True)
        self.assertEqual(drbackup.backup(self.d, "w1", "S1", out)["status"],
                         201)
        dst = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, dst, ignore_errors=True)
        status, _ = drbackup.restore(dst, "w1", out)
        self.assertEqual(status, 201)
        svc2 = WalletService(WalletStore(dst))
        self.assertEqual(svc2.get_dkg_nodes("w1"), {"nodes": NODES_UP})
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)


class AutoFailoverServiceTest(unittest.TestCase):
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

    def _failover(self, did, round, action, node=None, replacement=None,
                  key=None, approval=None, wallet="w1"):
        args = (wallet, did, round, action, node, replacement, key)
        if approval is not None:
            args = args + (approval,)
        return _call(self.svc.post_dkg_failover, *args)

    def _register_pair(self, did="d1", n1="n1", n2="n2",
                       k1=KEY_A, k2=KEY_B):
        self.assertEqual(self._post(did, "register", n1, key=k1)[0], 201)
        self.assertEqual(self._post(did, "register", n2, key=k2)[0], 201)

    def _commit_pair(self, did="d1", round=None, n1="n1", n2="n2"):
        self.assertEqual(
            self._post(did, "commit", n1, hash=HASH_A, round=round)[0], 201
        )
        self.assertEqual(
            self._post(did, "commit", n2, hash=HASH_B, round=round)[0], 201
        )

    def _prepare_commit_round(self, health, did="d1"):
        self.svc.put_dkg_nodes("w1", health)
        self._register_pair(did)
        self._commit_pair(did)

    def _failover_events(self, svc=None):
        svc = svc or self.svc
        return [
            e for e in svc.get_audit_events("w1")["events"]
            if e["type"] == "dkg_failover"
        ]

    # ---- 自动选择 ----------------------------------------------------------

    def test_auto_picks_first_up_non_participant(self):
        # n2 down；候选 n3(C)/n4(E)/n5 均 up，取 ID 升序首个 n3
        health = {
            "n1": {"key": KEY_A, "state": "up"},
            "n2": {"key": KEY_B, "state": "down"},
            "n4": {"key": KEY_E, "state": "up"},
            "n3": {"key": KEY_C, "state": "up"},
        }
        self._prepare_commit_round(health)
        code, view = self._failover("d1", 2, "replace", "n2")
        self.assertEqual(code, 201)
        self.assertEqual(view["nodes"], ["n1", "n3"])
        self.assertEqual(view["state"], "commit")
        self.assertEqual(view["committed"], [])
        self.assertEqual(view["shared"], [])

    def test_auto_accepts_banned_node_and_skips_down_candidate(self):
        # n1 ban；n3 down（不可作候选）、n4 up → 选 n4
        health = {
            "n1": {"key": KEY_A, "state": "ban"},
            "n2": {"key": KEY_B, "state": "up"},
            "n3": {"key": KEY_C, "state": "down"},
            "n4": {"key": KEY_E, "state": "up"},
        }
        self._prepare_commit_round(health)
        code, view = self._failover("d1", 2, "replace", "n1")
        self.assertEqual(code, 201)
        self.assertEqual(view["nodes"], ["n4", "n2"])

    def test_auto_writes_real_values_with_mode_key(self):
        self._prepare_commit_round(
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "down"},
                "n3": {"key": KEY_C, "state": "up"},
            }
        )
        code, _ = self._failover("d1", 2, "replace", "n2")
        self.assertEqual(code, 201)
        (event,) = self._failover_events()
        self.assertEqual(
            list(event),
            ["seq", "type", "at", "request_id", "actor_id", "reason",
             "details"],
        )
        self.assertEqual(
            list(event["details"]),
            ["id", "round", "action", "node", "replacement", "key",
             "state", "mode"],
        )
        self.assertEqual(event["details"]["mode"], "auto")
        # replacement/key 写实值而非 null
        self.assertEqual(event["details"]["replacement"], "n3")
        self.assertEqual(event["details"]["key"], KEY_C)
        self.assertEqual(event["details"]["node"], "n2")
        self.assertEqual(event["details"]["state"], "commit")
        self.assertIsNone(event["actor_id"])
        self.assertIsNone(event["reason"])
        # 落盘键序一致
        with open(os.path.join(self.d, "audit", "w1.json"),
                  encoding="utf-8") as f:
            log = json.load(f)
        (stored,) = [e for e in log["events"]
                     if e["type"] == "dkg_failover"]
        self.assertEqual(list(stored["details"])[-1], "mode")

    def test_one_null_one_set_is_400(self):
        self._prepare_commit_round(
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "down"},
                "n3": {"key": KEY_C, "state": "up"},
            }
        )
        code, _ = self._failover(
            "d1", 2, "replace", "n2", replacement=None, key=KEY_C
        )
        self.assertEqual(code, 400)
        code, _ = self._failover(
            "d1", 2, "replace", "n2", replacement="n3", key=None
        )
        self.assertEqual(code, 400)

    # ---- 违例 409 ----------------------------------------------------------

    def test_auto_requires_health_table(self):
        # 不配健康表：register/commit 后 auto 409
        self._register_pair()
        self._commit_pair()
        code, _ = self._failover("d1", 2, "replace", "n2")
        self.assertEqual(code, 409)
        self.assertEqual(self._failover_events(), [])

    def test_auto_node_must_be_down_or_banned(self):
        self._prepare_commit_round(
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "up"},
                "n3": {"key": KEY_C, "state": "up"},
            }
        )
        code, _ = self._failover("d1", 2, "replace", "n2")
        self.assertEqual(code, 409)
        self.assertEqual(self._failover_events(), [])

    def test_auto_without_eligible_candidate_409(self):
        # 健康表只有两参与方，故障后无 up 非参与节点
        self._prepare_commit_round(
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "down"},
            }
        )
        code, _ = self._failover("d1", 2, "replace", "n2")
        self.assertEqual(code, 409)
        # 候选虽存在但也是 down
        self.svc.put_dkg_nodes(
            "w1",
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "down"},
                "n3": {"key": KEY_C, "state": "ban"},
            },
        )
        code, _ = self._failover("d1", 2, "replace", "n2")
        self.assertEqual(code, 409)
        self.assertEqual(self._failover_events(), [])

    def test_auto_requires_commit_or_share_stage(self):
        # register 阶段（仅一方注册）即使健康表满足也 409
        self.svc.put_dkg_nodes(
            "w1",
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "down"},
                "n3": {"key": KEY_C, "state": "up"},
            },
        )
        self.assertEqual(self._post("d1", "register", "n1", key=KEY_A)[0],
                         201)
        code, _ = self._failover("d1", 2, "replace", "n2")
        self.assertEqual(code, 409)
        # node 不在用（换新会话 d2：两方注册后替换一个非参与节点）
        self._register_pair("d2")
        self._commit_pair("d2")
        code, _ = self._failover("d2", 2, "replace", "n3")
        self.assertEqual(code, 409)

    def test_auto_requires_approval_disabled(self):
        self._prepare_commit_round(
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "down"},
                "n3": {"key": KEY_C, "state": "up"},
            }
        )
        self.svc.put_dkg_failover_policy("w1", True)
        # 审批开启：双 null auto 首提 409，不落事件
        code, _ = self._failover("d1", 2, "replace", "n2")
        self.assertEqual(code, 409)
        self.assertEqual(self._failover_events(), [])

    def test_auto_with_approval_id_when_disabled_is_400(self):
        self._prepare_commit_round(
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "down"},
                "n3": {"key": KEY_C, "state": "up"},
            }
        )
        # 审批关闭却夹带 approval_request_id：400
        code, _ = self._failover(
            "d1", 2, "replace", "n2", approval="req-1"
        )
        self.assertEqual(code, 400)

    # ---- 重放：优先 200、不复查 --------------------------------------------

    def test_auto_replay_200_ignores_policy_health_stage(self):
        self._prepare_commit_round(
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "down"},
                "n3": {"key": KEY_C, "state": "up"},
            }
        )
        code, view = self._failover("d1", 2, "replace", "n2")
        self.assertEqual(code, 201)
        # 事后开启审批、把 n2 翻成 up、删除候选——重放仍 200 同体
        self.svc.put_dkg_failover_policy("w1", True)
        self.svc.put_dkg_nodes(
            "w1",
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "up"},
            },
        )
        # 并把派生轮推进到 done（重放不查阶段）
        self.svc.put_dkg_failover_policy("w1", False)
        self.assertEqual(
            self._post("d1", "commit", "n1", hash=HASH_A, round="2")[0],
            201,
        )
        self.assertEqual(
            self._post("d1", "commit", "n3", hash=HASH_B, round="2")[0],
            201,
        )
        self.assertEqual(
            self._post("d1", "share", "n1", hash=HASH_B, peer="n3",
                       round="2")[0],
            201,
        )
        code, done_view = self._post(
            "d1", "share", "n3", hash=HASH_A, peer="n1", round="2"
        )
        self.assertEqual(code, 201)
        self.assertEqual(done_view["state"], "done")
        # 再次开启审批后双 null 重放 round 2：仍 200，返回当前（done）视图
        self.svc.put_dkg_failover_policy("w1", True)
        code, replay = self._failover("d1", 2, "replace", "n2")
        self.assertEqual(code, 200)
        self.assertEqual(replay, done_view)
        # 重放不记事件：始终恰 1 条 dkg_failover
        self.assertEqual(len(self._failover_events()), 1)

    def test_auto_replay_mismatch_is_409(self):
        self._prepare_commit_round(
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "down"},
                "n3": {"key": KEY_C, "state": "up"},
            }
        )
        self.assertEqual(self._failover("d1", 2, "replace", "n2")[0], 201)
        # 同轮双 null 但 node 不同 → 409
        code, _ = self._failover("d1", 2, "replace", "n1")
        self.assertEqual(code, 409)
        # 手工实参打向 auto 轮 → 409
        code, _ = self._failover(
            "d1", 2, "replace", "n2", "n3", KEY_C
        )
        self.assertEqual(code, 409)
        # abort 打向同一轮 → 409
        code, _ = self._failover("d1", 2, "abort")
        self.assertEqual(code, 409)

    def test_auto_request_against_manual_round_is_409(self):
        self._prepare_commit_round(
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "down"},
                "n3": {"key": KEY_C, "state": "up"},
            }
        )
        # 手工替补 n2→n3（旧七键）
        code, _ = self._failover("d1", 2, "replace", "n2", "n3", KEY_C)
        self.assertEqual(code, 201)
        (event,) = self._failover_events()
        self.assertEqual(
            set(event["details"]),
            {"id", "round", "action", "node", "replacement", "key",
             "state"},
        )
        self.assertNotIn("mode", event["details"])
        # 对该手工轮发双 null auto 重放 → 409
        code, _ = self._failover("d1", 2, "replace", "n2")
        self.assertEqual(code, 409)
        # 手工同参重放仍 200
        code, _ = self._failover("d1", 2, "replace", "n2", "n3", KEY_C)
        self.assertEqual(code, 200)

    # ---- 并发 / 重启 / 灾备 ------------------------------------------------

    def test_concurrent_auto_single_201(self):
        self._prepare_commit_round(
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "down"},
                "n3": {"key": KEY_C, "state": "up"},
            }
        )
        codes = []
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            code, _ = self._failover("d1", 2, "replace", "n2")
            codes.append(code)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(codes), [200] * 7 + [201])
        self.assertEqual(len(self._failover_events()), 1)

    def test_restart_keeps_auto_round_and_replays(self):
        self._prepare_commit_round(
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "down"},
                "n3": {"key": KEY_C, "state": "up"},
            }
        )
        self.assertEqual(self._failover("d1", 2, "replace", "n2")[0], 201)
        before = self.svc.get_audit_events("w1")["events"]
        svc2 = WalletService(self.h.store)
        # 恢复不新增事件、seq 连续
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)
        view = svc2.get_dkg_session("w1", "d1", "2")
        self.assertEqual(view["nodes"], ["n1", "n3"])
        # 新进程上双 null 重放仍 200，不记事件
        code, replay = svc2.post_dkg_failover(
            "w1", "d1", 2, "replace", "n2", None, None
        )
        self.assertEqual(code, 200)
        self.assertEqual(replay, view)
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)

    def test_backup_restore_keeps_auto_round(self):
        self._prepare_commit_round(
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "down"},
                "n3": {"key": KEY_C, "state": "up"},
            }
        )
        self.assertEqual(self._failover("d1", 2, "replace", "n2")[0], 201)
        out = os.path.join(tempfile.mkdtemp(), "snap.tar")
        self.addCleanup(shutil.rmtree, os.path.dirname(out),
                        ignore_errors=True)
        self.assertEqual(drbackup.backup(self.d, "w1", "S1", out)["status"],
                         201)
        dst = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, dst, ignore_errors=True)
        status, _ = drbackup.restore(dst, "w1", out)
        self.assertEqual(status, 201)
        svc2 = WalletService(WalletStore(dst))
        self.assertEqual(
            svc2.get_dkg_session("w1", "d1", "2")["nodes"], ["n1", "n3"]
        )
        code, _ = svc2.post_dkg_failover(
            "w1", "d1", 2, "replace", "n2", None, None
        )
        self.assertEqual(code, 200)


class AutoFailoverRecoveryStrictTest(unittest.TestCase):
    """恢复时以事件前最近 node_state 严格核验 auto 选择：矛盾 fail-closed。"""

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
            code, _ = self.svc.post_dkg_stage(
                "w1", "d1", op, node, key, hsh, peer, None
            )
            self.assertEqual(code, 201)
        code, _ = self.svc.post_dkg_failover(
            "w1", "d1", 2, "replace", "n2", None, None
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

    def _failover(self, log):
        return next(e for e in log["events"]
                    if e["type"] == "dkg_failover")

    def _assert_refuses_ready(self):
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_tampered_replacement_is_fail_closed(self):
        def mutate(log):
            self._failover(log)["details"]["replacement"] = "n9"
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_tampered_key_is_fail_closed(self):
        def mutate(log):
            self._failover(log)["details"]["key"] = KEY_D
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_tampered_node_to_healthy_is_fail_closed(self):
        def mutate(log):
            self._failover(log)["details"]["node"] = "n1"
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_unknown_mode_is_fail_closed(self):
        def mutate(log):
            self._failover(log)["details"]["mode"] = "manual"
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_auto_without_prior_snapshot_is_fail_closed(self):
        def mutate(log):
            log["events"] = [
                e for e in log["events"] if e["type"] != "node_state"
            ]
            for i, event in enumerate(log["events"], 1):
                event["seq"] = i
            log["next_seq"] = len(log["events"]) + 1
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_later_health_flip_does_not_invalidate_recovery(self):
        # 事后新增一条把 n2 翻 up、n3 翻 down 的健康快照：恢复核验只看
        # 故障事件之前的快照，新表不影响历史 auto 选择。
        self.svc.put_dkg_nodes(
            "w1",
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "up"},
                "n3": {"key": KEY_C, "state": "down"},
            },
        )
        # 正常重建（不抛）
        svc2 = WalletService(self.h.store)
        self.assertEqual(
            svc2.get_dkg_session("w1", "d1", "2")["nodes"], ["n1", "n3"]
        )

    def test_snapshot_with_candidate_down_at_failover_is_fail_closed(self):
        # 把事前（唯一）node_state 快照里候选 n3 改成 down：当时无候选。
        def mutate(log):
            for event in log["events"]:
                if event["type"] == "node_state":
                    event["details"]["nodes"]["n3"]["state"] = "down"
        self._rewrite(mutate)
        self._assert_refuses_ready()

    def test_corrupt_audit_json_is_corrupt_data_error(self):
        with open(self._audit_path(), "wb") as f:
            f.write(b"{not valid json")
        # 直接读审计（不跑启动恢复编排）：损坏 JSON 为 CorruptDataError
        from threshold_wallet.audit import AuditStore

        with self.assertRaises(CorruptDataError):
            AuditStore(self.h.store.data_dir).events_by_type(
                "w1", "node_state"
            )
        # 启动恢复统一包装为 RecoveryError 阻止就绪
        self._assert_refuses_ready()


class NodeHealthHttpTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def test_http_nodes_crud_and_errors(self):
        with http_server(self.d) as srv:
            code, _ = srv.request(
                "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
            )
            self.assertEqual(code, 201)
            # 未配置 404
            code, _ = srv.request("GET", "/v1/wallets/w1/nodes")
            self.assertEqual(code, 404)
            # 钱包不存在 404
            code, _ = srv.request("GET", "/v1/wallets/nope/nodes")
            self.assertEqual(code, 404)
            code, _ = srv.request(
                "PUT", "/v1/wallets/nope/nodes", {"nodes": NODES_UP}
            )
            self.assertEqual(code, 404)
            # 多/缺键 400
            code, _ = srv.request(
                "PUT", "/v1/wallets/w1/nodes", {"nodes": NODES_UP, "x": 1}
            )
            self.assertEqual(code, 400)
            code, _ = srv.request("PUT", "/v1/wallets/w1/nodes", {})
            self.assertEqual(code, 400)
            # 非法值 400
            code, _ = srv.request(
                "PUT", "/v1/wallets/w1/nodes",
                {"nodes": {"n1": {"key": KEY_A, "state": "gone"}}},
            )
            self.assertEqual(code, 400)
            # 首建 200，归一升序
            code, body = srv.request(
                "PUT",
                "/v1/wallets/w1/nodes",
                {"nodes": {
                    "n2": {"key": KEY_B, "state": "down"},
                    "n1": {"key": KEY_A, "state": "up"},
                }},
            )
            self.assertEqual(code, 200)
            self.assertEqual(list(body["nodes"]), ["n1", "n2"])
            code, body = srv.request("GET", "/v1/wallets/w1/nodes")
            self.assertEqual(code, 200)
            self.assertEqual(list(body["nodes"]), ["n1", "n2"])

    def test_http_auto_failover_flow(self):
        with http_server(self.d) as srv:
            srv.request(
                "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
            )
            srv.request(
                "PUT", "/v1/wallets/w1/nodes", {"nodes": {
                    "n1": {"key": KEY_A, "state": "up"},
                    "n2": {"key": KEY_B, "state": "down"},
                    "n3": {"key": KEY_C, "state": "up"},
                }},
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
                code, _ = srv.request("POST", "/v1/dkg/w1/d1", body)
                self.assertEqual(code, 201)
            # 一项 null 400
            code, _ = srv.request(
                "POST", "/v1/dkg/w1/d1/failover",
                {"round": 2, "action": "replace", "node": "n2",
                 "replacement": None, "key": KEY_C},
            )
            self.assertEqual(code, 400)
            # 双 null auto 201
            code, view = srv.request(
                "POST", "/v1/dkg/w1/d1/failover",
                {"round": 2, "action": "replace", "node": "n2",
                 "replacement": None, "key": None},
            )
            self.assertEqual(code, 201)
            self.assertEqual(view["nodes"], ["n1", "n3"])
            # 重放 200
            code, view2 = srv.request(
                "POST", "/v1/dkg/w1/d1/failover",
                {"round": 2, "action": "replace", "node": "n2",
                 "replacement": None, "key": None},
            )
            self.assertEqual(code, 200)
            self.assertEqual(view2, view)
            # failover GET 不接受（仅 POST）
            code, _ = srv.request("GET", "/v1/dkg/w1/d1/failover")
            self.assertEqual(code, 404)

    def test_http_corrupt_health_scene_is_503(self):
        with http_server(self.d) as srv:
            srv.request(
                "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
            )
            code, _ = srv.request(
                "PUT", "/v1/wallets/w1/nodes", {"nodes": NODES_UP}
            )
            self.assertEqual(code, 200)
            # 服务运行期间篡改 node_state 事件：下一次持锁访问严格校验，
            # 由 HTTP 边界统一映射为 503 泛化文案。
            path = os.path.join(self.d, "audit", "w1.json")
            log = json.load(open(path, encoding="utf-8"))
            for event in log["events"]:
                if event["type"] == "node_state":
                    event["details"]["nodes"]["n1"]["state"] = "gone"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(log, f)
            code, body = srv.request("GET", "/v1/wallets/w1/nodes")
            self.assertEqual(code, 503)
            self.assertEqual(body, {"error": "service temporarily unavailable"})


if __name__ == "__main__":
    unittest.main()
