"""份额绑定（share-bind）测试。

覆盖：
- POST /v1/wallets/{W}/share-bind：体恰含 id/rotation/dkg/round/node/
  slot/approval 七键；round 为正整数、slot 为 1|2（均拒 bool）；
  未知轮换/DKG/节点/审批（含跨钱包审批）404；轮换非 prepared、round
  非当前 done 轮、node 非该轮 reinstate 换入的 up 节点、审批非
  approved、message 不符、槽位占用均 409；
- 首提 201 返回 V={id,node,slot,share_id}；同 id 同参重放 200、异参
  409；share_participant_reinstated 为唯一提交点（request_id=id、
  actor_id=approval、reason=null、details=V 固定键序）；
- 激活后绑定仅约束签名会话 /shares：绑定 share_id 的体恰为
  {node,share_id,signature}，node 不符 409、键集/签名错 400；未绑定
  份额、/sign、share-sign 不变；
- 重启/灾备恢复逐条复核，矛盾/损坏/IO 失败 fail-closed（503、拒绝
  就绪）。
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import tempfile
import threading
import unittest

from threshold_wallet.cli import main as cli_main
from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import (
    CorruptDataError,
    RecoveryError,
    WalletStore,
)

from tests.helpers import http_server, make_harness

KEY_A = "aa" * 32
KEY_B = "bb" * 32
KEY_C = "cc" * 32
HASH_A = "11" * 32
HASH_C = "33" * 32

HEALTH = {
    "n1": {"key": KEY_A, "state": "up"},
    "n2": {"key": KEY_B, "state": "up"},
    "n3": {"key": KEY_C, "state": "down"},
}


def _compact(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _rejoin_message(node="n3", key=KEY_C, round=1, dkg_id="d1",
                    rejoin_id="rj1"):
    return _compact(
        {
            "rejoin_id": rejoin_id,
            "dkg_id": dkg_id,
            "round": round,
            "node": node,
            "key": key,
        }
    )


def _reinstate_message(round=2, node="n2", replacement="n3", key=KEY_C,
                       dkg_id="d1"):
    return _compact(
        {
            "dkg_id": dkg_id,
            "round": round,
            "action": "reinstate",
            "node": node,
            "replacement": replacement,
            "key": key,
        }
    )


def _bind_message(bind_id="b1", rotation="r1", dkg="d1", round=2,
                  node="n3", slot=1):
    return _compact(
        {
            "id": bind_id,
            "rotation": rotation,
            "dkg": dkg,
            "round": round,
            "node": node,
            "slot": slot,
        }
    )


def _call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except ServiceError as exc:
        return exc.status, {"error": exc.message}


class ShareBindServiceTest(unittest.TestCase):
    """service 层：完整现场（reinstate 换入 n3 的第 2 轮已 done）。"""

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
            ("commit", "n2", None, HASH_C),
        ):
            code, _ = self.svc.post_dkg_stage(
                "w1", "d1", op, node, key, hsh, None
            )
            self.assertEqual(code, 201)
        # n3 经 rejoin 审批恢复为 up（轮外待命）
        self.svc.create_sign_request("w1", "apR", _rejoin_message())
        self.svc.approve("w1", "apR", "boss")
        code, _ = self.svc.post_node_rejoin(
            "w1", "n3", "rj1", "d1", 1, KEY_C, "apR"
        )
        self.assertEqual(code, 201)
        # reinstate：n3 换入第 2 轮顶替 n2
        self.svc.create_sign_request("w1", "ap2", _reinstate_message())
        self.svc.approve("w1", "ap2", "boss")
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "reinstate", "n2", "n3", KEY_C, "ap2",
        )
        self.assertEqual(code, 201)
        # 第 2 轮推进到 done（n1、n3 两方）
        for op, node, key, hsh, peer in (
            ("commit", "n1", None, HASH_A, None),
            ("commit", "n3", None, HASH_C, None),
            ("share", "n1", None, HASH_C, "n3"),
            ("share", "n3", None, HASH_A, "n1"),
        ):
            code, view = self.svc.post_dkg_stage(
                "w1", "d1", op, node, key, hsh, peer, "2"
            )
            self.assertEqual(code, 201)
        self.assertEqual(view["state"], "done")
        # prepared 轮换与绑定审批单
        code, self.rot = self.svc.create_share_rotation("w1", "r1")
        self.assertEqual(code, 201)
        self.svc.create_sign_request("w1", "apB", _bind_message())
        self.svc.approve("w1", "apB", "boss")

    def _bind(self, bind_id="b1", rotation="r1", dkg="d1", round=2,
              node="n3", slot=1, approval="apB"):
        return _call(
            self.svc.post_share_bind,
            "w1", bind_id, rotation, dkg, round, node, slot, approval,
        )

    def _events(self, svc=None, type_="share_participant_reinstated"):
        svc = svc or self.svc
        return [
            e for e in svc.get_audit_events("w1")["events"]
            if e["type"] == type_
        ]

    # ---- 201 / 视图 / 事件 -------------------------------------------------

    def test_bind_201_view_and_event(self):
        code, view = self._bind()
        self.assertEqual(code, 201)
        self.assertEqual(
            view,
            {"id": "b1", "node": "n3", "slot": 1,
             "share_id": "r1-share-1"},
        )
        self.assertEqual(list(view), ["id", "node", "slot", "share_id"])
        (event,) = self._events()
        self.assertEqual(event["request_id"], "b1")
        self.assertEqual(event["actor_id"], "apB")
        self.assertIsNone(event["reason"])
        self.assertEqual(event["details"], view)
        self.assertEqual(
            list(event["details"]), ["id", "node", "slot", "share_id"]
        )
        # 落盘外层规范序、details 键序
        with open(
            os.path.join(self.d, "audit", "w1.json"), encoding="utf-8"
        ) as f:
            log = json.load(f)
        stored = [
            e for e in log["events"]
            if e["type"] == "share_participant_reinstated"
        ][0]
        self.assertEqual(
            list(stored),
            ["actor_id", "at", "details", "reason", "request_id", "seq",
             "type"],
        )
        self.assertEqual(
            list(stored["details"]), ["id", "node", "slot", "share_id"]
        )

    def test_bind_slot2_second_bind(self):
        code, view = self._bind()
        self.assertEqual(code, 201)
        self.svc.create_sign_request(
            "w1", "apB2", _bind_message(bind_id="b2", slot=2)
        )
        self.svc.approve("w1", "apB2", "boss")
        code, view = self._bind(
            bind_id="b2", slot=2, approval="apB2"
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["share_id"], "r1-share-2")
        self.assertEqual(view["slot"], 2)

    # ---- 幂等重放 -----------------------------------------------------------

    def test_replay_same_params_200(self):
        code, view = self._bind()
        self.assertEqual(code, 201)
        code, again = self._bind()
        self.assertEqual(code, 200)
        self.assertEqual(again, view)
        # 重放不记事件
        self.assertEqual(len(self._events()), 1)

    def test_replay_different_params_409(self):
        self.assertEqual(self._bind()[0], 201)
        # 换审批单
        self.svc.create_sign_request("w1", "apB3", _bind_message())
        self.svc.approve("w1", "apB3", "boss")
        self.assertEqual(self._bind(approval="apB3")[0], 409)
        # 换 slot / node / round / dkg / rotation
        self.assertEqual(self._bind(slot=2)[0], 409)
        self.assertEqual(self._bind(node="n1")[0], 409)
        self.assertEqual(self._bind(round=1)[0], 409)
        self.assertEqual(self._bind(dkg="d2")[0], 409)
        self.assertEqual(self._bind(rotation="r2")[0], 409)
        self.assertEqual(len(self._events()), 1)

    # ---- 400 ----------------------------------------------------------------

    def test_invalid_params_400(self):
        self.assertEqual(self._bind(bind_id="bad id!")[0], 400)
        self.assertEqual(self._bind(rotation="")[0], 400)
        self.assertEqual(self._bind(dkg="*" * 129)[0], 400)
        self.assertEqual(self._bind(node="bad node")[0], 400)
        self.assertEqual(self._bind(approval=1)[0], 400)
        for bad_round in (True, 0, -1, 1.5, "2"):
            self.assertEqual(
                self._bind(round=bad_round)[0], 400, bad_round
            )
        for bad_slot in (True, False, 0, 3, 1.5, "1"):
            self.assertEqual(
                self._bind(slot=bad_slot)[0], 400, bad_slot
            )
        self.assertEqual(len(self._events()), 0)

    # ---- 404 ----------------------------------------------------------------

    def test_unknowns_404(self):
        self.assertEqual(
            _call(
                self.svc.post_share_bind,
                "ghost", "b1", "r1", "d1", 2, "n3", 1, "apB",
            )[0],
            404,
        )
        self.assertEqual(self._bind(rotation="ghost")[0], 404)
        self.assertEqual(self._bind(dkg="ghost")[0], 404)
        self.assertEqual(self._bind(node="n9")[0], 404)
        self.assertEqual(self._bind(approval="ghost")[0], 404)

    def test_cross_wallet_approval_404(self):
        # 审批单属于另一个钱包：本钱包查无此单，404
        self.svc.create_wallet("w2", 2)
        self.svc.put_policy("w2", 1, 600)
        self.svc.create_sign_request("w2", "apW2", _bind_message())
        self.svc.approve("w2", "apW2", "boss")
        self.assertEqual(self._bind(approval="apW2")[0], 404)

    # ---- 409 ----------------------------------------------------------------

    def test_rotation_not_prepared_409(self):
        # r1 激活后不再是 prepared
        self.svc.activate_share_rotation("w1", "r1")
        self.assertEqual(self._bind()[0], 409)

    def test_round_not_current_done_409(self):
        # 第 1 轮不是当前轮
        self.assertEqual(self._bind(round=1)[0], 409)
        # 第 3 轮不存在于当前
        self.assertEqual(self._bind(round=3)[0], 409)
        # 另一会话当前轮未 done
        for op, node, key in (
            ("register", "n1", KEY_A),
            ("register", "n2", KEY_B),
        ):
            code, _ = self.svc.post_dkg_stage(
                "w1", "d2", op, node, key, None, None
            )
            self.assertEqual(code, 201)
        self.assertEqual(self._bind(dkg="d2", round=1)[0], 409)

    def test_node_not_reinstated_409(self):
        # n1 在轮但非 reinstate 换入；n2 已被换出
        self.assertEqual(self._bind(node="n1")[0], 409)
        self.assertEqual(self._bind(node="n2")[0], 409)

    def test_node_not_up_409(self):
        # n3 事后被置为 down
        self.svc.put_dkg_nodes(
            "w1",
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "up"},
                "n3": {"key": KEY_C, "state": "down"},
            },
        )
        self.assertEqual(self._bind()[0], 409)

    def test_approval_not_approved_409(self):
        # pending 单
        self.svc.create_sign_request("w1", "apP", _bind_message())
        self.assertEqual(self._bind(approval="apP")[0], 409)
        # rejected 单
        self.svc.create_sign_request("w1", "apRj2", _bind_message())
        self.svc.reject("w1", "apRj2", "boss")
        self.assertEqual(self._bind(approval="apRj2")[0], 409)

    def test_approval_message_mismatch_409(self):
        self.svc.create_sign_request("w1", "apM", _bind_message(slot=2))
        self.svc.approve("w1", "apM", "boss")
        self.assertEqual(self._bind(approval="apM")[0], 409)
        self.svc.create_sign_request("w1", "apM2", "some other message")
        self.svc.approve("w1", "apM2", "boss")
        self.assertEqual(self._bind(approval="apM2")[0], 409)

    def test_slot_occupied_409(self):
        self.assertEqual(self._bind()[0], 201)
        self.svc.create_sign_request(
            "w1", "apB2", _bind_message(bind_id="b2")
        )
        self.svc.approve("w1", "apB2", "boss")
        self.assertEqual(
            self._bind(bind_id="b2", approval="apB2")[0], 409
        )

    # ---- 恢复 ----------------------------------------------------------------

    def test_restart_keeps_bindings_and_seq(self):
        code, view = self._bind()
        self.assertEqual(code, 201)
        before = self.svc.get_audit_events("w1")["events"]
        svc2 = WalletService(self.h.store)
        # 恢复不新增审计事件，seq 连续
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)
        # 重启后同参重放 200、异参 409
        code, again = _call(
            svc2.post_share_bind, "w1", "b1", "r1", "d1", 2, "n3", 1, "apB"
        )
        self.assertEqual(code, 200)
        self.assertEqual(again, view)
        self.assertEqual(
            _call(
                svc2.post_share_bind,
                "w1", "b1", "r1", "d1", 2, "n3", 2, "apB",
            )[0],
            409,
        )
        seqs = [e["seq"] for e in svc2.get_audit_events("w1")["events"]]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))

    def test_tampered_event_is_fail_closed(self):
        self.assertEqual(self._bind()[0], 201)
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for e in log["events"]:
            if e["type"] == "share_participant_reinstated":
                e["details"]["slot"] = 2
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_reordered_details_is_fail_closed(self):
        self.assertEqual(self._bind()[0], 201)
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for e in log["events"]:
            if e["type"] == "share_participant_reinstated":
                d = e["details"]
                e["details"] = {
                    "share_id": d["share_id"],
                    "slot": d["slot"],
                    "node": d["node"],
                    "id": d["id"],
                }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_corrupt_audit_json_is_fail_closed(self):
        self.assertEqual(self._bind()[0], 201)
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write("{not json")
        # 常驻持锁访问：损坏 JSON 抛 CorruptDataError（HTTP 边界转 503）
        with self.assertRaises(CorruptDataError):
            _call(
                self.svc.post_share_bind,
                "w1", "b2", "r1", "d1", 2, "n3", 2, "apB",
            )
        # 启动恢复：统一以 RecoveryError 阻止就绪
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_concurrent_binds_single_201(self):
        results = []
        results_lock = threading.Lock()

        def worker():
            code, _ = self._bind()
            with results_lock:
                results.append(code)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # 锁内并发恰一个 201，其余同参重放 200；只记一条事件
        self.assertEqual(sorted(results), [200] * 7 + [201])
        self.assertEqual(len(self._events()), 1)
        seqs = [
            e["seq"] for e in self.svc.get_audit_events("w1")["events"]
        ]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))

    def test_backup_restore_roundtrip_keeps_bindings(self):
        code, view = self._bind()
        self.assertEqual(code, 201)
        out_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, out_dir, ignore_errors=True)
        out = os.path.join(out_dir, "snap.tar")
        with contextlib.redirect_stdout(io.StringIO()):
            code = cli_main(
                [
                    "backup", "--data-dir", self.d, "--wallet-id", "w1",
                    "--snapshot-id", "snap-1", "--output", out,
                ]
            )
        self.assertEqual(code, 0)
        d2 = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d2, ignore_errors=True)
        with contextlib.redirect_stdout(io.StringIO()):
            code = cli_main(
                ["restore", "--data-dir", d2, "--wallet-id", "w1",
                 "--input", out]
            )
        self.assertEqual(code, 0)
        svc2 = WalletService(WalletStore(d2))
        # 恢复后绑定现场与幂等保持：同参重放 200 同体、异参 409
        code, again = _call(
            svc2.post_share_bind, "w1", "b1", "r1", "d1", 2, "n3", 1, "apB"
        )
        self.assertEqual(code, 200)
        self.assertEqual(again, view)
        self.assertEqual(
            _call(
                svc2.post_share_bind,
                "w1", "b1", "r1", "d1", 2, "n3", 2, "apB",
            )[0],
            409,
        )
        before = self.svc.get_audit_events("w1")["events"]
        after = svc2.get_audit_events("w1")["events"]
        self.assertEqual(
            [ (e["seq"], e["type"]) for e in after ],
            [ (e["seq"], e["type"]) for e in before ],
        )

    def test_slot_conflict_events_are_fail_closed(self):
        self.assertEqual(self._bind()[0], 201)
        # 伪造第二条同槽位绑定事件（不同 id）
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        seq = max(e["seq"] for e in log["events"]) + 1
        log["events"].append(
            {
                "actor_id": "apB",
                "at": "2026-09-26T00:00:00Z",
                "details": {
                    "id": "bX",
                    "node": "n3",
                    "slot": 1,
                    "share_id": "r1-share-1",
                },
                "reason": None,
                "request_id": "bX",
                "seq": seq,
                "type": "share_participant_reinstated",
            }
        )
        log["next_seq"] = seq + 1
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)


class ShareBindHttpTest(unittest.TestCase):
    """HTTP 层：路由、体键集与激活后 /shares 绑定约束。"""

    def setUp(self):
        self._ctx = http_server(tempfile.mkdtemp())
        self.srv = self._ctx.__enter__()
        self.addCleanup(self._ctx.__exit__, None, None, None)
        self.svc = self.srv.harness.service
        self.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
        self.request(
            "PUT", "/v1/wallets/w1/approval-policy",
            {"required_approvals": 1, "timeout_seconds": 600},
        )
        self.request("PUT", "/v1/wallets/w1/nodes", {"nodes": HEALTH})
        for op, node, key, hsh in (
            ("register", "n1", KEY_A, None),
            ("register", "n2", KEY_B, None),
            ("commit", "n1", None, HASH_A),
            ("commit", "n2", None, HASH_C),
        ):
            code, _ = self.request(
                "POST", "/v1/dkg/w1/d1",
                {"op": op, "node": node, "key": key, "hash": hsh,
                 "peer": None},
            )
            self.assertEqual(code, 201)
        self._approve("apR", _rejoin_message())
        code, _ = self.request(
            "POST", "/v1/wallets/w1/nodes/n3/rejoin",
            {"rejoin_id": "rj1", "dkg_id": "d1", "round": 1, "key": KEY_C,
             "approval_request_id": "apR"},
        )
        self.assertEqual(code, 201)
        self._approve("ap2", _reinstate_message())
        code, _ = self.request(
            "POST", "/v1/dkg/w1/d1/failover",
            {"round": 2, "action": "reinstate", "node": "n2",
             "replacement": "n3", "key": KEY_C,
             "approval_request_id": "ap2"},
        )
        self.assertEqual(code, 201)
        for op, node, hsh, peer in (
            ("commit", "n1", HASH_A, None),
            ("commit", "n3", HASH_C, None),
            ("share", "n1", HASH_C, "n3"),
            ("share", "n3", HASH_A, "n1"),
        ):
            code, _ = self.request(
                "POST", "/v1/dkg/w1/d1?round=2",
                {"op": op, "node": node, "key": None, "hash": hsh,
                 "peer": peer},
            )
            self.assertEqual(code, 201)
        code, self.rot = self.request(
            "POST", "/v1/wallets/w1/share-rotations", {"rotation_id": "r1"}
        )
        self.assertEqual(code, 201)
        self._approve("apB", _bind_message())

    def request(self, method, path, body=None):
        return self.srv.request(method, path, body)

    def _approve(self, rid, message):
        code, _ = self.request(
            "POST", "/v1/wallets/w1/sign-requests",
            {"id": rid, "message": message},
        )
        self.assertEqual(code, 201)
        code, _ = self.request(
            "POST", f"/v1/wallets/w1/sign-requests/{rid}/approve",
            {"approver_id": "boss"},
        )
        self.assertEqual(code, 200)

    def _bind_body(self, **over):
        body = {
            "id": "b1",
            "rotation": "r1",
            "dkg": "d1",
            "round": 2,
            "node": "n3",
            "slot": 1,
            "approval": "apB",
        }
        body.update(over)
        return body

    def test_bind_201_over_http(self):
        code, view = self.request(
            "POST", "/v1/wallets/w1/share-bind", self._bind_body()
        )
        self.assertEqual(code, 201)
        self.assertEqual(
            view,
            {"id": "b1", "node": "n3", "slot": 1,
             "share_id": "r1-share-1"},
        )
        # 同参重放 200
        code, again = self.request(
            "POST", "/v1/wallets/w1/share-bind", self._bind_body()
        )
        self.assertEqual(code, 200)
        self.assertEqual(again, view)

    def test_body_key_set_400(self):
        extra = self._bind_body(other="x")
        code, _ = self.request("POST", "/v1/wallets/w1/share-bind", extra)
        self.assertEqual(code, 400)
        missing = self._bind_body()
        del missing["slot"]
        code, _ = self.request("POST", "/v1/wallets/w1/share-bind", missing)
        self.assertEqual(code, 400)
        code, _ = self.request("POST", "/v1/wallets/w1/share-bind", {})
        self.assertEqual(code, 400)

    def test_unknown_wallet_404(self):
        code, _ = self.request(
            "POST", "/v1/wallets/ghost/share-bind", self._bind_body()
        )
        self.assertEqual(code, 404)

    # ---- 激活后 /shares 绑定约束 ---------------------------------------------

    def _activate_and_open_session(self):
        code, _ = self.request(
            "POST", "/v1/wallets/w1/share-bind", self._bind_body()
        )
        self.assertEqual(code, 201)
        code, _ = self.request(
            "POST", "/v1/wallets/w1/share-rotations/r1/activate"
        )
        self.assertEqual(code, 201)
        code, _ = self.request(
            "POST", "/v1/wallets/w1/sign-sessions",
            {"id": "s1", "message": "m", "timeout_seconds": 600},
        )
        self.assertEqual(code, 201)
        self._approve("s1", "m")

    def test_bound_share_requires_node(self):
        self._activate_and_open_session()
        sig1 = self.srv.harness.share_signature(
            "w1", "r1-share-1", "s1", "m"
        )
        # 绑定份额缺 node 键：400
        code, _ = self.request(
            "POST", "/v1/wallets/w1/sign-sessions/s1/shares",
            {"share_id": "r1-share-1", "signature": sig1},
        )
        self.assertEqual(code, 400)
        # 绑定份额夹带额外键：400
        code, _ = self.request(
            "POST", "/v1/wallets/w1/sign-sessions/s1/shares",
            {"node": "n3", "share_id": "r1-share-1", "signature": sig1,
             "extra": 1},
        )
        self.assertEqual(code, 400)
        # node 不符：409
        code, _ = self.request(
            "POST", "/v1/wallets/w1/sign-sessions/s1/shares",
            {"node": "n1", "share_id": "r1-share-1", "signature": sig1},
        )
        self.assertEqual(code, 409)
        # 正确 node：201
        code, view = self.request(
            "POST", "/v1/wallets/w1/sign-sessions/s1/shares",
            {"node": "n3", "share_id": "r1-share-1", "signature": sig1},
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["received_shares"], ["r1-share-1"])
        # 同值重放（带正确 node）：200
        code, _ = self.request(
            "POST", "/v1/wallets/w1/sign-sessions/s1/shares",
            {"node": "n3", "share_id": "r1-share-1", "signature": sig1},
        )
        self.assertEqual(code, 200)
        # 未绑定份额沿用旧体：201 并聚合 signed
        sig2 = self.srv.harness.share_signature(
            "w1", "r1-share-2", "s1", "m"
        )
        code, view = self.request(
            "POST", "/v1/wallets/w1/sign-sessions/s1/shares",
            {"share_id": "r1-share-2", "signature": sig2},
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "signed")

    def test_bound_share_bad_signature_400(self):
        self._activate_and_open_session()
        bad = self.srv.harness.share_signature(
            "w1", "r1-share-1", "s1", "other-message"
        )
        code, _ = self.request(
            "POST", "/v1/wallets/w1/sign-sessions/s1/shares",
            {"node": "n3", "share_id": "r1-share-1", "signature": bad},
        )
        self.assertEqual(code, 400)

    def test_sign_endpoint_unaffected(self):
        self._activate_and_open_session()
        # /sign 不使用 node 键，行为不变（审批单 s1 已 approved）
        sig1 = self.srv.harness.share_signature(
            "w1", "r1-share-1", "s1", "m"
        )
        sig2 = self.srv.harness.share_signature(
            "w1", "r1-share-2", "s1", "m"
        )
        code, view = self.request(
            "POST", "/v1/wallets/w1/sign",
            {
                "signing_request_id": "s1",
                "message": "m",
                "signatures": [
                    {"share_id": "r1-share-1", "signature": sig1},
                    {"share_id": "r1-share-2", "signature": sig2},
                ],
            },
        )
        self.assertEqual(code, 201)
        self.assertIn("signature", view)


if __name__ == "__main__":
    unittest.main()
