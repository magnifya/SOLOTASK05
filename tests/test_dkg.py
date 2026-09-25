"""可恢复两方 DKG（/v1/dkg/{W}/{D}）与审计 details 既定键序测试。

覆盖：
- 双方依序推进 register→commit→share→done，完成公钥为两 key 注册序拼接；
- 视图键序 {id,state,nodes,committed,shared,public_key}，三数组按注册序；
- 首提 201、同值重放 200 优先、非法 400、异值/错阶段/第三节点 409、
  钱包或非 register 未知流程 404；
- 状态仅由 dkg_stage 事件持久化：重启后续作、恢复不新增事件、矛盾
  现场 fail-closed（RecoveryError / 503）；
- session_participant_replaced / session_takeover / dkg_stage 的
  details 按 README 既定顺序落盘与查询；
- 灾备 backup/restore 后 DKG 视图与审计 seq 不变。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from threshold_wallet import drbackup
from threshold_wallet.audit import AuditStore
from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import RecoveryError, WalletStore

from tests.helpers import http_server, make_harness

KEY_A = "aa" * 32
KEY_B = "bb" * 32
KEY_C = "cc" * 32
HASH_A = "11" * 32
HASH_B = "22" * 32
HASH_C = "33" * 32


def _body(op, node, key=None, hash=None, peer=None):
    return {"op": op, "node": node, "key": key, "hash": hash, "peer": peer}


def _call(fn, *args):
    """把 ServiceError 归一为 (status, {"error": ...})，便于断言状态码。"""
    try:
        return fn(*args)
    except ServiceError as exc:
        return exc.status, {"error": exc.message}


class DkgServiceTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)

    def _post(self, did, op, node, key=None, hash=None, peer=None):
        return _call(
            self.svc.post_dkg_stage, "w1", did, op, node, key, hash, peer
        )

    def _get(self, did, wallet="w1"):
        return _call(self.svc.get_dkg_session, wallet, did)

    def _register_pair(self, did="d1"):
        code, _ = self._post(did, "register", "n1", key=KEY_A)
        self.assertEqual(code, 201)
        code, _ = self._post(did, "register", "n2", key=KEY_B)
        self.assertEqual(code, 201)

    def _commit_pair(self, did="d1"):
        code, _ = self._post(did, "commit", "n1", hash=HASH_A)
        self.assertEqual(code, 201)
        code, _ = self._post(did, "commit", "n2", hash=HASH_B)
        self.assertEqual(code, 201)

    def _complete(self, did="d1"):
        self._register_pair(did)
        self._commit_pair(did)
        code, _ = self._post(did, "share", "n1", hash=HASH_B, peer="n2")
        self.assertEqual(code, 201)
        code, view = self._post(did, "share", "n2", hash=HASH_A, peer="n1")
        self.assertEqual(code, 201)
        return view

    # ---- 状态机与视图 ---------------------------------------------------

    def test_happy_path_to_done(self):
        view = self._complete()
        self.assertEqual(view["state"], "done")
        self.assertEqual(view["nodes"], ["n1", "n2"])
        self.assertEqual(view["committed"], ["n1", "n2"])
        self.assertEqual(view["shared"], ["n1", "n2"])
        # 完成公钥为两份注册 key 按注册序拼接
        self.assertEqual(view["public_key"], KEY_A + KEY_B)

    def test_view_key_order(self):
        self._complete()
        view = self.svc.get_dkg_session("w1", "d1")
        self.assertEqual(
            list(view),
            ["id", "round", "state", "nodes", "committed", "shared",
             "public_key"],
        )
        self.assertEqual(view["round"], 1)

    def test_intermediate_states(self):
        code, view = self._post("d1", "register", "n1", key=KEY_A)
        self.assertEqual((code, view["state"]), (201, "register"))
        self.assertEqual(view["nodes"], ["n1"])
        self.assertEqual(view["committed"], [])
        self.assertEqual(view["shared"], [])
        self.assertIsNone(view["public_key"])
        code, view = self._post("d1", "register", "n2", key=KEY_B)
        self.assertEqual((code, view["state"]), (201, "commit"))
        code, view = self._post("d1", "commit", "n1", hash=HASH_A)
        self.assertEqual((code, view["state"]), (201, "commit"))
        self.assertEqual(view["committed"], ["n1"])
        code, view = self._post("d1", "commit", "n2", hash=HASH_B)
        self.assertEqual((code, view["state"]), (201, "share"))
        code, view = self._post("d1", "share", "n2", hash=HASH_A, peer="n1")
        self.assertEqual((code, view["state"]), (201, "share"))
        self.assertEqual(view["shared"], ["n2"])
        self.assertIsNone(view["public_key"])

    def test_arrays_follow_registration_order(self):
        # 注册序 n2,n1：三数组均按注册序，公钥按注册序拼接
        code, _ = self._post("d1", "register", "n2", key=KEY_B)
        self.assertEqual(code, 201)
        code, _ = self._post("d1", "register", "n1", key=KEY_A)
        self.assertEqual(code, 201)
        code, _ = self._post("d1", "commit", "n1", hash=HASH_A)
        self.assertEqual(code, 201)
        code, view = self._post("d1", "commit", "n2", hash=HASH_B)
        self.assertEqual(code, 201)
        self.assertEqual(view["nodes"], ["n2", "n1"])
        self.assertEqual(view["committed"], ["n2", "n1"])
        code, _ = self._post("d1", "share", "n1", hash=HASH_B, peer="n2")
        self.assertEqual(code, 201)
        code, view = self._post("d1", "share", "n2", hash=HASH_A, peer="n1")
        self.assertEqual(code, 201)
        self.assertEqual(view["shared"], ["n2", "n1"])
        self.assertEqual(view["public_key"], KEY_B + KEY_A)

    # ---- 幂等重放 ---------------------------------------------------------

    def test_same_value_replay_200(self):
        self._complete()
        for args in (
            ("register", "n1", KEY_A, None, None),
            ("register", "n2", KEY_B, None, None),
            ("commit", "n1", None, HASH_A, None),
            ("commit", "n2", None, HASH_B, None),
            ("share", "n1", None, HASH_B, "n2"),
            ("share", "n2", None, HASH_A, "n1"),
        ):
            op, node, key, hash_, peer = args
            code, view = self._post("d1", op, node, key=key, hash=hash_, peer=peer)
            self.assertEqual(code, 200, args)
            self.assertEqual(view["state"], "done")
        # 重放不记事件：恰 6 条 dkg_stage
        events = [
            e for e in self.svc.get_audit_events("w1")["events"]
            if e["type"] == "dkg_stage"
        ]
        self.assertEqual(len(events), 6)

    def test_replay_preempts_stage_judgement(self):
        # 同值重放 200 优先于阶段判定：register 阶段重放 commit 同值不可能，
        # 但 done 后同值重放 register/commit/share 仍 200
        self._complete()
        code, _ = self._post("d1", "register", "n1", key=KEY_A)
        self.assertEqual(code, 200)

    # ---- 400 --------------------------------------------------------------

    def test_invalid_params_400(self):
        bad = [
            # op 未知/类型错
            ("d1", "noop", "n1", KEY_A, None, None),
            ("d1", None, "n1", KEY_A, None, None),
            ("d1", 1, "n1", KEY_A, None, None),
            # node 非法
            ("d1", "register", "bad node!", KEY_A, None, None),
            ("d1", "register", "", KEY_A, None, None),
            ("d1", "register", None, KEY_A, None, None),
            # register：key 非 64 位小写 hex / 夹带 hash、peer
            ("d1", "register", "n1", "AA" * 32, None, None),
            ("d1", "register", "n1", "aa" * 31, None, None),
            ("d1", "register", "n1", "gg" * 32, None, None),
            ("d1", "register", "n1", None, None, None),
            ("d1", "register", "n1", KEY_A, HASH_A, None),
            ("d1", "register", "n1", KEY_A, None, "n2"),
            # commit：hash 非法 / 夹带 key、peer
            ("d1", "commit", "n1", None, "ZZ" * 32, None),
            ("d1", "commit", "n1", None, None, None),
            ("d1", "commit", "n1", KEY_A, HASH_A, None),
            ("d1", "commit", "n1", None, HASH_A, "n2"),
            # share：hash/peer 非法、夹带 key
            ("d1", "share", "n1", KEY_A, HASH_A, "n2"),
            ("d1", "share", "n1", None, None, "n2"),
            ("d1", "share", "n1", None, HASH_A, None),
            ("d1", "share", "n1", None, HASH_A, "bad peer!"),
        ]
        for did, op, node, key, hash_, peer in bad:
            code, _ = self._post(did, op, node, key=key, hash=hash_, peer=peer)
            self.assertEqual(code, 400, (did, op, node, key, hash_, peer))
        # 非法 dkg id
        code, _ = self._post("bad id!", "register", "n1", key=KEY_A)
        self.assertEqual(code, 400)
        code, _ = self._get("bad id!")
        self.assertEqual(code, 400)

    # ---- 404 --------------------------------------------------------------

    def test_unknown_wallet_404(self):
        code, _ = _call(
            self.svc.post_dkg_stage,
            "nope", "d1", "register", "n1", KEY_A, None, None,
        )
        self.assertEqual(code, 404)
        code, _ = self._get("d1", wallet="nope")
        self.assertEqual(code, 404)

    def test_non_register_unknown_session_404(self):
        code, _ = self._post("d1", "commit", "n1", hash=HASH_A)
        self.assertEqual(code, 404)
        code, _ = self._post("d1", "share", "n1", hash=HASH_A, peer="n2")
        self.assertEqual(code, 404)
        code, _ = self._get("d1")
        self.assertEqual(code, 404)

    # ---- 409 --------------------------------------------------------------

    def test_conflicts_409(self):
        self._register_pair()
        # 异值重放
        code, _ = self._post("d1", "register", "n1", key=KEY_C)
        self.assertEqual(code, 409)
        # 第三节点
        code, _ = self._post("d1", "register", "n3", key=KEY_C)
        self.assertEqual(code, 409)
        # 未注册节点 commit/share
        code, _ = self._post("d1", "commit", "n3", hash=HASH_C)
        self.assertEqual(code, 409)
        code, _ = self._post("d1", "share", "n3", hash=HASH_C, peer="n1")
        self.assertEqual(code, 409)
        self._commit_pair()
        # commit 异值重放
        code, _ = self._post("d1", "commit", "n1", hash=HASH_C)
        self.assertEqual(code, 409)
        # share：hash 不等于 peer 承诺
        code, _ = self._post("d1", "share", "n1", hash=HASH_C, peer="n2")
        self.assertEqual(code, 409)
        # share：peer 是自己 / 非参与方
        code, _ = self._post("d1", "share", "n1", hash=HASH_A, peer="n1")
        self.assertEqual(code, 409)
        code, _ = self._post("d1", "share", "n1", hash=HASH_C, peer="n3")
        self.assertEqual(code, 409)
        code, _ = self._post("d1", "share", "n1", hash=HASH_B, peer="n2")
        self.assertEqual(code, 201)
        # share 异值重放
        code, _ = self._post("d1", "share", "n1", hash=HASH_A, peer="n2")
        self.assertEqual(code, 409)
        code, _ = self._post("d1", "share", "n1", hash=HASH_B, peer="n1")
        self.assertEqual(code, 409)

    def test_wrong_stage_409(self):
        # 未齐两份注册即 commit/share
        code, _ = self._post("d1", "register", "n1", key=KEY_A)
        self.assertEqual(code, 201)
        code, _ = self._post("d1", "commit", "n1", hash=HASH_A)
        self.assertEqual(code, 409)
        code, _ = self._post("d1", "share", "n1", hash=HASH_A, peer="n2")
        self.assertEqual(code, 409)
        # 未齐两份承诺即 share
        self._register_pair("d2")
        code, _ = self._post("d2", "commit", "n1", hash=HASH_A)
        self.assertEqual(code, 201)
        code, _ = self._post("d2", "share", "n1", hash=HASH_B, peer="n2")
        self.assertEqual(code, 409)

    # ---- 持久化与恢复 -------------------------------------------------------

    def _dkg_events(self, svc=None):
        svc = svc or self.svc
        return [
            e for e in svc.get_audit_events("w1")["events"]
            if e["type"] == "dkg_stage"
        ]

    def test_restart_keeps_session(self):
        self._complete()
        before = self._dkg_events()
        svc2 = WalletService(self.h.store)
        view = svc2.get_dkg_session("w1", "d1")
        self.assertEqual(view["state"], "done")
        self.assertEqual(view["public_key"], KEY_A + KEY_B)
        # 恢复不新增审计事件，seq 连续
        self.assertEqual(self._dkg_events(svc2), before)
        seqs = [e["seq"] for e in svc2.get_audit_events("w1")["events"]]
        self.assertEqual(sorted(seqs), list(range(1, len(seqs) + 1)))

    def test_restart_mid_flow_resumes(self):
        self._register_pair()
        svc2 = WalletService(self.h.store)
        code, view = svc2.post_dkg_stage(
            "w1", "d1", "commit", "n1", None, HASH_A, None
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "commit")

    def test_event_shape_and_details_order(self):
        self._complete()
        events = self._dkg_events()
        self.assertEqual(len(events), 6)
        for event in events:
            self.assertEqual(
                set(event),
                {"seq", "type", "at", "request_id", "actor_id", "reason",
                 "details"},
            )
            self.assertEqual(event["request_id"], "d1")
            self.assertIsNone(event["actor_id"])
            self.assertIsNone(event["reason"])
            # details 恰七键且按 README 既定顺序
            self.assertEqual(
                list(event["details"]),
                ["id", "op", "node", "key", "hash", "peer", "state"],
            )
        first = events[0]["details"]
        self.assertEqual(
            first,
            {"id": "d1", "op": "register", "node": "n1", "key": KEY_A,
             "hash": None, "peer": None, "state": "register"},
        )
        last = events[-1]["details"]
        self.assertEqual(last["op"], "share")
        self.assertEqual(last["state"], "done")

    def test_details_order_on_disk(self):
        self._complete()
        with open(
            os.path.join(self.d, "audit", "w1.json"), encoding="utf-8"
        ) as f:
            log = json.load(f)
        for event in log["events"]:
            if event["type"] == "dkg_stage":
                self.assertEqual(
                    list(event["details"]),
                    ["id", "op", "node", "key", "hash", "peer", "state"],
                )

    def test_contradictory_log_is_fail_closed(self):
        self._complete()
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        # 篡改：commit 的 hash 与 share 确认不一致
        for event in log["events"]:
            if event["type"] == "dkg_stage" and event["details"]["op"] == "commit" and event["details"]["node"] == "n2":
                event["details"]["hash"] = HASH_C
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_tampered_state_field_is_fail_closed(self):
        self._register_pair()
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for event in log["events"]:
            if event["type"] == "dkg_stage":
                event["details"]["state"] = "done"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_skipped_stage_log_is_fail_closed(self):
        self._complete()
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        # 删除第二条 register：后续 commit 变成错阶段序列
        events = [
            e for e in log["events"]
            if not (
                e["type"] == "dkg_stage"
                and e["details"]["op"] == "register"
                and e["details"]["node"] == "n2"
            )
        ]
        for i, event in enumerate(events, 1):
            event["seq"] = i
        log["events"] = events
        log["next_seq"] = len(events) + 1
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    # ---- 灾备 ---------------------------------------------------------------

    def test_backup_restore_keeps_view_and_seq(self):
        self._complete()
        out = os.path.join(tempfile.mkdtemp(), "snap.tar")
        self.addCleanup(shutil.rmtree, os.path.dirname(out), ignore_errors=True)
        body = drbackup.backup(self.d, "w1", "S1", out)
        self.assertEqual(body["status"], 201)
        dst = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, dst, ignore_errors=True)
        status, _ = drbackup.restore(dst, "w1", out)
        self.assertEqual(status, 201)
        svc2 = WalletService(WalletStore(dst))
        view = svc2.get_dkg_session("w1", "d1")
        self.assertEqual(view["state"], "done")
        self.assertEqual(view["public_key"], KEY_A + KEY_B)
        before = self._dkg_events()
        after = [
            e for e in svc2.get_audit_events("w1")["events"]
            if e["type"] == "dkg_stage"
        ]
        self.assertEqual(before, after)
        seqs = [e["seq"] for e in svc2.get_audit_events("w1")["events"]]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))
        # 恢复后可继续重放（幂等 200）
        code, _ = svc2.post_dkg_stage(
            "w1", "d1", "register", "n1", KEY_A, None, None
        )
        self.assertEqual(code, 200)


class DkgHttpTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def test_http_flow_and_body_contract(self):
        with http_server(self.d) as srv:
            code, _ = srv.request(
                "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
            )
            self.assertEqual(code, 201)
            # 缺键/多键一律 400
            code, _ = srv.request(
                "POST", "/v1/dkg/w1/d1", {"op": "register", "node": "n1"}
            )
            self.assertEqual(code, 400)
            body = _body("register", "n1", key=KEY_A)
            body["extra"] = 1
            code, _ = srv.request("POST", "/v1/dkg/w1/d1", body)
            self.assertEqual(code, 400)
            # 完整流程
            code, view = srv.request(
                "POST", "/v1/dkg/w1/d1", _body("register", "n1", key=KEY_A)
            )
            self.assertEqual(code, 201)
            self.assertEqual(view["state"], "register")
            code, view = srv.request(
                "POST", "/v1/dkg/w1/d1", _body("register", "n2", key=KEY_B)
            )
            self.assertEqual(code, 201)
            code, view = srv.request(
                "POST", "/v1/dkg/w1/d1", _body("commit", "n1", hash=HASH_A)
            )
            self.assertEqual(code, 201)
            code, view = srv.request(
                "POST", "/v1/dkg/w1/d1", _body("commit", "n2", hash=HASH_B)
            )
            self.assertEqual(code, 201)
            code, view = srv.request(
                "POST", "/v1/dkg/w1/d1",
                _body("share", "n1", hash=HASH_B, peer="n2"),
            )
            self.assertEqual(code, 201)
            code, view = srv.request(
                "POST", "/v1/dkg/w1/d1",
                _body("share", "n2", hash=HASH_A, peer="n1"),
            )
            self.assertEqual(code, 201)
            self.assertEqual(view["state"], "done")
            code, view = srv.request("GET", "/v1/dkg/w1/d1")
            self.assertEqual(code, 200)
            self.assertEqual(view["public_key"], KEY_A + KEY_B)
            self.assertEqual(
                list(view),
                ["id", "round", "state", "nodes", "committed", "shared",
                 "public_key"],
            )
            self.assertEqual(view["round"], 1)
            # 未知会话/钱包 404；未知路径 404
            code, _ = srv.request("GET", "/v1/dkg/w1/nope")
            self.assertEqual(code, 404)
            code, _ = srv.request("GET", "/v1/dkg/nope/d1")
            self.assertEqual(code, 404)
            code, _ = srv.request("GET", "/v1/dkg/w1")
            self.assertEqual(code, 404)
            code, _ = srv.request("GET", "/v1/dkg/w1/d1/extra")
            self.assertEqual(code, 404)

    def test_http_no_private_key_in_logs(self):
        with http_server(self.d) as srv:
            srv.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
            srv.request(
                "POST", "/v1/dkg/w1/d1", _body("register", "n1", key=KEY_A)
            )
            for line in srv.logs:
                self.assertNotIn(KEY_A, line)
                self.assertNotIn("private", line)


class AuditDetailsOrderTest(unittest.TestCase):
    """session_participant_replaced / session_takeover 的 details 按
    README 既定顺序落盘与查询。"""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.create_sign_session("w1", "s1", "pay-100", 600)

    def _audit_log(self):
        with open(
            os.path.join(self.d, "audit", "w1.json"), encoding="utf-8"
        ) as f:
            return json.load(f)

    def test_replaced_details_order_on_disk_and_query(self):
        self.svc.replace_sign_session_participant("w1", "s1", "r1", "share-2")
        for event in self._audit_log()["events"]:
            if event["type"] == "session_participant_replaced":
                self.assertEqual(
                    list(event["details"]),
                    ["session_id", "old_share_id", "new_share_id"],
                )
        for event in self.svc.get_audit_events("w1")["events"]:
            if event["type"] == "session_participant_replaced":
                self.assertEqual(
                    list(event["details"]),
                    ["session_id", "old_share_id", "new_share_id"],
                )

    def test_takeover_details_order_on_disk_and_query(self):
        self.svc.takeover_sign_session_participant("w1", "s1", "t1", 1, "share-2")
        for event in self._audit_log()["events"]:
            if event["type"] == "session_takeover":
                self.assertEqual(
                    list(event["details"]),
                    ["takeover_id", "stage", "old_share_id", "new_share_id"],
                )
        for event in self.svc.get_audit_events("w1")["events"]:
            if event["type"] == "session_takeover":
                self.assertEqual(
                    list(event["details"]),
                    ["takeover_id", "stage", "old_share_id", "new_share_id"],
                )

    def test_details_order_normalized_on_read(self):
        # 旧现场（details 乱序落盘）读取时归一为 README 既定顺序
        self.svc.replace_sign_session_participant("w1", "s1", "r1", "share-2")
        path = os.path.join(self.d, "audit", "w1.json")
        log = self._audit_log()
        for event in log["events"]:
            if event["type"] == "session_participant_replaced":
                details = event["details"]
                event["details"] = {
                    "new_share_id": details["new_share_id"],
                    "session_id": details["session_id"],
                    "old_share_id": details["old_share_id"],
                }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        svc2 = WalletService(self.h.store)
        for event in svc2.get_audit_events("w1")["events"]:
            if event["type"] == "session_participant_replaced":
                self.assertEqual(
                    list(event["details"]),
                    ["session_id", "old_share_id", "new_share_id"],
                )
        # 追加新事件后落盘也归一为既定顺序
        svc2.put_policy("w1", 1, 600)
        for event in self._audit_log()["events"]:
            if event["type"] == "session_participant_replaced":
                self.assertEqual(
                    list(event["details"]),
                    ["session_id", "old_share_id", "new_share_id"],
                )

    def test_details_order_preserved_through_backup_restore(self):
        self.svc.replace_sign_session_participant("w1", "s1", "r1", "share-2")
        self.svc.takeover_sign_session_participant("w1", "s1", "t1", 1, "share-1")
        out = os.path.join(tempfile.mkdtemp(), "snap.tar")
        self.addCleanup(shutil.rmtree, os.path.dirname(out), ignore_errors=True)
        body = drbackup.backup(self.d, "w1", "S1", out)
        self.assertEqual(body["status"], 201)
        dst = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, dst, ignore_errors=True)
        status, _ = drbackup.restore(dst, "w1", out)
        self.assertEqual(status, 201)
        with open(
            os.path.join(dst, "audit", "w1.json"), encoding="utf-8"
        ) as f:
            log = json.load(f)
        expected = {
            "session_participant_replaced": [
                "session_id", "old_share_id", "new_share_id",
            ],
            "session_takeover": [
                "takeover_id", "stage", "old_share_id", "new_share_id",
            ],
        }
        for event in log["events"]:
            if event["type"] in expected:
                self.assertEqual(
                    list(event["details"]), expected[event["type"]]
                )


if __name__ == "__main__":
    unittest.main()
