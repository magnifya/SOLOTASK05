"""可恢复两方 DKG 的端到端测试（service + HTTP + 恢复/灾备/保序）。"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest

from tests.helpers import http_server, make_harness
from threshold_wallet import drbackup
from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import CorruptDataError, RecoveryError, WalletStore

K1 = "a" * 64
K2 = "b" * 64
K3 = "c" * 64
H1 = hashlib.sha256(b"share-1").hexdigest()
H2 = hashlib.sha256(b"share-2").hexdigest()
VIEW_KEYS = ["id", "state", "nodes", "committed", "shared", "public_key"]
DETAIL_KEYS = ["id", "op", "node", "key", "hash", "peer", "state"]


def _ordered_pairs(text: str):
    return json.loads(text, object_pairs_hook=lambda pairs: pairs)


class DkgServiceTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.h = make_harness(self.d)
        self.h.service.create_wallet("w1", 2)

    def _post(self, dkg_id, op, node, key=None, hash_value=None, peer=None):
        return self.h.service.submit_dkg_stage(
            "w1", dkg_id, op, node, key, hash_value, peer
        )

    def _happy_path(self, dkg_id="run-1"):
        stages = [
            ("register", "n1", K1, None, None),
            ("register", "n2", K2, None, None),
            ("commit", "n1", None, H1, None),
            ("commit", "n2", None, H2, None),
            ("share", "n1", None, H2, "n2"),
            ("share", "n2", None, H1, "n1"),
        ]
        for index, (op, node, key, hv, peer) in enumerate(stages):
            status, view = self._post(dkg_id, op, node, key, hv, peer)
            self.assertEqual(status, 201, (op, node))
        return view

    def test_full_flow_states_and_view(self):
        status, v = self._post("r", "register", "n1", key=K1)
        self.assertEqual((status, v["state"]), (201, "registering"))
        self.assertEqual(v["nodes"], ["n1"])
        self.assertEqual(v["committed"], [])
        self.assertEqual(v["shared"], [])
        self.assertIsNone(v["public_key"])
        self.assertEqual(list(v), VIEW_KEYS)

        _, v = self._post("r", "register", "n2", key=K2)
        self.assertEqual(v["state"], "committing")
        _, v = self._post("r", "commit", "n1", hash_value=H1)
        self.assertEqual((v["state"], v["committed"]), ("committing", ["n1"]))
        _, v = self._post("r", "commit", "n2", hash_value=H2)
        self.assertEqual((v["state"], v["committed"]), ("sharing", ["n1", "n2"]))
        _, v = self._post("r", "share", "n1", hash_value=H2, peer="n2")
        self.assertEqual((v["state"], v["shared"]), ("sharing", ["n1"]))
        _, v = self._post("r", "share", "n2", hash_value=H1, peer="n1")
        self.assertEqual(v["state"], "done")
        self.assertEqual(v["shared"], ["n1", "n2"])
        self.assertEqual(v["public_key"], K1 + K2)
        self.assertEqual(list(v), VIEW_KEYS)

    def test_replay_same_value_200_no_event(self):
        self._happy_path()
        status, v1 = self._post("run-1", "register", "n1", key=K1)
        self.assertEqual(status, 200)
        status, v2 = self._post("run-1", "share", "n2", hash_value=H1, peer="n1")
        self.assertEqual(status, 200)
        self.assertEqual(v2, v1)
        events = [
            e
            for e in self.h.service._audit.list_events("w1")
            if e["type"] == "dkg_stage"
        ]
        self.assertEqual(len(events), 6)

    def test_conflicting_value_409(self):
        self._post("r", "register", "n1", key=K1)
        with self.assertRaises(ServiceError) as ctx:
            self._post("r", "register", "n1", key=K2)
        self.assertEqual(ctx.exception.status, 409)
        self._post("r", "register", "n2", key=K2)
        self._post("r", "commit", "n1", hash_value=H1)
        with self.assertRaises(ServiceError) as ctx:
            self._post("r", "commit", "n1", hash_value=H2)
        self.assertEqual(ctx.exception.status, 409)

    def test_wrong_stage_409(self):
        self._post("r", "register", "n1", key=K1)
        self._post("r", "register", "n2", key=K2)
        # 已过 register 阶段
        with self.assertRaises(ServiceError) as ctx:
            self._post("r", "register", "n3", key=K3)
        self.assertEqual(ctx.exception.status, 409)
        # 尚未 commit 齐不能 share
        self._post("r", "commit", "n1", hash_value=H1)
        with self.assertRaises(ServiceError) as ctx:
            self._post("r", "share", "n1", hash_value=H1, peer="n2")
        self.assertEqual(ctx.exception.status, 409)

    def test_commit_or_share_unknown_flow_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self._post("ghost", "commit", "n1", hash_value=H1)
        self.assertEqual(ctx.exception.status, 404)
        with self.assertRaises(ServiceError) as ctx:
            self._post("ghost", "share", "n1", hash_value=H1, peer="n2")
        self.assertEqual(ctx.exception.status, 404)

    def test_unknown_wallet_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.h.service.submit_dkg_stage(
                "zz", "r", "register", "n1", K1, None, None
            )
        self.assertEqual(ctx.exception.status, 404)
        with self.assertRaises(ServiceError) as ctx:
            self.h.service.get_dkg("zz", "r")
        self.assertEqual(ctx.exception.status, 404)

    def test_get_unknown_process_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.h.service.get_dkg("w1", "nope")
        self.assertEqual(ctx.exception.status, 404)

    def test_invalid_payloads_400(self):
        bad = [
            ("register", "n1", None, None, None),  # key null
            ("register", "n1", "A" * 64, None, None),  # 大写 hex
            ("register", "n1", K1, H1, None),  # hash 非 null
            ("register", "n1", K1, None, "n2"),  # peer 非 null
            ("commit", "n1", None, None, None),  # hash null
            ("commit", "n1", K1, H1, None),  # key 非 null
            ("commit", "n1", None, "x" * 64, None),  # 非 hex 字符
            ("share", "n1", None, None, "n2"),  # 缺 hash
            ("share", "n1", None, H2, None),  # 缺 peer
            ("share", "n1", K1, H2, "n2"),  # key 非 null
        ]
        # 先让流程进入各阶段以便 share 类校验发生在存在的流程上
        self._post("r", "register", "n1", key=K1)
        for op, node, key, hv, peer in bad:
            with self.subTest(payload=(op, key, hv, peer)):
                with self.assertRaises(ServiceError) as ctx:
                    self._post("r", op, node, key=key, hash_value=hv, peer=peer)
                self.assertEqual(ctx.exception.status, 400)
        with self.assertRaises(ServiceError) as ctx:
            self._post("r", "frobnicate", "n1")
        self.assertEqual(ctx.exception.status, 400)
        with self.assertRaises(ServiceError) as ctx:
            self._post("r", "register", "bad node", key=K1)
        self.assertEqual(ctx.exception.status, 400)

    def test_share_peer_rules_409(self):
        self._happy_path_setup_for_share()
        # hash 与 peer 承诺不符
        with self.assertRaises(ServiceError) as ctx:
            self._post("r", "share", "n1", hash_value=H1, peer="n2")
        self.assertEqual(ctx.exception.status, 409)
        # peer 指向自己
        with self.assertRaises(ServiceError) as ctx:
            self._post("r", "share", "n1", hash_value=H1, peer="n1")
        self.assertEqual(ctx.exception.status, 409)
        # peer 未注册
        with self.assertRaises(ServiceError) as ctx:
            self._post("r", "share", "n1", hash_value=H1, peer="n3")
        self.assertEqual(ctx.exception.status, 409)

    def _happy_path_setup_for_share(self):
        self._post("r", "register", "n1", key=K1)
        self._post("r", "register", "n2", key=K2)
        self._post("r", "commit", "n1", hash_value=H1)
        self._post("r", "commit", "n2", hash_value=H2)

    def test_persistence_across_restart(self):
        self._happy_path()
        h2 = make_harness(self.d)
        view = h2.service.get_dkg("w1", "run-1")
        self.assertEqual(view["state"], "done")
        self.assertEqual(view["public_key"], K1 + K2)
        events = [
            e for e in h2.service._audit.list_events("w1")
            if e["type"] == "dkg_stage"
        ]
        self.assertEqual(len(events), 6)
        # 恢复不新增事件：再查询一次
        h2.service.get_dkg("w1", "run-1")
        events2 = [
            e for e in h2.service._audit.list_events("w1")
            if e["type"] == "dkg_stage"
        ]
        self.assertEqual(events, events2)

    def test_midflow_continues_after_restart(self):
        self._post("r", "register", "n1", key=K1)
        self._post("r", "register", "n2", key=K2)
        self._post("r", "commit", "n1", hash_value=H1)
        h2 = make_harness(self.d)
        _, v = h2.service.submit_dkg_stage(
            "w1", "r", "commit", "n2", None, H2, None
        )
        self.assertEqual(v["state"], "sharing")

    def test_event_details_null_for_unused_values(self):
        self._happy_path()
        events = {
            (e["details"]["op"], e["details"]["node"]): e["details"]
            for e in self.h.service._audit.list_events("w1")
            if e["type"] == "dkg_stage"
        }
        reg = events[("register", "n1")]
        self.assertEqual(reg["key"], K1)
        self.assertIsNone(reg["hash"])
        self.assertIsNone(reg["peer"])
        com = events[("commit", "n1")]
        self.assertIsNone(com["key"])
        self.assertEqual(com["hash"], H1)
        self.assertIsNone(com["peer"])
        shr = events[("share", "n1")]
        self.assertIsNone(shr["key"])
        self.assertEqual(shr["hash"], H2)
        self.assertEqual(shr["peer"], "n2")

    def test_no_share_or_private_material_in_dkg_file(self):
        self._happy_path()
        raw = open(os.path.join(self.d, "dkg", "w1.json"), "rb").read()
        text = raw.decode("utf-8")
        self.assertNotIn("share-1", text)  # 链下份额正文标识不出现
        self.assertNotIn("private", text)
        self.assertNotIn(b"share-2", raw)

    def test_audit_details_key_order_on_disk_and_query(self):
        self._happy_path()
        raw = open(os.path.join(self.d, "audit", "w1.json"), encoding="utf-8").read()
        pairs = _ordered_pairs(raw)
        top = pairs  # 顶层
        # 找到第一条 dkg_stage 事件，校验七字段与 details 键序
        for key, value in top:
            if key == "events":
                event_pairs = value
                break
        else:
            self.fail("no events")
        dkg_events = [
            ep for ep in event_pairs
            if dict(ep).get("type") == "dkg_stage"
        ]
        self.assertTrue(dkg_events)
        self.assertEqual(
            [k for k, _ in dkg_events[0]],
            ["seq", "type", "at", "request_id", "actor_id", "reason", "details"],
        )
        details_pairs = dict(dkg_events[0])["details"]
        self.assertEqual([k for k, _ in details_pairs], DETAIL_KEYS)
        # 查询路径同样保序
        queried = self.h.service.get_audit_events("w1")["events"]
        first_dkg = next(e for e in queried if e["type"] == "dkg_stage")
        self.assertEqual(list(first_dkg), [
            "seq", "type", "at", "request_id", "actor_id", "reason", "details"
        ])
        self.assertEqual(list(first_dkg["details"]), DETAIL_KEYS)

    def test_crash_window_rolls_forward_then_shape_corruption_503(self):
        self._happy_path()
        path = os.path.join(self.d, "dkg", "w1.json")
        data = json.loads(open(path, encoding="utf-8").read())
        # 形状合法但落后于已提交事件（崩溃窗口：第二份 share 事件已落盘、
        # 状态尚未更新）：恢复按提交点事件前滚纠正，不 503。
        del data["run-1"]["peers"]["n2"]
        data["run-1"]["state"] = "sharing"
        data["run-1"]["public_key"] = None
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        h2 = make_harness(self.d)
        self.assertEqual(h2.service.get_dkg("w1", "run-1")["state"], "done")

        # 形状损坏：fail-closed
        data["run-1"]["state"] = "bogus"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        with self.assertRaises((RecoveryError, CorruptDataError)):
            WalletService(WalletStore(self.d))

    def test_uncommitted_record_rolled_back(self):
        # 直接写业务记录但无事件：恢复必须删除（register 未提交）
        self._post("r", "register", "n1", key=K1)
        path = os.path.join(self.d, "dkg", "w1.json")
        data = json.loads(open(path, encoding="utf-8").read())
        data["zombie"] = {
            "id": "zombie",
            "state": "registering",
            "nodes": ["x"],
            "keys": {"x": K3},
            "hashes": {},
            "peers": {},
            "public_key": None,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        h2 = make_harness(self.d)
        with self.assertRaises(ServiceError) as ctx:
            h2.service.get_dkg("w1", "zombie")
        self.assertEqual(ctx.exception.status, 404)
        # 正常流程仍在
        self.assertEqual(h2.service.get_dkg("w1", "r")["state"], "registering")

    def test_corrupt_event_sequence_fails_closed(self):
        self._happy_path()
        path = os.path.join(self.d, "audit", "w1.json")
        log = json.loads(open(path, encoding="utf-8").read())
        # 制造第三节点注册事件（在末尾追加，破坏两方 DKG 语义）
        last = log["events"][-1]
        bogus = dict(last)
        bogus["seq"] = log["next_seq"]
        bogus["details"] = {
            "id": "run-1", "op": "register", "node": "n3",
            "key": K3, "hash": None, "peer": None, "state": "committing",
        }
        log["events"].append(bogus)
        log["next_seq"] += 1
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.d))


class DkgHttpTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def test_http_routes_and_body_key_order(self):
        with http_server(self.d) as srv:
            status, _ = srv.request("POST", "/v1/wallets",
                                   {"wallet_id": "w1", "shares": 2})
            self.assertEqual(status, 201)
            stages = [
                ("register", "n1", K1, None, None),
                ("register", "n2", K2, None, None),
                ("commit", "n1", None, H1, None),
                ("commit", "n2", None, H2, None),
                ("share", "n1", None, H2, "n2"),
                ("share", "n2", None, H1, "n1"),
            ]
            for index, (op, node, key, hv, peer) in enumerate(stages):
                status, body = srv.request(
                    "POST", "/v1/dkg/w1/run-1",
                    {"op": op, "node": node, "key": key,
                     "hash": hv, "peer": peer},
                )
                self.assertEqual(status, 201, body)
                self.assertEqual(list(body), VIEW_KEYS)
            # 同值重放 200
            status, body = srv.request(
                "POST", "/v1/dkg/w1/run-1",
                {"op": "register", "node": "n1", "key": K1,
                 "hash": None, "peer": None},
            )
            self.assertEqual(status, 200)
            # GET
            status, body = srv.request("GET", "/v1/dkg/w1/run-1")
            self.assertEqual(status, 200)
            self.assertEqual(list(body), VIEW_KEYS)
            self.assertEqual(body["public_key"], K1 + K2)

    def test_http_status_codes(self):
        with http_server(self.d) as srv:
            srv.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
            # 钱包 404
            status, _ = srv.request(
                "POST", "/v1/dkg/zz/r",
                {"op": "register", "node": "n1", "key": K1,
                 "hash": None, "peer": None},
            )
            self.assertEqual(status, 404)
            # 未知流程 commit 404
            status, _ = srv.request(
                "POST", "/v1/dkg/w1/ghost",
                {"op": "commit", "node": "n1", "key": None,
                 "hash": H1, "peer": None},
            )
            self.assertEqual(status, 404)
            status, _ = srv.request("GET", "/v1/dkg/w1/ghost")
            self.assertEqual(status, 404)
            # 多余键 400
            status, _ = srv.request(
                "POST", "/v1/dkg/w1/r",
                {"op": "register", "node": "n1", "key": K1,
                 "hash": None, "peer": None, "extra": 1},
            )
            self.assertEqual(status, 400)
            # 缺键 400
            status, _ = srv.request(
                "POST", "/v1/dkg/w1/r",
                {"op": "register", "node": "n1", "key": K1, "hash": None},
            )
            self.assertEqual(status, 400)
            # 非对象路径 404
            status, _ = srv.request("GET", "/v1/dkg/w1")
            self.assertEqual(status, 404)

    def test_http_conflict_and_invalid(self):
        with http_server(self.d) as srv:
            srv.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
            srv.request(
                "POST", "/v1/dkg/w1/r",
                {"op": "register", "node": "n1", "key": K1,
                 "hash": None, "peer": None},
            )
            status, _ = srv.request(
                "POST", "/v1/dkg/w1/r",
                {"op": "register", "node": "n1", "key": K2,
                 "hash": None, "peer": None},
            )
            self.assertEqual(status, 409)
            status, _ = srv.request(
                "POST", "/v1/dkg/w1/r",
                {"op": "register", "node": "n1", "key": "bad",
                 "hash": None, "peer": None},
            )
            self.assertEqual(status, 400)


class ParticipantEventOrderTest(unittest.TestCase):
    """session_participant_replaced / session_takeover 的 details 保序。"""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.h = make_harness(self.d)
        self.h.service.create_wallet("w1", 2)
        self.h.service.create_sign_session("w1", "sess-rp", "hi", 600)
        self.h.service.create_sign_session("w1", "sess-tk", "hi", 600)

    def test_replaced_details_order(self):
        self.h.service.replace_sign_session_participant(
            "w1", "sess-rp", "rp1", "share-1"
        )
        raw = open(os.path.join(self.d, "audit", "w1.json"), encoding="utf-8").read()
        ev = next(
            e for e in json.loads(raw)["events"]
            if e["type"] == "session_participant_replaced"
        )
        self.assertEqual(
            list(ev["details"]),
            ["session_id", "old_share_id", "new_share_id"],
        )

    def test_takeover_details_order(self):
        self.h.service.takeover_sign_session_participant(
            "w1", "sess-tk", "tk1", 1, "share-1"
        )
        raw = open(os.path.join(self.d, "audit", "w1.json"), encoding="utf-8").read()
        ev = next(
            e for e in json.loads(raw)["events"]
            if e["type"] == "session_takeover"
        )
        self.assertEqual(
            list(ev["details"]),
            ["takeover_id", "stage", "old_share_id", "new_share_id"],
        )


class DkgBackupRestoreTest(unittest.TestCase):
    def setUp(self):
        self.src = tempfile.mkdtemp()
        self.dst = tempfile.mkdtemp()
        self.out = tempfile.mkdtemp()
        self.h = make_harness(self.src)
        self.h.service.create_wallet("w1", 2)

    def _complete(self, service):
        for args in [
            ("register", "n1", K1, None, None),
            ("register", "n2", K2, None, None),
            ("commit", "n1", None, H1, None),
            ("commit", "n2", None, H2, None),
            ("share", "n1", None, H2, "n2"),
            ("share", "n2", None, H1, "n1"),
        ]:
            service.submit_dkg_stage("w1", "run-1", *args)

    def test_backup_restore_preserves_dkg(self):
        self._complete(self.h.service)
        snap = os.path.join(self.out, "a.tar")
        result = drbackup.backup(self.src, "w1", "snap-1", snap)
        self.assertEqual(result["status"], 201)
        self.assertIn("dkg/w1.json", [f["path"] for f in result["manifest"]["files"]])
        status, body = drbackup.restore(self.dst, "w1", snap)
        self.assertEqual(status, 201)
        restored = WalletService(WalletStore(self.dst))
        view = restored.get_dkg("w1", "run-1")
        self.assertEqual(view["state"], "done")
        self.assertEqual(view["public_key"], K1 + K2)
        # seq 与视图灾备后不变
        src_events = [
            e for e in self.h.service._audit.list_events("w1")
            if e["type"] == "dkg_stage"
        ]
        dst_events = [
            e for e in restored._audit.list_events("w1")
            if e["type"] == "dkg_stage"
        ]
        self.assertEqual([e["seq"] for e in src_events],
                         [e["seq"] for e in dst_events])
        self.assertEqual(
            [list(e["details"]) for e in dst_events],
            [DETAIL_KEYS] * 6,
        )

    def test_midflow_backup_restore_and_continue(self):
        self.h.service.submit_dkg_stage(
            "w1", "r", "register", "n1", K1, None, None
        )
        snap = os.path.join(self.out, "b.tar")
        self.assertEqual(drbackup.backup(self.src, "w1", "s2", snap)["status"], 201)
        status, _ = drbackup.restore(self.dst, "w1", snap)
        self.assertEqual(status, 201)
        restored = WalletService(WalletStore(self.dst))
        view = restored.get_dkg("w1", "r")
        self.assertEqual((view["state"], view["nodes"]), ("registering", ["n1"]))
        restored.submit_dkg_stage(
            "w1", "r", "register", "n2", K2, None, None
        )


if __name__ == "__main__":
    unittest.main()
