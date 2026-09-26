"""dkg_failover 审计语义漏检的 fail-closed 回归。

覆盖「审计事件」对 DKG 故障轮次恢复规则的公开契约：

- dkg_failover details 键序手工七键
  id,round,action,node,replacement,key,state（自动替补末加 mode 八键），
  落盘错序即 RecoveryError——绝不先归一抹平；
- dkg_failover **外层**七字段键序为落盘规范序
  actor_id,at,details,reason,request_id,seq,type，重排即 RecoveryError；
- abort 的 state 只能 aborted、手工/自动 replace 与 reinstate 只能 commit，
  以及轮次链/节点/健康表/rejoin/审批的上下文矛盾，启动与审计查询均按既有
  DKG 恢复规则重放并 fail-closed；
- 合法 JSON 中任一状态或上下文矛盾抛 RecoveryError；坏 JSON 抛
  CorruptDataError；审计文件 I/O 失败抛 OSError——三者在
  GET /v1/wallets/{W}/audit-events 均为 503、紧凑 UTF-8 单行
  {"error":...}；
- 失败保留审计文件原样、不写盘、不分配 seq、不返回部分结果；
- 成功体键序 wallet_id,events、事件按 seq 升序；dkg_failover 公开外层序
  seq,type,at,request_id,actor_id,reason,details，分页契约不变。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
import urllib.error
import urllib.request

from tests.helpers import http_server, make_harness
from threshold_wallet.service import WalletService
from threshold_wallet.store import CorruptDataError, RecoveryError, WalletStore

KEY_A = "aa" * 32
KEY_B = "bb" * 32
KEY_C = "cc" * 32
HASH_A = "11" * 32
HASH_B = "22" * 32

OUTER_CANONICAL = [
    "actor_id", "at", "details", "reason", "request_id", "seq", "type",
]
DETAILS_MANUAL = [
    "id", "round", "action", "node", "replacement", "key", "state",
]
DETAILS_AUTO = DETAILS_MANUAL + ["mode"]
PUBLIC_OUTER = [
    "seq", "type", "at", "request_id", "actor_id", "reason", "details",
]


class _DkgFailoverAuditBase(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)

    @property
    def _audit_path(self) -> str:
        return os.path.join(self.d, "audit", "w1.json")

    def _load(self) -> dict:
        with open(self._audit_path, encoding="utf-8") as f:
            return json.load(f)

    def _dump(self, log: dict) -> None:
        with open(self._audit_path, "w", encoding="utf-8") as f:
            json.dump(log, f)

    def _raw_bytes(self) -> bytes:
        with open(self._audit_path, "rb") as f:
            return f.read()

    def _register_commit_pair(self, did="d1") -> None:
        for node, key in (("n1", KEY_A), ("n2", KEY_B)):
            code, _ = self.svc.post_dkg_stage(
                "w1", did, "register", node, key, None, None
            )
            self.assertEqual(code, 201)
        for node, h in (("n1", HASH_A), ("n2", HASH_B)):
            code, _ = self.svc.post_dkg_stage(
                "w1", did, "commit", node, None, h, None
            )
            self.assertEqual(code, 201)

    def _manual_replace(self, did="d1", round_no=2) -> None:
        code, _ = self.svc.post_dkg_failover(
            "w1", did, round_no, "replace", "n2", "n3", KEY_C
        )
        self.assertEqual(code, 201)

    def _auto_replace(self, did="d1", round_no=2) -> None:
        # n2 down、n3 up：自动替补选 n3 写实值，事件 details 末加 mode。
        self.svc.put_dkg_nodes(
            "w1",
            {
                "n1": {"key": KEY_A, "state": "up"},
                "n2": {"key": KEY_B, "state": "down"},
                "n3": {"key": KEY_C, "state": "up"},
            },
        )
        code, _ = self.svc.post_dkg_failover(
            "w1", did, round_no, "replace", "n2", None, None
        )
        self.assertEqual(code, 201)

    def _abort(self, did="d1", round_no=2) -> None:
        code, _ = self.svc.post_dkg_failover(
            "w1", did, round_no, "abort", None, None, None
        )
        self.assertEqual(code, 201)

    def _only_failover(self, log: dict) -> dict:
        matches = [
            e for e in log["events"] if e["type"] == "dkg_failover"
        ]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def _tamper_failover(self, mutate) -> None:
        log = self._load()
        mutate(self._only_failover(log))
        self._dump(log)

    @staticmethod
    def _reorder(container: dict, order: list) -> None:
        rebuilt = {key: container[key] for key in order}
        container.clear()
        container.update(rebuilt)


# ---- 启动恢复：错序/矛盾一律阻止就绪 ---------------------------------------


class DkgFailoverStartupRejectTest(_DkgFailoverAuditBase):
    def _assert_blocks_startup(self) -> None:
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_manual_details_out_of_order_blocks(self):
        self._register_commit_pair()
        self._manual_replace()
        bad_order = ["state", "key", "replacement", "node", "action",
                     "round", "id"]

        def mutate(ev):
            ev["details"] = {k: ev["details"][k] for k in bad_order}

        self._tamper_failover(mutate)
        self._assert_blocks_startup()

    def test_auto_details_out_of_order_blocks(self):
        self._register_commit_pair()
        self._auto_replace()
        # mode 不在末位即违反既有七键加末键 mode 的落盘契约。
        bad_order = ["mode", "id", "round", "action", "node",
                     "replacement", "key", "state"]

        def mutate(ev):
            ev["details"] = {k: ev["details"][k] for k in bad_order}

        self._tamper_failover(mutate)
        self._assert_blocks_startup()

    def test_outer_fields_out_of_order_blocks(self):
        self._register_commit_pair()
        self._manual_replace()

        def mutate(ev):
            self._reorder(
                ev,
                ["seq", "type", "at", "request_id", "actor_id", "reason",
                 "details"],
            )

        self._tamper_failover(mutate)
        self._assert_blocks_startup()

    def test_abort_state_commit_blocks(self):
        self._register_commit_pair()
        self._abort()
        self._tamper_failover(lambda ev: ev["details"].__setitem__(
            "state", "commit"))
        self._assert_blocks_startup()

    def test_replace_state_aborted_blocks(self):
        self._register_commit_pair()
        self._manual_replace()
        self._tamper_failover(lambda ev: ev["details"].__setitem__(
            "state", "aborted"))
        self._assert_blocks_startup()

    def test_bad_json_blocks_as_corrupt(self):
        self._register_commit_pair()
        self._manual_replace()
        with open(self._audit_path, "w", encoding="utf-8") as f:
            f.write("{broken")
        # 审计读取层：坏 JSON 即 CorruptDataError
        with self.assertRaises(CorruptDataError):
            self.h.service._audit.check_log("w1")
        # 启动恢复统一以 RecoveryError 阻止就绪（与既有损坏现场约定一致）
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_healthy_scene_still_recovers_with_canonical_orders(self):
        self._register_commit_pair()
        self._manual_replace()
        log = self._load()
        stored = self._only_failover(log)
        self.assertEqual(list(stored), OUTER_CANONICAL)
        self.assertEqual(list(stored["details"]), DETAILS_MANUAL)
        # 健康现场重启不报错、不新增事件
        before = self.svc.get_audit_events("w1")["events"]
        svc2 = WalletService(self.h.store)
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)


# ---- 审计查询：与启动同一套 DKG 重放 ---------------------------------------


class DkgFailoverAuditQueryReplayTest(_DkgFailoverAuditBase):
    def _query(self):
        return self.svc.get_audit_events("w1")

    def test_query_replays_and_rejects_manual_details_reorder(self):
        self._register_commit_pair()
        self._manual_replace()
        bad_order = ["state", "key", "replacement", "node", "action",
                     "round", "id"]
        self._tamper_failover(
            lambda ev: ev.__setitem__(
                "details",
                {k: ev["details"][k] for k in bad_order},
            )
        )
        with self.assertRaises(RecoveryError):
            self._query()

    def test_query_replays_and_rejects_auto_details_reorder(self):
        self._register_commit_pair()
        self._auto_replace()
        bad_order = ["id", "round", "action", "node", "replacement",
                     "key", "mode", "state"]
        self._tamper_failover(
            lambda ev: ev.__setitem__(
                "details",
                {k: ev["details"][k] for k in bad_order},
            )
        )
        with self.assertRaises(RecoveryError):
            self._query()

    def test_query_replays_and_rejects_outer_reorder(self):
        self._register_commit_pair()
        self._manual_replace()
        self._tamper_failover(
            lambda ev: self._reorder(
                ev,
                ["seq", "type", "at", "request_id", "actor_id", "reason",
                 "details"],
            )
        )
        with self.assertRaises(RecoveryError):
            self._query()

    def test_query_rejects_state_context_contradiction(self):
        self._register_commit_pair()
        self._manual_replace()
        # replace 派生轮回到 commit：state=done 与轮次/动作矛盾。
        self._tamper_failover(lambda ev: ev["details"].__setitem__(
            "state", "done"))
        with self.assertRaises(RecoveryError):
            self._query()

    def test_query_bad_json_is_corrupt(self):
        self._register_commit_pair()
        self._manual_replace()
        with open(self._audit_path, "w", encoding="utf-8") as f:
            f.write("{broken")
        with self.assertRaises(CorruptDataError):
            self._query()

    def test_query_io_error_propagates_as_oserror(self):
        self._register_commit_pair()
        self._manual_replace()
        os.remove(self._audit_path)
        os.mkdir(self._audit_path)
        try:
            with self.assertRaises(OSError):
                self._query()
        finally:
            os.rmdir(self._audit_path)

    def test_failure_preserves_bytes_and_allocates_no_seq(self):
        self._register_commit_pair()
        self._manual_replace()
        log = self._load()
        n_before = len(log["events"])
        next_before = log["next_seq"]
        self._tamper_failover(lambda ev: self._reorder(
            ev,
            ["seq", "type", "at", "request_id", "actor_id", "reason",
             "details"],
        ))
        raw_before = self._raw_bytes()
        with self.assertRaises(RecoveryError):
            self._query()
        # 查询失败：文件原样保留、不写盘、不分配 seq
        self.assertEqual(self._raw_bytes(), raw_before)
        after = self._load()
        self.assertEqual(len(after["events"]), n_before)
        self.assertEqual(after["next_seq"], next_before)

    def test_success_envelope_and_orders(self):
        self._register_commit_pair()
        self._manual_replace()
        body = self._query()
        # 成功体键序 wallet_id,events；事件按 seq 升序
        self.assertEqual(list(body), ["wallet_id", "events"])
        self.assertEqual(body["wallet_id"], "w1")
        seqs = [e["seq"] for e in body["events"]]
        self.assertEqual(seqs, sorted(seqs))
        failover = [e for e in body["events"]
                    if e["type"] == "dkg_failover"]
        self.assertEqual(len(failover), 1)
        self.assertEqual(list(failover[0]), PUBLIC_OUTER)
        self.assertEqual(list(failover[0]["details"]), DETAILS_MANUAL)
        self.assertEqual(
            failover[0]["details"],
            {"id": "d1", "round": 2, "action": "replace", "node": "n2",
             "replacement": "n3", "key": KEY_C, "state": "commit"},
        )

    def test_auto_success_details_eight_keys_mode_last(self):
        self._register_commit_pair()
        self._auto_replace()
        (failover,) = [
            e for e in self._query()["events"]
            if e["type"] == "dkg_failover"
        ]
        self.assertEqual(list(failover), PUBLIC_OUTER)
        self.assertEqual(list(failover["details"]), DETAILS_AUTO)
        self.assertEqual(failover["details"]["mode"], "auto")
        self.assertEqual(failover["details"]["replacement"], "n3")
        self.assertEqual(failover["details"]["key"], KEY_C)
        self.assertIsNone(failover["actor_id"])

    def test_pagination_unchanged_after_replay(self):
        self._register_commit_pair()
        self._manual_replace()
        full = self._query()["events"]
        failover_seq = next(
            e["seq"] for e in full if e["type"] == "dkg_failover"
        )
        page = self.svc.get_audit_events(
            "w1", from_seq=failover_seq, limit=1
        )
        self.assertEqual([e["seq"] for e in page["events"]], [failover_seq])
        self.assertEqual(page["events"][0]["type"], "dkg_failover")


# ---- HTTP：三类错误均为 503、紧凑 UTF-8 单行、无部分结果 ------------------


class DkgFailoverAuditHttpTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    audit_path = property(
        lambda self: os.path.join(self.d, "audit", "w1.json")
    )

    def _raw_get(self, srv, path):
        req = urllib.request.Request(srv.base_url + path)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def _prepare(self, srv, auto=False):
        srv.request(
            "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
        )
        for node, key in (("n1", KEY_A), ("n2", KEY_B)):
            srv.request(
                "POST", "/v1/dkg/w1/d1",
                {"op": "register", "node": node, "key": key,
                 "hash": None, "peer": None},
            )
        for node, h in (("n1", HASH_A), ("n2", HASH_B)):
            srv.request(
                "POST", "/v1/dkg/w1/d1",
                {"op": "commit", "node": node, "key": None,
                 "hash": h, "peer": None},
            )
        if auto:
            srv.request(
                "PUT", "/v1/wallets/w1/nodes",
                {"nodes": {
                    "n1": {"key": KEY_A, "state": "up"},
                    "n2": {"key": KEY_B, "state": "down"},
                    "n3": {"key": KEY_C, "state": "up"},
                }},
            )
            code, _ = srv.request(
                "POST", "/v1/dkg/w1/d1/failover",
                {"round": 2, "action": "replace", "node": "n2",
                 "replacement": None, "key": None},
            )
        else:
            code, _ = srv.request(
                "POST", "/v1/dkg/w1/d1/failover",
                {"round": 2, "action": "replace", "node": "n2",
                 "replacement": "n3", "key": KEY_C},
            )
        self.assertEqual(code, 201)

    def _tamper(self, mutate):
        path = self.audit_path
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        failover = next(e for e in log["events"]
                        if e["type"] == "dkg_failover")
        mutate(failover)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)

    def _assert_503_compact(self, status, raw):
        self.assertEqual(status, 503)
        # 紧凑 UTF-8、单行、无末换行
        self.assertEqual(raw.count(b"\n"), 0)
        self.assertNotIn(b": ", raw)
        self.assertNotIn(b", ", raw)
        self.assertFalse(raw.endswith(b"\n"))
        self.assertEqual(
            json.loads(raw.decode("utf-8")),
            {"error": "service temporarily unavailable"},
        )
        # 不返回部分结果
        self.assertNotIn(b"events", raw)

    def test_outer_reorder_is_503_compact(self):
        with http_server(self.d) as srv:
            self._prepare(srv)
            path = self.audit_path
            with open(path, encoding="utf-8") as f:
                log = json.load(f)
            ev = next(e for e in log["events"]
                      if e["type"] == "dkg_failover")
            rebuilt = {k: ev[k] for k in [
                "seq", "type", "at", "request_id", "actor_id", "reason",
                "details",
            ]}
            ev.clear()
            ev.update(rebuilt)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(log, f)
            status, raw = self._raw_get(
                srv, "/v1/wallets/w1/audit-events"
            )
            self._assert_503_compact(status, raw)

    def test_details_reorder_is_503_compact(self):
        with http_server(self.d) as srv:
            self._prepare(srv)
            self._tamper(lambda ev: ev.__setitem__(
                "details",
                {k: ev["details"][k] for k in [
                    "state", "key", "replacement", "node", "action",
                    "round", "id",
                ]},
            ))
            status, raw = self._raw_get(
                srv, "/v1/wallets/w1/audit-events"
            )
            self._assert_503_compact(status, raw)

    def test_auto_details_reorder_is_503_compact(self):
        with http_server(self.d) as srv:
            self._prepare(srv, auto=True)
            self._tamper(lambda ev: ev.__setitem__(
                "details",
                {k: ev["details"][k] for k in [
                    "id", "round", "action", "node", "replacement", "key",
                    "mode", "state",
                ]},
            ))
            status, raw = self._raw_get(
                srv, "/v1/wallets/w1/audit-events"
            )
            self._assert_503_compact(status, raw)

    def test_state_contradiction_is_503_compact(self):
        with http_server(self.d) as srv:
            self._prepare(srv)
            self._tamper(lambda ev: ev["details"].__setitem__(
                "state", "aborted"))
            status, raw = self._raw_get(
                srv, "/v1/wallets/w1/audit-events"
            )
            self._assert_503_compact(status, raw)

    def test_bad_json_is_503_compact(self):
        with http_server(self.d) as srv:
            self._prepare(srv)
            with open(self.audit_path, "w", encoding="utf-8") as f:
                f.write("{broken")
            status, raw = self._raw_get(
                srv, "/v1/wallets/w1/audit-events"
            )
            self._assert_503_compact(status, raw)

    def test_io_error_is_503_compact(self):
        with http_server(self.d) as srv:
            self._prepare(srv)
            os.remove(self.audit_path)
            os.mkdir(self.audit_path)
            try:
                status, raw = self._raw_get(
                    srv, "/v1/wallets/w1/audit-events"
                )
                self._assert_503_compact(status, raw)
            finally:
                if os.path.isdir(self.audit_path):
                    shutil.rmtree(self.audit_path)

    def _raw_bytes(self) -> bytes:
        with open(self.audit_path, "rb") as f:
            return f.read()

    def test_failure_preserves_audit_file(self):
        with http_server(self.d) as srv:
            self._prepare(srv)
            self._tamper(lambda ev: ev["details"].__setitem__(
                "state", "done"))
            raw_before = self._raw_bytes()
            status, raw = self._raw_get(
                srv, "/v1/wallets/w1/audit-events"
            )
            self.assertEqual(status, 503)
            self.assertEqual(self._raw_bytes(), raw_before)

    def test_success_body_order_and_compact_wire(self):
        with http_server(self.d) as srv:
            self._prepare(srv)
            status, raw = self._raw_get(
                srv, "/v1/wallets/w1/audit-events"
            )
            self.assertEqual(status, 200)
            self.assertTrue(
                raw.startswith(b'{"wallet_id":"w1","events":[')
            )
            body = json.loads(raw)
            self.assertEqual(list(body), ["wallet_id", "events"])
            failover = next(e for e in body["events"]
                            if e["type"] == "dkg_failover")
            self.assertEqual(list(failover), PUBLIC_OUTER)
            self.assertEqual(list(failover["details"]), DETAILS_MANUAL)


if __name__ == "__main__":
    unittest.main()
