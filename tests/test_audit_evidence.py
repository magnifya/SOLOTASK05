"""区间逐条摘要证据 GET /v1/wallets/{id}/audit-evidence 的回归测试。

覆盖：
- 成功体八字段形状：wallet_id/range/events/event_digests/start_head/
  end_head/count/state；events 按 seq 升序且与 audit-events 公开视图一致
  （不含份额私钥等中间值）；event_digests 按既有七字段摘要规则与 events
  一一对应；
- start_head 为 from_seq 前一事件后的链头（from_seq=1 时为 64 个零），
  end_head 可由 start_head + event_digests 按既有递推规则复算，并与
  audit-integrity 的全链头在覆盖全区间时一致；
- 纯只读：不分配 seq、不改状态、不写审计文件；追加事件后以旧 end_head
  作为 expected_head 查询旧区间仍 200；
- 400（缺参/重复/from_seq 非法/to_seq 非法/expected_head 格式/范围非法）、
  404（钱包不存在/空钱包/to_seq 越界）、405（非 GET）、409（expected_head
  不匹配）、503（审计被篡改不可对账）。
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import unittest

from tests.helpers import http_server
from threshold_wallet import audit as audit_mod
from threshold_wallet.service import WalletService
from threshold_wallet.store import WalletStore


def _audit_path(data_dir: str, wallet_id: str = "w1") -> str:
    return os.path.join(data_dir, "audit", wallet_id + ".json")


def _load_audit(data_dir: str, wallet_id: str = "w1") -> dict:
    with open(_audit_path(data_dir, wallet_id), encoding="utf-8") as f:
        return json.load(f)


def _dump_audit(data_dir: str, data: dict, wallet_id: str = "w1") -> None:
    with open(_audit_path(data_dir, wallet_id), "w", encoding="utf-8") as f:
        json.dump(data, f)


def _replay(start_head: str, digests: list[str]) -> str:
    head = start_head
    for digest in digests:
        head = hashlib.sha256((head + digest).encode("ascii")).hexdigest()
    return head


class AuditEvidenceHttpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _three_events(self, srv) -> None:
        srv.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
        srv.request(
            "PUT",
            "/v1/wallets/w1/approval-policy",
            {"required_approvals": 1, "timeout_seconds": 60},
        )
        srv.request(
            "PUT",
            "/v1/wallets/w1/approval-policy",
            {"required_approvals": 2, "timeout_seconds": 120},
        )
        srv.request(
            "PUT",
            "/v1/wallets/w1/dkg-failover-policy",
            {"enabled": True},
        )

    def _evidence(self, srv, path_extra: str = ""):
        return srv.request(
            "GET",
            "/v1/wallets/w1/audit-evidence?from_seq=1&to_seq=3"
            + path_extra,
            None,
        )

    def test_success_shape_and_chain_recompute(self):
        with http_server(self.tmp) as srv:
            self._three_events(srv)
            status, body = self._evidence(srv)
            self.assertEqual(status, 200, body)
            self.assertEqual(
                set(body),
                {
                    "wallet_id",
                    "range",
                    "events",
                    "event_digests",
                    "start_head",
                    "end_head",
                    "count",
                    "state",
                },
            )
            self.assertEqual(body["wallet_id"], "w1")
            self.assertEqual(
                body["range"], {"from_seq": 1, "to_seq": 3}
            )
            self.assertEqual(body["count"], 3)
            self.assertEqual(body["state"], "valid")
            self.assertEqual([e["seq"] for e in body["events"]], [1, 2, 3])
            self.assertEqual(
                len(body["event_digests"]), len(body["events"])
            )
            self.assertEqual(body["start_head"], "0" * 64)
            # 逐条摘要按既有七字段摘要规则，与公开 events 一一对应
            for event, digest in zip(body["events"], body["event_digests"]):
                self.assertEqual(audit_mod._event_digest(event), digest)
            # end_head 可由 start_head 与逐条摘要按既有递推规则复算
            self.assertEqual(
                body["end_head"],
                _replay(body["start_head"], body["event_digests"]),
            )
            # 覆盖全区间时 end_head 即 audit-integrity 的全链头
            status, integrity = srv.request(
                "GET", "/v1/wallets/w1/audit-integrity", None
            )
            self.assertEqual(status, 200, integrity)
            self.assertEqual(integrity["head"], body["end_head"])
            self.assertEqual(integrity["count"], 3)

    def test_subrange_start_head_is_prior_head(self):
        with http_server(self.tmp) as srv:
            self._three_events(srv)
            status, sub = srv.request(
                "GET",
                "/v1/wallets/w1/audit-evidence?from_seq=2&to_seq=3",
                None,
            )
            self.assertEqual(status, 200, sub)
            self.assertEqual([e["seq"] for e in sub["events"]], [2, 3])
            self.assertEqual(sub["count"], 2)
            # start_head 等于仅含事件 1 时的链头
            status, first = srv.request(
                "GET",
                "/v1/wallets/w1/audit-evidence?from_seq=1&to_seq=1",
                None,
            )
            self.assertEqual(status, 200, first)
            self.assertEqual(sub["start_head"], first["end_head"])
            self.assertEqual(
                sub["end_head"],
                _replay(sub["start_head"], sub["event_digests"]),
            )
            # 单事件区间 [2,2]
            status, only2 = srv.request(
                "GET",
                "/v1/wallets/w1/audit-evidence?from_seq=2&to_seq=2",
                None,
            )
            self.assertEqual(status, 200, only2)
            self.assertEqual([e["seq"] for e in only2["events"]], [2])
            self.assertEqual(only2["start_head"], first["end_head"])
            self.assertEqual(
                only2["end_head"],
                _replay(only2["start_head"], only2["event_digests"]),
            )

    def test_events_use_public_view_without_secrets(self):
        with http_server(self.tmp) as srv:
            self._three_events(srv)
            status, body = self._evidence(srv)
            self.assertEqual(status, 200, body)
            status, public = srv.request(
                "GET", "/v1/wallets/w1/audit-events", None
            )
            self.assertEqual(status, 200, public)
            # 证据中的 events 与 audit-events 公开视图完全一致
            self.assertEqual(body["events"], public["events"])
            encoded = json.dumps(body, ensure_ascii=False)
            # 绝不外泄份额私钥/份额文件中间值
            self.assertNotIn("private_key", encoded)
            self.assertNotIn("private_bytes", encoded)

    def test_expected_head_match_and_mismatch(self):
        with http_server(self.tmp) as srv:
            self._three_events(srv)
            status, body = self._evidence(srv)
            self.assertEqual(status, 200, body)
            good = body["end_head"]
            status, ok = srv.request(
                "GET",
                "/v1/wallets/w1/audit-evidence?from_seq=1&to_seq=3"
                f"&expected_head={good}",
                None,
            )
            self.assertEqual(status, 200, ok)
            wrong = ("a" if good[0] != "a" else "b") + good[1:]
            status, resp = srv.request(
                "GET",
                "/v1/wallets/w1/audit-evidence?from_seq=1&to_seq=3"
                f"&expected_head={wrong}",
                None,
            )
            self.assertEqual(status, 409, resp)
            self.assertEqual(
                resp, {"error": "expected_head does not match chain head"}
            )

    def test_400_error_variants(self):
        with http_server(self.tmp) as srv:
            self._three_events(srv)
            base = "/v1/wallets/w1/audit-evidence"
            cases = [
                ("", "missing evidence parameters"),
                ("?from_seq=1", "missing evidence parameters"),
                ("?to_seq=1", "missing evidence parameters"),
                (
                    "?from_seq=1&to_seq=1&to_seq=2",
                    "duplicate evidence parameters",
                ),
                (
                    "?from_seq=1&from_seq=2&to_seq=2",
                    "duplicate evidence parameters",
                ),
                (
                    "?from_seq=1&to_seq=1&expected_head="
                    + "0" * 64
                    + f"&expected_head={'1' * 64}",
                    "duplicate evidence parameters",
                ),
                ("?from_seq=0&to_seq=1", "invalid from_seq"),
                ("?from_seq=-1&to_seq=1", "invalid from_seq"),
                ("?from_seq=1.5&to_seq=1", "invalid from_seq"),
                ("?from_seq=x&to_seq=1", "invalid from_seq"),
                ("?from_seq=true&to_seq=1", "invalid from_seq"),
                ("?from_seq=1&to_seq=0", "invalid to_seq"),
                ("?from_seq=1&to_seq=x", "invalid to_seq"),
                (
                    "?from_seq=1&to_seq=1&expected_head=zzz",
                    "invalid expected_head",
                ),
                (
                    "?from_seq=1&to_seq=1&expected_head=" + "0" * 63,
                    "invalid expected_head",
                ),
                (
                    "?from_seq=1&to_seq=1&expected_head=" + "0" * 65,
                    "invalid expected_head",
                ),
                (
                    "?from_seq=1&to_seq=1&expected_head=" + "A" * 64,
                    "invalid expected_head",
                ),
                ("?from_seq=3&to_seq=2", "invalid evidence range"),
                ("?from_seq=1&to_seq=1001", "invalid evidence range"),
                ("?from_seq=&to_seq=1", "invalid from_seq"),
            ]
            for query, error in cases:
                with self.subTest(query=query):
                    status, body = srv.request("GET", base + query, None)
                    self.assertEqual(status, 400, (query, body))
                    self.assertEqual(body, {"error": error})

    def test_404_variants(self):
        with http_server(self.tmp) as srv:
            self._three_events(srv)
            srv.request(
                "POST", "/v1/wallets", {"wallet_id": "empty", "shares": 2}
            )
            status, body = srv.request(
                "GET",
                "/v1/wallets/ghost/audit-evidence?from_seq=1&to_seq=1",
                None,
            )
            self.assertEqual(status, 404, body)
            status, body = srv.request(
                "GET",
                "/v1/wallets/empty/audit-evidence?from_seq=1&to_seq=1",
                None,
            )
            self.assertEqual(status, 404, body)
            self.assertEqual(body, {"error": "empty evidence range"})
            status, body = srv.request(
                "GET",
                "/v1/wallets/w1/audit-evidence?from_seq=1&to_seq=4",
                None,
            )
            self.assertEqual(status, 404, body)
            self.assertEqual(body, {"error": "evidence range out of bounds"})

    def test_405_for_non_get_methods(self):
        with http_server(self.tmp) as srv:
            self._three_events(srv)
            path = "/v1/wallets/w1/audit-evidence?from_seq=1&to_seq=1"
            for method, body in (
                ("POST", {}),
                ("PUT", {}),
                ("DELETE", None),
                ("PATCH", {}),
            ):
                status, resp = srv.request(method, path, body)
                self.assertEqual(status, 405, (method, resp))
                self.assertEqual(resp, {"error": "method not allowed"})

    def test_tampered_audit_returns_503(self):
        with http_server(self.tmp) as srv:
            self._three_events(srv)
            # 服务器仍在运行时篡改事件正文（不改链头）：下一次持锁访问
            # 严格对账失败，fail-closed 503，保留现场。
            log = _load_audit(self.tmp)
            log["events"][0]["details"]["timeout_seconds"] += 1
            _dump_audit(self.tmp, log)
            status, body = srv.request(
                "GET",
                "/v1/wallets/w1/audit-evidence?from_seq=1&to_seq=3",
                None,
            )
            self.assertEqual(status, 503, body)
            self.assertEqual(
                body, {"error": "service temporarily unavailable"}
            )

    def test_read_only_does_not_allocate_seq_or_write(self):
        with http_server(self.tmp) as srv:
            self._three_events(srv)
            before = open(_audit_path(self.tmp), encoding="utf-8").read()
            status, _ = self._evidence(srv)
            self.assertEqual(status, 200)
            # 纯只读：审计文件字节不变（next_seq/chain/正文均不动）
            self.assertEqual(
                open(_audit_path(self.tmp), encoding="utf-8").read(), before
            )
            # 再查 integrity，链计数仍为 3
            status, integrity = srv.request(
                "GET", "/v1/wallets/w1/audit-integrity", None
            )
            self.assertEqual(status, 200)
            self.assertEqual(integrity["count"], 3)

    def test_old_end_head_still_validates_after_append(self):
        with http_server(self.tmp) as srv:
            self._three_events(srv)
            status, old = self._evidence(srv)
            self.assertEqual(status, 200, old)
            old_end_head = old["end_head"]
            # 追加第 4 条事件
            srv.request(
                "PUT",
                "/v1/wallets/w1/approval-policy",
                {"required_approvals": 1, "timeout_seconds": 30},
            )
            # 追加后以旧 end_head 验证旧区间 [1,3] 仍然成立
            status, body = srv.request(
                "GET",
                "/v1/wallets/w1/audit-evidence?from_seq=1&to_seq=3"
                f"&expected_head={old_end_head}",
                None,
            )
            self.assertEqual(status, 200, body)
            self.assertEqual(body["end_head"], old_end_head)
            # 新区间 [4,4] 的 start_head 即旧 end_head
            status, fourth = srv.request(
                "GET",
                "/v1/wallets/w1/audit-evidence?from_seq=4&to_seq=4",
                None,
            )
            self.assertEqual(status, 200, fourth)
            self.assertEqual(fourth["start_head"], old_end_head)

    def test_range_boundary_exactly_1000_is_valid(self):
        # 区间上限 1000：to_seq - from_seq + 1 == 1000 合法（空钱包无事件，
        # 参数校验先于越界判定，故落在 404 而非 400）。
        with http_server(self.tmp) as srv:
            srv.request(
                "POST", "/v1/wallets", {"wallet_id": "w9", "shares": 2}
            )
            status, body = srv.request(
                "GET",
                "/v1/wallets/w9/audit-evidence?from_seq=1&to_seq=1000",
                None,
            )
            self.assertEqual(status, 404, body)
            self.assertEqual(body, {"error": "empty evidence range"})


class AuditEvidenceStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_range_evidence_heads_match_full_chain(self):
        store = audit_mod.AuditStore(self.tmp)
        for at in (
            "2026-09-20T00:00:00Z",
            "2026-09-20T00:00:01Z",
            "2026-09-20T00:00:02Z",
        ):
            store.append_event("w1", {"type": "policy_updated", "at": at,
                                      "request_id": None, "actor_id": None,
                                      "reason": None, "details": {}})
        total, events, start_head, end_head = store.range_evidence(
            "w1", 2, 3
        )
        self.assertEqual(total, 3)
        self.assertEqual([e["seq"] for e in events], [2, 3])
        self.assertEqual(start_head, audit_mod.compute_chain_head(
            store.all_events("w1")[:1]
        )[1])
        digests = [audit_mod._event_digest(e) for e in events]
        self.assertEqual(end_head, _replay(start_head, digests))
        # 全区间终点头与链元数据一致
        _, full_head = store.integrity("w1")
        self.assertEqual(
            store.range_evidence("w1", 1, 3)[3], full_head
        )

    def test_range_evidence_empty_log(self):
        store = audit_mod.AuditStore(self.tmp)
        total, events, start_head, end_head = store.range_evidence(
            "w1", 1, 1
        )
        self.assertEqual((total, events), (0, []))
        self.assertEqual(start_head, audit_mod.GENESIS_HEAD)
        self.assertEqual(end_head, audit_mod.GENESIS_HEAD)


if __name__ == "__main__":
    unittest.main()
