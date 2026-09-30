"""审计区间逐条证据 GET /v1/wallets/{id}/audit-evidence 的回归测试。

覆盖：
- 成功体形状（wallet_id/range/events/event_digests/start_head/end_head/
  count/state），events 按 seq 升序并沿用 audit-events 公开视图；
- event_digests 与 events 一一对应且为既有七字段摘要；start_head（含
  from_seq=1 时 64 个零）/end_head 可按既有递推规则复算，整段 end_head
  与 audit-integrity 链头一致；
- 纯只读：不分配 seq、不改状态、不写文件；追加后旧区间的 end_head 仍
  可作为 expected_head 验证；
- 400（缺参/重复/from_seq/to_seq/expected_head 格式/范围非法及次序）、
  404（钱包不存在/空钱包/越界）、405（非 GET）、409（expected_head 不
  符）、503（篡改现场）；
- 线路字节：UTF-8 紧凑 JSON、非 ASCII 不转义、无末换行。
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import unittest
import urllib.error
import urllib.request

from tests.helpers import http_server
from threshold_wallet import audit as audit_mod
from threshold_wallet.service import WalletService
from threshold_wallet.store import WalletStore

ZERO_HEAD = "0" * 64


def _audit_path(data_dir: str, wallet_id: str = "w1") -> str:
    return os.path.join(data_dir, "audit", wallet_id + ".json")


def _load_audit(data_dir: str, wallet_id: str = "w1") -> dict:
    with open(_audit_path(data_dir, wallet_id), encoding="utf-8") as f:
        return json.load(f)


def _dump_audit(data_dir: str, data: dict, wallet_id: str = "w1") -> None:
    with open(_audit_path(data_dir, wallet_id), "w", encoding="utf-8") as f:
        json.dump(data, f)


def _raw_event(**over) -> dict:
    event = {
        "type": "policy_updated",
        "at": "2026-09-21T00:00:00Z",
        "request_id": None,
        "actor_id": None,
        "reason": None,
        "details": {},
    }
    event.update(over)
    return event


def _replay(head: str, digests: list[str]) -> str:
    for digest in digests:
        head = hashlib.sha256((head + digest).encode("ascii")).hexdigest()
    return head


# ---- AuditStore.range_evidence 单元 ---------------------------------------


class RangeEvidenceStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.store = audit_mod.AuditStore(self.tmp)
        self.stamped = [
            self.store.append_event(
                "w1",
                _raw_event(
                    type="request_created",
                    request_id=f"r{i}",
                    at=f"2026-09-21T00:00:{i:02d}Z",
                ),
            )
            for i in range(1, 4)
        ]

    def test_missing_log_is_none(self):
        self.assertIsNone(self.store.range_evidence("ghost", 1, 1))

    def test_full_range_vectors(self):
        evidence = self.store.range_evidence("w1", 1, 3)
        self.assertEqual([e["seq"] for e in evidence["events"]], [1, 2, 3])
        self.assertEqual(evidence["count"], 3)
        self.assertEqual(evidence["start_head"], ZERO_HEAD)
        want_digests = [audit_mod._event_digest(e) for e in self.stamped]
        self.assertEqual(evidence["event_digests"], want_digests)
        self.assertEqual(
            evidence["end_head"], _replay(ZERO_HEAD, want_digests)
        )
        _, full_head = audit_mod.compute_chain_head(self.stamped)
        self.assertEqual(evidence["end_head"], full_head)

    def test_partial_range_heads(self):
        middle = self.store.range_evidence("w1", 2, 2)
        self.assertEqual([e["seq"] for e in middle["events"]], [2])
        # start_head = 第 1 条之后的链头
        _, head_after_1 = audit_mod.compute_chain_head(self.stamped[:1])
        self.assertEqual(middle["start_head"], head_after_1)
        # end_head = 第 2 条之后的链头
        _, head_after_2 = audit_mod.compute_chain_head(self.stamped[:2])
        self.assertEqual(middle["end_head"], head_after_2)
        self.assertEqual(
            middle["end_head"],
            _replay(middle["start_head"], middle["event_digests"]),
        )

    def test_returns_copies(self):
        evidence = self.store.range_evidence("w1", 1, 3)
        evidence["events"][0]["details"]["tampered"] = True
        again = self.store.range_evidence("w1", 1, 3)
        self.assertNotIn("tampered", again["events"][0]["details"])


# ---- HTTP 契约 ------------------------------------------------------------


class AuditEvidenceHttpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self._ctx = http_server(self.tmp)
        self.srv = self._ctx.__enter__()
        self.srv.request(
            "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
        )

    def tearDown(self):
        self._ctx.__exit__(None, None, None)

    def request(self, method, path, body=None):
        return self.srv.request(method, path, body)

    def evidence(self, query, expected=200):
        status, body = self.request(
            "GET", f"/v1/wallets/w1/audit-evidence?{query}"
        )
        self.assertEqual(status, expected, body)
        return body

    def append_raw(self, n: int, **over) -> None:
        """直接经 AuditStore 追加 n 条形状合法的原始事件（不经业务流）。"""
        audit = self.srv.harness.service._audit
        for i in range(n):
            audit.append_event(
                "w1", _raw_event(at=f"2026-09-21T00:{i // 60:02d}:{i % 60:02d}Z", **over)
            )

    def _raw_get(self, path: str, method: str = "GET"):
        req = urllib.request.Request(
            self.srv.base_url + path, method=method
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    # ---- 成功语义 --------------------------------------------------------

    def test_success_envelope_and_digests(self):
        self.append_raw(3)
        body = self.evidence("from_seq=1&to_seq=3")
        self.assertEqual(set(body), {
            "wallet_id", "range", "events", "event_digests",
            "start_head", "end_head", "count", "state",
        })
        self.assertEqual(body["wallet_id"], "w1")
        self.assertEqual(body["range"], {"from_seq": 1, "to_seq": 3})
        self.assertEqual(body["count"], 3)
        self.assertEqual(body["state"], "valid")
        self.assertEqual([e["seq"] for e in body["events"]], [1, 2, 3])
        self.assertEqual(len(body["event_digests"]), 3)
        self.assertEqual(body["start_head"], ZERO_HEAD)
        # 摘要与事件一一对应（七字段规则），三要素可复算 end_head
        for event, digest in zip(body["events"], body["event_digests"]):
            self.assertEqual(audit_mod._event_digest(event), digest)
        self.assertEqual(
            body["end_head"],
            _replay(body["start_head"], body["event_digests"]),
        )
        # 整段 end_head 即全链头
        _, integrity = self.request(
            "GET", "/v1/wallets/w1/audit-integrity"
        )
        self.assertEqual(body["end_head"], integrity["head"])

    def test_partial_range_local_heads(self):
        self.append_raw(4)
        body = self.evidence("from_seq=2&to_seq=3")
        self.assertEqual([e["seq"] for e in body["events"]], [2, 3])
        self.assertEqual(body["count"], 2)
        all_events = audit_mod.AuditStore(self.tmp).all_events("w1")
        _, head_after_1 = audit_mod.compute_chain_head(all_events[:1])
        _, head_after_3 = audit_mod.compute_chain_head(all_events[:3])
        self.assertEqual(body["start_head"], head_after_1)
        self.assertEqual(body["end_head"], head_after_3)
        self.assertEqual(
            body["end_head"],
            _replay(body["start_head"], body["event_digests"]),
        )

    def test_events_match_audit_events_public_view(self):
        # 制造一个非 ASCII reason 事件，验证证据事件与 audit-events 同视图
        self.srv.request(
            "PUT", "/v1/wallets/w1/approval-policy",
            {"required_approvals": 2, "timeout_seconds": 3600},
        )
        self.srv.request(
            "POST", "/v1/wallets/w1/sign-requests",
            {"id": "r1", "message": "pay-100"},
        )
        self.srv.request(
            "POST", "/v1/wallets/w1/sign-requests/r1/reject",
            {"approver_id": "alice", "reason": "拒绝"},
        )
        status, listed = self.request(
            "GET", "/v1/wallets/w1/audit-events"
        )
        self.assertEqual(status, 200)
        body = self.evidence("from_seq=1&to_seq=3")
        self.assertEqual(body["events"], listed["events"])
        self.assertEqual(
            body["event_digests"],
            [audit_mod._event_digest(e) for e in listed["events"]],
        )

    def test_expected_head_match_and_mismatch(self):
        self.append_raw(2)
        end_head = self.evidence("from_seq=1&to_seq=2")["end_head"]
        ok = self.evidence(
            f"from_seq=1&to_seq=2&expected_head={end_head}"
        )
        self.assertEqual(ok["end_head"], end_head)
        wrong = ("a" if end_head[0] != "a" else "b") + end_head[1:]
        status, body = self.request(
            "GET",
            f"/v1/wallets/w1/audit-evidence?from_seq=1&to_seq=2"
            f"&expected_head={wrong}",
        )
        self.assertEqual(status, 409, body)
        self.assertEqual(
            body["error"], "expected_head does not match chain head"
        )

    def test_read_only_and_append_then_old_head_still_valid(self):
        self.append_raw(2)
        before = self.evidence("from_seq=1&to_seq=2")
        # 纯只读：查询前后全链事件数不变
        _, integrity_before = self.request(
            "GET", "/v1/wallets/w1/audit-integrity"
        )
        for _ in range(3):
            self.evidence("from_seq=1&to_seq=2")
        _, integrity_after = self.request(
            "GET", "/v1/wallets/w1/audit-integrity"
        )
        self.assertEqual(
            integrity_before["count"], integrity_after["count"]
        )
        # 追加一条后：旧区间（1..2）的 end_head 仍是该范围结束后的链头，
        # 继续作为 expected_head 验证通过；扩大到新区间再用旧头则 409。
        self.append_raw(1)
        self.evidence(
            f"from_seq=1&to_seq=2&expected_head={before['end_head']}"
        )
        status, body = self.request(
            "GET",
            f"/v1/wallets/w1/audit-evidence?from_seq=1&to_seq=3"
            f"&expected_head={before['end_head']}",
        )
        self.assertEqual(status, 409, body)

    def test_range_1000_boundary(self):
        self.append_raw(1001)
        # 恰 1000 条：200
        body = self.evidence("from_seq=2&to_seq=1001")
        self.assertEqual(body["count"], 1000)
        # 1001 条：400 invalid evidence range（先于越界判定）
        status, resp = self.request(
            "GET", "/v1/wallets/w1/audit-evidence?from_seq=1&to_seq=1001"
        )
        self.assertEqual(status, 400, resp)
        self.assertEqual(resp["error"], "invalid evidence range")

    # ---- 400 参数矩阵 ----------------------------------------------------

    def test_missing_parameters(self):
        self.append_raw(1)
        for query in (
            "",
            "to_seq=1",
            "from_seq=1",
            "from_seq=&to_seq=1",
            "from_seq=1&to_seq=",
        ):
            status, body = self.request(
                "GET", f"/v1/wallets/w1/audit-evidence?{query}"
            )
            self.assertEqual(status, 400, query)
            self.assertEqual(
                body["error"], "missing evidence parameters", query
            )

    def test_duplicate_parameters(self):
        self.append_raw(3)
        for query in (
            "from_seq=1&from_seq=2&to_seq=3",
            "from_seq=1&to_seq=2&to_seq=3",
            "from_seq=1&to_seq=3"
            "&expected_head=" + ZERO_HEAD + "&expected_head=" + ZERO_HEAD,
        ):
            status, body = self.request(
                "GET", f"/v1/wallets/w1/audit-evidence?{query}"
            )
            self.assertEqual(status, 400, query)
            self.assertEqual(
                body["error"], "duplicate evidence parameters", query
            )
        # 缺参先于重复判定
        status, body = self.request(
            "GET",
            "/v1/wallets/w1/audit-evidence?from_seq=1&from_seq=2",
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "missing evidence parameters")

    def test_invalid_from_seq(self):
        self.append_raw(3)
        for value in ("0", "-1", "abc", "1.5", "true", "1x", "%2B1"):
            status, body = self.request(
                "GET",
                f"/v1/wallets/w1/audit-evidence"
                f"?from_seq={value}&to_seq=3",
            )
            self.assertEqual(status, 400, value)
            self.assertEqual(body["error"], "invalid from_seq", value)
        # 两侧皆非法：from_seq 先报
        status, body = self.request(
            "GET",
            "/v1/wallets/w1/audit-evidence?from_seq=0&to_seq=x",
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "invalid from_seq")
        # 带空白的十进制正整数合法（strip 后；查询串里的 + 解码为空格）
        self.evidence("from_seq=%201&to_seq=3")
        self.evidence("from_seq=+1&to_seq=3")

    def test_invalid_to_seq(self):
        self.append_raw(3)
        for value in ("0", "-2", "xyz", "2.0", "false"):
            status, body = self.request(
                "GET",
                f"/v1/wallets/w1/audit-evidence"
                f"?from_seq=1&to_seq={value}",
            )
            self.assertEqual(status, 400, value)
            self.assertEqual(body["error"], "invalid to_seq", value)
        # to_seq 非法先于 expected_head 格式与区间判定
        status, body = self.request(
            "GET",
            "/v1/wallets/w1/audit-evidence"
            "?from_seq=1&to_seq=x&expected_head=zzz",
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "invalid to_seq")

    def test_invalid_expected_head(self):
        self.append_raw(3)
        for value in ("zzz", "0" * 63, "0" * 65, "A" * 64, "g" * 64):
            status, body = self.request(
                "GET",
                f"/v1/wallets/w1/audit-evidence"
                f"?from_seq=1&to_seq=3&expected_head={value}",
            )
            self.assertEqual(status, 400, value)
            self.assertEqual(body["error"], "invalid expected_head", value)
        # expected_head 格式先于区间非法判定
        status, body = self.request(
            "GET",
            "/v1/wallets/w1/audit-evidence"
            "?from_seq=3&to_seq=1&expected_head=zzz",
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "invalid expected_head")

    def test_invalid_range(self):
        self.append_raw(3)
        status, body = self.request(
            "GET",
            "/v1/wallets/w1/audit-evidence?from_seq=3&to_seq=1",
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "invalid evidence range")

    # ---- 404 -------------------------------------------------------------

    def test_wallet_missing_404_before_param_validation(self):
        for query in ("", "?from_seq=0"):
            status, body = self.request(
                "GET", f"/v1/wallets/ghost/audit-evidence{query}"
            )
            self.assertEqual(status, 404, query)
        # 非法钱包标识 400（同 audit-integrity）
        status, _ = self.request(
            "GET",
            "/v1/wallets/bad%2Fid/audit-evidence?from_seq=1&to_seq=1",
        )
        self.assertEqual(status, 400)

    def test_empty_wallet_404(self):
        # 钱包存在但没有任何事件
        status, body = self.request(
            "GET",
            "/v1/wallets/w1/audit-evidence?from_seq=1&to_seq=1",
        )
        self.assertEqual(status, 404, body)
        self.assertEqual(body["error"], "empty evidence range")

    def test_range_out_of_bounds_404(self):
        self.append_raw(3)
        for query in ("from_seq=1&to_seq=4", "from_seq=4&to_seq=4"):
            status, body = self.request(
                "GET", f"/v1/wallets/w1/audit-evidence?{query}"
            )
            self.assertEqual(status, 404, query)
            self.assertEqual(
                body["error"], "evidence range out of bounds", query
            )

    # ---- 405 -------------------------------------------------------------

    def test_non_get_methods_405(self):
        for method, body in (
            ("POST", {}),
            ("PUT", {}),
            ("DELETE", None),
            ("PATCH", {}),
            ("OPTIONS", None),
        ):
            status, resp = self.request(
                method,
                "/v1/wallets/w1/audit-evidence?from_seq=1&to_seq=1",
                body,
            )
            self.assertEqual(status, 405, method)
            self.assertEqual(resp["error"], "method not allowed", method)
        # HEAD：405 状态头且无响应体
        status, raw = self._raw_get(
            "/v1/wallets/w1/audit-evidence?from_seq=1&to_seq=1",
            method="HEAD",
        )
        self.assertEqual(status, 405)
        self.assertEqual(raw, b"")

    # ---- 503 -------------------------------------------------------------

    def test_tampered_log_503(self):
        self.append_raw(1)
        log = _load_audit(self.tmp)
        log["events"][0]["details"]["x"] = 1
        _dump_audit(self.tmp, log)
        status, body = self.request(
            "GET",
            "/v1/wallets/w1/audit-evidence?from_seq=1&to_seq=1",
        )
        self.assertEqual(status, 503, body)
        self.assertEqual(
            body["error"], "service temporarily unavailable"
        )

    # ---- 线路字节 --------------------------------------------------------

    def test_wire_compact_utf8_no_trailing_newline(self):
        self.append_raw(1)
        status, raw = self._raw_get(
            "/v1/wallets/w1/audit-evidence?from_seq=1&to_seq=1"
        )
        self.assertEqual(status, 200)
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)
        self.assertFalse(raw.endswith(b"\n"))
        parsed = json.loads(raw.decode("utf-8"))
        self.assertEqual(parsed["wallet_id"], "w1")
        self.assertTrue(
            raw.startswith(b'{"wallet_id":"w1","range":{"from_seq":1')
        )
        # 错误体同样紧凑
        status, raw = self._raw_get(
            "/v1/wallets/w1/audit-evidence?from_seq=1&to_seq=x"
        )
        self.assertEqual(status, 400)
        self.assertNotIn(b": ", raw)
        self.assertFalse(raw.endswith(b"\n"))

    def test_wire_non_ascii_not_escaped(self):
        self.append_raw(1, reason="证据", actor_id=None)
        status, raw = self._raw_get(
            "/v1/wallets/w1/audit-evidence?from_seq=1&to_seq=1"
        )
        self.assertEqual(status, 200)
        self.assertIn("证据".encode("utf-8"), raw)
        self.assertNotIn(b"\\u", raw)


if __name__ == "__main__":
    unittest.main()
