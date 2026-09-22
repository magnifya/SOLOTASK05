"""审计日志 seq 语义矛盾（重号/缺口/next_seq 不符）必须 fail-closed。

JSON 可解析但 seq 不连续（重号或缺口）属于"语义矛盾的审计数据"：
- GET audit-events 必须 503，绝不返回重号/缺口序列；
- 任何追加新事件的写路由不得在矛盾日志上继续写（统一 503），
  绝不把历史"归一"或覆盖；现场原样保留。
JSON 不可解析时沿用既有隔离：仅审计读取/写入受影响，非审计路由可用。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from tests.helpers import http_server
from threshold_wallet.store import CorruptDataError, WalletStore


def _audit_path(tmp: str) -> str:
    return os.path.join(tmp, "audit", "w1.json")


def _load(tmp: str) -> dict:
    with open(_audit_path(tmp), encoding="utf-8") as f:
        return json.load(f)


def _dump(tmp: str, data: dict) -> str:
    raw = json.dumps(data)
    os.makedirs(os.path.dirname(_audit_path(tmp)), exist_ok=True)
    with open(_audit_path(tmp), "w", encoding="utf-8") as f:
        f.write(raw)
    return raw


class AuditSeqContradictionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _seed(self, srv):
        self.assertEqual(
            srv.request("POST", "/v1/wallets",
                        {"wallet_id": "w1", "shares": 2})[0],
            201,
        )
        self.assertEqual(
            srv.request(
                "PUT", "/v1/wallets/w1/approval-policy",
                {"required_approvals": 1, "timeout_seconds": 60},
            )[0],
            200,
        )
        self.assertEqual(
            srv.request(
                "POST", "/v1/wallets/w1/sign-requests",
                {"id": "r1", "message": "m"},
            )[0],
            201,
        )

    def _corrupt(self, mutate):
        data = _load(self.tmp)
        mutate(data)
        return _dump(self.tmp, data)

    def test_duplicate_seq_query_is_503(self):
        with http_server(self.tmp) as srv:
            self._seed(srv)
            raw = self._corrupt(lambda d: d.__setitem__(
                "events",
                [{**e, "seq": 1} for e in d["events"]],
            ))
            status, body = srv.request("GET", "/v1/wallets/w1/audit-events")
            self.assertEqual(status, 503, body)
            with open(_audit_path(self.tmp), encoding="utf-8") as f:
                self.assertEqual(f.read(), raw)  # 现场保留，不被覆盖

    def test_gap_seq_query_is_503(self):
        with http_server(self.tmp) as srv:
            self._seed(srv)
            self._corrupt(lambda d: d["events"].__setitem__(1, {**d["events"][1], "seq": 5}))
            status, body = srv.request("GET", "/v1/wallets/w1/audit-events")
            self.assertEqual(status, 503, body)

    def test_wrong_next_seq_query_is_503(self):
        with http_server(self.tmp) as srv:
            self._seed(srv)
            self._corrupt(lambda d: d.__setitem__("next_seq", 99))
            status, body = srv.request("GET", "/v1/wallets/w1/audit-events")
            self.assertEqual(status, 503, body)

    def test_append_onto_contradictory_log_is_503(self):
        with http_server(self.tmp) as srv:
            self._seed(srv)
            self._corrupt(lambda d: d.__setitem__(
                "events", [{**e, "seq": 1} for e in d["events"]]))
            # 再做一次会追加事件的写操作：必须 503，且不新增/归一历史
            status, body = srv.request(
                "PUT", "/v1/wallets/w1/approval-policy",
                {"required_approvals": 2, "timeout_seconds": 120},
            )
            self.assertEqual(status, 503, body)
            data = _load(self.tmp)
            self.assertTrue(all(e["seq"] == 1 for e in data["events"]))

    def test_healthy_consecutive_seq_still_reads(self):
        with http_server(self.tmp) as srv:
            self._seed(srv)
            status, body = srv.request("GET", "/v1/wallets/w1/audit-events")
            self.assertEqual(status, 200, body)
            self.assertEqual(
                [e["seq"] for e in body["events"]], [1, 2]
            )

    def test_store_reader_raises_on_contradiction(self):
        with http_server(self.tmp) as srv:
            self._seed(srv)
        self._corrupt(lambda d: d["events"].__setitem__(
            1, {**d["events"][1], "seq": 7}))
        from threshold_wallet.audit import AuditStore
        with self.assertRaises(CorruptDataError):
            AuditStore(self.tmp).list_events("w1")


if __name__ == "__main__":
    unittest.main()
