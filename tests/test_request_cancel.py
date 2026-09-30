"""审批单主动撤销（POST sign-requests/<rid>/cancel）端到端测试。"""
from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from threshold_wallet import audit as audit_mod

from tests.helpers import http_server
from threshold_wallet.cli import main
from threshold_wallet.service import WalletService
from threshold_wallet.store import WalletStore


class CancelTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self._ctx = http_server(self.dir)
        self.srv = self._ctx.__enter__()
        self.srv.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
        self.srv.request(
            "PUT", "/v1/wallets/w1/approval-policy",
            {"required_approvals": 2, "timeout_seconds": 3600},
        )

    def tearDown(self):
        self._ctx.__exit__(None, None, None)

    def req(self, method, path, body=None):
        return self.srv.request(method, path, body)

    def create(self, rid="r1", message="pay-100"):
        return self.req(
            "POST", "/v1/wallets/w1/sign-requests",
            {"id": rid, "message": message},
        )

    def cancel(self, rid="r1", cid="c1", reason="changed mind"):
        return self.req(
            "POST", f"/v1/wallets/w1/sign-requests/{rid}/cancel",
            {"cancel_id": cid, "reason": reason},
        )

    def test_full_contract(self):
        st, body = self.create()
        self.assertEqual(st, 201)
        # 400 形状
        for bad in (
            {"cancel_id": "c1"},
            {"reason": "x"},
            {"cancel_id": "c1", "reason": "x", "extra": 1},
            {"cancel_id": "c1", "reason": ""},
            {"cancel_id": "c1", "reason": "   "},
            {"cancel_id": "c1", "reason": "x" * 1025},
            {"cancel_id": "bad/id", "reason": "x"},
            {"cancel_id": "", "reason": "x"},
            {"cancel_id": 1, "reason": "x"},
            {"cancel_id": "c1", "reason": 1},
        ):
            s, b = self.req(
                "POST", "/v1/wallets/w1/sign-requests/r1/cancel", bad
            )
            self.assertEqual(s, 400, bad)
        # 非 JSON 对象
        url = f"{self.srv.base_url}/v1/wallets/w1/sign-requests/r1/cancel"
        raw = urllib.request.Request(
            url, data=b"[1,2]", method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(raw)
            self.fail()
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)
        # 404
        self.assertEqual(
            self.cancel(rid="nope")[0], 404
        )
        s2, _ = self.srv.request(
            "POST", "/v1/wallets/nope/sign-requests/r1/cancel",
            {"cancel_id": "c1", "reason": "x"},
        )
        self.assertEqual(s2, 404)
        # 首次 201
        st, body = self.cancel()
        self.assertEqual((st, body["state"]), (201, "cancelled"))
        self.assertEqual(body["reason"], "changed mind")
        # GET 显示 cancelled
        st, body = self.req("GET", "/v1/wallets/w1/sign-requests/r1")
        self.assertEqual((st, body["state"]), (200, "cancelled"))
        # 重放 200
        self.assertEqual(self.cancel()[0], 200)
        # 参数变化 409
        self.assertEqual(self.cancel(reason="other")[0], 409)
        self.assertEqual(self.cancel(cid="c2")[0], 409)
        # approve/reject/sign 409
        self.assertEqual(
            self.req("POST", "/v1/wallets/w1/sign-requests/r1/approve",
                     {"approver_id": "alice"})[0],
            409,
        )
        self.assertEqual(
            self.req("POST", "/v1/wallets/w1/sign-requests/r1/reject",
                     {"approver_id": "alice"})[0],
            409,
        )
        sigs = self.srv.harness.two_signatures("w1", "r1", "pay-100")
        self.assertEqual(
            self.req("POST", "/v1/wallets/w1/sign",
                     {"signing_request_id": "r1", "message": "pay-100",
                      "signatures": sigs})[0],
            409,
        )
        # 另一单复用 cancel_id -> 409
        self.create(rid="r2")
        self.assertEqual(self.cancel(rid="r2", cid="c1")[0], 409)
        # 对 approved/rejected/expired 撤销 -> 409
        st, _ = self.create(rid="r3")
        self.req("POST", "/v1/wallets/w1/sign-requests/r3/approve",
                 {"approver_id": "alice"})
        self.req("POST", "/v1/wallets/w1/sign-requests/r3/approve",
                 {"approver_id": "bob"})
        self.assertEqual(self.cancel(rid="r3", cid="c3")[0], 409)
        self.create(rid="r4")
        self.req("POST", "/v1/wallets/w1/sign-requests/r4/reject",
                 {"approver_id": "alice"})
        self.assertEqual(self.cancel(rid="r4", cid="c4")[0], 409)
        # 审计事件
        st, body = self.req("GET", "/v1/wallets/w1/audit-events")
        self.assertEqual(st, 200)
        cancels = [e for e in body["events"] if e["type"] == "request_cancelled"]
        self.assertEqual(len(cancels), 1)
        ev = cancels[0]
        self.assertEqual(ev["request_id"], "r1")
        self.assertEqual(ev["actor_id"], "c1")
        self.assertEqual(ev["reason"], "changed mind")
        self.assertEqual(
            ev["details"],
            {"cancel_id": "c1", "reason": "changed mind"},
        )
        seqs = [e["seq"] for e in body["events"]]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))

    def test_frozen_409(self):
        self.create(rid="f1")
        self.req("POST", "/v1/wallets/w1/freeze", {"reason": "incident"})
        self.assertEqual(self.cancel(rid="f1")[0], 409)

    def test_concurrent_only_one_201(self):
        self.create(rid="p1")
        results = []

        def worker(cid):
            results.append(self.cancel(rid="p1", cid=cid))

        threads = [threading.Thread(target=worker, args=(f"cc{i}",))
                   for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        statuses = sorted(s for s, _ in results)
        self.assertEqual(statuses.count(201), 1)
        self.assertTrue(all(s in (200, 409, 201) for s in statuses))
        # 只有赢者同参重放 200
        winner = next(cid for cid, (s, _) in zip(
            [f"cc{i}" for i in range(8)], results) if s == 201)
        self.assertEqual(self.cancel(rid="p1", cid=winner)[0], 200)
        st, body = self.req("GET", "/v1/wallets/w1/audit-events")
        self.assertEqual(
            sum(e["type"] == "request_cancelled" for e in body["events"]), 1
        )

    def test_crash_forward_and_rollback(self):
        self.create(rid="z1")
        self.assertEqual(self.cancel(rid="z1", cid="z9")[0], 201)
        audit_path = os.path.join(self.dir, "audit", "w1.json")
        req_path = os.path.join(self.dir, "requests", "w1.json")
        # 场景 1：删除撤销事件 -> 回滚 pending
        with open(audit_path, encoding="utf-8") as f:
            log = json.load(f)
        ev = log["events"].pop()
        assert ev["type"] == "request_cancelled"
        log["next_seq"] -= 1
        # 重算 chain
        count, head = audit_mod.compute_chain_head(log["events"])
        log["chain"] = {"algorithm": "sha256", "head": head, "count": count}
        with open(audit_path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        WalletService(WalletStore(self.dir))  # 启动恢复
        store = WalletStore(self.dir)
        self.assertEqual(store.get_request("w1", "z1")["state"], "pending")
        # 场景 2：事件在、记录 pending -> 前滚
        store.update_request("w1", "z1",
                             {**store.get_request("w1", "z1"),
                              "state": "pending"})
        with open(audit_path, encoding="utf-8") as f:
            log = json.load(f)
        log["events"].append(ev)
        log["next_seq"] += 1
        count, head = audit_mod.compute_chain_head(log["events"])
        log["chain"] = {"algorithm": "sha256", "head": head, "count": count}
        with open(audit_path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        WalletService(WalletStore(self.dir))
        self.assertEqual(
            WalletStore(self.dir).get_request("w1", "z1")["state"],
            "cancelled",
        )
        # 场景 3：矛盾（事件在但记录 approved）-> serve 拒绝就绪
        store2 = WalletStore(self.dir)
        rec = store2.get_request("w1", "z1")
        store2.update_request("w1", "z1", {**rec, "state": "approved"})
        with self.assertRaises(Exception):
            WalletService(WalletStore(self.dir))

    def test_cli(self):
        self.create(rid="q1")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main([
                "request-cancel", "--url", self.srv.base_url,
                "--wallet-id", "w1", "--signing-request-id", "q1",
                "--cancel-id", "cli1", "--reason", "via cli",
            ])
        self.assertEqual(rc, 0)
        self.assertIn("cancelled", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
