"""钱包应急冻结/解冻契约测试。

覆盖：
- security-state 视图、freeze/unfreeze 的 201/200/409 幂等与交替状态机；
- 请求体恰为 {"reason": ...} 的 400 边界与钱包 404；
- wallet_frozen/wallet_unfrozen 事件形状、details、seq 连续与重放不记；
- frozen 时全部既有写接口统一 409，查询/审计/security-state 仍可用；
- 重启与灾备恢复后状态折叠一致、seq 不变；
- 跨进程（多线程）并发同一操作只有一个 201；
- 损坏 JSON / 自相矛盾现场 fail-closed（503、拒绝就绪）。
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from threshold_wallet.audit import AuditStore
from threshold_wallet.drbackup import backup, restore
from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import CorruptDataError, RecoveryError, WalletStore
from tests.helpers import http_server

HEX32 = "a" * 64


class WalletFreezeHttpTest(unittest.TestCase):
    def setUp(self):
        self._ctx = http_server(tempfile.mkdtemp())
        self.srv = self._ctx.__enter__()
        self.url = self.srv.base_url

    def tearDown(self):
        self._ctx.__exit__(None, None, None)

    def request(self, method, path, body=None):
        return self.srv.request(method, path, body)

    def create_wallet(self, wallet_id="w1"):
        status, body = self.request(
            "POST", "/v1/wallets", {"wallet_id": wallet_id, "shares": 2}
        )
        self.assertEqual(status, 201, body)

    def freeze(self, reason="incident", wallet_id="w1"):
        return self.request(
            "POST", f"/v1/wallets/{wallet_id}/freeze", {"reason": reason}
        )

    def unfreeze(self, reason="resolved", wallet_id="w1"):
        return self.request(
            "POST",
            f"/v1/wallets/{wallet_id}/unfreeze",
            {"reason": reason},
        )

    def state(self, wallet_id="w1"):
        return self.request("GET", f"/v1/wallets/{wallet_id}/security-state")

    def test_default_state_is_active_with_null_reason(self):
        self.create_wallet()
        status, body = self.state()
        self.assertEqual(status, 200)
        self.assertEqual(
            body, {"wallet_id": "w1", "state": "active", "reason": None}
        )

    def test_freeze_unfreeze_transitions_and_views(self):
        self.create_wallet()
        status, body = self.freeze("incident-1")
        self.assertEqual(status, 201)
        self.assertEqual(
            body,
            {"wallet_id": "w1", "state": "frozen", "reason": "incident-1"},
        )
        self.assertEqual(self.freeze("incident-1")[0], 200)
        self.assertEqual(self.freeze("other")[0], 409)
        self.assertEqual(self.state()[1]["reason"], "incident-1")
        status, body = self.unfreeze("resolved-1")
        self.assertEqual(status, 201)
        self.assertEqual(
            body, {"wallet_id": "w1", "state": "active", "reason": None}
        )
        self.assertEqual(self.unfreeze("resolved-1")[0], 200)
        self.assertEqual(self.unfreeze("different")[0], 409)
        self.assertEqual(self.freeze("incident-2")[0], 201)
        self.assertEqual(self.state()[1]["reason"], "incident-2")

    def test_unfreeze_never_frozen_wallet_is_409(self):
        self.create_wallet()
        self.assertEqual(self.unfreeze("resolved")[0], 409)
        self.assertEqual(self.state()[1]["state"], "active")

    def test_freeze_body_must_be_exactly_reason_object(self):
        self.create_wallet()
        bad_bodies = (
            [],
            ["reason"],
            "x",
            12,
            True,
            None,
            {},
            {"reason": "x", "extra": 1},
            {"why": "x"},
            {"reason": ""},
            {"reason": "   "},
            {"reason": "\t\n"},
            {"reason": 1},
            {"reason": True},
            {"reason": "x" * 1025},
        )
        for body in bad_bodies:
            status, payload = self.request(
                "POST", "/v1/wallets/w1/freeze", body
            )
            self.assertEqual(status, 400, (body, payload))
            status, payload = self.request(
                "POST", "/v1/wallets/w1/unfreeze", body
            )
            self.assertEqual(status, 400, (body, payload))
        self.assertEqual(self.freeze("x" * 1024)[0], 201)
        self.assertEqual(self.unfreeze("  z  ")[0], 201)

    def test_raw_invalid_or_non_object_json_is_400(self):
        import urllib.error
        import urllib.request

        self.create_wallet()
        for raw in (b"", b"{broken", b"[1,2]", b"123"):
            req = urllib.request.Request(
                self.url + "/v1/wallets/w1/freeze",
                data=raw,
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req)
            self.assertEqual(ctx.exception.code, 400)

    def test_unknown_wallet_is_404(self):
        for method, path in (
            ("GET", "/v1/wallets/ghost/security-state"),
            ("POST", "/v1/wallets/ghost/freeze"),
            ("POST", "/v1/wallets/ghost/unfreeze"),
        ):
            body = {"reason": "x"} if method == "POST" else None
            status, payload = self.request(method, path, body)
            self.assertEqual(status, 404, (path, payload))

    def test_state_persisted_only_by_audit_events(self):
        self.create_wallet()
        self.freeze("r1")
        self.freeze("r1")  # 重放不记
        self.unfreeze("r2")
        self.freeze("r3")
        status, payload = self.request("GET", "/v1/wallets/w1/audit-events")
        self.assertEqual(status, 200)
        events = payload["events"]
        self.assertEqual(
            [event["type"] for event in events],
            ["wallet_frozen", "wallet_unfrozen", "wallet_frozen"],
        )
        self.assertEqual([event["seq"] for event in events], [1, 2, 3])
        for index, event in enumerate(events, start=1):
            self.assertEqual(
                set(event),
                {
                    "seq", "type", "at", "request_id", "actor_id",
                    "reason", "details",
                },
            )
            self.assertEqual(event["seq"], index)
            self.assertIsNone(event["request_id"])
            self.assertIsNone(event["actor_id"])
            self.assertIsNone(event["reason"])
            self.assertEqual(set(event["details"]), {"reason"})
        self.assertEqual(
            [event["details"]["reason"] for event in events],
            ["r1", "r2", "r3"],
        )

    def test_frozen_writes_all_conflict(self):
        self.create_wallet()
        self.freeze()
        writes = (
            ("PUT", "/v1/wallets/w1/approval-policy",
             {"required_approvals": 1, "timeout_seconds": 60}),
            ("PUT", "/v1/wallets/w1/transaction-policy",
             {"mode": "hot", "max_delta": 5, "allowed_assets": ["btc"]}),
            ("PUT", "/v1/wallets/w1/dkg-failover-policy", {"enabled": True}),
            ("PUT", "/v1/wallets/w1/nodes",
             {"nodes": {"n1": {"key": HEX32, "state": "up"}}}),
            ("PUT", "/v1/wallets/w1/chain-adapters",
             {"adapters": {"a1": "up"}}),
            ("POST", "/v1/wallets/w1/nodes/n1/rejoin",
             {"rejoin_id": "rj", "dkg_id": "d", "round": 2,
              "key": HEX32, "approval_request_id": "ap"}),
            ("POST", "/v1/wallets/w1/sign-requests",
             {"id": "r1", "message": "m"}),
            ("POST", "/v1/wallets/w1/sign-requests/r1/approve",
             {"approver_id": "a"}),
            ("POST", "/v1/wallets/w1/sign-requests/r1/reject",
             {"approver_id": "a"}),
            ("POST", "/v1/wallets/w1/sign",
             {"signing_request_id": "r1", "message": "m", "signatures": []}),
            ("POST", "/v1/wallets/w1/share-rotations",
             {"rotation_id": "rot"}),
            ("POST", "/v1/wallets/w1/share-rotations/rot/activate", None),
            ("POST", "/v1/wallets/w1/share-bind",
             {"id": "b", "rotation": "rot", "dkg": "d", "round": 1,
              "node": "n1", "slot": 1, "approval": "ap"}),
            ("POST", "/v1/wallets/w1/asset-operations",
             {"operation_id": "o", "asset_id": "btc", "delta": 1}),
            ("POST", "/v1/wallets/w1/asset-operations/o/commit", None),
            ("PUT", "/v1/wallets/w1/chain/btc",
             {"chain_id": "c", "enabled": True,
              "required_confirmations": 1, "reorg_window": 0}),
            ("POST", "/v1/wallets/w1/chain/o/report",
             {"chain_id": "c", "tx_id": HEX32, "block_height": 1,
              "block_hash": HEX32, "confirmations": 1}),
            ("PUT", "/v1/wallets/w1/chain/btc/arbitration",
             {"sources": {"s1": True}, "quorum": 2}),
            ("POST", "/v1/wallets/w1/chain/o/observe",
             {"source": "s1",
              "report": {"chain_id": "c", "tx_id": HEX32,
                         "block_height": 1, "block_hash": HEX32,
                         "confirmations": 1}}),
            ("POST", "/v1/wallets/w1/chain/o/dispatch",
             {"dispatch_id": "d1", "adapter_id": "a1",
              "approval_request_id": "ap"}),
            ("POST", "/v1/wallets/w1/chain/o/dispatch-auto",
             {"dispatch_id": "d2", "approval_request_id": "ap"}),
            ("POST", "/v1/wallets/w1/chain/d1/result",
             {"adapter_id": "a1", "state": "failed", "tx_id": None}),
            ("POST", "/v1/wallets/w1/chain/d1/confirm",
             {"adapter_id": "a1", "tx_id": HEX32, "block_height": 1,
              "block_hash": HEX32, "confirmations": 1}),
            ("POST", "/v1/wallets/w1/chain/d1/takeover",
             {"adapter_id": "a2", "approval_request_id": "ap"}),
            ("POST", "/v1/wallets/w1/chain/d1/isolate", {}),
            ("POST", "/v1/wallets/w1/chain/d1/settle", None),
            ("POST", "/v1/wallets/w1/sign-sessions",
             {"id": "ss", "message": "m", "timeout_seconds": 60}),
            ("POST", "/v1/wallets/w1/sign-sessions/ss/shares",
             {"share_id": "share-1", "signature": "0" * 128}),
            ("POST", "/v1/wallets/w1/sign-sessions/ss/participants/replace",
             {"replacement_id": "rp", "offline_share_id": "share-1"}),
            ("POST", "/v1/wallets/w1/sign-sessions/ss/participants/takeover",
             {"takeover_id": "tk", "stage": 1,
              "offline_share_id": "share-1"}),
            ("POST", "/v1/dkg/w1/d",
             {"op": "register", "node": "n1", "key": HEX32,
              "hash": None, "peer": None}),
            ("POST", "/v1/dkg/w1/d/failover",
             {"round": 2, "action": "abort", "node": None,
              "replacement": None, "key": None}),
        )
        for method, path, body in writes:
            status, payload = self.request(method, path, body)
            self.assertEqual(status, 409, (method, path, payload))
        events = self.request("GET", "/v1/wallets/w1/audit-events")[1][
            "events"
        ]
        self.assertEqual([e["type"] for e in events], ["wallet_frozen"])

    def test_frozen_reads_remain_available(self):
        self.create_wallet()
        self.freeze()
        reads = (
            ("GET", "/v1/wallets/w1"),
            ("GET", "/v1/wallets/w1/security-state"),
            ("GET", "/v1/wallets/w1/audit-events"),
            ("GET", "/v1/wallets/w1/transaction-policy"),
            ("GET", "/v1/wallets/w1/dkg-failover-policy"),
            ("GET", "/v1/wallets/w1/nodes"),
            ("GET", "/v1/wallets/w1/chain-adapters"),
            ("GET", "/v1/wallets/w1/sign-requests/r1"),
            ("GET", "/v1/wallets/w1/assets/btc"),
            ("GET", "/v1/wallets/w1/share-rotations/rot"),
            ("GET", "/v1/wallets/w1/sign-sessions/ss"),
            ("GET", "/v1/wallets/w1/chain/btc"),
            ("GET", "/v1/wallets/w1/chain/btc/arbitration"),
            ("GET", "/v1/wallets/w1/chain/d1/finality"),
            ("GET", "/v1/dkg/w1/d"),
        )
        for method, path in reads:
            status, payload = self.request(method, path)
            self.assertIn(status, (200, 404), (path, status, payload))
            self.assertNotIn(status, (409, 503), path)

    def test_active_semantics_unchanged_after_unfreeze(self):
        self.create_wallet()
        self.freeze()
        self.unfreeze()
        status, _ = self.request(
            "PUT",
            "/v1/wallets/w1/approval-policy",
            {"required_approvals": 1, "timeout_seconds": 60},
        )
        self.assertEqual(status, 200)
        status, _ = self.request(
            "POST", "/v1/wallets/w1/sign-requests", {"id": "r1", "message": "m"}
        )
        self.assertEqual(status, 201)


class WalletFreezePersistenceTest(unittest.TestCase):
    def _service(self, tmp):
        return WalletService(WalletStore(tmp))

    def test_state_and_gate_survive_restart(self):
        tmp = tempfile.mkdtemp()
        service = self._service(tmp)
        service.create_wallet("w1", 2)
        self.assertEqual(service.freeze_wallet("w1", "incident")[0], 201)
        # 新进程：同一 data-dir 重新构造服务（启动恢复折叠冻结事件）
        service = self._service(tmp)
        self.assertEqual(
            service.get_security_state("w1"),
            {"wallet_id": "w1", "state": "frozen", "reason": "incident"},
        )
        with self.assertRaises(ServiceError) as ctx:
            service.put_policy("w1", 1, 60)
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(service.unfreeze_wallet("w1", "resolved")[0], 201)
        service = self._service(tmp)
        self.assertEqual(
            service.get_security_state("w1")["state"], "active"
        )
        self.assertEqual(service.put_policy("w1", 1, 60)["wallet_id"], "w1")

    def test_concurrent_freeze_single_201_rest_200_single_event(self):
        tmp = tempfile.mkdtemp()
        self._service(tmp).create_wallet("w1", 2)

        def hit(_):
            return WalletService(WalletStore(tmp), recover=False).freeze_wallet(
                "w1", "same-reason"
            )

        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(hit, range(24)))
        statuses = sorted(status for status, _ in results)
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(200), 23)
        events = AuditStore(tmp).list_events("w1")
        self.assertEqual([e["type"] for e in events], ["wallet_frozen"])
        self.assertEqual(events[0]["seq"], 1)

    def test_dr_backup_restore_preserves_frozen_state_and_seq(self):
        src = tempfile.mkdtemp()
        dst = tempfile.mkdtemp()
        tar_path = os.path.join(tempfile.mkdtemp(), "snap.tar")
        service = self._service(src)
        service.create_wallet("w1", 2)
        service.freeze_wallet("w1", "dr-incident")
        self.assertEqual(backup(src, "w1", "snap-1", tar_path)["status"], 201)
        status, _ = restore(dst, "w1", tar_path)
        self.assertEqual(status, 201)
        restored = self._service(dst)
        self.assertEqual(
            restored.get_security_state("w1"),
            {"wallet_id": "w1", "state": "frozen", "reason": "dr-incident"},
        )
        events = AuditStore(dst).list_events("w1")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["seq"], 1)
        self.assertEqual(events[0]["type"], "wallet_frozen")
        # 冻结闸门随快照恢复：写接口仍 409；同快照重放 200

        with self.assertRaises(ServiceError) as ctx:
            restored.put_policy("w1", 1, 60)
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(restore(dst, "w1", tar_path)[0], 200)
        self.assertEqual(restored.unfreeze_wallet("w1", "fixed")[0], 201)

    def test_frozen_read_does_not_lazy_expire_request(self):
        # 冻结期间查询不允许任何写入：到点 pending 单不懒过期、不记事件；
        # 解冻后首次查询才按既有契约懒过期。
        tmp = tempfile.mkdtemp()
        service = self._service(tmp)
        service.create_wallet("w1", 2)
        service.put_policy("w1", 1, 1)
        self.assertEqual(
            service.create_sign_request("w1", "r1", "m")[0], 201
        )
        service.freeze_wallet("w1", "freeze")
        import time

        time.sleep(1.1)
        view = service.get_sign_request("w1", "r1")
        self.assertEqual(view["state"], "pending")
        events = AuditStore(tmp).list_events("w1")
        self.assertNotIn("request_expired", [e["type"] for e in events])
        service.unfreeze_wallet("w1", "release")
        view = service.get_sign_request("w1", "r1")
        self.assertEqual(view["state"], "expired")
        types_ = [e["type"] for e in AuditStore(tmp).list_events("w1")]
        self.assertIn("request_expired", types_)
        self.assertEqual(
            types_.count("wallet_frozen"), 1
        )
        self.assertEqual(
            types_.count("wallet_unfrozen"), 1
        )


class WalletFreezeRecoveryFailClosedTest(unittest.TestCase):
    def _audit_path(self, tmp, wallet_id="w1"):
        return os.path.join(tmp, "audit", f"{wallet_id}.json")

    def test_corrupt_json_is_corrupt_data_error_and_http_503(self):
        tmp = tempfile.mkdtemp()
        service = WalletService(WalletStore(tmp))
        service.create_wallet("w1", 2)
        service.freeze_wallet("w1", "r")
        with open(self._audit_path(tmp), "w", encoding="utf-8") as f:
            f.write("{broken")
        with self.assertRaises(CorruptDataError):
            WalletService(WalletStore(tmp), recover=False).get_security_state(
                "w1"
            )
        # 启动恢复同样失败（serve 据此拒绝就绪）
        with self.assertRaises(CorruptDataError):
            WalletService(WalletStore(tmp))

    def test_non_alternating_events_are_recovery_error(self):
        tmp = tempfile.mkdtemp()
        service = WalletService(WalletStore(tmp))
        service.create_wallet("w1", 2)
        service.freeze_wallet("w1", "r1")
        service.unfreeze_wallet("w1", "r2")
        path = self._audit_path(tmp)
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        duplicate = dict(data["events"][-1])
        duplicate["seq"] = len(data["events"]) + 1
        data["events"].append(duplicate)
        data["next_seq"] = duplicate["seq"] + 1
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(tmp))
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(tmp), recover=False).freeze_wallet(
                "w1", "r3"
            )

    def test_malformed_freeze_event_details_are_recovery_error(self):
        tmp = tempfile.mkdtemp()
        service = WalletService(WalletStore(tmp))
        service.create_wallet("w1", 2)
        service.freeze_wallet("w1", "r1")
        path = self._audit_path(tmp)
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        data["events"][0]["details"] = {"reason": "   "}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(tmp))


if __name__ == "__main__":
    unittest.main()
