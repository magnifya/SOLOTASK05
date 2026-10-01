"""资产粒度应急冻结/解冻契约测试。

覆盖：
- assets/<asset>/security-state 视图、freeze/unfreeze 的 201/200/409
  幂等与逐资产交替状态机；
- 请求体恰为 {"reason": ...} 的 400 边界、钱包/资产（无已提交操作）404；
- asset_frozen/asset_unfrozen 事件形状、details 绑定资产 id 与原因、
  seq 连续与重放不记；
- 资产 frozen 时改变该资产余额/version/操作状态/链上派发进程的写入口
  统一 409（含幂等重放），其他资产与只读接口不受影响，钱包冻结闸门
  优先；
- 重启与灾备恢复后状态折叠一致、seq 不变；
- 跨进程（多线程）并发同一操作只有一个 201；
- 损坏 JSON / 自相矛盾现场 fail-closed（503、拒绝就绪）。
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from threshold_wallet.audit import AuditStore
from threshold_wallet.drbackup import backup, restore
from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import CorruptDataError, RecoveryError, WalletStore
from tests.helpers import http_server

HEX32 = "a" * 64


class AssetFreezeHttpTest(unittest.TestCase):
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

    def commit_op(self, operation_id, asset_id, delta, wallet_id="w1"):
        status, body = self.request(
            "POST",
            f"/v1/wallets/{wallet_id}/asset-operations",
            {"operation_id": operation_id, "asset_id": asset_id,
             "delta": delta},
        )
        self.assertEqual(status, 201, body)
        status, body = self.request(
            "POST",
            f"/v1/wallets/{wallet_id}/asset-operations/{operation_id}/commit",
        )
        self.assertEqual(status, 201, body)

    def pending_op(self, operation_id, asset_id, delta, wallet_id="w1"):
        status, body = self.request(
            "POST",
            f"/v1/wallets/{wallet_id}/asset-operations",
            {"operation_id": operation_id, "asset_id": asset_id,
             "delta": delta},
        )
        self.assertEqual(status, 201, body)

    def freeze(self, reason="incident", asset_id="btc", wallet_id="w1"):
        return self.request(
            "POST",
            f"/v1/wallets/{wallet_id}/assets/{asset_id}/freeze",
            {"reason": reason},
        )

    def unfreeze(self, reason="resolved", asset_id="btc", wallet_id="w1"):
        return self.request(
            "POST",
            f"/v1/wallets/{wallet_id}/assets/{asset_id}/unfreeze",
            {"reason": reason},
        )

    def state(self, asset_id="btc", wallet_id="w1"):
        return self.request(
            "GET", f"/v1/wallets/{wallet_id}/assets/{asset_id}/security-state"
        )

    def test_default_state_is_active_with_null_reason(self):
        self.create_wallet()
        self.commit_op("o1", "btc", 5)
        status, body = self.state()
        self.assertEqual(status, 200)
        self.assertEqual(
            body,
            {"wallet_id": "w1", "asset_id": "btc",
             "state": "active", "reason": None},
        )

    def test_freeze_unfreeze_transitions_and_views(self):
        self.create_wallet()
        self.commit_op("o1", "btc", 5)
        status, body = self.freeze("incident-1")
        self.assertEqual(status, 201)
        self.assertEqual(
            body,
            {"wallet_id": "w1", "asset_id": "btc",
             "state": "frozen", "reason": "incident-1"},
        )
        self.assertEqual(self.freeze("incident-1")[0], 200)
        self.assertEqual(self.freeze("other")[0], 409)
        self.assertEqual(self.state()[1]["reason"], "incident-1")
        status, body = self.unfreeze("resolved-1")
        self.assertEqual(status, 201)
        self.assertEqual(
            body,
            {"wallet_id": "w1", "asset_id": "btc",
             "state": "active", "reason": None},
        )
        self.assertEqual(self.unfreeze("resolved-1")[0], 200)
        self.assertEqual(self.unfreeze("different")[0], 409)
        self.assertEqual(self.freeze("incident-2")[0], 201)
        self.assertEqual(self.state()[1]["reason"], "incident-2")

    def test_unfreeze_never_frozen_asset_is_409(self):
        self.create_wallet()
        self.commit_op("o1", "btc", 5)
        self.assertEqual(self.unfreeze("resolved")[0], 409)
        self.assertEqual(self.state()[1]["state"], "active")

    def test_asset_states_are_independent(self):
        self.create_wallet()
        self.commit_op("o1", "btc", 5)
        self.commit_op("e1", "eth", 3)
        self.assertEqual(self.freeze("btc-only")[0], 201)
        self.assertEqual(self.state("btc")[1]["state"], "frozen")
        self.assertEqual(self.state("eth")[1]["state"], "active")
        # 其他资产的写入口不受影响
        self.commit_op("e2", "eth", 2)
        status, _ = self.request(
            "PUT",
            "/v1/wallets/w1/chain/eth",
            {"chain_id": "c", "enabled": True,
             "required_confirmations": 1, "reorg_window": 0},
        )
        self.assertEqual(status, 200)

    def test_unknown_wallet_or_asset_without_committed_ops_is_404(self):
        self.create_wallet()
        self.pending_op("p1", "btc", 1)  # 仅 pending，无已提交操作
        for method, path, body in (
            ("GET", "/v1/wallets/ghost/assets/btc/security-state", None),
            ("POST", "/v1/wallets/ghost/assets/btc/freeze",
             {"reason": "x"}),
            ("POST", "/v1/wallets/ghost/assets/btc/unfreeze",
             {"reason": "x"}),
            ("GET", "/v1/wallets/w1/assets/btc/security-state", None),
            ("POST", "/v1/wallets/w1/assets/btc/freeze", {"reason": "x"}),
            ("POST", "/v1/wallets/w1/assets/btc/unfreeze", {"reason": "x"}),
            ("GET", "/v1/wallets/w1/assets/ghost/security-state", None),
            ("POST", "/v1/wallets/w1/assets/ghost/freeze", {"reason": "x"}),
        ):
            status, payload = self.request(method, path, body)
            self.assertEqual(status, 404, (path, payload))

    def test_freeze_body_must_be_exactly_reason_object(self):
        self.create_wallet()
        self.commit_op("o1", "btc", 5)
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
                "POST", "/v1/wallets/w1/assets/btc/freeze", body
            )
            self.assertEqual(status, 400, (body, payload))
            status, payload = self.request(
                "POST", "/v1/wallets/w1/assets/btc/unfreeze", body
            )
            self.assertEqual(status, 400, (body, payload))
        self.assertEqual(self.freeze("x" * 1024)[0], 201)
        self.assertEqual(self.unfreeze("  z  ")[0], 201)

    def test_raw_invalid_or_non_object_json_is_400(self):
        import urllib.error
        import urllib.request

        self.create_wallet()
        self.commit_op("o1", "btc", 5)
        for raw in (b"", b"{broken", b"[1,2]", b"123"):
            req = urllib.request.Request(
                self.url + "/v1/wallets/w1/assets/btc/freeze",
                data=raw,
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req)
            self.assertEqual(ctx.exception.code, 400)

    def test_state_persisted_only_by_audit_events(self):
        self.create_wallet()
        self.commit_op("o1", "btc", 5)
        self.commit_op("e1", "eth", 3)
        self.freeze("r1")
        self.freeze("r1")  # 重放不记
        self.unfreeze("r2")
        self.freeze("r3")
        self.freeze("e1", asset_id="eth")
        status, payload = self.request("GET", "/v1/wallets/w1/audit-events")
        self.assertEqual(status, 200)
        events = [
            event
            for event in payload["events"]
            if event["type"] in ("asset_frozen", "asset_unfrozen")
        ]
        self.assertEqual(
            [event["type"] for event in events],
            [
                "asset_frozen",
                "asset_unfrozen",
                "asset_frozen",
                "asset_frozen",
            ],
        )
        # 资产事件与其余事件共用同一连续 seq 序列
        all_events = payload["events"]
        self.assertEqual(
            [event["seq"] for event in all_events],
            list(range(1, len(all_events) + 1)),
        )
        for event in events:
            self.assertEqual(
                set(event),
                {
                    "seq", "type", "at", "request_id", "actor_id",
                    "reason", "details",
                },
            )
            self.assertIsNone(event["request_id"])
            self.assertIsNone(event["actor_id"])
            self.assertIsNone(event["reason"])
            self.assertEqual(set(event["details"]), {"asset_id", "reason"})
        self.assertEqual(
            [event["details"] for event in events],
            [
                {"asset_id": "btc", "reason": "r1"},
                {"asset_id": "btc", "reason": "r2"},
                {"asset_id": "btc", "reason": "r3"},
                {"asset_id": "eth", "reason": "e1"},
            ],
        )

    def test_frozen_asset_writes_all_conflict(self):
        self.create_wallet()
        self.commit_op("o1", "btc", 5)
        self.pending_op("o2", "btc", 1)
        # 真实的在途派发：result/confirm/takeover/isolate/settle 的闸门
        # 需要派发存在才能越过 404
        self.pending_op("o3", "btc", 1)
        self.request(
            "PUT",
            "/v1/wallets/w1/chain/btc",
            {"chain_id": "c", "enabled": True,
             "required_confirmations": 1, "reorg_window": 0},
        )
        self.request(
            "PUT",
            "/v1/wallets/w1/approval-policy",
            {"required_approvals": 1, "timeout_seconds": 600},
        )
        message = json.dumps(
            {"operation_id": "o3", "dispatch_id": "d1",
             "adapter_id": "a1", "chain_id": "c"},
            separators=(",", ":"),
        )
        self.request(
            "POST", "/v1/wallets/w1/sign-requests",
            {"id": "ap1", "message": message},
        )
        self.request(
            "POST", "/v1/wallets/w1/sign-requests/ap1/approve",
            {"approver_id": "boss"},
        )
        status, body = self.request(
            "POST",
            "/v1/wallets/w1/chain/o3/dispatch",
            {"dispatch_id": "d1", "adapter_id": "a1",
             "approval_request_id": "ap1"},
        )
        self.assertEqual(status, 201, body)

        self.assertEqual(self.freeze()[0], 201)
        writes = (
            ("POST", "/v1/wallets/w1/asset-operations",
             {"operation_id": "o4", "asset_id": "btc", "delta": 1}),
            ("POST", "/v1/wallets/w1/asset-operations/o2/commit", None),
            ("POST", "/v1/wallets/w1/asset-operations/o1/commit", None),
            ("POST", "/v1/wallets/w1/asset-operations/o2/cancel",
             {"cancel_id": "cx", "approval_request_id": "ap1"}),
            ("PUT", "/v1/wallets/w1/chain/btc",
             {"chain_id": "c", "enabled": True,
              "required_confirmations": 1, "reorg_window": 0}),
            ("PUT", "/v1/wallets/w1/chain/btc/arbitration",
             {"sources": {"s1": True, "s2": True}, "quorum": 2}),
            ("POST", "/v1/wallets/w1/chain/o2/report",
             {"chain_id": "c", "tx_id": HEX32, "block_height": 1,
              "block_hash": HEX32, "confirmations": 1}),
            ("POST", "/v1/wallets/w1/chain/o2/observe",
             {"source": "s1",
              "report": {"chain_id": "c", "tx_id": HEX32,
                         "block_height": 1, "block_hash": HEX32,
                         "confirmations": 1}}),
            ("POST", "/v1/wallets/w1/chain/o2/dispatch",
             {"dispatch_id": "d2", "adapter_id": "a1",
              "approval_request_id": "ap1"}),
            ("POST", "/v1/wallets/w1/chain/o2/dispatch-auto",
             {"dispatch_id": "d3", "approval_request_id": "ap1"}),
            # 已在途派发的推进与幂等重放一律 409
            ("POST", "/v1/wallets/w1/chain/o3/dispatch",
             {"dispatch_id": "d1", "adapter_id": "a1",
              "approval_request_id": "ap1"}),
            ("POST", "/v1/wallets/w1/chain/d1/result",
             {"adapter_id": "a1", "state": "failed", "tx_id": None}),
            ("POST", "/v1/wallets/w1/chain/d1/confirm",
             {"adapter_id": "a1", "tx_id": HEX32, "block_height": 1,
              "block_hash": HEX32, "confirmations": 1}),
            ("POST", "/v1/wallets/w1/chain/d1/takeover",
             {"adapter_id": "a2", "approval_request_id": "ap1"}),
            ("POST", "/v1/wallets/w1/chain/d1/isolate", {}),
            ("POST", "/v1/wallets/w1/chain/d1/settle", None),
        )
        for method, path, body in writes:
            status, payload = self.request(method, path, body)
            self.assertEqual(status, 409, (method, path, payload))
        # 零副作用：只有一条 asset_frozen 事件
        events = self.request("GET", "/v1/wallets/w1/audit-events")[1][
            "events"
        ]
        self.assertEqual(
            [
                e["type"]
                for e in events
                if e["type"] in ("asset_frozen", "asset_unfrozen")
            ],
            ["asset_frozen"],
        )
        # 账本/操作/派发现场不变
        asset = self.request("GET", "/v1/wallets/w1/assets/btc")[1]
        self.assertEqual(asset["balance"], 5)
        self.assertEqual(asset["version"], 1)
        op = self.request("GET", "/v1/wallets/w1/asset-operations/o2")[1]
        self.assertEqual(op["state"], "pending")

    def test_frozen_asset_reads_and_other_writes_remain(self):
        self.create_wallet()
        self.commit_op("o1", "btc", 5)
        self.freeze()
        reads = (
            ("GET", "/v1/wallets/w1"),
            ("GET", "/v1/wallets/w1/security-state"),
            ("GET", "/v1/wallets/w1/assets/btc"),
            ("GET", "/v1/wallets/w1/assets/btc/security-state"),
            ("GET", "/v1/wallets/w1/audit-events"),
            ("GET", "/v1/wallets/w1/asset-operations/o1"),
            ("GET", "/v1/wallets/w1/chain/btc"),
        )
        for method, path in reads:
            status, payload = self.request(method, path)
            self.assertIn(status, (200, 404), (path, status, payload))
            self.assertNotIn(status, (409, 503), path)
        # 与资产无关的既有写接口不受资产冻结影响
        status, _ = self.request(
            "PUT",
            "/v1/wallets/w1/approval-policy",
            {"required_approvals": 1, "timeout_seconds": 60},
        )
        self.assertEqual(status, 200)
        status, _ = self.request(
            "POST", "/v1/wallets/w1/sign-requests",
            {"id": "r1", "message": "m"},
        )
        self.assertEqual(status, 201)

    def test_wallet_freeze_gate_takes_priority(self):
        self.create_wallet()
        self.commit_op("o1", "btc", 5)
        self.freeze("asset-level")
        self.request("POST", "/v1/wallets/w1/freeze", {"reason": "w"})
        # 钱包冻结期间资产 freeze/unfreeze 之外的全部写入口 409；
        # 资产级 freeze/unfreeze/security-state 也不可用（钱包闸门优先）
        status, _ = self.freeze("asset-level")
        self.assertEqual(status, 409)
        status, _ = self.unfreeze("asset-level")
        self.assertEqual(status, 409)
        status, _ = self.state()
        self.assertEqual(status, 200)

    def test_active_semantics_unchanged_after_unfreeze(self):
        self.create_wallet()
        self.commit_op("o1", "btc", 5)
        self.freeze()
        self.unfreeze()
        self.commit_op("o2", "btc", 2)
        asset = self.request("GET", "/v1/wallets/w1/assets/btc")[1]
        self.assertEqual(asset["balance"], 7)
        self.assertEqual(asset["version"], 2)


class AssetFreezePersistenceTest(unittest.TestCase):
    def _service(self, tmp):
        return WalletService(WalletStore(tmp))

    def _committed_wallet(self, service, wallet_id="w1"):
        service.create_wallet(wallet_id, 2)
        service.create_asset_operation(wallet_id, "o1", "btc", 5)
        service.commit_asset_operation(wallet_id, "o1")

    def test_state_and_gate_survive_restart(self):
        tmp = tempfile.mkdtemp()
        service = self._service(tmp)
        self._committed_wallet(service)
        self.assertEqual(
            service.freeze_asset("w1", "btc", "incident")[0], 201
        )
        # 新进程：同一 data-dir 重新构造服务（启动恢复折叠冻结事件）
        service = self._service(tmp)
        self.assertEqual(
            service.get_asset_security_state("w1", "btc"),
            {"wallet_id": "w1", "asset_id": "btc",
             "state": "frozen", "reason": "incident"},
        )
        with self.assertRaises(ServiceError) as ctx:
            service.create_asset_operation("w1", "o2", "btc", 1)
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(
            service.unfreeze_asset("w1", "btc", "resolved")[0], 201
        )
        service = self._service(tmp)
        self.assertEqual(
            service.get_asset_security_state("w1", "btc")["state"], "active"
        )
        self.assertEqual(
            service.create_asset_operation("w1", "o2", "btc", 1)[0], 201
        )

    def test_concurrent_freeze_single_201_rest_200_single_event(self):
        tmp = tempfile.mkdtemp()
        self._committed_wallet(self._service(tmp))

        def hit(_):
            return WalletService(
                WalletStore(tmp), recover=False
            ).freeze_asset("w1", "btc", "same-reason")

        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(hit, range(24)))
        statuses = sorted(status for status, _ in results)
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(200), 23)
        events = [
            event
            for event in AuditStore(tmp).list_events("w1")
            if event["type"] == "asset_frozen"
        ]
        self.assertEqual(len(events), 1)

    def test_dr_backup_restore_preserves_frozen_state_and_seq(self):
        src = tempfile.mkdtemp()
        dst = tempfile.mkdtemp()
        tar_path = os.path.join(tempfile.mkdtemp(), "snap.tar")
        service = self._service(src)
        self._committed_wallet(service)
        service.freeze_asset("w1", "btc", "dr-incident")
        self.assertEqual(backup(src, "w1", "snap-1", tar_path)["status"], 201)
        status, _ = restore(dst, "w1", tar_path)
        self.assertEqual(status, 201)
        restored = self._service(dst)
        self.assertEqual(
            restored.get_asset_security_state("w1", "btc"),
            {"wallet_id": "w1", "asset_id": "btc",
             "state": "frozen", "reason": "dr-incident"},
        )
        events = [
            event
            for event in AuditStore(dst).list_events("w1")
            if event["type"] == "asset_frozen"
        ]
        self.assertEqual(len(events), 1)
        # 冻结闸门随快照恢复：该资产写入口仍 409；同快照重放 200
        with self.assertRaises(ServiceError) as ctx:
            restored.create_asset_operation("w1", "o2", "btc", 1)
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(restore(dst, "w1", tar_path)[0], 200)
        self.assertEqual(
            restored.unfreeze_asset("w1", "btc", "fixed")[0], 201
        )


class AssetFreezeRecoveryFailClosedTest(unittest.TestCase):
    def _audit_path(self, tmp, wallet_id="w1"):
        return os.path.join(tmp, "audit", f"{wallet_id}.json")

    def _frozen_wallet(self, tmp):
        service = WalletService(WalletStore(tmp))
        service.create_wallet("w1", 2)
        service.create_asset_operation("w1", "o1", "btc", 5)
        service.commit_asset_operation("w1", "o1")
        service.freeze_asset("w1", "btc", "r1")
        return service

    def test_corrupt_json_is_corrupt_data_error(self):
        tmp = tempfile.mkdtemp()
        self._frozen_wallet(tmp)
        with open(self._audit_path(tmp), "w", encoding="utf-8") as f:
            f.write("{broken")
        with self.assertRaises(CorruptDataError):
            WalletService(
                WalletStore(tmp), recover=False
            ).get_asset_security_state("w1", "btc")
        # 启动恢复同样失败（serve 据此拒绝就绪）
        with self.assertRaises(CorruptDataError):
            WalletService(WalletStore(tmp))

    def test_non_alternating_events_are_recovery_error(self):
        tmp = tempfile.mkdtemp()
        service = self._frozen_wallet(tmp)
        service.unfreeze_asset("w1", "btc", "r2")
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
            WalletService(WalletStore(tmp), recover=False).freeze_asset(
                "w1", "btc", "r3"
            )

    def test_malformed_freeze_event_details_are_recovery_error(self):
        tmp = tempfile.mkdtemp()
        self._frozen_wallet(tmp)
        path = self._audit_path(tmp)
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        target = next(
            event
            for event in data["events"]
            if event["type"] == "asset_frozen"
        )
        target["details"] = {"asset_id": "btc", "reason": "   "}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(tmp))

    def test_missing_asset_id_in_details_is_recovery_error(self):
        tmp = tempfile.mkdtemp()
        self._frozen_wallet(tmp)
        path = self._audit_path(tmp)
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        target = next(
            event
            for event in data["events"]
            if event["type"] == "asset_frozen"
        )
        target["details"] = {"reason": "r1"}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(tmp))

    def test_corrupt_scene_http_503(self):
        tmp = tempfile.mkdtemp()
        ctx = http_server(tmp)
        srv = ctx.__enter__()
        try:
            srv.request("POST", "/v1/wallets", {"wallet_id": "w1",
                                                "shares": 2})
            srv.request(
                "POST", "/v1/wallets/w1/asset-operations",
                {"operation_id": "o1", "asset_id": "btc", "delta": 5},
            )
            srv.request(
                "POST", "/v1/wallets/w1/asset-operations/o1/commit"
            )
            srv.request(
                "POST", "/v1/wallets/w1/assets/btc/freeze",
                {"reason": "r1"},
            )
            # 服务运行期间审计日志被外部破坏：持锁访问 fail-closed 503
            with open(self._audit_path(tmp), "w", encoding="utf-8") as f:
                f.write("{broken")
            status, _ = srv.request(
                "GET", "/v1/wallets/w1/assets/btc/security-state"
            )
            self.assertEqual(status, 503)
            status, _ = srv.request(
                "POST", "/v1/wallets/w1/assets/btc/unfreeze",
                {"reason": "r2"},
            )
            self.assertEqual(status, 503)
        finally:
            ctx.__exit__(None, None, None)


if __name__ == "__main__":
    unittest.main()
