"""审计防篡改摘要链与 GET audit-integrity 的回归测试。

覆盖：
- chain 元数据随追加原子落盘，重启/并发后续写，count/seq/head 一致；
- 旧记录缺链时追加即按事件顺序补算（不改写事件正文）；
- audit-integrity 的 200/400/404/405/409 与篡改现场一律 503；
- 冻结钱包仍可查询完整性；
- backup/restore 随快照携带并校验链，篡改快照恢复失败且不写目标。
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import threading
import unittest

from tests.helpers import http_server
from threshold_wallet import audit as audit_mod
from threshold_wallet import drbackup
from threshold_wallet.service import WalletService
from threshold_wallet.store import RecoveryError, WalletStore


def _audit_path(data_dir: str, wallet_id: str = "w1") -> str:
    return os.path.join(data_dir, "audit", wallet_id + ".json")


def _load_audit(data_dir: str, wallet_id: str = "w1") -> dict:
    with open(_audit_path(data_dir, wallet_id), encoding="utf-8") as f:
        return json.load(f)


def _dump_audit(data_dir: str, data: dict, wallet_id: str = "w1") -> None:
    with open(_audit_path(data_dir, wallet_id), "w", encoding="utf-8") as f:
        json.dump(data, f)


def _event(**over) -> dict:
    event = {
        "type": "policy_updated",
        "at": "2026-09-20T00:00:00Z",
        "request_id": None,
        "actor_id": None,
        "reason": None,
        "details": {},
    }
    event.update(over)
    return event


class AuditChainStorageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_chain_written_on_append_and_matches_vector(self):
        store = audit_mod.AuditStore(self.tmp)
        e1 = _event(details={"z": 1, "a": 2})
        s1 = store.append_event("w1", e1)
        log = _load_audit(self.tmp)
        self.assertEqual(set(log), {"wallet_id", "next_seq", "events", "chain"})
        self.assertEqual(
            log["chain"],
            {"algorithm": "sha256", "head": log["chain"]["head"],
             "count": 1},
        )
        self.assertEqual(set(log["chain"]), {"algorithm", "head", "count"})
        head = audit_mod.GENESIS_HEAD
        for stamped in (s1,):
            digest = audit_mod._event_digest(stamped)
            head = hashlib.sha256((head + digest).encode("ascii")).hexdigest()
        self.assertEqual(log["chain"]["head"], head)

    def test_chain_survives_restart_and_concurrent_appends(self):
        store = audit_mod.AuditStore(self.tmp)
        store.append_event("w1", _event())

        store = audit_mod.AuditStore(self.tmp)

        def append_one(k: int) -> None:
            store.append_event(
                "w1", _event(at=f"2026-09-20T00:00:{k:02d}Z")
            )

        threads = [
            threading.Thread(target=append_one, args=(k,)) for k in range(9)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        count, head = audit_mod.AuditStore(self.tmp).integrity("w1")
        log = _load_audit(self.tmp)
        self.assertEqual(count, 10)
        self.assertEqual(len(log["events"]), 10)
        self.assertEqual(
            [e["seq"] for e in log["events"]], list(range(1, 11))
        )
        self.assertEqual(log["chain"]["count"], 10)
        self.assertEqual(log["chain"]["head"], head)

    def test_legacy_log_without_chain_is_backfilled_on_append(self):
        store = audit_mod.AuditStore(self.tmp)
        store.append_event("w1", _event())
        log = _load_audit(self.tmp)
        del log["chain"]
        _dump_audit(self.tmp, log)
        # 缺链的旧记录：完整性校验视为不可对账（503），不静默通过
        with self.assertRaises(RecoveryError):
            audit_mod.AuditStore(self.tmp).integrity("w1")
        # 追加时按既有事件顺序补算，事件正文不变
        before = json.dumps(log["events"], sort_keys=True, ensure_ascii=False)
        store.append_event("w1", _event(at="2026-09-20T00:00:01Z"))
        after = _load_audit(self.tmp)
        self.assertEqual(
            json.dumps(after["events"][:1], sort_keys=True,
                       ensure_ascii=False),
            before,
        )
        count, head = audit_mod.AuditStore(self.tmp).integrity("w1")
        self.assertEqual((count, after["chain"]["head"]), (2, head))

    def test_tampered_chain_never_overwritten(self):
        store = audit_mod.AuditStore(self.tmp)
        store.append_event("w1", _event())
        log = _load_audit(self.tmp)
        log["chain"]["head"] = "0" * 64
        _dump_audit(self.tmp, log)
        with self.assertRaises(RecoveryError):
            store.backfill_chain("w1")
        with self.assertRaises(RecoveryError):
            store.append_event("w1", _event())
        self.assertEqual(_load_audit(self.tmp)["chain"]["head"], "0" * 64)


class AuditIntegrityHttpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _wallet_with_event(self, srv) -> str:
        srv.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
        srv.request(
            "PUT",
            "/v1/wallets/w1/approval-policy",
            {"required_approvals": 1, "timeout_seconds": 60},
        )
        status, body = srv.request(
            "GET", "/v1/wallets/w1/audit-integrity", None
        )
        self.assertEqual(status, 200, body)
        return body["head"]

    def test_get_integrity_and_expected_head(self):
        with http_server(self.tmp) as srv:
            head = self._wallet_with_event(srv)
            status, body = srv.request(
                "GET",
                f"/v1/wallets/w1/audit-integrity?expected_head={head}",
                None,
            )
            self.assertEqual(status, 200, body)
            self.assertEqual(
                body,
                {
                    "wallet_id": "w1",
                    "state": "valid",
                    "count": 1,
                    "head": head,
                },
            )
            wrong = ("a" if head[0] != "a" else "b") + head[1:]
            status, body = srv.request(
                "GET",
                f"/v1/wallets/w1/audit-integrity?expected_head={wrong}",
                None,
            )
            self.assertEqual(status, 409, body)

    def test_errors_400_404_405(self):
        with http_server(self.tmp) as srv:
            srv.request("POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2})
            for bad in ("zzz", "0" * 63, "0" * 65, "A" * 64):
                status, body = srv.request(
                    "GET",
                    f"/v1/wallets/w1/audit-integrity?expected_head={bad}",
                    None,
                )
                self.assertEqual(status, 400, (bad, body))
            status, _ = srv.request(
                "GET", "/v1/wallets/ghost/audit-integrity", None
            )
            self.assertEqual(status, 404)
            status, _ = srv.request(
                "GET", "/v1/wallets/bad%2Fid/audit-integrity", None
            )
            self.assertEqual(status, 400)
            for method, body in (
                ("POST", {}),
                ("PUT", {}),
                ("DELETE", None),
                ("PATCH", {}),
            ):
                status, resp = srv.request(
                    method, "/v1/wallets/w1/audit-integrity", body
                )
                self.assertEqual(status, 405, (method, resp))

    def test_frozen_wallet_still_queryable(self):
        with http_server(self.tmp) as srv:
            head = self._wallet_with_event(srv)
            status, _ = srv.request(
                "POST",
                "/v1/wallets/w1/freeze",
                {"reason": "incident"},
            )
            self.assertIn(status, (200, 201))
            status, body = srv.request(
                "GET", "/v1/wallets/w1/audit-integrity", None
            )
            self.assertEqual(status, 200, body)
            self.assertEqual(body["state"], "valid")
            self.assertEqual(body["count"], 2)
            self.assertNotEqual(body["head"], head)

    def test_empty_wallet_reports_genesis_head(self):
        with http_server(self.tmp) as srv:
            srv.request("POST", "/v1/wallets", {"wallet_id": "w2", "shares": 2})
            status, body = srv.request(
                "GET", "/v1/wallets/w2/audit-integrity", None
            )
            self.assertEqual(status, 200, body)
            self.assertEqual(body["count"], 0)
            self.assertEqual(body["head"], "0" * 64)

    def test_tampered_events_return_503(self):
        with http_server(self.tmp) as srv:
            self._wallet_with_event(srv)
            log = _load_audit(self.tmp)
            log["events"][0]["details"]["timeout_seconds"] += 1
            _dump_audit(self.tmp, log)
            status, body = srv.request(
                "GET", "/v1/wallets/w1/audit-integrity", None
            )
            self.assertEqual(status, 503, body)

    def test_legacy_missing_chain_is_backfilled_at_startup(self):
        with http_server(self.tmp) as srv:
            self._wallet_with_event(srv)
        log = _load_audit(self.tmp)
        expected_head = log["chain"]["head"]
        del log["chain"]
        _dump_audit(self.tmp, log)
        with http_server(self.tmp) as srv:
            status, body = srv.request(
                "GET", "/v1/wallets/w1/audit-integrity", None
            )
            self.assertEqual(status, 200, body)
            self.assertEqual(body["state"], "valid")
            self.assertEqual(body["head"], expected_head)
        # 启动补链只新增 chain 对象：事件正文、seq 与事件数不变
        migrated = _load_audit(self.tmp)
        self.assertEqual(migrated["chain"]["head"], expected_head)
        self.assertEqual(migrated["chain"]["count"], 1)
        self.assertEqual(len(migrated["events"]), 1)

    def test_mismatched_chain_refuses_readiness(self):
        with http_server(self.tmp) as srv:
            self._wallet_with_event(srv)
        log = _load_audit(self.tmp)
        log["chain"]["head"] = "0" * 64
        _dump_audit(self.tmp, log)
        # chain 与事件重算结果不符：serve 必须拒绝就绪
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmp))


class AuditChainBackupRestoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.out = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.addCleanup(shutil.rmtree, self.out, ignore_errors=True)

    def test_chain_flows_through_backup_restore(self):
        svc = WalletService(WalletStore(self.tmp))
        svc.create_wallet("w1", 2)
        svc.put_policy("w1", 1, 60)
        snap = os.path.join(self.out, "s.tar")
        drbackup.backup(self.tmp, "w1", "snap1", snap)
        target = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, target, ignore_errors=True)
        status, _ = drbackup.restore(target, "w1", snap)
        self.assertIn(status, (200, 201))
        restored = WalletService(WalletStore(target))
        view = restored.get_audit_integrity("w1")
        self.assertEqual(view["state"], "valid")
        self.assertEqual(view["count"], 1)

    def test_backup_backfills_legacy_chain_without_new_events(self):
        svc = WalletService(WalletStore(self.tmp))
        svc.create_wallet("w1", 2)
        svc.put_policy("w1", 1, 60)
        log = _load_audit(self.tmp)
        del log["chain"]
        _dump_audit(self.tmp, log)
        drbackup.backup(
            self.tmp, "w1", "snap1", os.path.join(self.out, "s.tar")
        )
        migrated = _load_audit(self.tmp)
        self.assertEqual(migrated["chain"]["count"], 1)
        self.assertEqual(len(migrated["events"]), 1)


if __name__ == "__main__":
    unittest.main()
