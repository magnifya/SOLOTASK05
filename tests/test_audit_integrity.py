"""审计完整性、账本语义与账本↔审计双向对账的 fail-closed 回归。

覆盖跨进程一致性任务中"损坏或语义矛盾的账本、意图、审计数据必须保留
现场并 fail-closed"对审计与账本语义层的补充契约：

- 审计文件 JSON 损坏、顶层非对象、events 非列表、事件七字段形状非法、
  seq 不从 1 起/不连续/重号、next_seq 与事件矛盾时，严格加载一律
  CorruptDataError；append 绝不清空历史后继续写；
- 仅持有审计数据的钱包（如只设过策略）审计损坏时，启动扫描必须发现并
  阻止就绪，serve 非零退出；
- 账本 JSON 合法但语义矛盾（committed version 不连续、余额重算不符、
  无提交却有资产条目、pending 快照不属任何提交前缀）时 fail-closed；
- committed 操作与 asset_operation_committed 事件必须一一对应：
  提交无事件、事件无提交、details 不符、重复事件均阻止就绪/返回 503。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from tests.helpers import http_server
from threshold_wallet.audit import AuditStore
from threshold_wallet.service import WalletService
from threshold_wallet.store import CorruptDataError, RecoveryError, WalletStore


def _write(path: str, payload: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(payload)


def _audit_path(data_dir: str, wallet_id: str = "w1") -> str:
    return os.path.join(data_dir, "audit", wallet_id + ".json")


def _ledger_path(data_dir: str, wallet_id: str = "w1") -> str:
    return os.path.join(data_dir, "assets", wallet_id + ".json")


def _load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _dump_json(path: str, data) -> None:
    with open(path, "w", encoding="utf-8") as f:
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


# ---- 审计文件严格加载 ------------------------------------------------------


class AuditStrictLoadTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.audit = AuditStore(self.tmp)
        self.audit.append_event("w1", _event())

    def _expect_corrupt(self, payload: str) -> None:
        _write(_audit_path(self.tmp), payload)
        with self.assertRaises(CorruptDataError):
            self.audit.check_log("w1")
        with self.assertRaises(CorruptDataError):
            self.audit.list_events("w1")
        with self.assertRaises(CorruptDataError):
            self.audit.append_event("w1", _event(type="request_created"))

    def test_missing_file_is_normal_empty(self):
        self.audit.check_log("ghost")
        self.assertEqual(self.audit.list_events("ghost"), [])

    def test_empty_events_is_valid(self):
        # 只有 events: [] 的日志合法（next_seq 字段缺省容忍）
        _write(_audit_path(self.tmp, "w2"), '{"events": []}')
        self.audit.check_log("w2")

    def test_json_and_shape_corruption_rejected(self):
        self._expect_corrupt("{broken")
        self._expect_corrupt("[1, 2]")
        self._expect_corrupt('{"wallet_id": "other", "events": []}')
        self._expect_corrupt('{"events": "nope"}')

    def test_malformed_event_rejected(self):
        good = _load_json(_audit_path(self.tmp))
        base = json.dumps(good["events"][0])
        bad_events = [
            '{"seq": 1}',  # 缺字段
            base.replace('"seq": 1', '"seq": 0'),
            base.replace('"seq": 1', '"seq": true'),
            base.replace('"seq": 1', '"seq": "1"'),
            base.replace('"type": "policy_updated"', '"type": ""'),
            base.replace('"2026-09-20T00:00:00Z"', '"nonsense"'),
            base.replace('"2026-09-20T00:00:00Z"', '"2026-09-20T00:00:00"'),
            base.replace('"details": {}', '"details": []'),
            base.replace('"request_id": null', '"request_id": 7'),
        ]
        for raw in bad_events:
            good["events"] = [json.loads(raw)]
            good["next_seq"] = 2
            _dump_json(_audit_path(self.tmp), good)
            with self.subTest(raw=raw[:40]):
                with self.assertRaises(CorruptDataError):
                    self.audit.check_log("w1")

    def test_seq_contiguity_enforced(self):
        good = _load_json(_audit_path(self.tmp))
        self.audit.append_event("w1", _event())  # seq 2
        good = _load_json(_audit_path(self.tmp))
        # 重号
        dup = json.loads(json.dumps(good))
        dup["events"][1]["seq"] = 1
        _dump_json(_audit_path(self.tmp), dup)
        with self.assertRaises(CorruptDataError):
            self.audit.check_log("w1")
        # 缺口（删 seq1，只留 seq2）
        gap = json.loads(json.dumps(good))
        gap["events"] = [gap["events"][1]]
        gap["next_seq"] = 3
        _dump_json(_audit_path(self.tmp), gap)
        with self.assertRaises(CorruptDataError):
            self.audit.check_log("w1")
        # next_seq 矛盾
        bad_next = json.loads(json.dumps(good))
        bad_next["next_seq"] = 99
        _dump_json(_audit_path(self.tmp), bad_next)
        with self.assertRaises(CorruptDataError):
            self.audit.check_log("w1")

    def test_append_on_corrupt_log_keeps_history(self):
        raw_before = open(_audit_path(self.tmp), encoding="utf-8").read()
        _write(_audit_path(self.tmp), "{broken")
        with self.assertRaises(CorruptDataError):
            self.audit.append_event("w1", _event())
        # 历史现场原样保留，绝不被归一为空日志覆盖
        self.assertEqual(
            open(_audit_path(self.tmp), encoding="utf-8").read(), "{broken"
        )
        del raw_before  # 健康文件内容仅用于对照

    def test_healthy_log_still_appends_contiguously(self):
        self.audit.append_event("w1", _event())
        self.audit.append_event("w1", _event())
        reopened = AuditStore(self.tmp)
        stamped = reopened.append_event("w1", _event())
        self.assertEqual(stamped["seq"], 4)
        self.assertEqual(
            [e["seq"] for e in reopened.list_events("w1")], [1, 2, 3, 4]
        )


# ---- 启动扫描：纯审计钱包损坏也必须阻止就绪 --------------------------------


class AuditStartupScanTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _audit_only_wallet(self) -> None:
        svc = WalletService(WalletStore(self.tmp))
        svc.create_wallet("w1", 2)
        svc.put_policy("w1", 1, 3600)  # 只产生审计事件，无账本/会话文件

    def test_corrupt_audit_blocks_readiness_without_other_files(self):
        self._audit_only_wallet()
        self.assertFalse(
            os.path.exists(_ledger_path(self.tmp))
        )
        _write(_audit_path(self.tmp), "{broken")
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmp))

    def test_serve_cli_refuses_to_start_on_corrupt_audit(self):
        from threshold_wallet import cli

        self._audit_only_wallet()
        _write(_audit_path(self.tmp), "{broken")
        code = cli.main(
            ["serve", "--host", "127.0.0.1", "--port", "0",
             "--data-dir", self.tmp]
        )
        self.assertNotEqual(code, 0)

    def test_healthy_audit_only_wallet_restarts_and_continues_seq(self):
        self._audit_only_wallet()
        svc = WalletService(WalletStore(self.tmp))  # 重启不报错
        svc.put_policy("w1", 2, 60)
        seqs = [e["seq"] for e in svc.get_audit_events("w1")["events"]]
        self.assertEqual(seqs, [1, 2])


# ---- 账本语义严格性 --------------------------------------------------------


class LedgerSemanticsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _healthy(self) -> WalletStore:
        svc = WalletService(WalletStore(self.tmp))
        svc.create_wallet("w1", 2)
        svc.create_asset_operation("w1", "d1", "BTC", 100)
        svc.commit_asset_operation("w1", "d1")
        svc.create_asset_operation("w1", "d2", "BTC", -30)
        svc.commit_asset_operation("w1", "d2")
        svc.create_asset_operation("w1", "p1", "BTC", 5)  # pending @ v2/bal70
        return WalletStore(self.tmp)

    def test_healthy_ledger_passes(self):
        self._healthy().check_asset_ledger_semantics("w1")

    def _tamper(self, mutate) -> None:
        path = _ledger_path(self.tmp)
        data = _load_json(path)
        mutate(data)
        _dump_json(path, data)

    def test_balance_tamper_rejected(self):
        self._healthy()
        self._tamper(lambda d: d["assets"]["BTC"].__setitem__("balance", 71))
        with self.assertRaises(CorruptDataError):
            WalletStore(self.tmp).check_asset_ledger_semantics("w1")

    def test_version_gap_rejected(self):
        self._healthy()
        self._tamper(lambda d: d["operations"]["d2"].__setitem__("version", 3))
        with self.assertRaises(CorruptDataError):
            WalletStore(self.tmp).check_asset_ledger_semantics("w1")

    def test_asset_entry_without_commits_rejected(self):
        self._healthy()

        def mutate(d):
            # 去掉唯一已提交操作但留下资产条目
            d["operations"]["d1"]["state"] = "pending"
            d["operations"]["d1"]["balance"] = 0
            d["operations"]["d1"]["version"] = 0
            d["operations"]["d2"]["state"] = "pending"
            d["operations"]["d2"]["balance"] = 0
            d["operations"]["d2"]["version"] = 0
        self._tamper(mutate)
        with self.assertRaises(CorruptDataError):
            WalletStore(self.tmp).check_asset_ledger_semantics("w1")

    def test_pending_snapshot_mismatch_rejected(self):
        self._healthy()
        self._tamper(lambda d: d["operations"]["p1"].__setitem__("balance", 99))
        with self.assertRaises(CorruptDataError):
            WalletStore(self.tmp).check_asset_ledger_semantics("w1")

    def test_semantic_corruption_blocks_startup_and_is_preserved(self):
        self._healthy()
        raw = open(_ledger_path(self.tmp), encoding="utf-8").read()
        self._tamper(lambda d: d["assets"]["BTC"].__setitem__("balance", 71))
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmp))
        # 未被归一或覆盖
        self.assertNotEqual(
            open(_ledger_path(self.tmp), encoding="utf-8").read(), raw
        )

    def test_semantic_corruption_returns_503_at_runtime(self):
        self._healthy()
        with http_server(self.tmp) as srv:
            self._tamper(lambda d: d["assets"]["BTC"].__setitem__("balance", 71))
            for method, path, body in (
                ("GET", "/v1/wallets/w1/assets/BTC", None),
                ("POST", "/v1/wallets/w1/asset-operations",
                 {"operation_id": "x", "asset_id": "BTC", "delta": 1}),
                ("POST", "/v1/wallets/w1/asset-operations/d1/commit", None),
            ):
                status, resp = srv.request(method, path, body)
                self.assertEqual(status, 503, (path, resp))
                self.assertEqual(resp, {"error": "service temporarily unavailable"})


# ---- 账本 ↔ asset_operation_committed 事件双向对账 -------------------------


class CommittedEventReconciliationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        svc = WalletService(WalletStore(self.tmp))
        svc.create_wallet("w1", 2)
        svc.create_asset_operation("w1", "op1", "BTC", 100)
        svc.commit_asset_operation("w1", "op1")

    def _renumber_events(self, events: list) -> list:
        for i, event in enumerate(events, 1):
            event["seq"] = i
        return events

    def _restart_expect_fail(self) -> None:
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.tmp))

    def test_committed_without_event_blocks(self):
        audit = _load_json(_audit_path(self.tmp))
        audit["events"] = [
            e for e in audit["events"]
            if e["type"] != "asset_operation_committed"
        ]
        self._renumber_events(audit["events"])
        audit["next_seq"] = len(audit["events"]) + 1
        _dump_json(_audit_path(self.tmp), audit)
        self._restart_expect_fail()

    def test_committed_event_without_committed_operation_blocks(self):
        ledger = _load_json(_ledger_path(self.tmp))
        # 操作退回 pending、资产条目删除：纯账本形状/语义合法，
        # 但与 committed 事件矛盾
        ledger["operations"]["op1"]["state"] = "pending"
        ledger["operations"]["op1"]["balance"] = 0
        ledger["operations"]["op1"]["version"] = 0
        ledger["assets"] = {}
        _dump_json(_ledger_path(self.tmp), ledger)
        self._restart_expect_fail()

    def test_event_details_mismatch_blocks(self):
        audit = _load_json(_audit_path(self.tmp))
        committed = next(
            e for e in audit["events"]
            if e["type"] == "asset_operation_committed"
        )
        committed["details"]["balance"] = 101
        _dump_json(_audit_path(self.tmp), audit)
        self._restart_expect_fail()

    def test_duplicate_committed_event_blocks(self):
        audit = _load_json(_audit_path(self.tmp))
        duplicate = json.loads(json.dumps(audit["events"][-1]))
        duplicate["seq"] = audit["next_seq"]
        audit["events"].append(duplicate)
        audit["next_seq"] += 1
        _dump_json(_audit_path(self.tmp), audit)
        self._restart_expect_fail()

    def test_healthy_scene_reconciles_across_restarts(self):
        svc = WalletService(WalletStore(self.tmp))
        svc.create_asset_operation("w1", "op2", "BTC", 20)
        svc.commit_asset_operation("w1", "op2")
        WalletService(WalletStore(self.tmp))  # 再重启仍一致
        store = WalletStore(self.tmp)
        self.assertEqual(store.get_asset("w1", "BTC"),
                         {"balance": 120, "version": 2})
        events = WalletService(WalletStore(self.tmp)).get_audit_events("w1")
        seqs = [e["seq"] for e in events["events"]]
        self.assertEqual(seqs, [1, 2])


if __name__ == "__main__":
    unittest.main()
