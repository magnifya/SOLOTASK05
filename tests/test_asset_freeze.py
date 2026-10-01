"""资产粒度应急冻结/解冻契约测试。

覆盖：
- GET assets/{id}/security-state 视图、freeze/unfreeze 的 201/200/409
  幂等与按资产的交替状态机；请求体恰为 {"reason"} 的 400 边界；
- 钱包不存在或资产尚无已提交操作 404；asset_id 非法 400；
- asset_frozen/asset_unfrozen 事件形状（绑定资产 id 与 reason、details
  键序、外层三 id）、seq 连续、重放不记；
- frozen 时改变该资产余额/version/操作状态或链上派发进程的写入口统一
  409（资产操作创建/提交/撤销、跨链确认与仲裁策略、report/observe、
  dispatch/dispatch-auto/result/confirm/takeover/isolate/settle），重放
  同样 409 且无懒过期/事件/现场变化；其他资产与只读接口不受影响；
- 钱包冻结闸门优先于资产冻结；
- 重启与灾备恢复后冻结折叠一致、seq 与摘要链/历史签名连续；
- 并发同一转换只有一个 201；
- 事件缺失、顺序矛盾、字段损坏、绑定资产无已提交操作 fail-closed
  （503、serve 拒绝就绪、保留现场）。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from threshold_wallet import audit as audit_mod
from threshold_wallet.audit import AuditStore
from threshold_wallet.drbackup import backup, restore
from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import CorruptDataError, RecoveryError, WalletStore
from tests.helpers import http_server, make_harness

HEX32 = "a" * 64


def _dispatch_message(
    operation_id="op1", dispatch_id="dp1", adapter_id="ad1", chain_id="ch1"
):
    return json.dumps(
        {
            "operation_id": operation_id,
            "dispatch_id": dispatch_id,
            "adapter_id": adapter_id,
            "chain_id": chain_id,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


class AssetFreezeHttpTest(unittest.TestCase):
    def setUp(self):
        self._ctx = http_server(tempfile.mkdtemp())
        self.srv = self._ctx.__enter__()
        self.url = self.srv.base_url
        self.create_wallet()
        # 一个有已提交余额的 btc 资产
        self.req(
            "POST",
            "/v1/wallets/w1/asset-operations",
            {"operation_id": "op0", "asset_id": "btc", "delta": 100},
        )
        self.req("POST", "/v1/wallets/w1/asset-operations/op0/commit")

    def tearDown(self):
        self._ctx.__exit__(None, None, None)

    def req(self, method, path, body=None):
        return self.srv.request(method, path, body)

    def create_wallet(self):
        status, _ = self.req(
            "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
        )
        self.assertEqual(status, 201)

    def state(self, asset="btc"):
        return self.req(
            "GET", f"/v1/wallets/w1/assets/{asset}/security-state"
        )

    def freeze(self, reason="incident", asset="btc"):
        return self.req(
            "POST",
            f"/v1/wallets/w1/assets/{asset}/freeze",
            {"reason": reason},
        )

    def unfreeze(self, reason="resolved", asset="btc"):
        return self.req(
            "POST",
            f"/v1/wallets/w1/assets/{asset}/unfreeze",
            {"reason": reason},
        )

    def test_default_state_active_with_null_reason(self):
        status, body = self.state()
        self.assertEqual(status, 200)
        self.assertEqual(
            body,
            {
                "wallet_id": "w1",
                "asset_id": "btc",
                "state": "active",
                "reason": None,
            },
        )
        self.assertEqual(list(body), ["wallet_id", "asset_id", "state", "reason"])

    def test_freeze_unfreeze_transitions(self):
        self.assertEqual(self.freeze("i1")[0], 201)
        self.assertEqual(
            self.state()[1],
            {
                "wallet_id": "w1",
                "asset_id": "btc",
                "state": "frozen",
                "reason": "i1",
            },
        )
        self.assertEqual(self.freeze("i1")[0], 200)
        self.assertEqual(self.freeze("other")[0], 409)
        self.assertEqual(self.unfreeze("r1")[0], 201)
        self.assertEqual(self.state()[1]["state"], "active")
        self.assertIsNone(self.state()[1]["reason"])
        self.assertEqual(self.unfreeze("r1")[0], 200)
        self.assertEqual(self.unfreeze("nope")[0], 409)
        self.assertEqual(self.freeze("i2")[0], 201)
        self.assertEqual(self.state()[1]["reason"], "i2")

    def test_unfreeze_never_frozen_asset_is_409(self):
        self.assertEqual(self.unfreeze("x")[0], 409)

    def test_body_must_be_exactly_reason_object(self):
        bad = (
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
        for body in bad:
            status, _ = self.req(
                "POST", "/v1/wallets/w1/assets/btc/freeze", body
            )
            self.assertEqual(status, 400, body)
            status, _ = self.req(
                "POST", "/v1/wallets/w1/assets/btc/unfreeze", body
            )
            self.assertEqual(status, 400, body)
        self.assertEqual(self.freeze("x" * 1024)[0], 201)
        self.assertEqual(self.unfreeze("  z  ")[0], 201)

    def test_unknown_wallet_is_404(self):
        for method, path in (
            ("GET", "/v1/wallets/ghost/assets/btc/security-state"),
            ("POST", "/v1/wallets/ghost/assets/btc/freeze"),
            ("POST", "/v1/wallets/ghost/assets/btc/unfreeze"),
        ):
            body = {"reason": "x"} if method == "POST" else None
            status, _ = self.req(method, path, body)
            self.assertEqual(status, 404, path)

    def test_asset_without_committed_operation_is_404(self):
        # 只有 pending 操作的资产不构成现场
        self.req(
            "POST",
            "/v1/wallets/w1/asset-operations",
            {"operation_id": "p1", "asset_id": "eth", "delta": 3},
        )
        for method, path in (
            ("GET", "/v1/wallets/w1/assets/eth/security-state"),
            ("POST", "/v1/wallets/w1/assets/eth/freeze"),
            ("POST", "/v1/wallets/w1/assets/eth/unfreeze"),
        ):
            body = {"reason": "x"} if method == "POST" else None
            self.assertEqual(self.req(method, path, body)[0], 404, path)

    def test_illegal_asset_id_is_400(self):
        for path in (
            "/v1/wallets/w1/assets/bad%2Fid/security-state",
            "/v1/wallets/w1/assets/bad%2Fid/freeze",
            "/v1/wallets/w1/assets/bad%2Fid/unfreeze",
        ):
            method = "GET" if path.endswith("security-state") else "POST"
            body = {"reason": "x"} if method == "POST" else None
            self.assertEqual(self.req(method, path, body)[0], 400, path)

    def test_events_carry_asset_id_and_reason(self):
        self.freeze("r1")
        self.freeze("r1")  # 重放不记
        self.unfreeze("r2")
        self.freeze("r3")
        events = self.req("GET", "/v1/wallets/w1/audit-events")[1]["events"]
        af = [
            e
            for e in events
            if e["type"] in ("asset_frozen", "asset_unfrozen")
        ]
        self.assertEqual(
            [e["type"] for e in af],
            ["asset_frozen", "asset_unfrozen", "asset_frozen"],
        )
        self.assertEqual([e["seq"] for e in af], [2, 3, 4])
        for e in af:
            self.assertEqual(
                set(e),
                {
                    "seq", "type", "at", "request_id", "actor_id",
                    "reason", "details",
                },
            )
            self.assertEqual(e["request_id"], "btc")
            self.assertIsNone(e["actor_id"])
            self.assertIsNone(e["reason"])
            self.assertEqual(list(e["details"]), ["asset_id", "reason"])
            self.assertEqual(e["details"]["asset_id"], "btc")
        self.assertEqual([e["details"]["reason"] for e in af],
                         ["r1", "r2", "r3"])

    def test_frozen_blocks_asset_writes_but_not_reads_or_other_assets(self):
        # 另一个有已提交余额的资产 eth
        self.req(
            "POST",
            "/v1/wallets/w1/asset-operations",
            {"operation_id": "e0", "asset_id": "eth", "delta": 5},
        )
        self.req("POST", "/v1/wallets/w1/asset-operations/e0/commit")
        # btc 上一个 pending 操作（供提交/撤销闸门测试）
        self.req(
            "POST",
            "/v1/wallets/w1/asset-operations",
            {"operation_id": "bp", "asset_id": "btc", "delta": 1},
        )
        self.freeze()
        writes = (
            ("POST", "/v1/wallets/w1/asset-operations",
             {"operation_id": "b2", "asset_id": "btc", "delta": 1}),
            ("POST", "/v1/wallets/w1/asset-operations/bp/commit", None),
            ("PUT", "/v1/wallets/w1/chain/btc",
             {"chain_id": "c", "enabled": True,
              "required_confirmations": 1, "reorg_window": 0}),
            ("PUT", "/v1/wallets/w1/chain/btc/arbitration",
             {"sources": {"s1": True}, "quorum": 2}),
        )
        for method, path, body in writes:
            status, payload = self.req(method, path, body)
            self.assertEqual(status, 409, (path, payload))

        # 只读接口仍返回磁盘现状（200/404），绝不 409/503
        status, payload = self.req("GET", "/v1/wallets/w1/assets/btc")
        self.assertEqual((status, payload["balance"], payload["version"]),
                         (200, 100, 1))
        self.assertEqual(self.state()[1]["state"], "frozen")

        # 其他资产的写入不受影响
        status, _ = self.req(
            "POST",
            "/v1/wallets/w1/asset-operations",
            {"operation_id": "e1", "asset_id": "eth", "delta": 2},
        )
        self.assertEqual(status, 201)
        self.assertEqual(
            self.req(
                "GET", "/v1/wallets/w1/assets/eth/security-state"
            )[1]["state"],
            "active",
        )

        # 没有任何写事件落盘（只有 op0 提交 + 三个资产冻结事件 + e0 提交）
        types_ = [
            e["type"]
            for e in self.req("GET", "/v1/wallets/w1/audit-events")[1][
                "events"
            ]
        ]
        self.assertNotIn("chain_policy", types_)
        self.assertNotIn("chain_vote", types_)
        self.assertEqual(types_.count("asset_frozen"), 1)

    def test_wallet_freeze_gate_takes_precedence(self):
        self.req("POST", "/v1/wallets/w1/freeze", {"reason": "wallet"})
        # 钱包冻结时资产冻结入口同样 409（钱包闸门优先），即便资产本身
        # active；不会写出 asset_frozen 事件。
        self.assertEqual(self.freeze("asset")[0], 409)
        types_ = [
            e["type"]
            for e in self.req("GET", "/v1/wallets/w1/audit-events")[1][
                "events"
            ]
        ]
        self.assertEqual(types_, [
            "asset_operation_committed", "wallet_frozen",
        ])


class AssetFreezeChainGateTest(unittest.TestCase):
    """frozen 资产的全部跨链写入口（含幂等重放）一律 409。"""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.svc = make_harness(self.d).service
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 600)
        # 已提交底账 + 一个在途派发的 pending 操作
        self.assertEqual(
            self.svc.create_asset_operation("w1", "op0", "BTC", 100)[0],
            201,
        )
        self.svc.commit_asset_operation("w1", "op0")
        self.assertEqual(
            self.svc.create_asset_operation("w1", "op1", "BTC", -50)[0],
            201,
        )
        self.svc.put_chain_policy("w1", "BTC", "ch1", True, 1, 2)
        self.svc.create_sign_request("w1", "ap1", _dispatch_message())
        self.svc.approve("w1", "ap1", "boss")
        code, self.view = self.svc.post_chain_dispatch(
            "w1", "op1", "dp1", "ad1", "ap1"
        )
        self.assertEqual(code, 201)

    def _freeze(self):
        self.assertEqual(self.svc.freeze_asset("w1", "BTC", "incident")[0],
                         201)

    def test_report_and_observe_blocked(self):
        self._freeze()
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_chain_report(
                "w1", "op1", "ch1", HEX32, 1, HEX32, 1
            )
        self.assertEqual(ctx.exception.status, 409)
        body = {
            "source": "s1",
            "report": {
                "chain_id": "ch1", "tx_id": HEX32, "block_height": 1,
                "block_hash": HEX32, "confirmations": 1,
            },
        }
        with self.assertRaises(ServiceError) as ctx:
            self.svc.observe("w1", "op1", body)
        self.assertEqual(ctx.exception.status, 409)

    def test_dispatch_replay_blocked(self):
        # 先制造同参重放 200 的现场，再冻结：重放转为 409
        self.assertEqual(
            self.svc.post_chain_dispatch(
                "w1", "op1", "dp1", "ad1", "ap1"
            )[0],
            200,
        )
        self._freeze()
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_chain_dispatch(
                "w1", "op1", "dp1", "ad1", "ap1"
            )
        self.assertEqual(ctx.exception.status, 409)

    def _broadcast_and_finalize(self):
        self.assertEqual(
            self.svc.post_chain_dispatch_result(
                "w1", "dp1", "ad1", "broadcasted", HEX32
            )[0],
            201,
        )
        self.assertEqual(
            self.svc.post_chain_dispatch_confirmation(
                "w1", "dp1", "ad1", HEX32, 1, HEX32, 1
            )[0],
            201,
        )

    def test_result_and_confirm_replay_blocked_when_frozen(self):
        self._broadcast_and_finalize()
        # 未冻结时同体重放 200
        self.assertEqual(
            self.svc.post_chain_dispatch_result(
                "w1", "dp1", "ad1", "broadcasted", HEX32
            )[0],
            200,
        )
        self._freeze()
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_chain_dispatch_result(
                "w1", "dp1", "ad1", "broadcasted", HEX32
            )
        self.assertEqual(ctx.exception.status, 409)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_chain_dispatch_confirmation(
                "w1", "dp1", "ad1", HEX32, 1, HEX32, 1
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_settle_replay_blocked_when_frozen(self):
        self._broadcast_and_finalize()
        self.assertEqual(self.svc.settle_chain_dispatch("w1", "dp1")[0], 201)
        self._freeze()
        with self.assertRaises(ServiceError) as ctx:
            self.svc.settle_chain_dispatch("w1", "dp1")
        self.assertEqual(ctx.exception.status, 409)

    def test_failed_dispatch_takeover_blocked(self):
        # 失败结果的派发：未冻结可接管，冻结后接管（含重放）409
        self.assertEqual(
            self.svc.post_chain_dispatch_result(
                "w1", "dp1", "ad1", "failed", None
            )[0],
            201,
        )
        self.svc.put_chain_adapters(
            "w1", {"ad1": "down", "ad2": "up"}
        )
        msg = json.dumps(
            {"dispatch_id": "dp1", "adapter_id": "ad2"},
            separators=(",", ":"),
        )
        self.svc.create_sign_request("w1", "ap2", msg)
        self.svc.approve("w1", "ap2", "boss")
        self._freeze()
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_chain_dispatch_takeover(
                "w1", "dp1", "ad2", "ap2"
            )
        self.assertEqual(ctx.exception.status, 409)

    def test_isolate_blocked(self):
        # 原适配器显式 down 才允许隔离；冻结后即便条件满足也 409
        self.svc.put_chain_adapters("w1", {"ad1": "down"})
        self._freeze()
        with self.assertRaises(ServiceError) as ctx:
            self.svc.post_chain_dispatch_isolate("w1", "dp1")
        self.assertEqual(ctx.exception.status, 409)

    def test_cancel_blocked_and_no_lazy_expiry(self):
        # 撤销审批单
        msg = json.dumps(
            {"operation_id": "op1", "cancel_id": "c1"},
            separators=(",", ":"),
        )
        self.svc.create_sign_request("w1", "cap", msg)
        self.svc.approve("w1", "cap", "boss")
        self._freeze()
        with self.assertRaises(ServiceError) as ctx:
            self.svc.cancel_asset_operation("w1", "op1", "c1", "cap")
        self.assertEqual(ctx.exception.status, 409)

    def test_freeze_writes_no_events_and_replay_after_unfreeze(self):
        before = AuditStore(self.d).list_events("w1")
        self._freeze()
        # 上述各 409 调用
        for fn in (
            lambda: self.svc.post_chain_report(
                "w1", "op1", "ch1", HEX32, 1, HEX32, 1
            ),
            lambda: self.svc.create_asset_operation("w1", "x", "BTC", 1),
        ):
            with self.assertRaises(ServiceError):
                fn()
        types_ = [e["type"] for e in AuditStore(self.d).list_events("w1")]
        self.assertEqual(
            types_,
            [e["type"] for e in before] + ["asset_frozen"],
        )
        # 解冻后行为恢复（重放派发 200）
        self.assertEqual(self.svc.unfreeze_asset("w1", "BTC", "ok")[0], 201)
        self.assertEqual(
            self.svc.post_chain_dispatch(
                "w1", "op1", "dp1", "ad1", "ap1"
            )[0],
            200,
        )


class AssetFreezePersistenceTest(unittest.TestCase):
    def _service(self, tmp):
        return WalletService(WalletStore(tmp))

    def _seed(self, tmp):
        svc = self._service(tmp)
        svc.create_wallet("w1", 2)
        svc.create_asset_operation("w1", "o1", "btc", 10)
        svc.commit_asset_operation("w1", "o1")
        return svc

    def test_state_and_gate_survive_restart(self):
        tmp = tempfile.mkdtemp()
        svc = self._seed(tmp)
        self.assertEqual(svc.freeze_asset("w1", "btc", "inc")[0], 201)
        svc2 = self._service(tmp)
        self.assertEqual(
            svc2.get_asset_security_state("w1", "btc"),
            {
                "wallet_id": "w1",
                "asset_id": "btc",
                "state": "frozen",
                "reason": "inc",
            },
        )
        with self.assertRaises(ServiceError) as ctx:
            svc2.create_asset_operation("w1", "o2", "btc", 1)
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(svc2.unfreeze_asset("w1", "btc", "ok")[0], 201)
        svc3 = self._service(tmp)
        self.assertEqual(
            svc3.get_asset_security_state("w1", "btc")["state"], "active"
        )
        self.assertEqual(
            svc3.create_asset_operation("w1", "o3", "btc", 1)[0], 201
        )

    def test_concurrent_freeze_single_201(self):
        tmp = tempfile.mkdtemp()
        self._seed(tmp)

        def hit(_):
            return WalletService(WalletStore(tmp), recover=False).freeze_asset(
                "w1", "btc", "same"
            )

        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(hit, range(24)))
        statuses = sorted(s for s, _ in results)
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(200), 23)
        events = [
            e
            for e in AuditStore(tmp).list_events("w1")
            if e["type"] == "asset_frozen"
        ]
        self.assertEqual(len(events), 1)

    def test_dr_backup_restore_preserves_state_and_seq(self):
        src = tempfile.mkdtemp()
        dst = tempfile.mkdtemp()
        tar = os.path.join(tempfile.mkdtemp(), "s.tar")
        svc = self._seed(src)
        svc.freeze_asset("w1", "btc", "dr-inc")
        self.assertEqual(backup(src, "w1", "snap-1", tar)["status"], 201)
        self.assertEqual(restore(dst, "w1", tar)[0], 201)
        restored = self._service(dst)
        self.assertEqual(
            restored.get_asset_security_state("w1", "btc")["state"],
            "frozen",
        )
        with self.assertRaises(ServiceError) as ctx:
            restored.create_asset_operation("w1", "o2", "btc", 1)
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(restore(dst, "w1", tar)[0], 200)
        self.assertEqual(
            restored.unfreeze_asset("w1", "btc", "fixed")[0], 201
        )
        # 摘要链仍有效
        integrity = restored.get_audit_integrity("w1")
        self.assertEqual(integrity["state"], "valid")


class AssetFreezeFailClosedTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        svc = WalletService(WalletStore(self.d))
        svc.create_wallet("w1", 2)
        svc.create_asset_operation("w1", "o1", "btc", 10)
        svc.commit_asset_operation("w1", "o1")
        svc.freeze_asset("w1", "btc", "r1")
        svc.unfreeze_asset("w1", "btc", "r2")

    def _path(self):
        return os.path.join(self.d, "audit", "w1.json")

    def _load(self):
        with open(self._path(), encoding="utf-8") as f:
            return json.load(f)

    def _save_rechain(self, data):
        count, head = audit_mod.compute_chain_head(data["events"])
        data["chain"] = {
            "algorithm": "sha256", "head": head, "count": count
        }
        with open(self._path(), "w", encoding="utf-8") as f:
            json.dump(data, f)

    def test_non_alternating_events_fail_closed(self):
        data = self._load()
        dup = dict(data["events"][-1])
        dup["seq"] = len(data["events"]) + 1
        data["events"].append(dup)
        data["next_seq"] = dup["seq"] + 1
        self._save_rechain(data)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.d))

    def test_malformed_reason_fails_closed(self):
        data = self._load()
        data["events"][1]["details"]["reason"] = "   "
        self._save_rechain(data)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.d))

    def test_details_key_reorder_fails_closed(self):
        data = self._load()
        for e in data["events"]:
            if e["type"] == "asset_frozen":
                e["details"] = {"reason": "r1", "asset_id": "btc"}
        self._save_rechain(data)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.d))

    def test_asset_id_binding_mismatch_fails_closed(self):
        data = self._load()
        e = data["events"][1]
        e["request_id"] = "eth"  # 与 details.asset_id 不符
        self._save_rechain(data)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.d))

    def test_freeze_event_without_committed_op_fails_closed(self):
        data = self._load()
        # 把冻结事件改绑到一个无已提交操作的资产
        for e in data["events"]:
            if e["type"] in ("asset_frozen", "asset_unfrozen"):
                e["request_id"] = "ghost"
                e["details"]["asset_id"] = "ghost"
        self._save_rechain(data)
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.d))

    def test_corrupt_json_is_corrupt_data_error(self):
        with open(self._path(), "w", encoding="utf-8") as f:
            f.write("{broken")
        with self.assertRaises(CorruptDataError):
            WalletService(WalletStore(self.d))

    def test_deleted_ledger_with_freeze_event_fails_closed(self):
        # 冻结事件仍在、账本文件被删：不可对账（503），既不 404 也不放行
        os.remove(os.path.join(self.d, "assets", "w1.json"))
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.d), recover=False).get_asset_security_state(
                "w1", "btc"
            )
        with self.assertRaises(RecoveryError):
            WalletService(WalletStore(self.d), recover=False).create_asset_operation(
                "w1", "o9", "eth", 1
            )

    def test_http_503_on_unreconcilable_scene(self):
        # 在运行中的服务器上制造矛盾现场（启动恢复在构造服务时已过，
        # 故这里验证持锁访问的懒恢复/对账把矛盾映射为 503）。
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        with http_server(tmp) as srv:
            srv.request("POST", "/v1/wallets",
                       {"wallet_id": "w1", "shares": 2})
            srv.request(
                "POST", "/v1/wallets/w1/asset-operations",
                {"operation_id": "o1", "asset_id": "btc", "delta": 10},
            )
            srv.request("POST", "/v1/wallets/w1/asset-operations/o1/commit")
            srv.request("POST", "/v1/wallets/w1/assets/btc/freeze",
                       {"reason": "r1"})
            srv.request("POST", "/v1/wallets/w1/assets/btc/unfreeze",
                       {"reason": "r2"})
            path = os.path.join(tmp, "audit", "w1.json")
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            dup = dict(data["events"][-1])
            dup["seq"] = len(data["events"]) + 1
            data["events"].append(dup)
            data["next_seq"] = dup["seq"] + 1
            count, head = audit_mod.compute_chain_head(data["events"])
            data["chain"] = {
                "algorithm": "sha256", "head": head, "count": count
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f)
            status, body = srv.request(
                "GET", "/v1/wallets/w1/assets/btc/security-state"
            )
            self.assertEqual(status, 503, body)


if __name__ == "__main__":
    unittest.main()
