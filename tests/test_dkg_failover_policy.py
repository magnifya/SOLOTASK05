"""DKG 故障审批开关与审批门控测试。

覆盖：
- P=PUT/GET /v1/wallets/{W}/dkg-failover-policy：PUT 仅收 {"enabled":
  bool}，GET/PUT 200 同体，缺省 false；非法 400、钱包 404；同值也记
  dkg_failover_policy_updated（request_id/actor_id/reason 为 null，
  details={enabled}）；策略纯由事件恢复，重启/灾备保持；
- F=/v1/dkg/{W}/{D}/failover：禁用时沿用旧五键；启用时恰收六键，
  approval_request_id 须指向同钱包既有 approved 审批单，message 逐字
  为紧凑 JSON；未知/pending/rejected/expired/message 不符/轮次变化均
  409 且 DKG 现场不变；首提 201 并追加唯一 dkg_failover；已提交故障
  同参重放优先 200 不复查，异参 409；
- 损坏/矛盾策略事件 fail-closed（启动拒绝就绪、常驻 503）。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from threshold_wallet import drbackup
from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import RecoveryError, WalletStore

from tests.helpers import http_server, make_harness

KEY_A = "aa" * 32
KEY_B = "bb" * 32
KEY_C = "cc" * 32
HASH_A = "11" * 32
HASH_B = "22" * 32


def _failover_message(did, round, action, node, replacement, key):
    """审批单 message 的契约紧凑 JSON（键序固定）。"""
    return json.dumps(
        {
            "dkg_id": did,
            "round": round,
            "action": action,
            "node": node,
            "replacement": replacement,
            "key": key,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _call(fn, *args):
    """把 ServiceError 归一为 (status, {"error": ...})，便于断言状态码。"""
    try:
        return fn(*args)
    except ServiceError as exc:
        return exc.status, {"error": exc.message}


class DkgFailoverPolicyServiceTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)

    def _events(self, event_type, svc=None):
        svc = svc or self.svc
        return [
            e
            for e in svc.get_audit_events("w1")["events"]
            if e["type"] == event_type
        ]

    # ---- P：策略端点 ------------------------------------------------------

    def test_default_policy_is_disabled(self):
        self.assertEqual(self.svc.get_dkg_failover_policy("w1"),
                         {"enabled": False})

    def test_get_unknown_wallet_404(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_dkg_failover_policy("nope")
        self.assertEqual(ctx.exception.status, 404)

    def test_get_invalid_wallet_400(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.get_dkg_failover_policy("bad id!")
        self.assertEqual(ctx.exception.status, 400)

    def test_put_invalid_enabled_400(self):
        for bad in ("true", 1, 0, None, [], {}, "yes", 2):
            with self.assertRaises(ServiceError) as ctx:
                self.svc.put_dkg_failover_policy("w1", bad)
            self.assertEqual(ctx.exception.status, 400, bad)
        # 钱包 404 优先
        with self.assertRaises(ServiceError) as ctx:
            self.svc.put_dkg_failover_policy("nope", True)
        self.assertEqual(ctx.exception.status, 404)

    def test_put_get_same_body_and_same_value_logs(self):
        body = self.svc.put_dkg_failover_policy("w1", True)
        self.assertEqual(body, {"enabled": True})
        self.assertEqual(self.svc.get_dkg_failover_policy("w1"),
                         {"enabled": True})
        # 同值更新也记事件
        self.svc.put_dkg_failover_policy("w1", True)
        self.svc.put_dkg_failover_policy("w1", False)
        events = self._events("dkg_failover_policy_updated")
        self.assertEqual(
            [e["details"]["enabled"] for e in events],
            [True, True, False],
        )

    def test_policy_event_shape(self):
        self.svc.put_dkg_failover_policy("w1", True)
        (event,) = self._events("dkg_failover_policy_updated")
        self.assertEqual(
            set(event),
            {"seq", "type", "at", "request_id", "actor_id", "reason",
             "details"},
        )
        self.assertIsNone(event["request_id"])
        self.assertIsNone(event["actor_id"])
        self.assertIsNone(event["reason"])
        self.assertEqual(event["details"], {"enabled": True})
        # 落盘 JSON：details 恰含 enabled
        with open(os.path.join(self.d, "audit", "w1.json"),
                  encoding="utf-8") as f:
            log = json.load(f)
        (stored,) = [
            e for e in log["events"]
            if e["type"] == "dkg_failover_policy_updated"
        ]
        self.assertEqual(stored["details"], {"enabled": True})

    def test_policy_recovered_from_events_after_restart(self):
        self.svc.put_dkg_failover_policy("w1", True)
        self.svc.put_dkg_failover_policy("w1", False)
        self.svc.put_dkg_failover_policy("w1", True)
        svc2 = WalletService(self.h.store)
        # 恢复不新增事件；取最后一条
        self.assertEqual(svc2.get_dkg_failover_policy("w1"),
                         {"enabled": True})
        before = self.svc.get_audit_events("w1")["events"]
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)

    def test_tampered_policy_event_is_fail_closed(self):
        self.svc.put_dkg_failover_policy("w1", True)
        path = os.path.join(self.d, "audit", "w1.json")
        log = json.load(open(path, encoding="utf-8"))
        for event in log["events"]:
            if event["type"] == "dkg_failover_policy_updated":
                event["details"] = {"enabled": "yes"}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        # 启动拒绝就绪
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)
        # 常驻请求同样 fail-closed（服务层直接抛 RecoveryError，
        # 由 HTTP 边界统一映射为 503）
        with self.assertRaises(RecoveryError):
            self.svc.get_dkg_failover_policy("w1")

    def test_policy_event_with_actor_is_fail_closed(self):
        self.svc.put_dkg_failover_policy("w1", True)
        path = os.path.join(self.d, "audit", "w1.json")
        log = json.load(open(path, encoding="utf-8"))
        for event in log["events"]:
            if event["type"] == "dkg_failover_policy_updated":
                event["actor_id"] = "mallory"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    def test_backup_restore_keeps_policy_and_seq(self):
        self.svc.put_dkg_failover_policy("w1", True)
        before = self.svc.get_audit_events("w1")["events"]
        out = os.path.join(tempfile.mkdtemp(), "snap.tar")
        self.addCleanup(shutil.rmtree, os.path.dirname(out),
                        ignore_errors=True)
        body = drbackup.backup(self.d, "w1", "S1", out)
        self.assertEqual(body["status"], 201)
        dst = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, dst, ignore_errors=True)
        status, _ = drbackup.restore(dst, "w1", out)
        self.assertEqual(status, 201)
        svc2 = WalletService(WalletStore(dst))
        self.assertEqual(svc2.get_dkg_failover_policy("w1"),
                         {"enabled": True})
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)

    # ---- F：审批门控 ------------------------------------------------------

    def _register_commit_pair(self, did="d1"):
        for node, key in (("n1", KEY_A), ("n2", KEY_B)):
            code, _ = _call(
                self.svc.post_dkg_stage,
                "w1", did, "register", node, key, None, None,
            )
            self.assertEqual(code, 201)
        for node, h in (("n1", HASH_A), ("n2", HASH_B)):
            code, _ = _call(
                self.svc.post_dkg_stage,
                "w1", did, "commit", node, None, h, None,
            )
            self.assertEqual(code, 201)

    def _enable_and_approve(
        self, request_id, did="d1", round=2, action="replace",
        node="n2", replacement="n3", key=KEY_C, approver="boss",
    ):
        self.svc.put_dkg_failover_policy("w1", True)
        # 建审批单需要审批策略（sign-requests 契约不变）
        self.svc.put_policy("w1", 1, 3600)
        message = _failover_message(
            did, round, action, node, replacement, key
        )
        code, _ = self.svc.create_sign_request("w1", request_id, message)
        self.assertEqual(code, 201)
        return self.svc.approve("w1", request_id, approver)

    def test_disabled_keeps_five_keys(self):
        self._register_commit_pair()
        # 禁用：五键照旧 201
        code, view = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", "n3", KEY_C,
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["nodes"], ["n1", "n3"])
        self.assertEqual(
            len(self._events("dkg_failover_policy_updated")), 0
        )

    def test_disabled_rejects_sixth_key_400(self):
        self._register_commit_pair()
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", "n3", KEY_C, "r1",
        )
        self.assertEqual(code, 400)

    def test_enabled_requires_six_keys(self):
        self._register_commit_pair()
        self.svc.put_dkg_failover_policy("w1", True)
        # 缺 approval_request_id
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", "n3", KEY_C,
        )
        self.assertEqual(code, 400)
        # 显式 None / 非法标识
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", "n3", KEY_C, None,
        )
        self.assertEqual(code, 400)
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", "n3", KEY_C, "bad id!",
        )
        self.assertEqual(code, 400)

    def test_unknown_approval_request_409_and_unchanged(self):
        self._register_commit_pair()
        self.svc.put_dkg_failover_policy("w1", True)
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", "n3", KEY_C, "ghost",
        )
        self.assertEqual(code, 409)
        # DKG 现场不变：无 failover 事件，视图仍停留在基线轮 commit
        self.assertEqual(self._events("dkg_failover"), [])
        view = self.svc.get_dkg_session("w1", "d1")
        self.assertEqual(view["round"], 1)
        self.assertEqual(view["state"], "share")

    def test_other_wallet_approval_request_409(self):
        self._register_commit_pair()
        self.svc.put_dkg_failover_policy("w1", True)
        self.svc.create_wallet("w2", 2)
        self.svc.put_dkg_failover_policy("w2", True)
        # 审批单建在 w2：对 w1 即未知
        svc2_policy = self.svc.put_policy("w2", 1, 3600)
        self.assertEqual(svc2_policy["wallet_id"], "w2")
        message = _failover_message(
            "d1", 2, "replace", "n2", "n3", KEY_C
        )
        self.svc.create_sign_request("w2", "r1", message)
        self.svc.approve("w2", "r1", "boss")
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", "n3", KEY_C, "r1",
        )
        self.assertEqual(code, 409)

    def test_pending_approval_409(self):
        self._register_commit_pair()
        self.svc.put_dkg_failover_policy("w1", True)
        self.svc.put_policy("w1", 1, 3600)
        message = _failover_message(
            "d1", 2, "replace", "n2", "n3", KEY_C
        )
        self.svc.create_sign_request("w1", "r1", message)
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", "n3", KEY_C, "r1",
        )
        self.assertEqual(code, 409)
        self.assertEqual(self._events("dkg_failover"), [])

    def test_rejected_approval_409(self):
        self._register_commit_pair()
        self.svc.put_dkg_failover_policy("w1", True)
        self.svc.put_policy("w1", 1, 3600)
        message = _failover_message(
            "d1", 2, "replace", "n2", "n3", KEY_C
        )
        self.svc.create_sign_request("w1", "r1", message)
        self.svc.reject("w1", "r1", "boss")
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", "n3", KEY_C, "r1",
        )
        self.assertEqual(code, 409)
        self.assertEqual(self._events("dkg_failover"), [])

    def test_expired_approval_409_and_records_expiry(self):
        self._register_commit_pair()
        # 1 秒超时的审批策略；pending 单到点由 failover 操作懒过期
        self.svc.put_dkg_failover_policy("w1", True)
        self.svc.put_policy("w1", 1, 1)
        message = _failover_message(
            "d1", 2, "replace", "n2", "n3", KEY_C
        )
        self.svc.create_sign_request("w1", "r1", message)
        import time

        time.sleep(1.05)
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", "n3", KEY_C, "r1",
        )
        self.assertEqual(code, 409)
        # 懒过期原子记一次 request_expired；仍无故障事件
        expired = self._events("request_expired")
        self.assertEqual(len(expired), 1)
        self.assertEqual(self._events("dkg_failover"), [])
        # 审批单视图确为 expired
        self.assertEqual(
            self.svc.get_sign_request("w1", "r1")["state"], "expired"
        )

    def test_message_mismatch_409(self):
        self._register_commit_pair()
        # 审批 message 与提交参数逐字不符（key 不同）
        self._enable_and_approve("r1", key=KEY_C)
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", "n3", "bb" * 32, "r1",
        )
        self.assertEqual(code, 409)
        # 非紧凑/键序不同的等价 JSON 也不接受
        self.svc.create_sign_request(
            "w1", "r2",
            json.dumps(
                {
                    "key": KEY_C, "replacement": "n3", "node": "n2",
                    "action": "replace", "round": 2, "dkg_id": "d1",
                }
            ),
        )
        self.svc.approve("w1", "r2", "boss")
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", "n3", KEY_C, "r2",
        )
        self.assertEqual(code, 409)

    def test_message_is_verbatim_compact_json(self):
        self._register_commit_pair()
        view = self._enable_and_approve("r1")
        self.assertEqual(view["state"], "approved")
        request = self.svc.get_sign_request("w1", "r1")
        self.assertEqual(
            request["message"],
            '{"dkg_id":"d1","round":2,"action":"replace","node":"n2",'
            '"replacement":"n3","key":"' + KEY_C + '"}',
        )
        code, view = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", "n3", KEY_C, "r1",
        )
        self.assertEqual(code, 201)

    def test_abort_requires_approval_when_enabled(self):
        self._register_commit_pair()
        self._enable_and_approve(
            "rA", round=2, action="abort", node=None, replacement=None,
            key=None,
        )
        code, view = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "abort", None, None, None, "rA",
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "aborted")
        self.assertEqual(view["nodes"], [])

    def test_approved_round_drift_409_and_unchanged(self):
        self._register_commit_pair()
        # 禁用时先把当前轮推进到第 2 轮
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", "n3", KEY_C,
        )
        self.assertEqual(code, 201)
        self.svc.put_dkg_failover_policy("w1", True)
        self.svc.put_policy("w1", 1, 3600)
        # 审批单与提交逐字一致（abort 第 4 轮），但当前轮为 2、
        # 下一轮必须是 3：跳号 409 且 DKG 现场不变
        message = _failover_message(
            "d1", 4, "abort", None, None, None
        )
        self.svc.create_sign_request("w1", "r1", message)
        self.svc.approve("w1", "r1", "boss")
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 4, "abort", None, None, None, "r1",
        )
        self.assertEqual(code, 409)
        # 审批 message 的轮次与提交轮次不一致同样 409
        self.svc.create_sign_request(
            "w1", "r2",
            _failover_message("d1", 2, "abort", None, None, None),
        )
        self.svc.approve("w1", "r2", "boss")
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 3, "abort", None, None, None, "r2",
        )
        self.assertEqual(code, 409)
        # 仅一条故障事件（禁用时提交的第 2 轮）
        self.assertEqual(len(self._events("dkg_failover")), 1)

    def test_approved_first_submit_201_appends_unique_event(self):
        self._register_commit_pair()
        self._enable_and_approve("r1")
        code, view = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", "n3", KEY_C, "r1",
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["round"], 2)
        failovers = self._events("dkg_failover")
        self.assertEqual(len(failovers), 1)
        # 故障事件不携带审批标识
        self.assertEqual(
            list(failovers[0]["details"]),
            ["id", "round", "action", "node", "replacement", "key",
             "state"],
        )
        self.assertIsNone(failovers[0]["actor_id"])

    def test_replay_200_preempts_without_recheck(self):
        self._register_commit_pair()
        self._enable_and_approve("r1")
        code, view = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", "n3", KEY_C, "r1",
        )
        self.assertEqual(code, 201)
        # 同参（六键）重放：即使指向未知/pending/拒绝单也优先 200
        for other_id in ("r1", "ghost", "rX"):
            code, view2 = _call(
                self.svc.post_dkg_failover,
                "w1", "d1", 2, "replace", "n2", "n3", KEY_C, other_id,
            )
            self.assertEqual(code, 200, other_id)
            self.assertEqual(view2, view)
        # 五键同参重放同样优先 200、不复查审批
        code, view2 = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", "n3", KEY_C,
        )
        self.assertEqual(code, 200)
        self.assertEqual(view2, view)
        # 异参 409
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "replace", "n1", "n3", KEY_C, "r1",
        )
        self.assertEqual(code, 409)
        # 首提唯一：仍恰 1 条故障事件
        self.assertEqual(len(self._events("dkg_failover")), 1)

    def test_replay_after_policy_toggle_five_keys(self):
        self._register_commit_pair()
        # 禁用时提交五键故障
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", "n3", KEY_C,
        )
        self.assertEqual(code, 201)
        # 事后启用：五键同参重放仍 200（优先于键集/审批校验）
        self.svc.put_dkg_failover_policy("w1", True)
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", "n3", KEY_C,
        )
        self.assertEqual(code, 200)

    def test_disable_again_restores_five_key_path(self):
        self._register_commit_pair()
        self.svc.put_dkg_failover_policy("w1", True)
        self.svc.put_dkg_failover_policy("w1", False)
        code, view = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", "n3", KEY_C,
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "commit")

    def test_concurrent_approved_failover_single_201(self):
        self._register_commit_pair()
        self._enable_and_approve("r1")
        import threading

        codes = []
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            code, _ = _call(
                self.svc.post_dkg_failover,
                "w1", "d1", 2, "replace", "n2", "n3", KEY_C, "r1",
            )
            codes.append(code)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(codes), [200] * 7 + [201])
        self.assertEqual(len(self._events("dkg_failover")), 1)

    def test_restart_keeps_policy_round_and_seq(self):
        self._register_commit_pair()
        self._enable_and_approve("r1")
        code, _ = _call(
            self.svc.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", "n3", KEY_C, "r1",
        )
        self.assertEqual(code, 201)
        before = self.svc.get_audit_events("w1")["events"]
        svc2 = WalletService(self.h.store)
        self.assertEqual(svc2.get_dkg_failover_policy("w1"),
                         {"enabled": True})
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)
        view = svc2.get_dkg_session("w1", "d1", "2")
        self.assertEqual(view["nodes"], ["n1", "n3"])
        seqs = [e["seq"] for e in svc2.get_audit_events("w1")["events"]]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))


class DkgFailoverPolicyHttpTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def test_http_policy_endpoints(self):
        with http_server(self.d) as srv:
            code, _ = srv.request(
                "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
            )
            self.assertEqual(code, 201)
            # 缺省 false
            code, body = srv.request(
                "GET", "/v1/wallets/w1/dkg-failover-policy"
            )
            self.assertEqual(code, 200)
            self.assertEqual(body, {"enabled": False})
            # PUT 非法 400
            for bad in ({"enabled": "yes"}, {"enabled": 1}, {}):
                code, _ = srv.request(
                    "PUT", "/v1/wallets/w1/dkg-failover-policy", bad
                )
                self.assertEqual(code, 400, bad)
            # 多键 400
            code, _ = srv.request(
                "PUT", "/v1/wallets/w1/dkg-failover-policy",
                {"enabled": True, "extra": 1},
            )
            self.assertEqual(code, 400)
            # PUT 200 同体
            code, body = srv.request(
                "PUT", "/v1/wallets/w1/dkg-failover-policy",
                {"enabled": True},
            )
            self.assertEqual(code, 200)
            self.assertEqual(body, {"enabled": True})
            code, body = srv.request(
                "GET", "/v1/wallets/w1/dkg-failover-policy"
            )
            self.assertEqual(code, 200)
            self.assertEqual(body, {"enabled": True})
            # 钱包 404
            code, _ = srv.request(
                "GET", "/v1/wallets/nope/dkg-failover-policy"
            )
            self.assertEqual(code, 404)
            code, _ = srv.request(
                "PUT", "/v1/wallets/nope/dkg-failover-policy",
                {"enabled": True},
            )
            self.assertEqual(code, 404)

    def test_http_gated_failover_flow(self):
        with http_server(self.d) as srv:
            srv.request(
                "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
            )
            for node, key in (("n1", KEY_A), ("n2", KEY_B)):
                code, _ = srv.request(
                    "POST", "/v1/dkg/w1/d1",
                    {"op": "register", "node": node, "key": key,
                     "hash": None, "peer": None},
                )
                self.assertEqual(code, 201)
            for node, h in (("n1", HASH_A), ("n2", HASH_B)):
                code, _ = srv.request(
                    "POST", "/v1/dkg/w1/d1",
                    {"op": "commit", "node": node, "key": None,
                     "hash": h, "peer": None},
                )
                self.assertEqual(code, 201)
            # 启用故障审批 + 审批策略
            code, _ = srv.request(
                "PUT", "/v1/wallets/w1/dkg-failover-policy",
                {"enabled": True},
            )
            self.assertEqual(code, 200)
            code, _ = srv.request(
                "PUT", "/v1/wallets/w1/approval-policy",
                {"required_approvals": 1, "timeout_seconds": 3600},
            )
            self.assertEqual(code, 200)
            five = {"round": 2, "action": "replace", "node": "n2",
                    "replacement": "n3", "key": KEY_C}
            # 五键：禁用时合法，启用后 400
            code, _ = srv.request(
                "POST", "/v1/dkg/w1/d1/failover", five
            )
            self.assertEqual(code, 400)
            # 未知审批单 409
            code, _ = srv.request(
                "POST", "/v1/dkg/w1/d1/failover",
                {**five, "approval_request_id": "r1"},
            )
            self.assertEqual(code, 409)
            # 建审批单（message 逐字紧凑 JSON）并批准
            message = (
                '{"dkg_id":"d1","round":2,"action":"replace",'
                '"node":"n2","replacement":"n3","key":"' + KEY_C + '"}'
            )
            code, _ = srv.request(
                "POST", "/v1/wallets/w1/sign-requests",
                {"id": "r1", "message": message},
            )
            self.assertEqual(code, 201)
            code, _ = srv.request(
                "POST", "/v1/wallets/w1/sign-requests/r1/approve",
                {"approver_id": "boss"},
            )
            self.assertEqual(code, 200)
            # 六键首提 201
            code, view = srv.request(
                "POST", "/v1/dkg/w1/d1/failover",
                {**five, "approval_request_id": "r1"},
            )
            self.assertEqual(code, 201)
            self.assertEqual(view["nodes"], ["n1", "n3"])
            # 同参重放 200（五键亦优先）
            code, _ = srv.request(
                "POST", "/v1/dkg/w1/d1/failover", five
            )
            self.assertEqual(code, 200)
            # 非法第七键 400
            code, _ = srv.request(
                "POST", "/v1/dkg/w1/d1/failover",
                {**five, "approval_request_id": "r1", "x": 1},
            )
            self.assertEqual(code, 400)


if __name__ == "__main__":
    unittest.main()
