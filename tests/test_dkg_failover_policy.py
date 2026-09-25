"""DKG 故障审批策略（/v1/wallets/{W}/dkg-failover-policy）测试。

覆盖：
- 策略 GET/PUT：缺省 false、200 同体、非法 400、钱包 404、同值也记
  dkg_failover_policy_updated 事件（request_id/actor_id/reason 为
  null，details 恰为 {"enabled":...}），策略仅由事件恢复；
- 策略启用时 failover 恰收旧五键加 approval_request_id：审批单未知/
  pending/rejected/expired/文案不符/轮次变化均 409 且现场不变，
  approved 且 R=当前轮+1 可执行 201；已提交旧五键同参重放优先 200
  且不复查审批，异参 409；
- 策略禁用时沿用旧五键（夹带 approval_request_id 一律 400）；
- 重启/灾备保持策略、轮次与 seq；篡改策略事件 fail-closed。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from threshold_wallet import drbackup
from threshold_wallet.service import ServiceError, WalletService
from threshold_wallet.store import RecoveryError, WalletStore

from tests.helpers import http_server, make_harness

KEY_A = "aa" * 32
KEY_B = "bb" * 32
KEY_C = "cc" * 32
KEY_D = "dd" * 32
HASH_A = "11" * 32
HASH_B = "22" * 32


def _call(fn, *args, **kwargs):
    """把 ServiceError 归一为 (status, {"error": ...})，便于断言状态码。

    返回 (status, body)：服务方法返回 (status, view) 元组时原样返回，
    返回裸视图（PUT/GET 策略等成功即 200 的接口）时包装为 (200, view)。
    """
    try:
        result = fn(*args, **kwargs)
    except ServiceError as exc:
        return exc.status, {"error": exc.message}
    if isinstance(result, tuple):
        return result
    return 200, result


_UNSET = object()


def _approval_message(did, round_no, action, node=None, replacement=None,
                      key=None):
    """审批单 message：本次故障参数的紧凑 JSON（键序如契约）。"""
    return json.dumps(
        {"dkg_id": did, "round": round_no, "action": action,
         "node": node, "replacement": replacement, "key": key},
        separators=(",", ":"),
    )


class DkgFailoverPolicyServiceTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.h = make_harness(self.d)
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)

    # ---- 辅助 -------------------------------------------------------------

    def _post(self, did, op, node, key=None, hash=None, peer=None,
              round=None):
        return _call(
            self.svc.post_dkg_stage,
            "w1", did, op, node, key, hash, peer, round,
        )

    def _failover(self, did, round, action, node=None, replacement=None,
                  key=None, wallet="w1", approval=_UNSET):
        kwargs = {}
        if approval is not _UNSET:
            kwargs["approval_request_id"] = approval
        return _call(
            self.svc.post_dkg_failover,
            wallet, did, round, action, node, replacement, key, **kwargs,
        )

    def _register_pair(self, did="d1"):
        code, _ = self._post(did, "register", "n1", key=KEY_A)
        self.assertEqual(code, 201)
        code, _ = self._post(did, "register", "n2", key=KEY_B)
        self.assertEqual(code, 201)

    def _commit_pair(self, did="d1", round=None, n1="n1", n2="n2"):
        code, _ = self._post(did, "commit", n1, hash=HASH_A, round=round)
        self.assertEqual(code, 201)
        code, _ = self._post(did, "commit", n2, hash=HASH_B, round=round)
        self.assertEqual(code, 201)

    def _events(self, event_type, svc=None):
        svc = svc or self.svc
        return [
            e for e in svc.get_audit_events("w1")["events"]
            if e["type"] == event_type
        ]

    def _enable_policy(self):
        code, body = _call(self.svc.put_dkg_failover_policy,
                           "w1", {"enabled": True})
        self.assertEqual(code, 200)
        self.assertEqual(body, {"enabled": True})

    def _make_approval(self, rid, message, approve=True):
        """建审批单（按需批准）；审批策略 required_approvals=1。"""
        _call(self.svc.put_policy, "w1", 1, 3600)
        code, _ = _call(self.svc.create_sign_request, "w1", rid, message)
        self.assertEqual(code, 201)
        if approve:
            code, body = _call(self.svc.approve, "w1", rid, "approver-1")
            self.assertEqual(code, 200)
            self.assertEqual(body["state"], "approved")

    # ---- 策略 GET/PUT ------------------------------------------------------

    def test_policy_default_false(self):
        code, body = _call(self.svc.get_dkg_failover_policy, "w1")
        self.assertEqual(code, 200)
        self.assertEqual(body, {"enabled": False})

    def test_policy_unknown_wallet_404(self):
        code, _ = _call(self.svc.get_dkg_failover_policy, "nope")
        self.assertEqual(code, 404)
        code, _ = _call(self.svc.put_dkg_failover_policy,
                        "nope", {"enabled": True})
        self.assertEqual(code, 404)

    def test_put_policy_validation_400(self):
        for bad in (
            {},                       # 缺键
            {"enabled": True, "x": 1},  # 多键
            {"enabled": 1},           # 非布尔
            {"enabled": 0},
            {"enabled": "true"},
            {"enabled": None},
            {"Enabled": True},
            [],                       # 非对象
            "enabled",
        ):
            code, _ = _call(self.svc.put_dkg_failover_policy, "w1", bad)
            self.assertEqual(code, 400, bad)
        # 非法钱包 id
        code, _ = _call(self.svc.put_dkg_failover_policy,
                        "bad id!", {"enabled": True})
        self.assertEqual(code, 400)
        # 合法 true/false 均 200 同体
        for value in (True, False):
            code, body = _call(self.svc.put_dkg_failover_policy,
                               "w1", {"enabled": value})
            self.assertEqual(code, 200)
            self.assertEqual(body, {"enabled": value})

    def test_policy_events_same_value_recorded(self):
        for value in (True, True, False):
            code, _ = _call(self.svc.put_dkg_failover_policy,
                            "w1", {"enabled": value})
            self.assertEqual(code, 200)
        events = self._events("dkg_failover_policy_updated")
        # 同值更新也记：恰 3 条
        self.assertEqual(len(events), 3)
        self.assertEqual(
            [e["details"] for e in events],
            [{"enabled": True}, {"enabled": True}, {"enabled": False}],
        )
        for event in events:
            self.assertIsNone(event["request_id"])
            self.assertIsNone(event["actor_id"])
            self.assertIsNone(event["reason"])
            self.assertEqual(list(event["details"]), ["enabled"])
        # 策略由事件恢复：最后一条生效
        code, body = _call(self.svc.get_dkg_failover_policy, "w1")
        self.assertEqual((code, body), (200, {"enabled": False}))

    def test_policy_recovered_from_events_after_restart(self):
        self._enable_policy()
        before = self.svc.get_audit_events("w1")["events"]
        svc2 = WalletService(self.h.store)
        # 恢复不新增审计事件；策略由事件重建
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)
        self.assertEqual(svc2.get_dkg_failover_policy("w1"),
                         {"enabled": True})
        # 事件之外不落任何策略状态文件
        self.assertFalse(
            os.path.exists(os.path.join(self.d, "dkg-failover-policies"))
        )

    def test_tampered_policy_event_is_fail_closed(self):
        self._enable_policy()
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for event in log["events"]:
            if event["type"] == "dkg_failover_policy_updated":
                event["details"]["enabled"] = "yes"  # 篡改：非布尔
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)
        with self.assertRaises(RecoveryError):
            self.svc.get_dkg_failover_policy("w1")

    def test_policy_event_with_request_id_is_fail_closed(self):
        self._enable_policy()
        path = os.path.join(self.d, "audit", "w1.json")
        with open(path, encoding="utf-8") as f:
            log = json.load(f)
        for event in log["events"]:
            if event["type"] == "dkg_failover_policy_updated":
                event["request_id"] = "d1"  # 篡改：request_id 非 null
        with open(path, "w", encoding="utf-8") as f:
            json.dump(log, f)
        with self.assertRaises(RecoveryError):
            WalletService(self.h.store)

    # ---- 禁用时的旧五键契约 -------------------------------------------------

    def test_disabled_rejects_approval_key(self):
        self._register_pair()
        code, _ = self._failover("d1", 2, "abort", approval="ap1")
        self.assertEqual(code, 400)
        # 旧五键行为不变
        code, view = self._failover("d1", 2, "abort")
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "aborted")

    # ---- 启用时的审批门控 ----------------------------------------------------

    def test_enabled_requires_approval_key(self):
        self._enable_policy()
        self._register_pair()
        # 缺 approval_request_id
        code, _ = self._failover("d1", 2, "abort")
        self.assertEqual(code, 400)
        # 非法 approval_request_id
        for bad in ("bad id!", "", None, 1, True):
            code, _ = self._failover("d1", 2, "abort", approval=bad)
            self.assertEqual(code, 400, bad)
        # 现场不变：无 dkg_failover 事件，仍在第 1 轮
        self.assertEqual(self._events("dkg_failover"), [])
        code, view = _call(self.svc.get_dkg_session, "w1", "d1")
        self.assertEqual((code, view["round"]), (200, 1))

    def test_approved_failover_201(self):
        self._enable_policy()
        self._register_pair()
        self._commit_pair()
        message = _approval_message(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C
        )
        self._make_approval("ap1", message)
        code, view = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C,
            approval="ap1",
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["round"], 2)
        self.assertEqual(view["state"], "commit")
        self.assertEqual(view["nodes"], ["n1", "n3"])
        # 恰一条 dkg_failover 事件，形状与旧约一致
        events = self._events("dkg_failover")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["request_id"], "d1/2")
        self.assertEqual(
            list(events[0]["details"]),
            ["id", "round", "action", "node", "replacement", "key",
             "state"],
        )

    def test_approved_abort_201(self):
        self._enable_policy()
        self._register_pair()
        message = _approval_message("d1", 2, "abort")
        self._make_approval("ap1", message)
        code, view = self._failover("d1", 2, "abort", approval="ap1")
        self.assertEqual(code, 201)
        self.assertEqual(view["state"], "aborted")
        self.assertEqual(view["nodes"], [])

    def test_approval_unknown_pending_rejected_409(self):
        self._enable_policy()
        self._register_pair()
        # 未知审批单
        code, _ = self._failover("d1", 2, "abort", approval="nope")
        self.assertEqual(code, 409)
        # pending（未批准）
        message = _approval_message("d1", 2, "abort")
        self._make_approval("ap1", message, approve=False)
        code, _ = self._failover("d1", 2, "abort", approval="ap1")
        self.assertEqual(code, 409)
        # rejected
        code, body = _call(self.svc.reject, "w1", "ap1", "approver-1")
        self.assertEqual(code, 200)
        self.assertEqual(body["state"], "rejected")
        code, _ = self._failover("d1", 2, "abort", approval="ap1")
        self.assertEqual(code, 409)
        # 现场不变
        self.assertEqual(self._events("dkg_failover"), [])
        code, view = _call(self.svc.get_dkg_session, "w1", "d1")
        self.assertEqual((code, view["round"], view["state"]),
                         (200, 1, "commit"))

    def test_approval_expired_409(self):
        self._enable_policy()
        self._register_pair()
        message = _approval_message("d1", 2, "abort")
        # pending 单到点懒过期后为 expired，不可执行
        self._make_approval("ap1", message, approve=False)
        # 把审批单 t1 改到过去，模拟超时
        record = dict(self.h.store.get_request("w1", "ap1"))
        record["t1"] = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat().replace("+00:00", "Z")
        self.h.store.update_request("w1", "ap1", record)
        code, _ = self._failover("d1", 2, "abort", approval="ap1")
        self.assertEqual(code, 409)
        # 懒过期已按 sign-requests 契约持久化
        _, view = _call(self.svc.get_sign_request, "w1", "ap1")
        self.assertEqual(view["state"], "expired")
        self.assertEqual(self._events("dkg_failover"), [])

    def test_approval_message_mismatch_409(self):
        self._enable_policy()
        self._register_pair()
        self._commit_pair()
        base = {"dkg_id": "d1", "round": 2, "action": "replace",
                "node": "n2", "replacement": "n3", "key": KEY_C}
        variants = [
            # 非紧凑（带空格）
            json.dumps(base),
            # 键序不同
            json.dumps(dict(reversed(list(base.items()))),
                       separators=(",", ":")),
            # 参数不同（轮次/动作/节点/换入/key 各异）
            _approval_message("d1", 3, "replace", node="n2",
                              replacement="n3", key=KEY_C),
            _approval_message("d1", 2, "abort"),
            _approval_message("d1", 2, "replace", node="n1",
                              replacement="n3", key=KEY_C),
            _approval_message("d1", 2, "replace", node="n2",
                              replacement="n4", key=KEY_C),
            _approval_message("d1", 2, "replace", node="n2",
                              replacement="n3", key=KEY_D),
            _approval_message("d2", 2, "replace", node="n2",
                              replacement="n3", key=KEY_C),
        ]
        for i, message in enumerate(variants):
            self._make_approval(f"ap{i}", message)
            code, _ = self._failover(
                "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C,
                approval=f"ap{i}",
            )
            self.assertEqual(code, 409, message)
        self.assertEqual(self._events("dkg_failover"), [])

    def test_round_changed_409(self):
        self._enable_policy()
        self._register_pair()
        self._commit_pair()
        # stale 审批锁定 round=2、换入 n9（与将要提交的故障参数不同）；
        # 先用另一张审批单把会话推进到第 2 轮
        stale = _approval_message(
            "d1", 2, "replace", node="n2", replacement="n9", key=KEY_C
        )
        self._make_approval("ap-stale", stale)
        first = _approval_message(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C
        )
        self._make_approval("ap1", first)
        code, _ = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C,
            approval="ap1",
        )
        self.assertEqual(code, 201)
        # 轮次已推进：round=2 不再是当前轮 +1（旧轮 409）
        code, _ = self._failover(
            "d1", 2, "replace", node="n2", replacement="n9", key=KEY_C,
            approval="ap-stale",
        )
        self.assertEqual(code, 409)
        # 审批锁定的 R=2 与当前轮 +1=3 不符（文案不符 409）
        code, _ = self._failover(
            "d1", 3, "replace", node="n2", replacement="n9", key=KEY_C,
            approval="ap-stale",
        )
        self.assertEqual(code, 409)
        # 现场不变：仍恰 1 条 dkg_failover，当前轮仍为 2
        self.assertEqual(len(self._events("dkg_failover")), 1)
        code, view = _call(self.svc.get_dkg_session, "w1", "d1", "2")
        self.assertEqual((code, view["round"]), (200, 2))

    def test_replay_200_without_recheck(self):
        self._enable_policy()
        self._register_pair()
        self._commit_pair()
        message = _approval_message(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C
        )
        self._make_approval("ap1", message)
        code, view = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C,
            approval="ap1",
        )
        self.assertEqual(code, 201)
        # 同参重放 200 同体，且不复查审批（换一个未知审批单也 200）
        code, view2 = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C,
            approval="ap1",
        )
        self.assertEqual(code, 200)
        self.assertEqual(view2, view)
        code, _ = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C,
            approval="nope",
        )
        self.assertEqual(code, 200)
        # 异参 409
        code, _ = self._failover(
            "d1", 2, "replace", node="n1", replacement="n3", key=KEY_C,
            approval="ap1",
        )
        self.assertEqual(code, 409)
        # 重放不记事件：仍恰 1 条 dkg_failover
        self.assertEqual(len(self._events("dkg_failover")), 1)

    def test_sequential_approved_failovers(self):
        self._enable_policy()
        self._register_pair()
        self._commit_pair()
        self._make_approval(
            "ap1",
            _approval_message("d1", 2, "replace", node="n2",
                              replacement="n3", key=KEY_C),
        )
        code, _ = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C,
            approval="ap1",
        )
        self.assertEqual(code, 201)
        self._commit_pair(round="2", n1="n1", n2="n3")
        # 后续故障基于当前轮（第 2 轮），审批锁定 round=3
        self._make_approval(
            "ap2",
            _approval_message("d1", 3, "replace", node="n1",
                              replacement="n4", key=KEY_D),
        )
        code, view = self._failover(
            "d1", 3, "replace", node="n1", replacement="n4", key=KEY_D,
            approval="ap2",
        )
        self.assertEqual(code, 201)
        self.assertEqual(view["round"], 3)
        self.assertEqual(view["nodes"], ["n4", "n3"])

    def test_restart_keeps_policy_rounds_and_seq(self):
        self._enable_policy()
        self._register_pair()
        self._commit_pair()
        self._make_approval(
            "ap1",
            _approval_message("d1", 2, "replace", node="n2",
                              replacement="n3", key=KEY_C),
        )
        code, _ = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C,
            approval="ap1",
        )
        self.assertEqual(code, 201)
        before = self.svc.get_audit_events("w1")["events"]
        svc2 = WalletService(self.h.store)
        self.assertEqual(svc2.get_audit_events("w1")["events"], before)
        self.assertEqual(svc2.get_dkg_failover_policy("w1"),
                         {"enabled": True})
        view = svc2.get_dkg_session("w1", "d1", "2")
        self.assertEqual(view["nodes"], ["n1", "n3"])
        # 重启后同参重放仍 200（策略仍启用，但不复查审批）
        code, _ = _call(
            svc2.post_dkg_failover,
            "w1", "d1", 2, "replace", "n2", "n3", KEY_C,
            approval_request_id="ap1",
        )
        self.assertEqual(code, 200)
        seqs = [e["seq"] for e in svc2.get_audit_events("w1")["events"]]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))

    def test_backup_restore_keeps_policy_and_rounds(self):
        self._enable_policy()
        self._register_pair()
        self._commit_pair()
        self._make_approval(
            "ap1",
            _approval_message("d1", 2, "replace", node="n2",
                              replacement="n3", key=KEY_C),
        )
        code, _ = self._failover(
            "d1", 2, "replace", node="n2", replacement="n3", key=KEY_C,
            approval="ap1",
        )
        self.assertEqual(code, 201)
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
        self.assertEqual(svc2.get_audit_events("w1")["events"],
                         self.svc.get_audit_events("w1")["events"])
        view = svc2.get_dkg_session("w1", "d1", "2")
        self.assertEqual(view["nodes"], ["n1", "n3"])


class DkgFailoverPolicyHttpTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def test_http_policy_flow(self):
        with http_server(self.d) as srv:
            code, _ = srv.request(
                "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
            )
            self.assertEqual(code, 201)
            # 缺省 false
            code, body = srv.request(
                "GET", "/v1/wallets/w1/dkg-failover-policy"
            )
            self.assertEqual((code, body), (200, {"enabled": False}))
            # 非法请求体 400
            for bad in ({}, {"enabled": 1}, {"enabled": True, "x": 1}):
                code, _ = srv.request(
                    "PUT", "/v1/wallets/w1/dkg-failover-policy", bad
                )
                self.assertEqual(code, 400, bad)
            # 设置/查询同体
            code, body = srv.request(
                "PUT", "/v1/wallets/w1/dkg-failover-policy",
                {"enabled": True},
            )
            self.assertEqual((code, body), (200, {"enabled": True}))
            code, body = srv.request(
                "GET", "/v1/wallets/w1/dkg-failover-policy"
            )
            self.assertEqual((code, body), (200, {"enabled": True}))
            # 钱包不存在 404
            code, _ = srv.request(
                "GET", "/v1/wallets/nope/dkg-failover-policy"
            )
            self.assertEqual(code, 404)
            code, _ = srv.request(
                "PUT", "/v1/wallets/nope/dkg-failover-policy",
                {"enabled": True},
            )
            self.assertEqual(code, 404)

    def test_http_failover_with_approval(self):
        with http_server(self.d) as srv:
            srv.request(
                "POST", "/v1/wallets", {"wallet_id": "w1", "shares": 2}
            )
            for node, key in (("n1", KEY_A), ("n2", KEY_B)):
                srv.request(
                    "POST", "/v1/dkg/w1/d1",
                    {"op": "register", "node": node, "key": key,
                     "hash": None, "peer": None},
                )
            base = {"round": 2, "action": "abort", "node": None,
                    "replacement": None, "key": None}
            # 策略禁用：夹带 approval_request_id 一律 400；旧五键 201
            code, _ = srv.request(
                "POST", "/v1/dkg/w1/d1/failover",
                {**base, "approval_request_id": "ap1"},
            )
            self.assertEqual(code, 400)
            # 启用策略
            code, _ = srv.request(
                "PUT", "/v1/wallets/w1/dkg-failover-policy",
                {"enabled": True},
            )
            self.assertEqual(code, 200)
            # 启用后旧五键（缺 approval_request_id）400
            code, _ = srv.request("POST", "/v1/dkg/w1/d1/failover", base)
            self.assertEqual(code, 400)
            # 未知审批单 409
            code, _ = srv.request(
                "POST", "/v1/dkg/w1/d1/failover",
                {**base, "approval_request_id": "ap1"},
            )
            self.assertEqual(code, 409)
            # 审批流沿用 sign-requests 契约
            code, _ = srv.request(
                "PUT", "/v1/wallets/w1/approval-policy",
                {"required_approvals": 1, "timeout_seconds": 3600},
            )
            self.assertEqual(code, 200)
            message = _approval_message("d1", 2, "abort")
            code, _ = srv.request(
                "POST", "/v1/wallets/w1/sign-requests",
                {"id": "ap1", "message": message},
            )
            self.assertEqual(code, 201)
            code, _ = srv.request(
                "POST", "/v1/wallets/w1/sign-requests/ap1/approve",
                {"approver_id": "a1"},
            )
            self.assertEqual(code, 200)
            # approved 且 R=当前轮+1：201
            code, view = srv.request(
                "POST", "/v1/dkg/w1/d1/failover",
                {**base, "approval_request_id": "ap1"},
            )
            self.assertEqual(code, 201)
            self.assertEqual(view["state"], "aborted")
            # 同参重放 200
            code, _ = srv.request(
                "POST", "/v1/dkg/w1/d1/failover",
                {**base, "approval_request_id": "ap1"},
            )
            self.assertEqual(code, 200)


if __name__ == "__main__":
    unittest.main()
