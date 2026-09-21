"""共享 data-dir 并发请求的锁内线性化回归测试。

固定以下不变量（修复"锁外快照决定 404/409/幂等/策略结果"缺口）：

- 任何读取或修改钱包状态的操作，在拿到该钱包跨进程事务锁之前不得给出
  结论：另一事务持锁在途时（包括建钱包本身），请求必须阻塞到对方提交，
  再以锁内线性化顺序判定 404/400/409/幂等与策略结果；
- 策略 PUT 与资产首次创建、批准与 cold 首签、轮换激活与首签、资产提交
  与资产查询交错时，后到者只看到已提交状态，绝不读到旧策略、未批准、
  旧公钥或半完成余额；
- 同一把锁串行后，同一操作仍只有一个首次 201，其余 200 同体。
"""

from __future__ import annotations

import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from tests.helpers import make_harness
from threshold_wallet.service import ServiceError


class _Gate:
    """让被 hook 的存储调用在仍持有钱包事务锁时停住，直到放行。"""

    def __init__(self):
        self.parked = threading.Event()
        self.proceed = threading.Event()

    def wait(self):
        self.parked.set()
        self.proceed.wait(timeout=10)


def _status(call):
    try:
        call()
    except ServiceError as exc:
        return exc.status
    raise AssertionError("expected ServiceError")


class NoDecisionBeforeLockTest(unittest.TestCase):
    """建钱包事务持锁在途时，任何状态路由都不得先用锁外快照给出结论。

    修复前 sign/GET 等会在加锁前先读钱包元数据决定 404：建钱包在途
    （元数据尚未落盘）时立即返回 404，而正确线性化顺序应是阻塞到建钱包
    提交，再按已存在的钱包继续。
    """

    def setUp(self):
        self.h = make_harness(tempfile.mkdtemp())
        self.svc = self.h.service
        self.gate = _Gate()
        self._real_create = self.h.store.create_wallet

        def gated_create(wallet_id, shares, created_at):
            # service 已在该钱包事务锁内调用本方法：在此停住即模拟在途事务
            self.gate.wait()
            return self._real_create(wallet_id, shares, created_at)

        self.h.store.create_wallet = gated_create

    def tearDown(self):
        # 保证任何卡住的线程被放行
        self.gate.proceed.set()

    def _start(self, target):
        holder = {}

        def run():
            holder["result"] = target()

        thread = threading.Thread(target=run)
        thread.start()
        self.assertTrue(self.gate.parked.wait(timeout=5))
        return thread, holder

    def test_get_wallet_blocks_then_sees_created_wallet(self):
        thread, holder = self._start(lambda: self.svc.create_wallet("w1", 2))
        t2 = threading.Thread(target=lambda: holder.setdefault(
            "get", self.svc.get_wallet("w1")))
        t2.start()
        t2.join(timeout=0.3)
        # 建钱包未提交前绝不允许用锁外快照回答 404
        self.assertNotIn("get", holder)
        self.gate.proceed.set()
        thread.join(5)
        t2.join(5)
        self.assertEqual(holder["get"]["wallet_id"], "w1")

    def test_sign_blocks_then_wallet_exists(self):
        thread, holder = self._start(lambda: self.svc.create_wallet("w1", 2))

        def call():
            # 份额数都不对：钱包存在后应在线性化点得到 400，而不是 404
            return self.svc.sign("w1", "r1", "m", [])

        t2 = threading.Thread(
            target=lambda: holder.setdefault("code", _status(call)))
        t2.start()
        t2.join(timeout=0.3)
        self.assertNotIn("code", holder, "sign 在锁外抢先返回了结论")
        self.gate.proceed.set()
        thread.join(5)
        t2.join(5)
        self.assertEqual(holder["code"], 400)

    def test_create_request_blocks_then_wallet_exists(self):
        thread, holder = self._start(lambda: self.svc.create_wallet("w1", 2))

        def call():
            return self.svc.create_sign_request("w1", "r1", "m")

        t2 = threading.Thread(
            target=lambda: holder.setdefault("code", _status(call)))
        t2.start()
        t2.join(timeout=0.3)
        self.assertNotIn("code", holder)
        self.gate.proceed.set()
        thread.join(5)
        t2.join(5)
        # 钱包已建（线性化在后）但尚无审批策略 -> 409，绝不是锁外 404
        self.assertEqual(holder["code"], 409)

    def test_audit_get_blocks_then_wallet_exists(self):
        thread, holder = self._start(lambda: self.svc.create_wallet("w1", 2))
        t2 = threading.Thread(
            target=lambda: holder.setdefault(
                "audit", self.svc.get_audit_events("w1")))
        t2.start()
        t2.join(timeout=0.3)
        self.assertNotIn("audit", holder)
        self.gate.proceed.set()
        thread.join(5)
        t2.join(5)
        self.assertEqual(holder["audit"]["events"], [])

    def test_asset_get_blocks_then_wallet_exists(self):
        thread, holder = self._start(lambda: self.svc.create_wallet("w1", 2))

        def call():
            return self.svc.get_asset("w1", "btc")

        t2 = threading.Thread(
            target=lambda: holder.setdefault("code", _status(call)))
        t2.start()
        t2.join(timeout=0.3)
        self.assertNotIn("code", holder)
        self.gate.proceed.set()
        thread.join(5)
        t2.join(5)
        # 钱包存在（404 优先级先过），资产不存在 -> 资产 404，而非钱包 404
        self.assertEqual(holder["code"], 404)


class PolicyAssetInterleaveTest(unittest.TestCase):
    """交易策略 PUT 与资产首次创建交错：创建只按锁提交时已生效的策略判定。"""

    def setUp(self):
        self.h = make_harness(tempfile.mkdtemp())
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)

    def test_policy_commits_before_asset_create_which_then_rejects(self):
        gate = _Gate()
        real_save = self.h.store.save_transaction_policy

        def gated(wallet_id, policy):
            gate.wait()
            return real_save(wallet_id, policy)

        self.h.store.save_transaction_policy = gated
        holder = {}

        def put():
            holder["put"] = self.svc.put_transaction_policy(
                "w1", "hot", 5, ["btc"])

        t1 = threading.Thread(target=put)
        t1.start()
        self.assertTrue(gate.parked.wait(5))

        def create():
            return self.svc.create_asset_operation("w1", "op1", "btc", 100)

        t2 = threading.Thread(
            target=lambda: holder.setdefault(
                "create", _status(create)))
        t2.start()
        t2.join(0.3)
        self.assertNotIn("create", holder, "创建不得越过在途策略事务")
        gate.proceed.set()
        t1.join(5)
        t2.join(5)
        # 线性化顺序：策略先提交（max_delta=5），创建随后按新策略判定 409
        self.assertEqual(holder["create"], 409)
        # 失败不得产生账本/事件副作用
        self.assertIsNone(self.h.store.get_asset_operation("w1", "op1"))
        self.assertEqual(_status(lambda: self.svc.get_asset("w1", "btc")), 404)

    def test_asset_create_in_flight_blocks_policy_put(self):
        # 先放一个在途创建（持锁停在写账本时），PUT 必须等其提交；
        # 创建时刻无策略 -> 201，策略不影响已存在 pending。
        self.svc.create_asset_operation("w1", "op1", "eth", 100)
        gate = _Gate()
        real_create = self.h.store.create_asset_operation

        def gated(wallet_id, operation_id, record):
            gate.wait()
            return real_create(wallet_id, operation_id, record)

        self.h.store.create_asset_operation = gated
        holder = {}

        def create():
            holder["create"] = self.svc.create_asset_operation(
                "w1", "op2", "eth", 100)

        t1 = threading.Thread(target=create)
        t1.start()
        self.assertTrue(gate.parked.wait(5))
        t2 = threading.Thread(target=lambda: holder.setdefault(
            "put", self.svc.put_transaction_policy("w1", "hot", 5, ["btc"])))
        t2.start()
        t2.join(0.3)
        self.assertNotIn("put", holder)
        gate.proceed.set()
        t1.join(5)
        t2.join(5)
        self.assertEqual(holder["create"][0], 201)
        self.assertEqual(holder["put"]["mode"], "hot")
        # 白名单更新后，已存在的 pending(op2, eth) 重放仍 200 且不复查
        status, view = self.svc.create_asset_operation("w1", "op2", "eth", 100)
        self.assertEqual(status, 200)
        self.assertEqual(view["state"], "pending")


class ApproveColdSignInterleaveTest(unittest.TestCase):
    """批准与 cold 首签交错：批准提交前首签拿不到 approved，提交后即 201。"""

    def setUp(self):
        self.h = make_harness(tempfile.mkdtemp())
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.put_policy("w1", 1, 3600)
        self.svc.put_transaction_policy("w1", "cold", 1000, ["btc"])
        self.svc.create_sign_request("w1", "r1", "m")
        self.sigs = self.h.two_signatures("w1", "r1", "m")

    def test_sign_blocks_until_approve_commits_then_201(self):
        gate = _Gate()
        real_update = self.h.store.update_request

        def gated(wallet_id, rid, record):
            # 批准在锁内写审批单时停住：此时磁盘上仍是 pending
            if record.get("state") == "approved":
                gate.wait()
            return real_update(wallet_id, rid, record)

        self.h.store.update_request = gated
        holder = {}

        def approve():
            holder["approve"] = self.svc.approve("w1", "r1", "alice")

        t1 = threading.Thread(target=approve)
        t1.start()
        self.assertTrue(gate.parked.wait(5))

        def sign():
            return self.svc.sign("w1", "r1", "m", self.sigs)

        t2 = threading.Thread(target=lambda: holder.setdefault("sign", sign()))
        t2.start()
        t2.join(0.3)
        self.assertNotIn("sign", holder, "cold 首签不得越过在途批准读到 pending")
        gate.proceed.set()
        t1.join(5)
        t2.join(5)
        self.assertEqual(holder["sign"][0], 201)
        # 立即重放 200 同体，且只有一个首提事件
        status, body = self.svc.sign("w1", "r1", "m", self.sigs)
        self.assertEqual(status, 200)
        self.assertEqual(body["signature"], holder["sign"][1]["signature"])
        types = [e["type"] for e in self.svc.get_audit_events("w1")["events"]]
        self.assertEqual(types.count("request_signed"), 1)

    def test_sign_before_approval_is_409_then_approval_and_sign(self):
        # 未批准时首签 409 且无副作用；批准后 201
        self.assertEqual(
            _status(lambda: self.svc.sign("w1", "r1", "m", self.sigs)), 409)
        self.svc.approve("w1", "r1", "alice")
        status, _ = self.svc.sign("w1", "r1", "m", self.sigs)
        self.assertEqual(status, 201)


class RotationSignInterleaveTest(unittest.TestCase):
    """轮换激活与首签交错：激活在途时首签阻塞；激活后旧份额 400、
    激活前已首签的请求重放 200。"""

    def setUp(self):
        self.h = make_harness(tempfile.mkdtemp())
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        # 激活前先首签 rold
        self.old_sigs = self.h.two_signatures("w1", "rold", "m")
        self.assertEqual(self.svc.sign("w1", "rold", "m", self.old_sigs)[0], 201)
        _, prepared = self.svc.create_share_rotation("w1", "rot-1")
        self.new_share_ids = prepared["share_ids"]

    def test_sign_blocks_during_activation_then_rejects_old_shares(self):
        gate = _Gate()
        real_save_meta = self.h.store.save_wallet_meta

        def gated(wallet_id, meta):
            # 换入窗口：新份额/公钥正在落盘
            gate.wait()
            return real_save_meta(wallet_id, meta)

        self.h.store.save_wallet_meta = gated
        holder = {}
        t1 = threading.Thread(target=lambda: holder.setdefault(
            "activate", self.svc.activate_share_rotation("w1", "rot-1")))
        t1.start()
        self.assertTrue(gate.parked.wait(5))

        new_sigs = [
            {
                "share_id": sid,
                "signature": self.h.share_signature("w1", sid, "rnew", "m"),
            }
            for sid in self.new_share_ids
        ]

        def sign_new():
            return self.svc.sign("w1", "rnew", "m", new_sigs)

        t2 = threading.Thread(target=lambda: holder.setdefault("sign", sign_new()))
        t2.start()
        t2.join(0.3)
        self.assertNotIn("sign", holder, "首签不得读到半换入公钥")
        gate.proceed.set()
        t1.join(5)
        t2.join(5)
        self.assertEqual(holder["activate"][0], 201)
        self.assertEqual(holder["sign"][0], 201)

        # 激活后未首签请求用旧份额 -> 400
        def sign_old():
            return self.svc.sign("w1", "r2", "m", self.old_sigs)
        self.assertEqual(_status(sign_old), 400)
        # 激活前已首签的请求重放 200 同体
        status, body = self.svc.sign("w1", "rold", "m", self.old_sigs)
        self.assertEqual(status, 200)
        self.assertEqual(body["signature"], self.h.store.get_signature(
            "w1", "rold")["signature"])


class CommitQueryInterleaveTest(unittest.TestCase):
    """资产提交在途时查询必须阻塞，提交后只看到最终余额/version。"""

    def setUp(self):
        self.h = make_harness(tempfile.mkdtemp())
        self.svc = self.h.service
        self.svc.create_wallet("w1", 2)
        self.svc.create_asset_operation("w1", "op1", "btc", 100)

    def test_get_asset_blocks_until_commit_visible(self):
        gate = _Gate()
        real_commit = self.h.store.commit_asset_operation

        def gated(wallet_id, op_id, op_rec, asset_id, asset_rec):
            gate.wait()
            return real_commit(wallet_id, op_id, op_rec, asset_id, asset_rec)

        self.h.store.commit_asset_operation = gated
        holder = {}
        t1 = threading.Thread(target=lambda: holder.setdefault(
            "commit", self.svc.commit_asset_operation("w1", "op1")))
        t1.start()
        self.assertTrue(gate.parked.wait(5))
        t2 = threading.Thread(target=lambda: holder.setdefault(
            "get", self.svc.get_asset("w1", "btc")))
        t2.start()
        t2.join(0.3)
        self.assertNotIn("get", holder)
        gate.proceed.set()
        t1.join(5)
        t2.join(5)
        self.assertEqual(holder["commit"][0], 201)
        self.assertEqual((holder["get"]["balance"], holder["get"]["version"]),
                         (100, 1))

    def test_concurrent_commits_single_201_rest_200_same_body(self):
        def attempt(_):
            return self.svc.commit_asset_operation("w1", "op1")

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(attempt, range(16)))
        codes = sorted(c for c, _ in results)
        self.assertEqual(codes.count(201), 1)
        self.assertEqual(codes.count(200), 15)
        bodies = {tuple(sorted(r.items())) for _, r in results}
        self.assertEqual(len(bodies), 1)
        asset = self.svc.get_asset("w1", "btc")
        self.assertEqual((asset["balance"], asset["version"]), (100, 1))
        types = [e["type"] for e in self.svc.get_audit_events("w1")["events"]]
        self.assertEqual(types.count("asset_operation_committed"), 1)


if __name__ == "__main__":
    unittest.main()
