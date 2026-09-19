"""多进程/多实例共用一个 data-dir 的并发与故障测试。

- 双 service 实例（各自独立 store，仅靠 flock 互斥）线程级并发：
  激活、签名、建钱包、激活与签名交错，均只能有一个首次提交；
- 真实子进程并发激活/签名：跨进程事务锁保证状态一致、审计连续；
- 异常退出（kill -9）后 flock 由内核释放，不会被陈旧锁阻塞。

可独立运行：python -m unittest tests.test_multiprocess -v
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from threshold_wallet import crypto
from threshold_wallet.audit import AuditStore
from threshold_wallet.service import WalletService
from threshold_wallet.store import WalletStore

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _new_service(data_dir: str) -> WalletService:
    return WalletService(WalletStore(data_dir))


def _run_concurrently(fn_a, fn_b):
    """用起跑栅栏让两个调用尽量同时进入，返回 [result_a, result_b]。"""
    barrier = threading.Barrier(3)
    results = [None, None]

    def make_callable(index, fn):
        def call():
            barrier.wait()
            results[index] = fn()

        return call

    threads = [
        threading.Thread(target=make_callable(0, fn_a)),
        threading.Thread(target=make_callable(1, fn_b)),
    ]
    for t in threads:
        t.start()
    barrier.wait()
    for t in threads:
        t.join(timeout=30)
    return results


class DualInstanceConcurrencyTest(unittest.TestCase):
    """两个 WalletService 实例共用同一 data-dir（等价于两个服务进程）。"""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp()
        self.svc_a = _new_service(self.data_dir)
        self.svc_b = _new_service(self.data_dir)
        self.wallet = self.svc_a.create_wallet("w1", 2)

    def _events(self):
        return AuditStore(self.data_dir).list_events("w1")

    def _sign_args(self, service, request_id, message, share_ids):
        signatures = []
        for sid in share_ids:
            share = service._store.get_share("w1", sid)
            payload = crypto.build_payload(request_id, message)
            signatures.append(
                {
                    "share_id": sid,
                    "signature": crypto.sign_share(
                        bytes.fromhex(share["private_key"]), payload
                    ).hex(),
                }
            )
        return ("w1", request_id, message, signatures)

    def test_concurrent_create_wallet_single_success(self):
        svc_c = _new_service(self.data_dir)
        svc_d = _new_service(self.data_dir)
        results = _run_concurrently(
            lambda: self._create_quietly(svc_c, "w-race"),
            lambda: self._create_quietly(svc_d, "w-race"),
        )
        statuses = sorted(r[0] for r in results)
        self.assertEqual(statuses, [201, 409])
        # 落盘的钱包元数据与份额文件一致（公钥可由份额文件复现）
        store = WalletStore(self.data_dir)
        meta = store.get_wallet("w-race")
        pubs = b""
        for entry in meta["shares"]:
            share = store.get_share("w-race", entry["share_id"])
            self.assertEqual(share["public_key"], entry["public_key"])
            pubs += bytes.fromhex(share["public_key"])
        self.assertEqual(pubs.hex(), meta["public_key"])

    @staticmethod
    def _create_quietly(service, wallet_id):
        try:
            return 201, service.create_wallet(wallet_id, 2)
        except Exception as exc:
            return getattr(exc, "status", 500), str(exc)

    def test_concurrent_activate_single_first_commit(self):
        status, prep = self.svc_a.create_share_rotation("w1", "rot-1")
        self.assertEqual(status, 201)
        results = _run_concurrently(
            lambda: self.svc_a.activate_share_rotation("w1", "rot-1"),
            lambda: self.svc_b.activate_share_rotation("w1", "rot-1"),
        )
        statuses = sorted(r[0] for r in results)
        # 只能一个首次提交（201），另一个为幂等重放（200）
        self.assertEqual(statuses, [200, 201])
        for _, body in results:
            self.assertEqual(body["state"], "active")
            self.assertEqual(body["public_key"], prep["public_key"])
        # 钱包元数据一次性切到新公钥， activated 事件恰好一条
        meta = self.svc_a._store.get_wallet("w1")
        self.assertEqual(meta["public_key"], prep["public_key"])
        activated = [
            e for e in self._events() if e["type"] == "share_rotation_activated"
        ]
        self.assertEqual(len(activated), 1)
        self.assertEqual([e["seq"] for e in self._events()], [1, 2])

    def test_concurrent_sign_single_first_commit(self):
        args_a = self._sign_args(self.svc_a, "req-1", "m", ("share-1", "share-2"))
        args_b = self._sign_args(self.svc_b, "req-1", "m", ("share-1", "share-2"))
        results = _run_concurrently(
            lambda: self.svc_a.sign(*args_a),
            lambda: self.svc_b.sign(*args_b),
        )
        statuses = sorted(r[0] for r in results)
        self.assertEqual(statuses, [200, 201])
        # 两个响应的签名相同：不存在半签名或两种聚合结果
        self.assertEqual(results[0][1]["signature"], results[1][1]["signature"])
        signed = [e for e in self._events() if e["type"] == "request_signed"]
        self.assertEqual(len(signed), 1)

    def test_sign_and_activate_race_no_mixed_state(self):
        """签名与激活跨实例交错：旧份额签名要么整体先提交（201），
        要么在激活后被拒（400）；绝不出现半签名或混合公钥。"""
        status, prep = self.svc_a.create_share_rotation("w1", "rot-1")
        self.assertEqual(status, 201)
        old_pub = self.wallet["public_key"]
        sign_args = self._sign_args(
            self.svc_a, "req-race", "pay", ("share-1", "share-2")
        )
        sign_result, activate_result = _run_concurrently(
            lambda: self._sign_quietly(self.svc_a, sign_args),
            lambda: self.svc_b.activate_share_rotation("w1", "rot-1"),
        )
        self.assertEqual(activate_result[0], 201)
        meta = self.svc_a._store.get_wallet("w1")
        # 激活提交后钱包公钥必须是新公钥，绝不混合
        self.assertEqual(meta["public_key"], prep["public_key"])
        self.assertNotEqual(meta["public_key"], old_pub)
        signature_record = self.svc_a._store.get_signature("w1", "req-race")
        if sign_result[0] == 201:
            # 签名先于激活提交：记录完整落盘，重放仍 200
            self.assertIsNotNone(signature_record)
            status, replay = self.svc_b.sign(*sign_args)
            self.assertEqual(status, 200)
            self.assertEqual(
                replay["signature"], signature_record["signature"]
            )
        else:
            # 激活先提交：旧份额签名被拒（400），且无半签名残留
            self.assertEqual(sign_result[0], 400)
            self.assertIsNone(signature_record)
        # 激活后未首签的请求：旧份额一律 400，新份额 201
        old_again = self._sign_args(
            self.svc_a, "req-new", "pay2", ("share-1", "share-2")
        )
        # share-1/share-2 文件已删除，构造旧份额签名改用激活前的私钥备份：
        # 这里直接验证未知 share_id 被拒即可
        status, _ = self._sign_quietly(
            self.svc_b,
            ("w1", "req-new", "pay2", old_again[3]),
        )
        self.assertEqual(status, 400)
        new_args = self._sign_args(
            self.svc_b, "req-new", "pay2", prep["share_ids"]
        )
        status, body = self.svc_b.sign(*new_args)
        self.assertEqual(status, 201)
        self.assertEqual(len(bytes.fromhex(body["signature"])), 128)
        # 审计 seq 连续升序、无重复、无缺口
        seqs = [e["seq"] for e in self._events()]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))

    @staticmethod
    def _sign_quietly(service, args):
        try:
            return service.sign(*args)
        except Exception as exc:
            return getattr(exc, "status", 500), {"error": str(exc)}


class CrossProcessTest(unittest.TestCase):
    """真实子进程并发：跨进程事务锁与审计连续性。"""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp()
        self.service = _new_service(self.data_dir)
        self.wallet = self.service.create_wallet("w1", 2)

    def _run_worker(self, code: str, *args: str) -> list:
        env = dict(os.environ)
        env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            [sys.executable, "-c", code, *args],
            capture_output=True,
            text=True,
            env=env,
            cwd=REPO_ROOT,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout.strip())

    def test_two_processes_concurrent_activate(self):
        status, prep = self.service.create_share_rotation("w1", "rot-1")
        self.assertEqual(status, 201)
        worker = (
            "import json, sys\n"
            "from threshold_wallet.service import WalletService\n"
            "from threshold_wallet.store import WalletStore\n"
            "svc = WalletService(WalletStore(sys.argv[1]))\n"
            "out = []\n"
            "for _ in range(10):\n"
            "    try:\n"
            "        status, _ = svc.activate_share_rotation('w1', 'rot-1')\n"
            "        out.append(status)\n"
            "    except Exception as exc:\n"
            "        out.append(getattr(exc, 'status', 500))\n"
            "print(json.dumps(out))\n"
        )
        env = dict(os.environ)
        env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
        procs = [
            subprocess.Popen(
                [sys.executable, "-c", worker, self.data_dir],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                cwd=REPO_ROOT,
            )
            for _ in range(2)
        ]
        all_statuses = []
        for proc in procs:
            stdout, stderr = proc.communicate(timeout=120)
            self.assertEqual(proc.returncode, 0, stderr)
            all_statuses.extend(json.loads(stdout.strip()))
        # 两个进程共 20 次激活：恰好一个 201，其余全部 200
        self.assertEqual(sorted(all_statuses), [201] + [200] * 19)
        meta = self.service._store.get_wallet("w1")
        self.assertEqual(meta["public_key"], prep["public_key"])
        events = AuditStore(self.data_dir).list_events("w1")
        activated = [
            e for e in events if e["type"] == "share_rotation_activated"
        ]
        self.assertEqual(len(activated), 1)
        seqs = [e["seq"] for e in events]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))

    def test_two_processes_concurrent_sign(self):
        worker = (
            "import json, sys\n"
            "from threshold_wallet import crypto\n"
            "from threshold_wallet.service import WalletService\n"
            "from threshold_wallet.store import WalletStore\n"
            "svc = WalletService(WalletStore(sys.argv[1]))\n"
            "sigs = []\n"
            "for sid in ('share-1', 'share-2'):\n"
            "    share = svc._store.get_share('w1', sid)\n"
            "    payload = crypto.build_payload('req-x', 'm')\n"
            "    sigs.append({'share_id': sid, 'signature': crypto.sign_share(\n"
            "        bytes.fromhex(share['private_key']), payload).hex()})\n"
            "out = []\n"
            "for _ in range(10):\n"
            "    try:\n"
            "        status, body = svc.sign('w1', 'req-x', 'm', sigs)\n"
            "        out.append((status, body.get('signature')))\n"
            "    except Exception as exc:\n"
            "        out.append((getattr(exc, 'status', 500), None))\n"
            "print(json.dumps(out))\n"
        )
        env = dict(os.environ)
        env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
        procs = [
            subprocess.Popen(
                [sys.executable, "-c", worker, self.data_dir],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                cwd=REPO_ROOT,
            )
            for _ in range(2)
        ]
        statuses, signatures = [], set()
        for proc in procs:
            stdout, stderr = proc.communicate(timeout=120)
            self.assertEqual(proc.returncode, 0, stderr)
            for status, signature in json.loads(stdout.strip()):
                statuses.append(status)
                signatures.add(signature)
        # 恰好一个首签 201，其余重放 200，且聚合签名唯一
        self.assertEqual(sorted(statuses), [201] + [200] * 19)
        self.assertEqual(len(signatures), 1)
        events = AuditStore(self.data_dir).list_events("w1")
        signed = [e for e in events if e["type"] == "request_signed"]
        self.assertEqual(len(signed), 1)

    def test_killed_process_leaves_no_stale_lock(self):
        """持有钱包锁的进程被 kill -9 后，新进程能立即获得锁继续工作。"""
        holder = (
            "import sys, time\n"
            "from threshold_wallet.locks import WalletLockManager\n"
            "import os\n"
            "m = WalletLockManager(os.path.join(sys.argv[1], 'locks'))\n"
            "with m.hold('w1'):\n"
            "    print('locked', flush=True)\n"
            "    time.sleep(60)\n"
        )
        env = dict(os.environ)
        env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.Popen(
            [sys.executable, "-c", holder, self.data_dir],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            cwd=REPO_ROOT,
        )
        try:
            self.assertEqual(proc.stdout.readline().strip(), "locked")
            proc.kill()  # SIGKILL：模拟节点崩溃
            proc.wait(timeout=10)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
        # 崩溃进程持有的 flock 已由内核释放：操作应在数秒内完成
        service2 = _new_service(self.data_dir)
        start = time.monotonic()
        policy = service2.put_policy("w1", 1, 3600)
        elapsed = time.monotonic() - start
        self.assertEqual(policy["required_approvals"], 1)
        self.assertLess(elapsed, 10)
        events = AuditStore(self.data_dir).list_events("w1")
        self.assertEqual([e["seq"] for e in events], [1])


if __name__ == "__main__":
    unittest.main()
