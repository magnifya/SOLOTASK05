"""锁文件首次初始化的跨线程/跨进程竞态回归测试。

多个执行流并发首次获取同一把钱包锁时，锁文件内容必须恰为合法 JSON
"{}"，而不是在 flock 之前各自追加产生的 "{}{}" 等内容。
"""

from __future__ import annotations

import os
import shutil
import tempfile
import threading
import unittest

from threshold_wallet.flock import FileLock, wallet_lock_path


class LockFileInitRaceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_concurrent_first_acquire_writes_valid_json_once(self):
        path = wallet_lock_path(self.tmp, "w1")
        n = 32
        barrier = threading.Barrier(n)

        def acquire_once() -> None:
            barrier.wait()
            with FileLock(path):
                pass

        threads = [threading.Thread(target=acquire_once) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        with open(path, "rb") as f:
            content = f.read()
        self.assertEqual(content, b"{}", content)


if __name__ == "__main__":
    unittest.main()
