"""CLI 测试：create/sign/show 通过 HTTP 打向真实测试服务器，share-sign 走本地。"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest

from tests.helpers import http_server
from threshold_wallet.cli import main


class CliTest(unittest.TestCase):
    def setUp(self):
        self._ctx = http_server(tempfile.mkdtemp())
        self.srv = self._ctx.__enter__()
        self.url = self.srv.base_url
        self.data_dir = self.srv.harness.tmpdir

    def tearDown(self):
        self._ctx.__exit__(None, None, None)

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue().strip(), err.getvalue().strip()

    def assertSingleLineJson(self, text):
        self.assertEqual(len(text.splitlines()), 1, text)
        return json.loads(text)

    def test_create_ok_single_line_json(self):
        code, out, err = self.run_cli(
            "create", "--url", self.url, "--wallet-id", "w1", "--shares", "2"
        )
        self.assertEqual(code, 0, err)
        body = self.assertSingleLineJson(out)
        self.assertEqual(body["share_ids"], ["share-1", "share-2"])
        self.assertEqual(len(bytes.fromhex(body["public_key"])), 64)

    def test_create_bad_shares_exit_1(self):
        code, out, err = self.run_cli(
            "create", "--url", self.url, "--wallet-id", "w2", "--shares", "3"
        )
        self.assertEqual(code, 1)
        self.assertEqual(self.assertSingleLineJson(err)["error"], "shares must equal 2")

    def test_create_duplicate_exit_1(self):
        self.run_cli("create", "--url", self.url, "--wallet-id", "w1", "--shares", "2")
        code, _, err = self.run_cli(
            "create", "--url", self.url, "--wallet-id", "w1", "--shares", "2"
        )
        self.assertEqual(code, 1)
        self.assertIn("already exists", json.loads(err)["error"])

    def test_show_ok_and_missing(self):
        self.run_cli("create", "--url", self.url, "--wallet-id", "w1", "--shares", "2")
        code, out, _ = self.run_cli("show", "--url", self.url, "--wallet-id", "w1")
        self.assertEqual(code, 0)
        body = self.assertSingleLineJson(out)
        self.assertIn("public_key", body)
        self.assertIn("created_at", body)
        self.assertNotIn("private_key", body)

        code, _, err = self.run_cli("show", "--url", self.url, "--wallet-id", "ghost")
        self.assertEqual(code, 1)
        self.assertIn("not found", json.loads(err)["error"])

    def test_full_sign_flow_via_cli(self):
        self.run_cli("create", "--url", self.url, "--wallet-id", "w1", "--shares", "2")

        def share_sign(share_id):
            code, out, err = self.run_cli(
                "share-sign",
                "--data-dir", self.data_dir,
                "--wallet-id", "w1",
                "--share-id", share_id,
                "--signing-request-id", "req-1",
                "--message", "pay-100",
            )
            self.assertEqual(code, 0, err)
            return self.assertSingleLineJson(out)["signature"]

        h1, h2 = share_sign("share-1"), share_sign("share-2")
        code, out, err = self.run_cli(
            "sign",
            "--url", self.url,
            "--wallet-id", "w1",
            "--signing-request-id", "req-1",
            "--message", "pay-100",
            "--signature", f"share-1={h1}",
            "--signature", f"share-2={h2}",
        )
        self.assertEqual(code, 0, err)
        body = self.assertSingleLineJson(out)
        self.assertEqual(len(bytes.fromhex(body["signature"])), 128)

        # 重放仍成功（幂等 200）
        code2, out2, _ = self.run_cli(
            "sign",
            "--url", self.url,
            "--wallet-id", "w1",
            "--signing-request-id", "req-1",
            "--message", "pay-100",
            "--signature", f"share-1={h1}",
            "--signature", f"share-2={h2}",
        )
        self.assertEqual(code2, 0)
        self.assertEqual(json.loads(out2)["signature"], body["signature"])

    def test_sign_missing_share_exit_1(self):
        self.run_cli("create", "--url", self.url, "--wallet-id", "w1", "--shares", "2")
        code, out, err = self.run_cli(
            "sign",
            "--url", self.url,
            "--wallet-id", "w1",
            "--signing-request-id", "req-x",
            "--message", "m",
            "--signature", "share-1=" + "00" * 64,
        )
        self.assertEqual(code, 1)
        self.assertIn("2 share signatures", json.loads(err)["error"])

    def test_share_sign_unknown_share_exit_1(self):
        self.run_cli("create", "--url", self.url, "--wallet-id", "w1", "--shares", "2")
        code, _, err = self.run_cli(
            "share-sign",
            "--data-dir", self.data_dir,
            "--wallet-id", "w1",
            "--share-id", "share-9",
            "--signing-request-id", "r",
            "--message", "m",
        )
        self.assertEqual(code, 1)
        self.assertIn("not found", json.loads(err)["error"])

    def test_serve_refuses_to_start_when_recovery_fails(self):
        # 构造一个无法对账为一致状态的 data-dir：钱包已切换到新份额、
        # active 已落盘，但激活事件与全部备份都缺失。serve 必须在绑定
        # 端口前以退出码 1 + 单行 JSON 失败，绝不静默带着半完成态就绪。
        import os
        import shutil
        import tempfile

        from tests.test_activation_recovery import _SceneBuilder

        bad_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, bad_dir, ignore_errors=True)
        _SceneBuilder(bad_dir).scene_switched_without_backup_or_event()
        # 场景里残留的暂存新份额文件保留无妨；关键是无事件、无旧份额备份
        self.assertTrue(os.path.isdir(bad_dir))
        code, out, err = self.run_cli(
            "serve",
            "--host", "127.0.0.1",
            "--port", "0",
            "--data-dir", bad_dir,
        )
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        payload = self.assertSingleLineJson(err)
        self.assertIn("recovery", payload["error"])


if __name__ == "__main__":
    unittest.main()
