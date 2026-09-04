import os
import runpy
import sys
import types
import unittest
from unittest import mock


SCRIPT_PATH = "nodeseek_sign.py"


class FailureExitTests(unittest.TestCase):
    def run_script(self, response_factory, ns_cookie=""):
        sent_messages = []

        curl_cffi = types.ModuleType("curl_cffi")
        curl_cffi.requests = types.SimpleNamespace(request=response_factory)

        yescaptcha = types.ModuleType("yescaptcha")
        yescaptcha.YesCaptchaSolver = object
        yescaptcha.YesCaptchaSolverError = Exception

        turnstile_solver = types.ModuleType("turnstile_solver")
        turnstile_solver.TurnstileSolver = object
        turnstile_solver.TurnstileSolverError = Exception

        notify = types.ModuleType("notify")
        notify.send = lambda title, message: sent_messages.append((title, message))

        modules = {
            "curl_cffi": curl_cffi,
            "yescaptcha": yescaptcha,
            "turnstile_solver": turnstile_solver,
            "notify": notify,
        }
        environment = {"NS_COOKIE": ns_cookie}

        with mock.patch.dict(os.environ, environment, clear=True), mock.patch.dict(sys.modules, modules):
            with self.assertRaises(SystemExit) as exit_context:
                runpy.run_path(SCRIPT_PATH, run_name="__main__")

        return exit_context.exception.code, sent_messages

    def test_cloudflare_challenge_exits_nonzero_and_notifies(self):
        response = types.SimpleNamespace(
            status_code=403,
            text="Just a moment... Cloudflare",
            json=lambda: {},
        )

        exit_code, sent_messages = self.run_script(lambda *args, **kwargs: response, "session=test")

        self.assertEqual(exit_code, 1)
        self.assertEqual(sent_messages[0][0], "NodeSeek 签到失败")
        self.assertIn("forbidden", sent_messages[0][1])

    def test_successful_signin_exits_zero(self):
        def request(_method, url, **_kwargs):
            if "/api/attendance" in url:
                return types.SimpleNamespace(
                    status_code=200,
                    text="",
                    json=lambda: {"success": True, "message": "签到收益5个鸡腿"},
                )
            return types.SimpleNamespace(
                status_code=200,
                text="",
                json=lambda: {"success": False, "data": []},
            )

        exit_code, _ = self.run_script(request, "session=test")

        self.assertEqual(exit_code, 0)

    def test_missing_configuration_exits_nonzero(self):
        exit_code, sent_messages = self.run_script(lambda *args, **kwargs: None)

        self.assertEqual(exit_code, 1)
        self.assertEqual(sent_messages[0][0], "NodeSeek 签到失败")
        self.assertIn("未配置账号或Cookie", sent_messages[0][1])


if __name__ == "__main__":
    unittest.main()
