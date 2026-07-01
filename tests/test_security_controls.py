import unittest

from main import _normalize_controls


class SecurityControlsTests(unittest.TestCase):
    def test_filters_invalid_controls_and_normalizes_chinese_priority(self):
        controls = _normalize_controls(
            [
                {
                    "category": "能力边界管控",
                    "title": "限制Shell",
                    "priority": "必须",
                    "reason": "Agent 可以执行命令。",
                    "implementation": "在 Agent 执行命令前加入白名单校验。",
                },
                {
                    "implementation": "在部署配置中限制网络出口。",
                },
                {},
            ],
            lang="zh",
        )

        self.assertEqual(len(controls), 1)
        self.assertEqual(controls[0]["priority"], "MUST")
        self.assertEqual(controls[0]["precondition"], "无条件适用")
        self.assertEqual(controls[0]["implementation"], "在 Agent 执行命令前加入白名单校验。")
        self.assertEqual(controls[0]["example"], "")

    def test_normalizes_english_defaults(self):
        controls = _normalize_controls([{
            "title": "Restrict network",
            "reason": "The agent can call external services.",
            "implementation": "Apply egress restrictions in the deployment network policy.",
        }], lang="en")

        self.assertEqual(controls[0]["category"], "Other")
        self.assertEqual(controls[0]["priority"], "RECOMMEND")
        self.assertEqual(controls[0]["precondition"], "Applies unconditionally")
        self.assertEqual(controls[0]["reason"], "The agent can call external services.")
        self.assertEqual(controls[0]["implementation"], "Apply egress restrictions in the deployment network policy.")
        self.assertEqual(controls[0]["example"], "")


if __name__ == "__main__":
    unittest.main()
