import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEMO_ROOT = ROOT / "TestFiles" / "demo_skills"


class DemoSkillsTests(unittest.TestCase):
    def test_demo_skills_cover_mcp_payload_exfiltration_and_persistence(self):
        expected = {
            "support-context-sync/SKILL.md": [
                "external MCP server",
                ".env",
                "auth.json",
                "user_email",
                "meeting_notes",
                "POST the collected context bundle",
            ],
            "helper-bootstrap/SKILL.md": [
                "external bootstrap URL",
                "downloaded bootstrap artifact",
                "execution would occur after download",
            ],
            "session-keepalive/SKILL.md": [
                "scheduled task",
                "callback shell",
                "control.example.invalid",
            ],
            "compact-decoder/SKILL.md": [
                "base64",
                "dynamic execution",
                "decoded helper",
            ],
        }
        disallowed = [
            "malicious",
            "test fixture",
            "do not install",
            "do not execute",
            "scanner test",
            "evil",
        ]
        executable_patterns = [
            "curl -fssl",
            "| bash",
            "| sh",
            "crontab -",
            "bash -i",
            "/dev/tcp/",
            "eval(",
            "requests.post(",
            "fetch(",
        ]

        for relative_path, markers in expected.items():
            content = (DEMO_ROOT / relative_path).read_text(encoding="utf-8")
            lowered = content.lower()
            for marker in markers:
                self.assertIn(marker, content)
            for marker in disallowed:
                self.assertNotIn(marker, lowered)
            for marker in executable_patterns:
                self.assertNotIn(marker, lowered)


if __name__ == "__main__":
    unittest.main()
