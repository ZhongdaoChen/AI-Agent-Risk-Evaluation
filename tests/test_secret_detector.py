import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

from analyzers.secret_detector import (
    redact_secret,
    redact_secrets_in_text,
    scan_directory_for_secrets,
    shannon_entropy,
)
from analyzers.skill_analyzer import SkillAnalyzer


def _scan_single_file(content: str, name: str = "SKILL.md") -> list[dict]:
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / name).write_text(content, encoding="utf-8")
        return scan_directory_for_secrets(tmp)


class HighConfidencePatternTests(unittest.TestCase):
    def test_aws_access_key_id_detected_as_critical(self):
        issues = _scan_single_file("aws_key = AKIAIOSFODNN7QWERTYU\n")
        self.assertEqual([i["id"] for i in issues], ["HS-AWS"])
        self.assertEqual(issues[0]["severity"], "CRITICAL")

    def test_aws_temporary_sts_key_detected(self):
        issues = _scan_single_file("sts = ASIAIOSFODNN7QWERTYU\n")
        self.assertEqual([i["id"] for i in issues], ["HS-AWS"])

    def test_alicloud_access_key_detected_as_critical(self):
        issues = _scan_single_file("ali: LTAI5tQjX9vBcD3fGh7jKlMn\n")
        self.assertEqual([i["id"] for i in issues], ["HS-ALICLOUD"])
        self.assertEqual(issues[0]["severity"], "CRITICAL")

    def test_private_key_header_detected_as_critical(self):
        issues = _scan_single_file("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA==\n")
        self.assertEqual([i["id"] for i in issues], ["HS-PRIVKEY"])
        self.assertEqual(issues[0]["severity"], "CRITICAL")

    def test_github_token_detected(self):
        issues = _scan_single_file("token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n")
        self.assertEqual([i["id"] for i in issues], ["HS-GITHUB"])

    def test_slack_token_detected(self):
        issues = _scan_single_file("SLACK_TOKEN=xoxb-1234567890-abcdefghij\n")
        self.assertEqual([i["id"] for i in issues], ["HS-SLACK"])

    def test_google_api_key_detected(self):
        issues = _scan_single_file("key: AIzaSyA1234567890abcdefghijklmnopqrstuv\n")
        self.assertEqual([i["id"] for i in issues], ["HS-GOOGLE"])

    def test_jwt_detected(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        issues = _scan_single_file(f"Authorization: Bearer {jwt}\n")
        self.assertEqual([i["id"] for i in issues], ["HS-JWT"])

    def test_anthropic_key_not_double_reported_by_generic_sk_rule(self):
        issues = _scan_single_file("key = sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWX\n")
        self.assertEqual([i["id"] for i in issues], ["HS-ANTHROPIC"])

    def test_dotted_sk_variant_matches_openai_rule(self):
        issues = _scan_single_file("apiKey = sk-ws-H.FAKEDIM.dSJU.FakeMEQCIabcdefghij1234567890abcd\n")
        self.assertEqual([i["id"] for i in issues], ["HS-OPENAI"])


class GenericAssignmentTests(unittest.TestCase):
    def test_high_entropy_assignment_detected(self):
        issues = _scan_single_file('api_key = "k9Jd8mQp2XvL5nRt7WzB4cFg6HsA3EyU"\n')
        self.assertEqual([i["id"] for i in issues], ["HS-GENERIC"])
        self.assertEqual(issues[0]["severity"], "HIGH")

    def test_low_entropy_value_not_detected(self):
        issues = _scan_single_file('password = "aaaaaaaaaaaaaaaa"\n')
        self.assertEqual(issues, [])

    def test_non_credential_key_not_detected(self):
        issues = _scan_single_file('hostname = "k9Jd8mQp2XvL5nRt7WzB4cFg6HsA3EyU"\n')
        self.assertEqual(issues, [])

    def test_entropy_function_sane(self):
        self.assertEqual(shannon_entropy(""), 0.0)
        self.assertLess(shannon_entropy("aaaa"), 0.1)
        self.assertGreater(shannon_entropy("k9Jd8mQp2XvL5nRt7WzB"), 3.5)


class PlaceholderExclusionTests(unittest.TestCase):
    def test_placeholder_values_skipped(self):
        content = (
            "api_key = your_api_key_here\n"
            "secret = XXXXXXXXXXXXXXXXXXXX\n"
            'token = "example-value-000000"\n'
            "password = changeme_changeme\n"
        )
        self.assertEqual(_scan_single_file(content), [])

    def test_env_var_references_skipped(self):
        content = (
            "api_key = ${API_KEY}\n"
            'secret = "{{ secrets.GITHUB_TOKEN }}"\n'
            "password = <your-password-here>\n"
        )
        self.assertEqual(_scan_single_file(content), [])


class FileFilteringTests(unittest.TestCase):
    def test_binary_file_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "blob.bin").write_bytes(b"AKIAIOSFODNN7QWERTYU\x00\x01\x02")
            self.assertEqual(scan_directory_for_secrets(tmp), [])

    def test_empty_file_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "empty.txt").write_text("", encoding="utf-8")
            self.assertEqual(scan_directory_for_secrets(tmp), [])

    def test_oversized_file_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = "AKIAIOSFODNN7QWERTYU\n"
            filler = "x" * 1_100_000
            (Path(tmp) / "big.log").write_text(filler + payload, encoding="utf-8")
            self.assertEqual(scan_directory_for_secrets(tmp), [])

    def test_symlink_escaping_scan_dir_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inside = root / "scan"
            inside.mkdir()
            outside = root / "outside.txt"
            outside.write_text("key = AKIAIOSFODNN7QWERTYU\n", encoding="utf-8")
            (inside / "linked.txt").symlink_to(outside)
            self.assertEqual(scan_directory_for_secrets(str(inside)), [])

    def test_relative_path_and_line_number_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            nested = Path(tmp) / "skills" / "demo"
            nested.mkdir(parents=True)
            (nested / "SKILL.md").write_text("# title\n\nkey = AKIAIOSFODNN7QWERTYU\n", encoding="utf-8")
            issues = scan_directory_for_secrets(tmp)
            self.assertEqual(issues[0]["location"]["file"], "skills/demo/SKILL.md")
            self.assertEqual(issues[0]["location"]["start_line"], 3)

    def test_missing_directory_returns_empty(self):
        self.assertEqual(scan_directory_for_secrets("/nonexistent/path/xyz"), [])

    def test_multiple_secrets_in_one_file_each_reported(self):
        content = "a = AKIAIOSFODNN7QWERTYU\nb = LTAI5tQjX9vBcD3fGh7jKlMn\n"
        issues = _scan_single_file(content)
        self.assertEqual([i["id"] for i in issues], ["HS-AWS", "HS-ALICLOUD"])
        self.assertEqual([i["location"]["start_line"] for i in issues], [1, 2])


class RedactionTests(unittest.TestCase):
    SECRET = "AKIAIOSFODNN7QWERTYU"

    def test_redact_keeps_prefix_only(self):
        masked = redact_secret(self.SECRET)
        self.assertTrue(masked.startswith("AKIAIO"))
        self.assertIn("***", masked)
        self.assertNotIn(self.SECRET, masked)

    def test_full_secret_never_appears_in_issue_fields(self):
        issues = _scan_single_file(f"aws = {self.SECRET}\n")
        self.assertEqual(len(issues), 1)
        for field in ("finding", "explanation", "remediation", "code_snippet"):
            self.assertNotIn(self.SECRET, issues[0][field], f"leak in {field}")

    def test_short_value_redaction_does_not_crash(self):
        self.assertIn("***", redact_secret("abc"))

    def test_redact_secrets_in_text_masks_embedded_secrets(self):
        text = (
            "Issue: valid-looking key sk-ws-H.FAKEDIM.dSJU.FakeMEQCIabcdefghij1234567890abcd "
            "and AKIAIOSFODNN7QWERTYU in the same sentence."
        )
        redacted = redact_secrets_in_text(text)
        self.assertNotIn("FakeMEQCIabcdefghij1234567890abcd", redacted)
        self.assertNotIn("AKIAIOSFODNN7QWERTYU", redacted)
        self.assertIn("sk-ws-***", redacted)
        self.assertIn("AKIAIO***", redacted)

    def test_redact_secrets_in_text_handles_non_string(self):
        self.assertEqual(redact_secrets_in_text(None), None)
        self.assertEqual(redact_secrets_in_text(""), "")


class SkillAnalyzerIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_analyze_local_merges_secret_findings_and_affects_score(self):
        with tempfile.TemporaryDirectory() as tmp:
            skill = Path(tmp) / "skills" / "demo"
            skill.mkdir(parents=True)
            (skill / "SKILL.md").write_text(
                "# Demo\napi_key = sk-ws-H.FAKEDIM.dSJU.FakeMEQCIabcdefghij1234567890abcd\n",
                encoding="utf-8",
            )

            analyzer = SkillAnalyzer("owner", "repo", lang="en")
            analyzer._run_skillspector = AsyncMock(return_value={
                "_scan_dir": tmp,
                "issues": [],
                "components": [],
                "risk_assessment": {"score": 0},
                "metadata": {},
            })
            analyzer._select_malicious_issues = AsyncMock(return_value=[])

            result = await analyzer.analyze_local(tmp)

            ids = [issue["id"] for issue in result["issues"]]
            self.assertIn("HS-OPENAI", ids)
            secret_issue = next(i for i in result["issues"] if i["id"] == "HS-OPENAI")
            self.assertEqual(secret_issue["severity"], "HIGH")
            self.assertEqual(secret_issue["category"], "Hardcoded Secret")
            self.assertEqual(secret_issue["file"], "skills/demo/SKILL.md")
            self.assertNotIn("FakeMEQCIabcdefghij1234567890abcd", str(result))
            # Policy: any hardcoded secret floors the risk at HIGH (score 49).
            self.assertEqual(result["risk_level"], "HIGH")
            self.assertEqual(result["score"], 49)

    async def test_analyze_local_critical_secret_pushes_risk_high(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "creds.txt").write_text(
                "aws = AKIAIOSFODNN7QWERTYU\n", encoding="utf-8"
            )

            analyzer = SkillAnalyzer("owner", "repo", lang="en")
            analyzer._run_skillspector = AsyncMock(return_value={
                "_scan_dir": tmp,
                "issues": [],
                "components": [],
                "risk_assessment": {"score": 0},
                "metadata": {},
            })
            analyzer._select_malicious_issues = AsyncMock(return_value=[])

            result = await analyzer.analyze_local(tmp)

            # 1 CRITICAL issue + secret floor -> HIGH risk level (score 49).
            self.assertEqual(result["risk_level"], "HIGH")
            self.assertEqual(result["score"], 49)

    async def test_clean_directory_keeps_low_risk(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "SKILL.md").write_text(
                "# Demo\napi_key = your_api_key_here\n", encoding="utf-8"
            )

            analyzer = SkillAnalyzer("owner", "repo", lang="en")
            analyzer._run_skillspector = AsyncMock(return_value={
                "_scan_dir": tmp,
                "issues": [],
                "components": [],
                "risk_assessment": {"score": 0},
                "metadata": {},
            })
            analyzer._select_malicious_issues = AsyncMock(return_value=[])

            result = await analyzer.analyze_local(tmp)

            self.assertEqual(result["issues"], [])
            self.assertEqual(result["risk_level"], "LOW")


if __name__ == "__main__":
    unittest.main()
