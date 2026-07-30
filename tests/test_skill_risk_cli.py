import json
import importlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch


class SkillRiskCliTests(unittest.TestCase):
    def _fake_result(self):
        return {
            "score": 75,
            "risk_level": "MEDIUM",
            "summary": "SkillSpector scanned 1 component",
            "findings": [
                {
                    "type": "INFO",
                    "title": "📊 Risk Assessment",
                    "detail": "<div>Risk block</div>",
                    "is_html": True,
                },
                {
                    "type": "INFO",
                    "title": "🧩 Components",
                    "detail": "<div>Component block</div>",
                    "is_html": True,
                },
            ],
            "metrics": {
                "components_scanned": 1,
                "raw_issues_found": 2,
                "counted_high_critical_issues": 1,
                "recommendation": "CAUTION",
            },
            "issues": [
                {
                    "id": "E2",
                    "severity": "HIGH",
                    "category": "Data Exfiltration",
                    "file": "skills/demo/SKILL.md",
                    "line": 7,
                    "finding": "Skill sends secrets to an external endpoint.",
                }
            ],
        }

    def _fake_result_with_risk(self, risk_level):
        result = self._fake_result()
        result["risk_level"] = risk_level
        return result

    def test_scan_writes_json_and_markdown_outputs_for_local_repo(self):
        try:
            appsec_skill_security_checker = importlib.import_module("appsec_skill_security_checker")
        except ModuleNotFoundError:
            self.fail("appsec_skill_security_checker CLI module is missing")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            skill_dir = repo / "skills" / "demo"
            skill_dir.mkdir(parents=True)
            (skill_dir / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
            json_path = root / "result.json"
            md_path = root / "summary.md"

            fake_result = self._fake_result()

            with patch.object(appsec_skill_security_checker.SkillAnalyzer, "analyze_local", new=AsyncMock(return_value=fake_result)) as scan:
                exit_code = appsec_skill_security_checker.main([
                    "scan",
                    "--repo",
                    str(repo),
                    "--skills",
                    "skills/demo",
                    "--output",
                    str(json_path),
                    "--summary-output",
                    str(md_path),
                    "--lang",
                    "en",
                ])

            self.assertEqual(exit_code, 0)
            resolved_repo = str(repo.resolve())
            scan.assert_awaited_once_with(resolved_repo, ["skills/demo"])
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            html_path = json_path.with_suffix(".html")
            self.assertEqual(payload["schema_version"], "1.0")
            self.assertEqual(payload["tool"], "appsec-skill-security-checker")
            self.assertEqual(payload["scan"]["mode"], "local")
            self.assertEqual(payload["scan"]["repo_path"], resolved_repo)
            self.assertEqual(payload["scan"]["skills"], ["skills/demo"])
            self.assertEqual(payload["result"]["risk_level"], "MEDIUM")
            self.assertEqual(payload["issues"][0]["file"], "skills/demo/SKILL.md")
            self.assertEqual(payload["exit_code"], 0)
            self.assertNotIn("findings", payload["raw_result"])

            markdown = md_path.read_text(encoding="utf-8")
            self.assertIn("## Skill Risk Scan", markdown)
            self.assertIn("Risk: MEDIUM", markdown)
            self.assertIn("| HIGH | E2 | skills/demo/SKILL.md:7 |", markdown)

            html = html_path.read_text(encoding="utf-8")
            self.assertIn("<h1>Skill Risk Scan Details</h1>", html)
            self.assertIn("<h2>📊 Risk Assessment</h2>", html)
            self.assertIn("<div>Risk block</div>", html)
            self.assertIn("<h2>🧩 Components</h2>", html)
            self.assertIn("<div>Component block</div>", html)

    def test_scan_writes_default_json_markdown_and_html_outputs(self):
        try:
            appsec_skill_security_checker = importlib.import_module("appsec_skill_security_checker")
        except ModuleNotFoundError:
            self.fail("appsec_skill_security_checker CLI module is missing")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            old_cwd = Path.cwd()

            with patch.object(appsec_skill_security_checker.SkillAnalyzer, "analyze_local", new=AsyncMock(return_value=self._fake_result())):
                try:
                    os.chdir(root)
                    exit_code = appsec_skill_security_checker.main(["scan", "--repo", str(repo)])
                finally:
                    os.chdir(old_cwd)

            json_path = root / "repo-skill-security-report.json"
            md_path = root / "repo-skill-security-report.md"
            html_path = root / "repo-skill-security-report.html"
            self.assertEqual(exit_code, 0)
            self.assertTrue(json_path.exists())
            self.assertTrue(md_path.exists())
            self.assertTrue(html_path.exists())
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["result"]["risk_level"], "MEDIUM")
            self.assertNotIn("findings", payload["raw_result"])
            self.assertIn("## Skill Risk Scan", md_path.read_text(encoding="utf-8"))
            self.assertIn("<h1>Skill Risk Scan Details</h1>", html_path.read_text(encoding="utf-8"))

    def test_scan_loads_dotenv_before_running_analyzer(self):
        try:
            appsec_skill_security_checker = importlib.import_module("appsec_skill_security_checker")
        except ModuleNotFoundError:
            self.fail("appsec_skill_security_checker CLI module is missing")

        fake_result = {
            "score": 100,
            "risk_level": "LOW",
            "summary": "ok",
            "findings": [],
            "metrics": {},
            "issues": [],
        }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            (root / ".env").write_text(
                "QWEN_API_KEY=cli-dotenv-key\nPYTHONPATH=/tmp/poisoned\n",
                encoding="utf-8",
            )
            old_cwd = Path.cwd()

            async def analyze_local(repo_path, skill_paths):
                self.assertEqual(os.getenv("QWEN_API_KEY"), "cli-dotenv-key")
                self.assertIsNone(os.getenv("PYTHONPATH"))
                return fake_result

            with patch.dict(os.environ, {}, clear=True):
                with patch.object(appsec_skill_security_checker.SkillAnalyzer, "analyze_local", new=AsyncMock(side_effect=analyze_local)):
                    try:
                        os.chdir(root)
                        exit_code = appsec_skill_security_checker.main(["scan", "--repo", str(repo)])
                    finally:
                        os.chdir(old_cwd)

        self.assertEqual(exit_code, 0)

    def test_scan_exits_one_for_high_or_critical_risk_by_default(self):
        try:
            appsec_skill_security_checker = importlib.import_module("appsec_skill_security_checker")
        except ModuleNotFoundError:
            self.fail("appsec_skill_security_checker CLI module is missing")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()

            for risk_level in ("HIGH", "CRITICAL"):
                with self.subTest(risk_level=risk_level):
                    with patch.object(
                        appsec_skill_security_checker.SkillAnalyzer,
                        "analyze_local",
                        new=AsyncMock(return_value=self._fake_result_with_risk(risk_level)),
                    ):
                        exit_code = appsec_skill_security_checker.main([
                            "scan",
                            "--repo",
                            str(repo),
                            "--output",
                            str(root / f"{risk_level.lower()}.json"),
                            "--summary-output",
                            str(root / f"{risk_level.lower()}.md"),
                        ])

                    self.assertEqual(exit_code, 1)

    def test_scan_no_longer_accepts_fail_on_option(self):
        try:
            appsec_skill_security_checker = importlib.import_module("appsec_skill_security_checker")
        except ModuleNotFoundError:
            self.fail("appsec_skill_security_checker CLI module is missing")

        parser = appsec_skill_security_checker._build_parser()
        with self.assertRaises(SystemExit) as raised:
            parser.parse_args(["scan", "--fail-on", "HIGH"])

        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
