import json
import importlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch


class SkillRiskCliTests(unittest.TestCase):
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

            fake_result = {
                "score": 75,
                "risk_level": "MEDIUM",
                "summary": "SkillSpector scanned 1 component",
                "findings": [],
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
            self.assertEqual(payload["schema_version"], "1.0")
            self.assertEqual(payload["tool"], "appsec-skill-security-checker")
            self.assertEqual(payload["scan"]["mode"], "local")
            self.assertEqual(payload["scan"]["repo_path"], resolved_repo)
            self.assertEqual(payload["scan"]["skills"], ["skills/demo"])
            self.assertEqual(payload["result"]["risk_level"], "MEDIUM")
            self.assertEqual(payload["issues"][0]["file"], "skills/demo/SKILL.md")
            self.assertEqual(payload["exit_code"], 0)

            markdown = md_path.read_text(encoding="utf-8")
            self.assertIn("## Skill Risk Scan", markdown)
            self.assertIn("Risk: MEDIUM", markdown)
            self.assertIn("| HIGH | E2 | skills/demo/SKILL.md:7 |", markdown)


if __name__ == "__main__":
    unittest.main()
