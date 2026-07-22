import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class UiLabelTests(unittest.TestCase):
    def test_module_titles_use_precise_agent_risk_wording(self):
        index_html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        main_py = (ROOT / "main.py").read_text(encoding="utf-8")

        for expected in [
            "Agent能力/爆炸半径分析",
            "Agent安全护栏",
            "开源项目声誉与活跃度",
            "Agent Capability / Blast Radius",
            "Agent Guardrails",
            "Open-source Reputation & Activity",
        ]:
            self.assertIn(expected, index_html)

        for expected in [
            "🤖 Agent Capability / Blast Radius",
            "🛡️ Agent Guardrails",
            "⭐ Open-source Reputation & Activity",
        ]:
            self.assertIn(expected, main_py)

    def test_scope_boundary_copy_does_not_call_out_malware_scanning(self):
        index_html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")

        self.assertNotIn("不是恶意代码扫描", index_html)
        self.assertIn("能力边界说明：本工具仅做静态代码分析", index_html)

    def test_readme_documents_skill_security_quality_balance_strategy(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        for expected in [
            "SkillSpector provides broad discovery",
            "rule allowlist reduces noise",
            "qwen-plus performs semantic malicious-intent review",
            "malicious_intent = true",
            "final_risk = HIGH or CRITICAL",
            "raw hits / kept / filtered",
        ]:
            self.assertIn(expected, readme)

    def test_progress_rows_can_render_execution_details(self):
        index_html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")

        self.assertIn("prog-detail-", index_html)
        self.assertIn("progress_detail", index_html)

    def test_default_token_warning_keeps_manual_token_input_visible(self):
        index_html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")

        self.assertIn('id="tokenSection" class="mt-2"', index_html)
        self.assertIn("text-yellow-600", index_html)
        self.assertIn("fa-triangle-exclamation", index_html)
        self.assertIn(
            "Default token doesn't have read permission to adidas internal repos.",
            index_html,
        )
        self.assertNotIn("Default token configured — no manual entry needed", index_html)


if __name__ == "__main__":
    unittest.main()
