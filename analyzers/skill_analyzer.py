"""
Skill Security Quality analyzer backed by NVIDIA SkillSpector.

This adapter delegates skill-focused scanning to SkillSpector's full pipeline
(static patterns, AST/YARA/OSV checks, plus optional LLM semantic analyzers),
then maps the result into this app's existing score/findings contract.

Module output intentionally shows only:
  1. Risk Assessment
  2. Components
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any

import httpx
from openai import AsyncOpenAI


class SkillAnalyzer:
    GITHUB_BASE = "https://api.github.com"
    QWEN_OPENAI_BASE = "https://dashscope.aliyuncs.com/compatible-mode/v1"
    QWEN_MODEL = "qwen-plus"
    INTENT_MODEL = "qwen-turbo"
    FILE_CONTEXT_MAX_CHARS = 2000
    FILE_RISK_RECOMMENDATION = {
        "LOW": "SAFE",
        "MEDIUM": "CAUTION",
        "HIGH": "DO_NOT_INSTALL",
        "CRITICAL": "DO_NOT_INSTALL",
    }
    MALICIOUS_RULE_IDS = {
        "RA1", "RA2",
        "SC2", "SC3",
        "TT3", "TT4", "TT5",
        "YR1", "YR2", "YR3", "YR4",
    }
    MALICIOUS_RULE_PREFIXES = ("AST", "MCP", "TP")

    def __init__(self, owner: str, repo: str, token: str = None, lang: str = "zh"):
        self.owner = owner
        self.repo = repo
        self.lang = lang
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "AI-Risk-Evaluator/1.0",
        }
        if token:
            self.headers["Authorization"] = f"token {token}"

    async def analyze(self) -> dict:
        temp_root: str | None = None
        try:
            temp_root, repo_dir = await self._download_repo_snapshot()
            report = await self._run_skillspector(repo_dir)
            filtered_issues = await self._select_malicious_issues(report, repo_dir)
            if self.lang != "en":
                filtered_issues = await self._localize_issues_for_display(filtered_issues)
            return self._render_result(report, repo_dir, filtered_issues)
        except Exception as e:
            return self._error_result(str(e))
        finally:
            if temp_root:
                shutil.rmtree(temp_root, ignore_errors=True)

    async def _download_repo_snapshot(self) -> tuple[str, str]:
        async with httpx.AsyncClient(headers=self.headers, timeout=60, follow_redirects=True) as gh:
            repo_meta = await gh.get(f"{self.GITHUB_BASE}/repos/{self.owner}/{self.repo}")
            repo_meta.raise_for_status()
            default_branch = repo_meta.json().get("default_branch", "main")

            zip_resp = await gh.get(
                f"{self.GITHUB_BASE}/repos/{self.owner}/{self.repo}/zipball/{default_branch}"
            )
            zip_resp.raise_for_status()

        temp_root = tempfile.mkdtemp(prefix="skillscan-")
        zip_path = Path(temp_root) / "repo.zip"
        zip_path.write_bytes(zip_resp.content)

        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(temp_root)

        extracted_dirs = [p for p in Path(temp_root).iterdir() if p.is_dir()]
        repo_dir = extracted_dirs[0] if extracted_dirs else Path(temp_root)
        return temp_root, str(repo_dir)

    async def _run_skillspector(self, repo_dir: str) -> dict[str, Any]:
        report_dir = tempfile.mkdtemp(prefix="skillspector-report-")
        report_path = Path(report_dir) / "report.json"
        try:
            env = os.environ.copy()
            cmd = [
                "python3",
                "-m",
                "skillspector.cli",
                "scan",
                repo_dir,
                "--format",
                "json",
                "--output",
                str(report_path),
            ]

            qwen_key = os.getenv("QWEN_API_KEY", "")
            if qwen_key:
                env.update(
                    {
                        "SKILLSPECTOR_PROVIDER": "openai",
                        "OPENAI_API_KEY": qwen_key,
                        "OPENAI_BASE_URL": self.QWEN_OPENAI_BASE,
                        "SKILLSPECTOR_MODEL": self.QWEN_MODEL,
                    }
                )
            else:
                cmd.append("--no-llm")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            stdout, stderr = await proc.communicate()

            if report_path.exists():
                return json.loads(report_path.read_text(encoding="utf-8"))

            stderr_text = stderr.decode("utf-8", errors="ignore").strip()
            stdout_text = stdout.decode("utf-8", errors="ignore").strip()
            if proc.returncode != 0:
                if "No module named skillspector" in stderr_text:
                    raise RuntimeError("SkillSpector dependency not installed")
                raise RuntimeError(
                    f"SkillSpector scan failed (exit {proc.returncode}): {stderr_text or stdout_text}"
                )
            raise RuntimeError("SkillSpector did not produce a JSON report")
        finally:
            shutil.rmtree(report_dir, ignore_errors=True)

    async def _select_malicious_issues(self, report: dict[str, Any], repo_dir: str) -> list[dict[str, Any]]:
        raw_issues = report.get("issues", []) or []
        candidates = [
            issue for issue in raw_issues
            if str(issue.get("severity", "LOW")).upper() in {"HIGH", "CRITICAL"}
        ]
        if not candidates:
            return []

        qwen_key = os.getenv("QWEN_API_KEY", "")
        if not qwen_key:
            return self._filter_malicious_issues_heuristic(candidates)

        prompt_items = []
        for idx, issue in enumerate(candidates):
            location = issue.get("location") or {}
            file_path = str(location.get("file", ""))
            prompt_items.append({
                "index": idx,
                "rule_id": issue.get("id") or issue.get("rule_id"),
                "category": issue.get("category"),
                "severity": issue.get("severity"),
                "file": file_path,
                "finding": issue.get("finding"),
                "explanation": issue.get("explanation") or issue.get("message"),
                "code_snippet": issue.get("code_snippet"),
                "file_excerpt": self._read_file_excerpt(repo_dir, file_path),
            })

        system_prompt = (
            "You are a security reviewer for AI agent skills. "
            "Your job is to decide whether each candidate finding shows SUBJECTIVE ATTACK INTENT, "
            "not merely bad engineering or insufficient validation. "
            "Keep a finding only when the skill appears to deliberately steal secrets, exfiltrate data, "
            "execute hidden or remote payloads, establish persistence/backdoors, or perform sensitive actions "
            "that are clearly unrelated to the skill's declared purpose. "
            "Do NOT keep findings that are merely about missing validation, generic dangerous APIs, powerful but legitimate capabilities, "
            "prompt-injection-like wording in docs/comments, ordinary dependency CVEs, or broad design concerns without clear malicious intent. "
            "Purpose mismatch matters a lot: if a skill whose declared purpose is benign suddenly asks to read .env, tokens, credentials, or send data to an external destination, "
            "that is malicious. Return strict JSON only."
        )
        user_prompt = json.dumps({
            "task": "For each candidate, decide whether it should be kept as malicious intent.",
            "output_schema": {
                "decisions": [
                    {
                        "index": 0,
                        "malicious_intent": True,
                        "reason": "1 sentence explaining why this is clearly malicious rather than sloppy design"
                    }
                ]
            },
            "candidates": prompt_items,
        }, ensure_ascii=False)

        try:
            client = AsyncOpenAI(api_key=qwen_key, base_url=self.QWEN_OPENAI_BASE)
            resp = await client.chat.completions.create(
                model=self.INTENT_MODEL,
                temperature=0.0,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
            raw = (resp.choices[0].message.content or "").strip()
            data = json.loads(raw)
            decisions = data.get("decisions", []) or []
            keep_map = {
                int(item.get("index")): str(item.get("reason", "")).strip()
                for item in decisions
                if item.get("malicious_intent") is True
            }
            kept: list[dict[str, Any]] = []
            for idx, issue in enumerate(candidates):
                if idx in keep_map:
                    issue = dict(issue)
                    issue["intent"] = keep_map[idx]
                    kept.append(issue)
            return kept
        except Exception:
            return self._filter_malicious_issues_heuristic(candidates)

    def _read_file_excerpt(self, repo_dir: str, file_path: str) -> str:
        if not file_path:
            return ""
        try:
            full_path = Path(repo_dir) / file_path
            if not full_path.exists() or not full_path.is_file():
                return ""
            text = full_path.read_text(encoding="utf-8", errors="ignore")
            return text[: self.FILE_CONTEXT_MAX_CHARS]
        except Exception:
            return ""

    async def _localize_issues_for_display(self, issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not issues:
            return issues

        translated = [dict(issue) for issue in issues]
        qwen_key = os.getenv("QWEN_API_KEY", "")
        if not qwen_key:
            return translated

        items = []
        for idx, issue in enumerate(translated):
            items.append({
                "index": idx,
                "finding": issue.get("finding") or "",
                "explanation": issue.get("explanation") or issue.get("message") or "",
                "remediation": issue.get("remediation") or "",
                "intent": issue.get("intent") or "",
            })

        system_prompt = (
            "You are translating security scanner output into Simplified Chinese for a technical UI. "
            "Preserve the original meaning exactly. Use concise, natural cybersecurity wording. "
            "Do not translate code, file paths, domains, rule IDs, environment variable names, or code snippets. "
            "Return strict JSON only."
        )
        user_prompt = json.dumps({
            "task": "Translate each non-empty free-text field into Simplified Chinese.",
            "output_schema": {
                "translations": [
                    {
                        "index": 0,
                        "finding": "",
                        "explanation": "",
                        "remediation": "",
                        "intent": "",
                    }
                ]
            },
            "items": items,
        }, ensure_ascii=False)

        try:
            client = AsyncOpenAI(api_key=qwen_key, base_url=self.QWEN_OPENAI_BASE)
            resp = await client.chat.completions.create(
                model=self.INTENT_MODEL,
                temperature=0.0,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
            data = json.loads((resp.choices[0].message.content or "").strip())
            for item in data.get("translations", []) or []:
                idx = item.get("index")
                if not isinstance(idx, int) or idx < 0 or idx >= len(translated):
                    continue
                target = translated[idx]
                for field in ("finding", "explanation", "remediation", "intent"):
                    value = item.get(field)
                    if isinstance(value, str) and value.strip():
                        target[field] = value.strip()
            return translated
        except Exception:
            return translated

    def _render_result(self, report: dict[str, Any], repo_dir: str, issues: list[dict[str, Any]]) -> dict:
        en = self.lang == "en"
        risk = report.get("risk_assessment", {}) or {}
        components = report.get("components", []) or []
        raw_issues = report.get("issues", []) or []
        meta = report.get("metadata", {}) or {}

        skillspector_score = int(risk.get("score", 0) or 0)  # higher = worse
        effective_risk_score = self._compute_issue_score(
            issues,
            bool(meta.get("has_executable_scripts")),
            count_medium_low=False,
        )
        platform_score = max(0, min(100, 100 - effective_risk_score))  # higher = safer
        risk_level = self._score_to_risk_from_skillspector(effective_risk_score)
        recommendation = self.FILE_RISK_RECOMMENDATION[risk_level]
        counted_issues = issues

        findings = [
            {
                "type": "INFO",
                "title": "📊 Risk Assessment" if en else "📊 风险评估",
                "detail": self._render_risk_assessment(
                    platform_score,
                    risk_level,
                    recommendation,
                    len(raw_issues),
                    len(counted_issues),
                    skillspector_score,
                    meta,
                    en,
                ),
                "is_html": True,
            },
            {
                "type": "INFO",
                "title": "🧩 Components" if en else "🧩 组件明细",
                "detail": self._render_components(components, issues, repo_dir, en),
                "is_html": True,
            },
        ]

        summary = (
            f"SkillSpector scanned {len(components)} components · kept {len(issues)} malicious high/critical issues "
            f"from {len(raw_issues)} raw findings · risk {risk_level}"
            if en
            else f"SkillSpector 已扫描 {len(components)} 个组件 · 从 {len(raw_issues)} 个原始发现中保留 "
                 f"{len(issues)} 个恶意高危/严重问题 · 风险等级 {self._severity_label(risk_level, en)}"
        )
        return {
            "score": platform_score,
            "risk_level": risk_level,
            "summary": summary,
            "findings": findings,
            "metrics": {
                "components_scanned": len(components),
                "issues_found": len(issues),
                "raw_issues_found": len(raw_issues),
                "counted_high_critical_issues": len(counted_issues),
                "effective_risk_score": effective_risk_score,
                "skillspector_risk_score": skillspector_score,
                "skillspector_risk_level": risk_level,
                "recommendation": recommendation,
                "llm_requested": meta.get("llm_requested", False),
                "llm_available": meta.get("llm_available", False),
                "llm_enabled": bool(meta.get("llm_requested", False) and meta.get("llm_available", False)),
                "has_executable_scripts": meta.get("has_executable_scripts", False),
                "skillspector_version": meta.get("skillspector_version", ""),
            },
        }

    def _render_risk_assessment(
        self,
        display_risk_score: int,
        risk_level: str,
        recommendation: str,
        raw_issue_count: int,
        counted_issue_count: int,
        raw_skillspector_score: int,
        meta: dict[str, Any],
        en: bool,
    ) -> str:
        severity_color = {
            "LOW": "#16a34a",
            "MEDIUM": "#ca8a04",
            "HIGH": "#dc2626",
            "CRITICAL": "#991b1b",
        }.get(risk_level, "#475569")
        llm_mode = (
            "static + LLM semantic analyzers"
            if meta.get("llm_requested") and meta.get("llm_available")
            else "static analyzers only"
        )
        llm_mode_zh = (
            "静态 + LLM 语义分析"
            if meta.get("llm_requested") and meta.get("llm_available")
            else "仅静态分析"
        )
        recommendation_label = self._recommendation_label(recommendation, en)
        severity_label = self._severity_label(risk_level, en)
        return f"""
<div style="font-size:11px;">
  <table style="width:100%;border-collapse:collapse;background:#f8fafc;border-radius:6px;overflow:hidden;border:1px solid #e2e8f0;">
    <tbody>
      <tr style="border-bottom:1px solid #e2e8f0;"><td style="padding:6px 8px;font-weight:600;">{'Risk Score' if en else '风险分数'}</td><td style="padding:6px 8px;text-align:right;color:{severity_color};font-weight:700;">{display_risk_score} / 100</td></tr>
      <tr style="border-bottom:1px solid #e2e8f0;"><td style="padding:6px 8px;font-weight:600;">{'Severity' if en else '严重级别'}</td><td style="padding:6px 8px;text-align:right;color:{severity_color};font-weight:700;">{self._esc(severity_label)}</td></tr>
      <tr style="border-bottom:1px solid #e2e8f0;"><td style="padding:6px 8px;font-weight:600;">{'Recommendation' if en else '建议'}</td><td style="padding:6px 8px;text-align:right;">{self._esc(recommendation_label)}</td></tr>
      <tr style="border-bottom:1px solid #e2e8f0;"><td style="padding:6px 8px;font-weight:600;">{'Counted Issues' if en else '计分问题数'}</td><td style="padding:6px 8px;text-align:right;">{counted_issue_count} {'(malicious High / Critical)' if en else '（仅统计恶意高危 / 严重）'}</td></tr>
      <tr style="border-bottom:1px solid #e2e8f0;"><td style="padding:6px 8px;font-weight:600;">{'Raw Findings' if en else '原始发现数'}</td><td style="padding:6px 8px;text-align:right;">{raw_issue_count}</td></tr>
      <tr style="border-bottom:1px solid #e2e8f0;"><td style="padding:6px 8px;font-weight:600;">{'Raw SkillSpector Score' if en else 'SkillSpector 原始分数'}</td><td style="padding:6px 8px;text-align:right;">{raw_skillspector_score} / 100 {'(unfiltered)' if en else '（未过滤）'}</td></tr>
      <tr><td style="padding:6px 8px;font-weight:600;">{'Analysis Mode' if en else '分析模式'}</td><td style="padding:6px 8px;text-align:right;">{self._esc(llm_mode if en else llm_mode_zh)}</td></tr>
    </tbody>
  </table>
</div>"""

    def _render_components(
        self,
        components: list[dict[str, Any]],
        issues: list[dict[str, Any]],
        repo_dir: str,
        en: bool,
    ) -> str:
        if not components:
            return (
                "No components reported by SkillSpector."
                if en
                else "SkillSpector 未返回组件信息。"
            )

        summaries = [self._build_component_summary(comp, issues, en) for comp in components]
        summaries.sort(key=lambda item: (self._severity_rank(item["severity"]), item["display_score"], item["path"]))
        visible_rows = [self._render_component_row(item, en) for item in summaries if item["severity"] in {"CRITICAL", "HIGH"}]
        collapsed_rows = [self._render_component_row(item, en) for item in summaries if item["severity"] in {"MEDIUM", "LOW"}]

        source_label = repo_dir if en else repo_dir
        collapsed_group = ""
        if collapsed_rows:
            collapsed_title = (
                f"Low / Medium Components ({len(collapsed_rows)})"
                if en else
                f"中低风险组件（{len(collapsed_rows)}）"
            )
            collapsed_group = f"""
<details style="border-top:1px solid #e2e8f0;background:#f8fafc;">
  <summary style="cursor:pointer;padding:10px 12px;font-weight:700;color:#475569;list-style:none;">{self._esc(collapsed_title)}</summary>
  <div style="border-top:1px solid #e2e8f0;">{''.join(collapsed_rows)}</div>
</details>"""

        return f"""
<div style="font-size:11px;">
  <div style="margin-bottom:6px;color:#64748b;">{self._esc(source_label)}</div>
  <div style="border:1px solid #e2e8f0;border-radius:6px;overflow:hidden;background:#f8fafc;">
    <div style="display:grid;grid-template-columns:2.3fr 0.9fr 1.4fr 0.75fr 0.95fr 1.2fr 0.6fr 0.6fr;gap:0;padding:6px 8px;background:#e2e8f0;font-weight:600;color:#475569;">
      <div>{'Path' if en else '路径'}</div>
      <div>{'Type' if en else '类型'}</div>
      <div>{'Dimension' if en else '维度'}</div>
      <div style="text-align:right;">{'Score' if en else '分数'}</div>
      <div>{'Severity' if en else '严重级别'}</div>
      <div>{'Recommendation' if en else '建议'}</div>
      <div style="text-align:right;">{'Lines' if en else '行数'}</div>
      <div style="text-align:center;">{'Exec' if en else '可执行'}</div>
    </div>
    <div>{''.join(visible_rows)}{collapsed_group}</div>
  </div>
</div>"""

    def _build_component_summary(
        self,
        comp: dict[str, Any],
        issues: list[dict[str, Any]],
        en: bool,
    ) -> dict[str, Any]:
        path = str(comp.get("path", ""))
        related = [
            issue for issue in issues
            if str((issue.get("location") or {}).get("file", "")) == path
        ]
        if not related:
            related = [issue for issue in issues if str((issue.get("location") or {}).get("file", "")).endswith(path)]

        raw_risk_score = self._compute_issue_score(related, bool(comp.get("executable")))
        display_score = max(0, min(100, 100 - raw_risk_score))
        severity = self._score_to_risk_from_skillspector(raw_risk_score)
        recommendation = self.FILE_RISK_RECOMMENDATION[severity]
        dimensions = self._collect_dimensions(related, en)

        return {
            "path": path,
            "type": str(comp.get("type", "")),
            "lines": comp.get("lines", ""),
            "executable": bool(comp.get("executable")),
            "display_score": display_score,
            "risk_score": raw_risk_score,
            "severity": severity,
            "recommendation": recommendation,
            "dimensions": dimensions,
            "issues": related,
        }

    def _render_component_row(self, summary: dict[str, Any], en: bool) -> str:
        severity = summary["severity"]
        sev_color = {
            "LOW": "#16a34a",
            "MEDIUM": "#ca8a04",
            "HIGH": "#dc2626",
            "CRITICAL": "#991b1b",
        }.get(severity, "#475569")
        recommendation = self._recommendation_label(summary["recommendation"], en)
        severity_label = self._severity_label(severity, en)
        dimensions = ", ".join(summary["dimensions"]) if summary["dimensions"] else ("None" if en else "无")
        issues = summary["issues"]
        issue_count_label = (
            f"{len(issues)} issue(s)" if en else f"{len(issues)} 个问题"
        )

        issue_detail = self._render_component_issues(issues, en)
        return f"""
<details style="border-top:1px solid #e2e8f0;">
  <summary style="list-style:none;cursor:pointer;padding:0;">
    <div style="display:grid;grid-template-columns:2.3fr 0.9fr 1.4fr 0.75fr 0.95fr 1.2fr 0.6fr 0.6fr;gap:0;padding:8px 8px;align-items:start;">
      <div style="font-family:monospace;color:#0f172a;padding-right:8px;word-break:break-all;">{self._esc(summary['path'])}</div>
      <div style="padding-right:8px;">{self._esc(self._component_type_label(summary['type'], en))}</div>
      <div style="padding-right:8px;color:#334155;">{self._esc(dimensions)}</div>
      <div style="text-align:right;padding-right:8px;font-weight:700;color:{sev_color};">{summary['display_score']}</div>
      <div style="padding-right:8px;color:{sev_color};font-weight:700;">{self._esc(severity_label)}</div>
      <div style="padding-right:8px;">{self._esc(recommendation)}</div>
      <div style="text-align:right;padding-right:8px;">{self._esc(str(summary['lines']))}</div>
      <div style="text-align:center;">{'Yes' if en and summary['executable'] else 'No' if en else '是' if summary['executable'] else '否'}</div>
    </div>
  </summary>
  <div style="padding:0 10px 10px 10px;background:#ffffff;border-top:1px solid #e2e8f0;">
    <div style="padding:8px 0 6px 0;color:#64748b;font-weight:600;">{self._esc(issue_count_label)}</div>
    {issue_detail}
  </div>
</details>"""

    def _render_component_issues(self, issues: list[dict[str, Any]], en: bool) -> str:
        if not issues:
            return (
                "<div style='color:#64748b;padding:4px 0;'>No issues for this file.</div>"
                if en else
                "<div style='color:#64748b;padding:4px 0;'>该文件未发现问题。</div>"
            )

        blocks = []
        for issue in issues:
            severity = str(issue.get("severity", "LOW")).upper()
            sev_color = {
                "LOW": "#16a34a",
                "MEDIUM": "#ca8a04",
                "HIGH": "#dc2626",
                "CRITICAL": "#991b1b",
            }.get(severity, "#475569")
            rule_id = str(issue.get("id") or issue.get("rule_id") or "")
            dimension = self._issue_dimension(issue, en)
            location = issue.get("location") or {}
            line = location.get("start_line")
            explanation = issue.get("explanation") or issue.get("message") or ""
            remediation = issue.get("remediation") or ""
            snippet = issue.get("code_snippet") or ""
            confidence = issue.get("confidence")
            confidence_str = f"{int(round(float(confidence) * 100))}%" if isinstance(confidence, (int, float)) else "-"

            blocks.append(
                "<div style='border:1px solid #e2e8f0;border-radius:6px;padding:8px 10px;margin-bottom:8px;background:#f8fafc;'>"
                f"<div style='display:flex;justify-content:space-between;gap:8px;align-items:flex-start;'>"
                f"<div style='font-weight:700;color:#0f172a;'>{self._esc(rule_id or dimension)}</div>"
                f"<div style='color:{sev_color};font-weight:700;'>{self._esc(self._severity_label(severity, en))}</div>"
                "</div>"
                f"<div style='margin-top:4px;color:#475569;'><b>{'Dimension' if en else '维度'}:</b> {self._esc(dimension)}</div>"
                + (f"<div style='margin-top:4px;color:#475569;'><b>{'Line' if en else '行号'}:</b> {self._esc(str(line))}</div>" if line else "")
                + (f"<div style='margin-top:4px;color:#475569;'><b>{'Confidence' if en else '置信度'}:</b> {confidence_str}</div>" if confidence is not None else "")
                + (f"<div style='margin-top:6px;color:#334155;line-height:1.6;'><b>{'Issue' if en else '问题'}:</b> {self._esc(str(explanation))}</div>" if explanation else "")
                + (f"<div style='margin-top:6px;color:#334155;line-height:1.6;'><b>{'Recommendation' if en else '修复建议'}:</b> {self._esc(str(remediation))}</div>" if remediation else "")
                + (f"<div style='margin-top:6px;'><div style='font-weight:600;color:#475569;margin-bottom:3px;'>{'Code Snippet' if en else '代码片段'}</div><div style='font-family:monospace;background:#fff;border:1px solid #e2e8f0;border-radius:4px;padding:6px;white-space:pre-wrap;word-break:break-all;color:#1e293b;'>{self._esc(str(snippet))}</div></div>" if snippet else "")
                + "</div>"
            )
        return "".join(blocks)

    def _collect_dimensions(self, issues: list[dict[str, Any]], en: bool) -> list[str]:
        dimensions: list[str] = []
        seen = set()
        for issue in issues:
            dim = self._issue_dimension(issue, en)
            if dim not in seen:
                seen.add(dim)
                dimensions.append(dim)
        return dimensions[:3]

    def _issue_dimension(self, issue: dict[str, Any], en: bool) -> str:
        category = issue.get("category")
        if category:
            return self._localize_category(str(category), en)

        rule_id = str(issue.get("id") or issue.get("rule_id") or "").upper()
        mapping = {
            "SSD": ("Semantic Security", "语义安全"),
            "P": ("Prompt Injection", "提示词注入"),
            "E": ("Data Exfiltration", "数据外传"),
            "PE": ("Privilege Escalation", "权限提升"),
            "SC": ("Supply Chain", "供应链"),
            "EA": ("Excessive Agency", "过度代理能力"),
            "OH": ("Output Handling", "输出处理"),
            "MP": ("Memory Poisoning", "记忆污染"),
            "TM": ("Tool Misuse", "工具滥用"),
            "RA": ("Rogue Agent", "失控代理"),
            "TR": ("Trigger Abuse", "触发器滥用"),
            "AST": ("Dangerous Execution", "危险执行"),
            "TT": ("Taint Flow", "污点传播"),
            "YR": ("YARA / Malware", "YARA / 恶意模式"),
            "MCP": ("MCP Security", "MCP 安全"),
        }
        for prefix, labels in sorted(mapping.items(), key=lambda item: -len(item[0])):
            if rule_id.startswith(prefix):
                return labels[0] if en else labels[1]
        return "Other" if en else "其他"

    def _severity_label(self, severity: str, en: bool) -> str:
        if en:
            return str(severity).upper()
        return {
            "LOW": "低",
            "MEDIUM": "中",
            "HIGH": "高",
            "CRITICAL": "严重",
        }.get(str(severity).upper(), str(severity))

    def _recommendation_label(self, recommendation: str, en: bool) -> str:
        rec = str(recommendation).upper()
        if en:
            return rec.replace("_", " ")
        return {
            "SAFE": "可安装",
            "CAUTION": "谨慎安装",
            "DO_NOT_INSTALL": "禁止安装",
        }.get(rec, rec.replace("_", " "))

    def _localize_category(self, category: str, en: bool) -> str:
        if en:
            return category
        mapping = {
            "Semantic Security": "语义安全",
            "Prompt Injection": "提示词注入",
            "Data Exfiltration": "数据外传",
            "Privilege Escalation": "权限提升",
            "Supply Chain": "供应链",
            "Excessive Agency": "过度代理能力",
            "Output Handling": "输出处理",
            "Memory Poisoning": "记忆污染",
            "Tool Misuse": "工具滥用",
            "Rogue Agent": "失控代理",
            "Trigger Abuse": "触发器滥用",
            "Dangerous Execution": "危险执行",
            "Taint Flow": "污点传播",
            "YARA / Malware": "YARA / 恶意模式",
            "MCP Security": "MCP 安全",
        }
        return mapping.get(category, category)

    def _component_type_label(self, component_type: str, en: bool) -> str:
        value = str(component_type)
        if en:
            return value
        mapping = {
            "code": "代码",
            "config": "配置",
            "prompt": "提示词",
            "workflow": "工作流",
            "binary": "二进制",
            "script": "脚本",
            "document": "文档",
            "documentation": "文档",
            "data": "数据",
        }
        return mapping.get(value.lower(), value)

    def _compute_issue_score(self, issues: list[dict[str, Any]], executable: bool,
                             count_medium_low: bool = True) -> int:
        score = 0
        for issue in issues:
            sev = str(issue.get("severity", "LOW")).upper()
            if sev == "CRITICAL":
                score += 50
            elif sev == "HIGH":
                score += 25
            elif sev == "MEDIUM" and count_medium_low:
                score += 10
            elif sev == "LOW" and count_medium_low:
                score += 5
        if executable:
            score = int(score * 1.3)
        return max(0, min(100, score))

    def _filter_malicious_issues_heuristic(self, issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
        filtered: list[dict[str, Any]] = []
        for issue in issues:
            severity = str(issue.get("severity", "LOW")).upper()
            if severity not in {"HIGH", "CRITICAL"}:
                continue
            if self._looks_intentionally_malicious(issue):
                filtered.append(issue)
        return filtered

    def _looks_intentionally_malicious(self, issue: dict[str, Any]) -> bool:
        rule_id = str(issue.get("id") or issue.get("rule_id") or "").upper()
        text = self._issue_text(issue)

        if rule_id in {"TT3", "TT4", "TT5", "YR1", "YR2", "YR3", "YR4", "RA1", "RA2", "SC2", "SC3"}:
            return True

        sensitive_words = (
            "api key", "apikey", "token", "secret", "credential", "password",
            "ssh", "id_rsa", ".env", "os.environ", "getenv", "environment variable",
            "private key", "auth key",
        )
        outbound_words = (
            "exfil", "transmit", "send", "post(", "requests.post", "httpx.post",
            "webhook", "discord", "telegram", "pastebin", "http://", "https://",
            "curl ", "wget ", "socket", "upload", "leak",
        )
        exec_words = (
            "exec(", "eval(", "os.system", "subprocess", "bash -c", "shell=true",
            "compile(", "__import__", "popen(",
        )
        stealth_words = ("backdoor", "reverse shell", "c2", "cron", "startup", "launchd", "nohup")
        obfuscation_words = ("base64", "obfuscat", "encoded payload", "hex", "rot13")

        has_sensitive = any(word in text for word in sensitive_words)
        has_outbound = any(word in text for word in outbound_words)
        has_external_domain = bool(re.search(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", text))
        has_exec = any(word in text for word in exec_words)
        has_stealth = any(word in text for word in stealth_words)
        has_obfuscation = any(word in text for word in obfuscation_words)
        if not has_outbound and has_external_domain and any(word in text for word in ("send", "sent", "upload", "transmit", "forward")):
            has_outbound = True

        if rule_id == "E2":
            return has_sensitive and has_outbound
        if rule_id == "E4":
            return has_outbound and ("context" in text or "prompt" in text or has_sensitive)
        if rule_id == "PE3":
            return has_sensitive and (has_outbound or has_exec or has_stealth)
        if rule_id.startswith("AST"):
            return has_exec and (has_outbound or has_sensitive or has_obfuscation or has_stealth)
        if rule_id.startswith(("MCP", "TP")):
            return has_outbound or has_sensitive or has_exec or has_stealth or has_obfuscation

        return False

    def _issue_text(self, issue: dict[str, Any]) -> str:
        parts = [
            issue.get("finding"),
            issue.get("explanation"),
            issue.get("code_snippet"),
            issue.get("intent"),
        ]
        return " ".join(str(part or "") for part in parts).lower()

    def _score_to_risk_from_skillspector(self, score: int) -> str:
        if score >= 81:
            return "CRITICAL"
        if score >= 51:
            return "HIGH"
        if score >= 21:
            return "MEDIUM"
        return "LOW"

    def _severity_rank(self, severity: str) -> int:
        return {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
        }.get(str(severity).upper(), 9)

    def _error_result(self, msg: str) -> dict:
        en = self.lang == "en"
        return {
            "score": 50,
            "risk_level": "UNKNOWN",
            "summary": msg,
            "findings": [
                {
                    "type": "INFO",
                    "title": "Skill analysis error" if en else "Skill 分析错误",
                    "detail": msg,
                }
            ],
            "metrics": {
                "components_scanned": 0,
                "issues_found": 0,
            },
        }

    def _score_to_risk(self, score: int) -> str:
        if score >= 75:
            return "LOW"
        if score >= 55:
            return "MEDIUM"
        if score >= 35:
            return "HIGH"
        return "CRITICAL"

    def _esc(self, s: str) -> str:
        return (
            str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )
