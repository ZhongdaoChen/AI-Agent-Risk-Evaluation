"""
AI Safety Guardrails Analyzer — LLM Edition
Uses Qwen to holistically understand the project's AI safety posture.
No regex. The model understands context, intent, and implementation quality.
"""
import base64
import json
import os
import httpx
from typing import List
from analyzers.utils import smart_truncate, boost_imports, ENTRY_NAMES

SYSTEM_PROMPT = """You are an AI security expert specializing in AI agent safety controls and guardrails.

You will be given source files from an AI agent project. Your job is to identify:
1. Safety mechanisms that ARE present (POSITIVE)
2. Dangerous patterns that are absent or misconfigured (risks)

Return ONLY valid JSON — no markdown, no commentary outside JSON:
{
  "findings": [
    {
      "mechanism": "<concise name of the safety control or risk, max 70 chars>",
      "type": "POSITIVE" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "description": "<clear explanation: what this control does or why this pattern is dangerous, 1-3 sentences>",
      "evidence": "<exact code or text snippet proving your finding, max 200 chars>",
      "file": "<filename only, e.g. agent.py or README.md>",
      "line": <integer line number, or null>,
      "score_delta": <integer>
    }
  ],
  "overall_assessment": "<2-3 sentence summary of this project's AI safety posture>"
}

═══════════════════════════════════════════
WHAT TO DETECT AND HOW TO SCORE IT
═══════════════════════════════════════════

POSITIVE safety controls — report these when genuinely implemented:
  • Human-in-the-loop: agent pauses and asks a human before executing high-risk actions
    → score_delta = +15
  • Step / iteration / turn limits: explicit cap on how many steps the agent can take
    → score_delta = +15
  • Input validation / sanitization: user input or external data is checked/cleaned before use
    → score_delta = +10
  • Output validation / filtering: model responses are checked before being acted upon
    → score_delta = +10
  • Tool allowlist / permission system: explicit list of permitted tools, not all tools enabled by default
    → score_delta = +10
  • Prompt injection detection or defense mechanism
    → score_delta = +8
  • Sandboxing / isolated execution environment for agent actions
    → score_delta = +8
  • Rate limiting or throttling of tool calls / API requests
    → score_delta = +5
  • Audit logging: agent actions are recorded for traceability
    → score_delta = +5
  • README documents safety practices (human-in-the-loop, guardrails, responsible use)
    → score_delta = +3 to +5 (higher if detailed, lower if just a mention)

RISKS — report these when found:
  • LLM output directly passed to exec() or eval() without sanitization
    → type=CRITICAL, score_delta = -25
  • User input concatenated directly into system prompt (prompt injection vulnerability)
    → type=CRITICAL, score_delta = -15
  • Agent can execute arbitrary shell commands derived from LLM output with no validation
    → type=HIGH, score_delta = -12
  • No safety mechanisms found at all (agent runs fully autonomously with zero controls)
    → type=HIGH, score_delta = -15  [only report this if truly nothing was found]

═══════════════════════════════════════════
CRITICAL RULES — read carefully
═══════════════════════════════════════════
• ONLY report a POSITIVE finding if you see actual working code implementing it — not just a comment, import name, or TODO
• For README mentions: only credit if the README actually explains how the mechanism works, not just uses the word
• Do NOT duplicate: each unique mechanism should appear once (pick the best/clearest evidence)
• Evidence must be an exact excerpt from the provided code/text — no paraphrasing
• If a mechanism partially exists (e.g., step limit is defined but never enforced), note it as LOW with lower score_delta
• Test files, examples, and mock code should be noted as such and scored lower
• Be honest about absence — if a major control is missing, say so clearly
- All text fields (mechanism, description) MUST be written in Chinese (Simplified Chinese). Evidence should keep the original code snippet.
"""

# Score delta bounds per type (LLM can propose, we clamp to these)
DELTA_BOUNDS = {
    "POSITIVE": (3, 15),
    "LOW":      (-5, 5),
    "MEDIUM":   (-10, -1),
    "HIGH":     (-15, -8),
    "CRITICAL": (-30, -12),
}

MAX_LINES_PER_FILE    = 550   # stage 2 deep scan (up from 350)
STAGE1_PREVIEW_LINES  = 50
STAGE1_MAX_CANDIDATES = 40
STAGE2_MAX_FILES      = 15
QWEN_TURBO_MODEL      = "qwen-turbo"


class AISafetyAnalyzer:
    GITHUB_BASE = "https://api.github.com"
    QWEN_BASE   = "https://dashscope.aliyuncs.com/compatible-mode/v1"
    QWEN_MODEL  = "qwen-plus"

    def __init__(self, owner: str, repo: str, token: str = None, lang: str = "zh"):
        self.owner = owner
        self.repo  = repo
        self.lang  = lang
        self.gh_headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "AI-Risk-Evaluator/1.0",
        }
        if token:
            self.gh_headers["Authorization"] = f"token {token}"
        self.qwen_key = os.getenv("QWEN_API_KEY", "")

    # ─────────────────────────────────────────────────────────────────────────
    # Main entry
    # ─────────────────────────────────────────────────────────────────────────
    async def analyze(self) -> dict:
        async with httpx.AsyncClient(headers=self.gh_headers, timeout=30) as client:
            # 1. Get repo metadata
            repo_r = await client.get(f"{self.GITHUB_BASE}/repos/{self.owner}/{self.repo}")
            repo_r.raise_for_status()
            default_branch = repo_r.json().get("default_branch", "main")

            # 2. Get file tree
            tree_r = await client.get(
                f"{self.GITHUB_BASE}/repos/{self.owner}/{self.repo}/git/trees/{default_branch}",
                params={"recursive": "1"},
            )
            if tree_r.status_code != 200:
                return self._error_result("无法获取代码树")

            all_files = [f["path"] for f in tree_r.json().get("tree", []) if f.get("type") == "blob"]
            candidates = self._select_files(all_files)  # up to 40 candidates

            # 3. Fetch README (always include)
            readme_path = ""
            readme_content = ""
            for name in ["README.md", "readme.md", "README.rst", "README.txt"]:
                if any(f.lower() == name.lower() for f in all_files):
                    readme_path = name
                    readme_content = await self._fetch_file(client, name, default_branch)
                    if readme_content:
                        candidates = [name] + [f for f in candidates if f.lower() != name.lower()]
                        break

            # 3b. Import tracking: fetch entry files and boost their imports
            entry_contents: dict = {}
            for path in all_files:
                if path.split("/")[-1] in ENTRY_NAMES:
                    c = await self._fetch_file(client, path, default_branch)
                    if c:
                        entry_contents[path] = c
            if entry_contents:
                candidates = boost_imports(entry_contents, all_files, candidates, STAGE1_MAX_CANDIDATES)

            # 4. Stage 1: fetch 50-line previews of all candidates
            previews: dict = {}
            for path in candidates:
                content = await self._fetch_file(client, path, default_branch)
                if content:
                    previews[path] = "\n".join(content.splitlines()[:STAGE1_PREVIEW_LINES])

            if not self.qwen_key:
                return self._error_result("QWEN_API_KEY not configured")

            # 5. Stage 1: cheap LLM selects top 15 files
            selected_paths = await self._stage1_rank_files(previews, readme_path)

            # 6. Stage 2: fetch + smart-truncate selected files
            file_contents: List[tuple] = []
            for path in selected_paths:
                content = await self._fetch_file(client, path, default_branch)
                if content:
                    truncated = smart_truncate(content, MAX_LINES_PER_FILE, mode="safety")
                    file_contents.append((path, truncated))

        # 7. Build combined prompt
        sections = []
        if readme_content:
            readme_excerpt = "\n".join(readme_content.splitlines()[:200])
            sections.append(f"=== FILE: {readme_path} ===\n{readme_excerpt}")
        for path, numbered in file_contents:
            if path != readme_path:
                sections.append(f"=== FILE: {path} ===\n{numbered}")

        if not sections:
            return self._error_result("无法从该仓库获取文件")

        combined = "\n\n".join(sections)

        # 8. Call deep LLM
        llm_findings = await self._call_llm(combined)

        # 7. Build result
        return self._build_result(
            llm_findings,
            default_branch,
            len(file_contents),
            readme_path,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Stage 1: file ranker (qwen-turbo)
    # ─────────────────────────────────────────────────────────────────────────
    async def _stage1_rank_files(self, previews: dict, readme_path: str) -> list:
        """Use cheap model to select the most safety-relevant files for deep scan."""
        preview_text = ""
        for path, snippet in previews.items():
            preview_text += f"\n--- {path} ---\n{snippet}\n"

        if self.lang == "en":
            prompt = f"""You are a code file relevance ranker.

Task: From the candidate file previews below, select the {STAGE2_MAX_FILES} most relevant files for analyzing "AI Agent safety guardrails".

Prioritize:
- Files containing human approval / confirmation / dry_run / safety check logic
- Files with tool allowlists, step limits, rate limits
- Agent main flow files (main.py, agent.py, runner.py, etc.)
- README (if it has system prompts or safety descriptions)
- Files containing prompt / system_prompt / instructions

Exclude: test files, pure config files, empty files, documentation without code.

Candidate file previews:
{preview_text}

Return in JSON format with only the file path list:
{{"selected_files": ["path1", "path2", ...]}}"""
            sys_content = "You are a code file relevance ranking expert. Output strict JSON."
        else:
            prompt = f"""你是一个代码文件相关性排序器。

任务：从下列候选文件的预览中，选出最适合用来分析「AI Agent 安全护栏」的 {STAGE2_MAX_FILES} 个文件。

优先选择：
- 包含 human approval / confirmation / dry_run / safety check 逻辑的文件
- 包含工具调用白名单、步骤限制、速率限制的文件
- Agent 主流程文件（main.py、agent.py、runner.py 等）
- README（如果有系统提示词或安全说明）
- 包含 prompt / system_prompt / instructions 的文件

排除：测试文件、纯配置文件、空文件、无实质代码的文档。

候选文件预览：
{preview_text}

以 JSON 格式返回，只包含文件路径列表：
{{"selected_files": ["path1", "path2", ...]}}"""
            sys_content = "你是代码文件相关性排序专家，输出严格的 JSON。"

        payload = {
            "model": QWEN_TURBO_MODEL,
            "temperature": 0.0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": sys_content},
                {"role": "user",   "content": prompt},
            ],
        }
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                r = await client.post(
                    f"{self.QWEN_BASE}/chat/completions",
                    headers={"Authorization": f"Bearer {self.qwen_key}", "Content-Type": "application/json"},
                    json=payload,
                )
                r.raise_for_status()
                data = json.loads(r.json()["choices"][0]["message"]["content"])
                selected = data.get("selected_files", [])
                valid = [p for p in selected if p in previews]
                # Pad if LLM returned too few
                if len(valid) < STAGE2_MAX_FILES:
                    for p in previews:
                        if p not in valid:
                            valid.append(p)
                        if len(valid) >= STAGE2_MAX_FILES:
                            break
                return valid[:STAGE2_MAX_FILES]
        except Exception:
            return list(previews.keys())[:STAGE2_MAX_FILES]

    # ─────────────────────────────────────────────────────────────────────────
    # LLM call
    # ─────────────────────────────────────────────────────────────────────────
    async def _call_llm(self, combined_source: str) -> list:
        if not self.qwen_key:
            return []
        sys_prompt = SYSTEM_PROMPT
        if self.lang == "en":
            sys_prompt = SYSTEM_PROMPT.replace(
                "- All text fields (mechanism, description) MUST be written in Chinese (Simplified Chinese). Evidence should keep the original code snippet.",
                "IMPORTANT: Output ALL text fields (mechanism, description, overall_assessment) in English only. Evidence should keep the original code snippet."
            )
        payload = {
            "model": self.QWEN_MODEL,
            "temperature": 0.05,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": sys_prompt},
                {"role": "user",   "content": f"Analyze the following AI agent project files for safety guardrails:\n\n{combined_source}"},
            ],
        }
        try:
            async with httpx.AsyncClient(timeout=120) as client:
                r = await client.post(
                    f"{self.QWEN_BASE}/chat/completions",
                    headers={"Authorization": f"Bearer {self.qwen_key}", "Content-Type": "application/json"},
                    json=payload,
                )
                r.raise_for_status()
                raw = r.json()["choices"][0]["message"]["content"]
                data = json.loads(raw)
                return data.get("findings", [])
        except Exception as e:
            return [{"mechanism": f"LLM analysis error: {e}", "type": "LOW",
                     "description": str(e), "evidence": "", "file": "", "line": None, "score_delta": 0}]

    # ─────────────────────────────────────────────────────────────────────────
    # Build structured result from LLM findings
    # ─────────────────────────────────────────────────────────────────────────
    def _build_result(self, llm_findings: list, branch: str, files_scanned: int, readme_path: str) -> dict:
        score = 40  # pessimistic baseline
        score_steps = [("基准分（AI Agent 自主运行，默认保守评分）", 40, 40)]
        findings = []
        positive_count = 0
        negative_count = 0

        SEVERITY_ICON = {
            "POSITIVE": "✅",
            "LOW":      "ℹ️",
            "MEDIUM":   "🔍",
            "HIGH":     "⚠️",
            "CRITICAL": "🚨",
        }

        for f in llm_findings:
            ftype       = str(f.get("type", "LOW")).upper()
            mechanism   = str(f.get("mechanism", "Unknown"))
            description = str(f.get("description", ""))
            evidence    = str(f.get("evidence", ""))
            filepath    = str(f.get("file", ""))
            line_no     = f.get("line")
            raw_delta   = int(f.get("score_delta", 0))

            # Clamp score_delta to reasonable bounds per type
            lo, hi = DELTA_BOUNDS.get(ftype, (-30, 15))
            delta = max(lo, min(hi, raw_delta))

            score += delta
            score_steps.append((mechanism, delta, score))

            is_pos = (ftype == "POSITIVE")
            if is_pos:
                positive_count += 1
            elif ftype in ("CRITICAL", "HIGH", "MEDIUM"):
                negative_count += 1

            # Build GitHub link
            file_link = self._make_file_link(filepath, line_no, branch)

            # Build evidence block
            context_html = ""
            if evidence:
                evidence_lines = evidence.splitlines()
                rows = []
                for i, ln in enumerate(evidence_lines):
                    lnum = (line_no or 1) + i
                    is_first = (i == 0)
                    bg     = "background:#fef3c7;" if is_first else "background:#f8fafc;"
                    border = "border-left:3px solid #f59e0b;" if is_first else "border-left:3px solid transparent;"
                    rows.append(
                        f'<div style="{bg}{border}padding:1px 6px;display:flex;gap:6px;">'
                        f'<span style="color:#94a3b8;min-width:28px;text-align:right;user-select:none">{lnum}</span>'
                        f'<span style="white-space:pre-wrap;word-break:break-all;">{self._esc(ln)}</span>'
                        f'</div>'
                    )
                context_html = (
                    '<div style="margin-top:6px;border:1px solid #e2e8f0;border-radius:6px;'
                    'overflow:hidden;font-family:monospace;font-size:11px;line-height:1.5;">'
                    + "".join(rows) + '</div>'
                )

            color_cls = "text-green-700 bg-green-50" if is_pos else "text-red-700 bg-red-50"
            delta_badge = f'+{delta}' if delta >= 0 else str(delta)
            detail_html = (
                f'<div class="mt-1 text-xs {color_cls} px-2 py-1 rounded">{self._esc(description)}</div>'
                + (f'<div class="mt-1 text-xs text-gray-500">📍 Evidence: {file_link}</div>' if file_link else "")
                + context_html
            )

            icon = SEVERITY_ICON.get(ftype, "🔍")
            title_html = (
                f'{icon} {self._esc(mechanism)} '
                f'<span style="color:{"#16a34a" if is_pos else "#dc2626"};font-size:10px;font-weight:bold;">({delta_badge} pts)</span>'
            )
            findings.append({
                "type": ftype,
                "title": title_html,
                "detail": detail_html,
                "is_html": True,
            })

        # Penalty if zero mechanisms found
        if positive_count == 0:
            penalty = -15
            score += penalty
            score_steps.append(("未检测到安全机制（惩罚项）", penalty, score))
            findings.append({
                "type": "HIGH",
                "title": "⚠️ 未检测到安全护栏",
                "detail": "未发现输入校验、步骤限制、人工审批等安全控制，Agent 可能完全自主运行，无任何安全护栏。",
                "is_html": False,
            })

        score = max(0, min(100, score))

        # Score breakdown card
        criteria_rows = "".join([
            f'<tr style="border-bottom:1px solid #f1f5f9;">'
            f'<td style="padding:3px 8px;color:#374151;">{self._esc(label)}</td>'
            f'<td style="padding:3px 8px;text-align:right;font-weight:bold;'
            f'color:{"#16a34a" if d >= 0 else "#dc2626"};">{"+" if d >= 0 else ""}{d}</td>'
            f'<td style="padding:3px 8px;text-align:right;color:#6b7280;">{total}</td>'
            f'</tr>'
            for label, d, total in score_steps
        ])
        score_html = f"""
<div style="font-size:11px;">
  <table style="width:100%;border-collapse:collapse;background:#f8fafc;border-radius:6px;overflow:hidden;border:1px solid #e2e8f0;">
    <thead>
      <tr style="background:#e2e8f0;font-weight:600;color:#475569;">
        <th style="padding:4px 8px;text-align:left;">评分项</th>
        <th style="padding:4px 8px;text-align:right;">分值变化</th>
        <th style="padding:4px 8px;text-align:right;">累计得分</th>
      </tr>
    </thead>
    <tbody>{criteria_rows}</tbody>
    <tfoot>
      <tr style="background:#1e1b4b;color:white;font-weight:bold;">
        <td style="padding:4px 8px;">最终得分（0-100封顶）</td>
        <td></td>
        <td style="padding:4px 8px;text-align:right;font-size:13px;">{score}</td>
      </tr>
    </tfoot>
  </table>
  <div style="margin-top:6px;color:#6b7280;line-height:1.6;">
    <b>LLM评分参考（近似值）：</b><br/>
    基准分 <b>40</b> · 人工审批 <b>+15</b> · 步骤限制 <b>+15</b> · 输入校验 <b>+10</b><br/>
    输出过滤 <b>+10</b> · 工具白名单 <b>+10</b> · 提示注入防御 <b>+8</b> · 沙箱隔离 <b>+8</b><br/>
    速率限制 <b>+5</b> · 审计日志 <b>+5</b> · README安全文档 <b>+3~+5</b><br/>
    LLM输出直接exec/eval <b>−25</b> · 用户输入拼入system prompt <b>−15</b> · 无安全机制惩罚 <b>−15</b>
  </div>
</div>"""
        findings.insert(0, {
            "type": "INFO",
            "title": f"📊 Score Breakdown — Final: <b>{score}</b> / 100",
            "detail": score_html,
            "is_html": True,
        })

        return {
            "score": score,
            "risk_level": self._score_to_risk(score),
            "summary": f"{positive_count} 项安全控制，{negative_count} 项风险 · {files_scanned} 个文件已扫描（LLM分析）",
            "findings": findings,
            "metrics": {
                "positive_mechanisms": positive_count,
                "negative_patterns": negative_count,
                "files_scanned": files_scanned,
            },
        }

    # ─────────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────────
    def _select_files(self, files: List[str]) -> List[str]:
        priority, secondary = [], []
        skip = {"node_modules", ".git", "dist", "build", "__pycache__", "venv", ".venv", "site-packages"}
        src_ext = {".py", ".ts", ".js", ".go", ".rs", ".java", ".kt"}
        agent_kw = ["agent", "tool", "safety", "guardrail", "prompt", "llm", "chain",
                    "run", "main", "app", "workflow", "executor", "planner", "action"]
        for f in files:
            parts = f.split("/")
            if any(p in skip for p in parts):
                continue
            name = parts[-1].lower()
            ext = ("." + name.rsplit(".", 1)[-1]) if "." in name else ""
            if any(kw in f.lower() for kw in agent_kw) and ext in src_ext:
                priority.append(f)
            elif ext in src_ext and len(parts) <= 3:
                secondary.append(f)
        return (priority + secondary)[:STAGE1_MAX_CANDIDATES]

    def _make_file_link(self, filepath: str, line_no, branch: str) -> str:
        if not filepath:
            return ""
        base_url = f"https://github.com/{self.owner}/{self.repo}/blob/{branch}/{filepath}"
        url = f"{base_url}#L{line_no}" if line_no else base_url
        label = f"{filepath}:{line_no}" if line_no else filepath
        return (
            f'<a href="{url}" target="_blank" '
            f'class="underline text-indigo-600 hover:text-indigo-800 font-mono text-xs">'
            f'{self._esc(label)}</a>'
        )

    async def _fetch_file(self, client: httpx.AsyncClient, path: str, branch: str) -> str:
        try:
            r = await client.get(
                f"{self.GITHUB_BASE}/repos/{self.owner}/{self.repo}/contents/{path}",
                params={"ref": branch},
            )
            if r.status_code != 200:
                return ""
            data = r.json()
            if data.get("encoding") == "base64":
                return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
            return data.get("content", "")
        except Exception:
            return ""

    def _esc(self, s: str) -> str:
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    def _error_result(self, msg: str) -> dict:
        return {
            "score": 50, "risk_level": "UNKNOWN", "summary": msg,
            "findings": [{"type": "INFO", "title": "扫描错误", "detail": msg}],
            "metrics": {},
        }

    def _score_to_risk(self, score: int) -> str:
        if score >= 75:  return "LOW"
        elif score >= 55: return "MEDIUM"
        elif score >= 35: return "HIGH"
        return "CRITICAL"
