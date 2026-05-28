"""
Agent Capability Analyzer — LLM Edition
Enumerates what operations an AI agent can potentially perform:
what it can DO to your system, not traditional code vulnerabilities.
"""
import httpx
import base64
import json
import os
import re
from typing import List, Dict

def _esc(s: str) -> str:
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

# ── Risk weight per capability category ──────────────────────────────────────
CATEGORY_RISK = {
    "terminal":       {"label": "终端 / Shell 执行",          "icon": "💻", "weight": 25},
    "code_execution": {"label": "代码解释器 / REPL",           "icon": "⚙️",  "weight": 22},
    "computer_use":   {"label": "计算机 / 桌面控制",           "icon": "🖥️",  "weight": 22},
    "file_write":     {"label": "文件系统写入 / 删除",         "icon": "✏️",  "weight": 18},
    "database_write": {"label": "数据库写入",                  "icon": "🗄️",  "weight": 18},
    "email":          {"label": "邮件 / 消息发送",             "icon": "📧",  "weight": 15},
    "cloud_services": {"label": "云服务（AWS/GCP/Azure）",     "icon": "☁️", "weight": 15},
    "external_api":   {"label": "外部 API 调用",               "icon": "🌐",  "weight": 12},
    "browser":        {"label": "网页浏览器自动化",            "icon": "🌍",  "weight": 12},
    "file_read":      {"label": "文件系统读取",                "icon": "📂",  "weight": 8},
    "database_read":  {"label": "数据库读取",                  "icon": "🔍",  "weight": 8},
    "web_search":     {"label": "网络 / 互联网搜索",           "icon": "🔎",  "weight": 5},
    "memory":         {"label": "长期记忆 / 存储",             "icon": "🧠",  "weight": 5},
    "auth":           {"label": "凭证 / 认证访问",             "icon": "🔑",  "weight": 10},
    "other":          {"label": "其他能力",                    "icon": "🔧",  "weight": 5},
}

# Map LLM severity to display type
SEV_TYPE = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "INFO": "LOW"}

SYSTEM_PROMPT = """You are an AI agent security analyst. Your job is NOT to find code bugs — your job is to enumerate every operation this AI agent is capable of performing on the host system or external services.

Think of yourself as building a "capability inventory" or "blast radius map": if this agent runs in our environment, what can it DO?

Return ONLY valid JSON — no markdown, no text outside the JSON:
{
  "capabilities": [
    {
      "category": "<one of the categories below>",
      "name": "<short capability name, max 60 chars, e.g. 'Execute arbitrary shell commands via bash tool'>",
      "severity": "HIGH" | "MEDIUM" | "LOW",
      "description": "<1-2 sentences: what exactly can the agent do, and what is the potential impact>",
      "evidence": "<exact code snippet proving this capability exists, max 180 chars>",
      "file": "<filename>",
      "line": <integer or null>
    }
  ],
  "capability_summary": "<2-3 sentence summary of the agent's overall capability profile and blast radius>"
}

CATEGORIES (use exactly these strings):
- "terminal"        — can run shell/bash/cmd commands
- "code_execution"  — has Python/JS/code interpreter or REPL
- "computer_use"    — can control mouse, keyboard, screenshot, GUI
- "file_write"      — can create, write, modify, or delete files/directories
- "file_read"       — can read files, list directories
- "database_write"  — can INSERT/UPDATE/DELETE in databases
- "database_read"   — can SELECT/query databases
- "email"           — can send emails, Slack/Teams/Discord messages
- "cloud_services"  — uses AWS/GCP/Azure/S3/Lambda/etc.
- "external_api"    — makes HTTP calls to external services/APIs
- "browser"         — can open URLs, scrape pages, fill forms, click
- "web_search"      — can search the internet (Google, Bing, DuckDuckGo, Tavily, etc.)
- "memory"          — uses persistent memory, vector stores, long-term state
- "auth"            — accesses credentials, OAuth tokens, API keys, secrets
- "other"           — any significant capability not covered above

SEVERITY GUIDE:
- HIGH:   The agent can cause irreversible or high-impact side effects (delete files, send emails, run shell commands, modify databases, control computer)
- MEDIUM: The agent reads data, makes external calls, or browses the web — lower impact but still noteworthy
- LOW:    Informational — the agent uses memory, search, or other benign capabilities

RULES:
- Report each DISTINCT capability once — do not duplicate
- Only report capabilities backed by actual code evidence (tool definitions, function calls, imports, configurations)
- Be specific: "reads files from any path" is better than "reads files"
- If a tool is defined but appears disabled or gated, note that in the description
- Include capabilities from README/docs if the code implements them
- Do NOT report general LLM API calls (to OpenAI/Anthropic/Qwen etc.) as "external_api" unless the agent TOOLS explicitly call external services beyond the LLM provider
- Focus on what the AGENT does, not what its dependencies do internally
- All text fields (name, description) MUST be written in Chinese (Simplified Chinese). Evidence should keep the original code snippet.
"""


class CodeAnalyzer:
    GITHUB_BASE = "https://api.github.com"
    QWEN_BASE   = "https://dashscope.aliyuncs.com/compatible-mode/v1"
    QWEN_MODEL        = "qwen-plus"
    QWEN_TURBO_MODEL  = "qwen-turbo"
    STAGE1_PREVIEW_LINES  = 50    # lines read per file in stage 1
    STAGE1_MAX_CANDIDATES = 40    # candidate files sent to stage 1 ranker
    STAGE2_MAX_FILES      = 15    # files selected for deep analysis
    MAX_LINES_PER_FILE    = 600   # deep scan lines in stage 2 (up from 400)

    def __init__(self, owner: str, repo: str, token: str = None):
        self.owner = owner
        self.repo  = repo
        self.gh_headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "AI-Risk-Evaluator/1.0",
        }
        if token:
            self.gh_headers["Authorization"] = f"token {token}"
        self.qwen_key = os.getenv("QWEN_API_KEY", "")

    # ── Main entry ────────────────────────────────────────────────────────────

    async def analyze(self) -> dict:
        async with httpx.AsyncClient(headers=self.gh_headers, timeout=30) as gh:
            repo_r = await gh.get(f"{self.GITHUB_BASE}/repos/{self.owner}/{self.repo}")
            repo_r.raise_for_status()
            default_branch = repo_r.json().get("default_branch", "main")

            tree_r = await gh.get(
                f"{self.GITHUB_BASE}/repos/{self.owner}/{self.repo}/git/trees/{default_branch}",
                params={"recursive": "1"},
            )
            if tree_r.status_code != 200:
                return self._error_result("Cannot fetch repository tree")

            all_files = [f["path"] for f in tree_r.json().get("tree", []) if f.get("type") == "blob"]
            candidates = self._select_files(all_files)  # up to 40 candidates

            # Always include README
            readme_path = None
            for name in ["README.md", "readme.md"]:
                if any(f.lower() == name.lower() for f in all_files):
                    readme_path = name
                    candidates = [name] + [f for f in candidates if f.lower() != name.lower()]
                    break

            # ── Stage 1: fetch 50-line previews of all candidates ─────────────
            previews: Dict[str, str] = {}
            for path in candidates:
                content = await self._fetch_file(gh, path, default_branch)
                if content:
                    snippet = "\n".join(content.splitlines()[:self.STAGE1_PREVIEW_LINES])
                    previews[path] = snippet

            # ── Stage 1: cheap LLM selects top 15 files ──────────────────────
            if not self.qwen_key:
                return self._error_result("QWEN_API_KEY not configured")

            selected_paths = await self._stage1_rank_files(previews, readme_path)

            # ── Stage 2: fetch full content (600 lines) of selected files ─────
            file_contents: Dict[str, str] = {}
            for path in selected_paths:
                content = await self._fetch_file(gh, path, default_branch)
                if content:
                    file_contents[path] = content

        # Build combined source for deep LLM call
        sections = []
        for path, content in file_contents.items():
            lines = content.splitlines()[:self.MAX_LINES_PER_FILE]
            numbered = "\n".join(f"{i+1:4d} | {l}" for i, l in enumerate(lines))
            sections.append(f"=== FILE: {path} ===\n{numbered}")
        combined = "\n\n".join(sections)

        raw_caps, summary = await self._call_llm(combined)

        return self._build_result(raw_caps, summary, default_branch, len(file_contents))

    # ── Stage 1: file ranker (qwen-turbo) ────────────────────────────────────

    async def _stage1_rank_files(self, previews: Dict[str, str], readme_path: str) -> List[str]:
        """Use cheap model to rank candidate files and return top STAGE2_MAX_FILES paths."""
        preview_text = ""
        for path, snippet in previews.items():
            preview_text += f"\n--- {path} ---\n{snippet}\n"

        prompt = f"""你是一个代码文件相关性排序器。

任务：从下列候选文件的预览中，选出最适合用来分析「AI Agent 具备哪些操作能力（爆炸半径）」的 {self.STAGE2_MAX_FILES} 个文件。

优先选择：
- 定义了工具/tool/skill/action/executor 的文件
- 包含 shell/bash/file/database/cloud/email/browser 等操作的文件
- Agent 的主入口文件（main.py、app.py、agent.py 等）
- README（如果存在）

排除：测试文件、配置文件、文档文件、空文件。

候选文件预览：
{preview_text}

以 JSON 格式返回，只包含文件路径列表：
{{"selected_files": ["path1", "path2", ...]}}"""

        payload = {
            "model": self.QWEN_TURBO_MODEL,
            "temperature": 0.0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": "你是代码文件相关性排序专家，输出严格的 JSON。"},
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
                # Validate: only return paths that exist in previews
                valid = [p for p in selected if p in previews]
                # Fallback: if LLM returns too few, pad with remaining candidates
                if len(valid) < self.STAGE2_MAX_FILES:
                    for p in previews:
                        if p not in valid:
                            valid.append(p)
                        if len(valid) >= self.STAGE2_MAX_FILES:
                            break
                return valid[:self.STAGE2_MAX_FILES]
        except Exception:
            # Fallback to original keyword-based selection
            return list(previews.keys())[:self.STAGE2_MAX_FILES]

    # ── LLM call ──────────────────────────────────────────────────────────────

    async def _call_llm(self, combined_source: str):
        payload = {
            "model": self.QWEN_MODEL,
            "temperature": 0.05,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": f"Enumerate all capabilities of this AI agent:\n\n{combined_source}"},
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
                data = json.loads(r.json()["choices"][0]["message"]["content"])
                return data.get("capabilities", []), data.get("capability_summary", "")
        except Exception as e:
            return [], f"LLM error: {e}"

    # ── Build result ──────────────────────────────────────────────────────────

    def _build_result(self, raw_caps: list, summary: str, branch: str, files_scanned: int) -> dict:
        # Group by category
        grouped: Dict[str, list] = {}
        for cap in raw_caps:
            cat = cap.get("category", "other")
            grouped.setdefault(cat, []).append(cap)

        # Score: start at 100, deduct by capability risk weights
        score = 100
        score_steps = [("基准分（未发现能力）", 100, 100)]
        findings = []

        # Category severity order for display
        CAT_ORDER = ["terminal","code_execution","computer_use","file_write","database_write",
                     "email","cloud_services","auth","external_api","browser",
                     "file_read","database_read","web_search","memory","other"]

        high_count = med_count = low_count = 0

        for cat in CAT_ORDER:
            caps = grouped.get(cat, [])
            if not caps:
                continue

            meta = CATEGORY_RISK.get(cat, CATEGORY_RISK["other"])
            # Deduct once per category (even if multiple findings in category)
            deduct = meta["weight"]
            score -= deduct
            score_steps.append((f'{meta["icon"]} {meta["label"]}', -deduct, score))

            for cap in caps:
                sev     = cap.get("severity", "MEDIUM")
                name    = cap.get("name", "Unknown capability")
                desc    = cap.get("description", "")
                evidence= cap.get("evidence", "")
                filepath= cap.get("file", "")
                line_no = cap.get("line")

                ftype = SEV_TYPE.get(sev, "MEDIUM")
                if ftype == "HIGH":   high_count += 1
                elif ftype == "MEDIUM": med_count += 1
                else: low_count += 1

                file_link = self._make_file_link(filepath, line_no, branch)

                # Evidence block — shown in detail (expanded view)
                evidence_html = ""
                if evidence:
                    evidence_html = (
                        f'<div style="margin-top:6px;">'
                        f'<div style="font-size:10px;font-weight:600;color:#475569;margin-bottom:2px;">📎 Code Evidence</div>'
                        f'<div style="border:1px solid #e2e8f0;border-radius:6px;overflow:hidden;'
                        f'font-family:monospace;font-size:11px;background:#f8fafc;">'
                        f'<div style="padding:6px 10px;color:#1e293b;white-space:pre-wrap;word-break:break-all;">'
                        f'{_esc(evidence)}</div>'
                        f'</div>'
                        f'</div>'
                    )

                # Inline evidence snippet shown directly on the title row (first 80 chars)
                inline_evidence = ""
                if evidence:
                    short = evidence.strip().splitlines()[0][:80]
                    inline_evidence = (
                        f' <span style="font-family:monospace;font-size:10px;color:#64748b;'
                        f'background:#f1f5f9;padding:1px 5px;border-radius:3px;margin-left:4px;">'
                        f'{_esc(short)}{"…" if len(evidence.strip()) > 80 else ""}</span>'
                    )

                sev_color = {"HIGH":"#dc2626","MEDIUM":"#ca8a04","LOW":"#6b7280"}.get(sev,"#6b7280")
                detail_html = (
                    f'<div style="color:{sev_color};font-weight:500;margin-bottom:4px;">{_esc(desc)}</div>'
                    + (f'<div style="color:#6b7280;font-size:10px;margin:2px 0;">📍 Source: {file_link}</div>' if file_link else "")
                    + evidence_html
                )

                icon = {"HIGH":"⚠️","MEDIUM":"🔍","LOW":"ℹ️"}.get(sev,"🔍")
                findings.append({
                    "type":    ftype,
                    "title":   f'{icon} {meta["icon"]} {_esc(name)}{inline_evidence}',
                    "detail":  detail_html,
                    "is_html": True,
                })

        score = max(0, min(100, score))

        # Capability summary card
        if summary:
            findings.insert(0, {
                "type":    "POSITIVE",
                "title":   "📋 能力摘要",
                "detail":  f'<div style="color:#374151;line-height:1.6;">{_esc(summary)}</div>',
                "is_html": True,
            })

        # Score breakdown
        criteria_rows = "".join([
            f'<tr style="border-bottom:1px solid #f1f5f9;">'
            f'<td style="padding:3px 8px;color:#374151;">{_esc(str(label))}</td>'
            f'<td style="padding:3px 8px;text-align:right;font-weight:bold;color:{"#16a34a" if d>=0 else "#dc2626"};">{"+" if d>=0 else ""}{d}</td>'
            f'<td style="padding:3px 8px;text-align:right;color:#6b7280;">{total}</td>'
            f'</tr>'
            for label, d, total in score_steps
        ])
        score_html = f"""<div style="font-size:11px;">
  <div style="margin-bottom:6px;color:#6b7280;">
    分数反映<b>爆炸半径</b>：检测到的能力越强，分数越低。<br/>
    终端/Shell <b>−25</b> · 代码执行/计算机控制 <b>−22</b> · 文件写入/数据库写入 <b>−18</b> ·
    邮件/云服务 <b>−15</b> · 凭证访问 <b>−10</b> · 外部API/浏览器 <b>−12</b> · 文件读取 <b>−8</b> · 搜索 <b>−5</b>
  </div>
  <table style="width:100%;border-collapse:collapse;background:#f8fafc;border-radius:6px;overflow:hidden;border:1px solid #e2e8f0;">
    <thead><tr style="background:#e2e8f0;font-weight:600;color:#475569;">
      <th style="padding:4px 8px;text-align:left;">发现的能力</th>
      <th style="padding:4px 8px;text-align:right;">分值变化</th>
      <th style="padding:4px 8px;text-align:right;">累计得分</th>
    </tr></thead>
    <tbody>{criteria_rows}</tbody>
    <tfoot><tr style="background:#1e1b4b;color:white;font-weight:bold;">
      <td style="padding:4px 8px;">最终得分（0-100封顶）</td>
      <td></td>
      <td style="padding:4px 8px;text-align:right;font-size:13px;">{score}</td>
    </tr></tfoot>
  </table>
</div>"""

        findings.insert(0, {
            "type":    "INFO",
            "title":   f'📊 Score Breakdown — Final: <b>{score}</b> / 100',
            "detail":  score_html,
            "is_html": True,
        })

        total_caps = high_count + med_count + low_count
        return {
            "score":      score,
            "risk_level": self._score_to_risk(score),
            "summary":    f"{total_caps} 项能力 · {high_count} 高影响 · {files_scanned} 个文件已扫描（LLM分析）",
            "findings":   findings,
            "metrics": {
                "files_scanned":   files_scanned,
                "total_capabilities": total_caps,
                "high_impact":     high_count,
                "medium_impact":   med_count,
                "low_impact":      low_count,
                "llm_model":       self.QWEN_MODEL,
            },
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _select_files(self, files: List[str]) -> List[str]:
        priority, secondary = [], []
        skip = {"node_modules",".git","dist","build","__pycache__","venv",".venv","site-packages"}
        src_ext = {".py",".ts",".js",".go",".rs",".java",".kt"}
        kw = ["tool","agent","skill","action","executor","capability","function","plugin",
              "run","main","app","workflow","handler","command","bash","shell","email",
              "file","browser","search","memory","database","db","api","cloud","aws"]
        for f in files:
            parts = f.split("/")
            if any(p in skip for p in parts): continue
            name = parts[-1].lower()
            ext  = ("." + name.split(".")[-1]) if "." in name else ""
            if ext in src_ext and any(k in f.lower() for k in kw): priority.append(f)
            elif ext in src_ext and len(parts) <= 3:                secondary.append(f)
        return (priority + secondary)[:self.STAGE1_MAX_CANDIDATES]

    def _make_file_link(self, filepath: str, line_no, branch: str) -> str:
        if not filepath:
            return ""
        base = f"https://github.com/{self.owner}/{self.repo}/blob/{branch}/{filepath}"
        url  = f"{base}#L{line_no}" if line_no else base
        label = f"{filepath}:{line_no}" if line_no else filepath
        return (
            f'<a href="{url}" target="_blank" '
            f'class="underline text-indigo-600 hover:text-indigo-800 font-mono text-xs">'
            f'{_esc(label)}</a>'
        )

    async def _fetch_file(self, client, path: str, branch: str) -> str:
        try:
            r = await client.get(
                f"{self.GITHUB_BASE}/repos/{self.owner}/{self.repo}/contents/{path}",
                params={"ref": branch},
            )
            if r.status_code != 200: return ""
            data = r.json()
            if data.get("encoding") == "base64":
                return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
            return data.get("content","")
        except Exception:
            return ""

    def _error_result(self, msg):
        return {"score":50,"risk_level":"UNKNOWN","summary":msg,
                "findings":[{"type":"INFO","title":"分析不可用","detail":msg}],"metrics":{}}

    def _score_to_risk(self, score):
        if score >= 75: return "LOW"
        if score >= 55: return "MEDIUM"
        if score >= 35: return "HIGH"
        return "CRITICAL"

