"""
Skill Security Analyzer
Evaluates the security implementation quality of individual skills/tools defined in an AI Agent repo.

Checks per skill:
  1. Parameter schema quality   — type constraints, enum, maxLength
  2. Input injection risk       — params concatenated into shell/sql/prompt
  3. Capability vs declaration  — does code match what the skill claims to do?
  4. Data exfiltration risk     — does the skill send params/context to external URLs?
  5. Description injection      — is the skill description user-controllable?
  6. Least-privilege            — does a high-risk skill declare approval requirements?
"""
import asyncio
import base64
import json
import re
from typing import Dict, List, Optional, Tuple

import httpx

# ── LLM Prompt ────────────────────────────────────────────────────────────────

SYSTEM_PROMPT_ZH = """你是一名 AI Agent 安全工程师，专门审查 AI Agent 中 Skill/Tool 定义的实现安全性。

你的任务不是找通用代码漏洞，而是评估每个 Skill 的安全实现质量：
- 参数有没有类型/范围约束？
- 参数有没有直接拼接到 shell/SQL/prompt 中（注入风险）？
- Skill 的实际能力和其描述是否一致（声明 vs 实现）？
- Skill 是否将参数或上下文数据发送给外部 URL（数据外传）？
- Skill description 是否包含可被用户输入影响的动态内容（prompt 劫持）？
- 高危 Skill（shell/file/db）是否有审批/确认机制？

返回严格 JSON，不要任何 Markdown：
{
  "skills": [
    {
      "name": "<skill 名称>",
      "file": "<文件路径>",
      "line": <行号或 null>,
      "risk_level": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE",
      "issues": [
        {
          "type": "INJECTION" | "NO_VALIDATION" | "EXFILTRATION" | "OVER_PRIVILEGED" | "DESC_INJECTION" | "MISMATCH" | "INFO",
          "title": "<问题标题，≤60字>",
          "detail": "<具体说明：哪个参数/哪行代码，风险是什么>",
          "evidence": "<原始代码片段，≤200字符>"
        }
      ],
      "good_practices": ["<做得好的安全实践，如有>"]
    }
  ],
  "summary": "<2-3句总结：整体 skill 安全质量，主要风险模式>",
  "score_delta": <整数，范围 -40 到 0，基于整体风险严重程度>
}

评分参考：
- 有 CRITICAL 问题（注入/外传）：-30 ~ -40
- 有 HIGH 问题（无校验/越权）：-15 ~ -25
- 有 MEDIUM 问题：-5 ~ -10
- 仅有 LOW/INFO：0 ~ -5
- 所有 skill 实现良好：0
"""

SYSTEM_PROMPT_EN = """You are an AI Agent security engineer specializing in reviewing the security implementation quality of Skill/Tool definitions in AI Agents.

Your job is NOT to find general code bugs, but to evaluate each skill's security implementation:
- Do parameters have type/range constraints?
- Are parameters directly concatenated into shell/SQL/prompt (injection risk)?
- Does the skill's actual capability match its description (declaration vs implementation)?
- Does the skill send parameters or context data to external URLs (data exfiltration)?
- Does the skill description contain dynamic content controllable by user input (prompt hijacking)?
- Do high-risk skills (shell/file/db) have approval/confirmation mechanisms?

Return strict JSON only, no Markdown:
{
  "skills": [
    {
      "name": "<skill name>",
      "file": "<file path>",
      "line": <line number or null>,
      "risk_level": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE",
      "issues": [
        {
          "type": "INJECTION" | "NO_VALIDATION" | "EXFILTRATION" | "OVER_PRIVILEGED" | "DESC_INJECTION" | "MISMATCH" | "INFO",
          "title": "<issue title, ≤60 chars>",
          "detail": "<specific explanation: which parameter/line, what is the risk>",
          "evidence": "<original code snippet, ≤200 chars>"
        }
      ],
      "good_practices": ["<good security practices found, if any>"]
    }
  ],
  "summary": "<2-3 sentence summary: overall skill security quality, main risk patterns>",
  "score_delta": <integer, range -40 to 0, based on overall severity>
}

Scoring guide:
- Has CRITICAL issues (injection/exfiltration): -30 ~ -40
- Has HIGH issues (no validation/over-privileged): -15 ~ -25
- Has MEDIUM issues: -5 ~ -10
- Only LOW/INFO: 0 ~ -5
- All skills well-implemented: 0
"""

# ── Skill file discovery patterns ─────────────────────────────────────────────

SKILL_PRIORITY_DIRS = {
    "skill", "skills", "tool", "tools", "action", "actions",
    "plugin", "plugins", "capability", "capabilities",
    "function", "functions", "executor", "executors",
    "handler", "handlers", "command", "commands",
    "integration", "integrations",
}

SKILL_FILENAME_KW = {
    "skill", "tool", "action", "plugin", "capability", "executor",
    "handler", "command", "function", "bash", "shell", "terminal",
    "email", "browser", "search", "database", "db", "file_op",
    "cloud", "aws", "gcp", "azure", "webhook",
}

SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", "__pycache__",
    "venv", ".venv", "site-packages", "test", "tests",
    "spec", "specs", "fixtures", "mocks", "migrations",
    "assets", "static", "public", "docs", ".github",
}

SRC_EXT = {".py", ".ts", ".js", ".go", ".rs", ".java", ".kt", ".rb", ".php"}

# Skill definition patterns to detect in source code
SKILL_DEF_PATTERNS = [
    # Python decorators
    r"@tool\b", r"@skill\b", r"@action\b", r"@function_tool\b",
    r"@register_tool\b", r"@mcp\.tool\b",
    # Class inheritance
    r"class\s+\w+\s*\(\s*BaseTool\b", r"class\s+\w+\s*\(\s*Tool\b",
    r"class\s+\w+\s*\(\s*BaseAction\b",
    # Function/dict definitions
    r"\"type\"\s*:\s*\"function\"",   # OpenAI function calling
    r"\"inputSchema\"",               # MCP tool schema
    r"tools\s*=\s*\[",               # tool array
    r"functions\s*=\s*\[",           # functions array
    r"StructuredTool\.from_function", # LangChain
    r"Tool\(",                        # generic Tool()
]


class SkillAnalyzer:
    GITHUB_BASE = "https://api.github.com"
    QWEN_BASE   = "https://dashscope.aliyuncs.com/compatible-mode/v1"
    QWEN_MODEL  = "qwen-plus"

    MAX_FILES_TO_SCAN  = 20   # max skill files to send to LLM
    MAX_LINES_PER_FILE = 300  # lines to read per skill file

    def __init__(self, owner: str, repo: str, token: str = None, lang: str = "zh"):
        self.owner = owner
        self.repo  = repo
        self.lang  = lang
        self.headers = {
            "Accept":     "application/vnd.github.v3+json",
            "User-Agent": "AI-Risk-Evaluator/1.0",
        }
        if token:
            self.headers["Authorization"] = f"token {token}"

    # ── Public entry point ────────────────────────────────────────────────────

    async def analyze(self) -> dict:
        en = self.lang == "en"

        async with httpx.AsyncClient(headers=self.headers, timeout=30) as gh:
            # 1. Get default branch + all files
            try:
                meta = (await gh.get(f"{self.GITHUB_BASE}/repos/{self.owner}/{self.repo}")).json()
                default_branch = meta.get("default_branch", "main")
                tree_r = await gh.get(
                    f"{self.GITHUB_BASE}/repos/{self.owner}/{self.repo}/git/trees/{default_branch}",
                    params={"recursive": "1"},
                )
                all_files: List[str] = [
                    i["path"] for i in tree_r.json().get("tree", [])
                    if i.get("type") == "blob"
                ]
            except Exception as e:
                return self._error_result(f"Failed to fetch repo tree: {e}", en)

            # 2. Discover skill files
            skill_files = self._find_skill_files(all_files)
            if not skill_files:
                return {
                    "score":      100,
                    "risk_level": "LOW",
                    "summary":    "No skill/tool definition files detected" if en else "未检测到 Skill/Tool 定义文件",
                    "findings":   [{
                        "type":  "INFO",
                        "title": "No skill files found" if en else "未发现 Skill 文件",
                        "detail": "No dedicated skill/tool directories or recognizable skill definitions detected." if en
                                  else "未发现专用 skill/tool 目录或可识别的 Skill 定义文件。",
                    }],
                    "metrics": {"skill_files_found": 0, "skills_analyzed": 0},
                }

            # 3. Fetch file contents and filter to those with actual skill definitions
            file_contents: Dict[str, str] = {}
            fetch_tasks = [self._fetch_file(gh, f, default_branch) for f in skill_files]
            contents = await asyncio.gather(*fetch_tasks, return_exceptions=True)
            for path, content in zip(skill_files, contents):
                if isinstance(content, str) and content:
                    file_contents[path] = content

            # Keep only files that actually contain skill definitions
            skill_files_confirmed = {
                path: content
                for path, content in file_contents.items()
                if self._contains_skill_definition(content)
            }

            if not skill_files_confirmed:
                # Fall back to all fetched files if none pass the filter
                skill_files_confirmed = file_contents

            # Trim to max files
            trimmed = dict(list(skill_files_confirmed.items())[:self.MAX_FILES_TO_SCAN])

            # 4. Run LLM analysis
            llm_result = await self._run_llm_analysis(trimmed, default_branch, en)
            return llm_result

    # ── File discovery ─────────────────────────────────────────────────────────

    def _find_skill_files(self, all_files: List[str]) -> List[str]:
        scored: List[Tuple[int, str]] = []
        for f in all_files:
            parts = f.split("/")
            if any(p in SKIP_DIRS for p in parts):
                continue
            name  = parts[-1].lower()
            ext   = ("." + name.rsplit(".", 1)[-1]) if "." in name else ""
            if ext not in SRC_EXT:
                # Also allow JSON/YAML for schema-based skill definitions
                if ext not in {".json", ".yaml", ".yml"}:
                    continue
            stem  = name.rsplit(".", 1)[0] if "." in name else name

            score = 0
            # Direct child of a priority directory
            if len(parts) >= 2 and parts[-2].lower() in SKILL_PRIORITY_DIRS:
                score += 50
            # Any ancestor is a priority directory
            elif any(p.lower() in SKILL_PRIORITY_DIRS for p in parts[:-1]):
                score += 30
            # Filename contains skill keywords
            fname_hits = sum(1 for k in SKILL_FILENAME_KW if k in stem)
            score += fname_hits * 25
            # Shallow files get a small bonus
            score += max(0, 8 - len(parts) * 2)

            if score > 0:
                scored.append((score, f))

        scored.sort(key=lambda x: -x[0])
        return [f for _, f in scored[:self.MAX_FILES_TO_SCAN * 3]]  # over-fetch, filter later

    def _contains_skill_definition(self, content: str) -> bool:
        for pattern in SKILL_DEF_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False

    # ── File fetching ──────────────────────────────────────────────────────────

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
                raw = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
                lines = raw.splitlines()
                return "\n".join(lines[:self.MAX_LINES_PER_FILE])
        except Exception:
            pass
        return ""

    # ── LLM analysis ──────────────────────────────────────────────────────────

    async def _run_llm_analysis(
        self,
        file_contents: Dict[str, str],
        branch: str,
        en: bool,
    ) -> dict:
        if not file_contents:
            return self._error_result("No skill file content to analyze", en)

        # Build context block
        blocks = []
        for path, content in file_contents.items():
            blocks.append(f"=== FILE: {path} ===\n{content}\n")
        context = "\n".join(blocks)

        # Truncate total context to ~12k chars
        if len(context) > 12000:
            context = context[:12000] + "\n...(truncated)"

        user_prompt = (
            f"Please analyze the security implementation quality of the skills/tools defined in the following files from the repo `{self.owner}/{self.repo}`.\n\n"
            f"Focus on:\n"
            f"1. Parameter validation gaps (missing type/range constraints)\n"
            f"2. Injection risks (params concatenated into shell/SQL/prompt)\n"
            f"3. Data exfiltration (params sent to external URLs)\n"
            f"4. Over-privileged skills lacking approval gates\n"
            f"5. Description injection (dynamic/user-controlled skill descriptions)\n\n"
            f"{context}"
        ) if en else (
            f"请分析以下来自仓库 `{self.owner}/{self.repo}` 的文件中定义的 Skill/Tool 的安全实现质量。\n\n"
            f"重点关注：\n"
            f"1. 参数校验缺失（缺少类型/范围约束）\n"
            f"2. 注入风险（参数直接拼接到 shell/SQL/prompt）\n"
            f"3. 数据外传（参数发送到外部 URL）\n"
            f"4. 越权 Skill 缺少审批门控\n"
            f"5. description 注入（动态/用户可控的 skill 描述）\n\n"
            f"{context}"
        )

        try:
            from openai import AsyncOpenAI
            import os
            client = AsyncOpenAI(
                api_key=os.getenv("QWEN_API_KEY", ""),
                base_url=self.QWEN_BASE,
            )
            sys_prompt = SYSTEM_PROMPT_EN if en else SYSTEM_PROMPT_ZH
            resp = await client.chat.completions.create(
                model=self.QWEN_MODEL,
                messages=[
                    {"role": "system", "content": sys_prompt},
                    {"role": "user",   "content": user_prompt},
                ],
                temperature=0.1,
                max_tokens=3000,
            )
            raw = resp.choices[0].message.content.strip()
        except Exception as e:
            return self._error_result(f"LLM call failed: {e}", en)

        return self._parse_llm_result(raw, file_contents, branch, en)

    # ── Result parsing ─────────────────────────────────────────────────────────

    def _parse_llm_result(
        self,
        raw: str,
        file_contents: Dict[str, str],
        branch: str,
        en: bool,
    ) -> dict:
        # Strip markdown code fences if present
        clean = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.MULTILINE)
        clean = re.sub(r"\s*```$", "", clean.strip(), flags=re.MULTILINE)

        try:
            data = json.loads(clean)
        except json.JSONDecodeError:
            m = re.search(r"\{.*\}", clean, re.DOTALL)
            if m:
                try:
                    data = json.loads(m.group(0))
                except Exception:
                    return self._error_result("Failed to parse LLM JSON response", en)
            else:
                return self._error_result("LLM returned non-JSON response", en)

        skills     = data.get("skills", [])
        summary    = data.get("summary", "")
        score_delta = max(-40, min(0, int(data.get("score_delta", 0))))

        # Build findings list
        findings: List[dict] = []
        critical_count = 0
        high_count     = 0
        medium_count   = 0
        skills_total   = len(skills)

        ISSUE_TYPE_LABEL = {
            "INJECTION":      ("💉 注入风险",        "💉 Injection Risk"),
            "NO_VALIDATION":  ("⚠️ 无参数校验",      "⚠️ No Validation"),
            "EXFILTRATION":   ("📤 数据外传",         "📤 Data Exfiltration"),
            "OVER_PRIVILEGED":("🔓 越权无审批",       "🔓 Over-Privileged"),
            "DESC_INJECTION": ("🎭 描述注入",         "🎭 Description Injection"),
            "MISMATCH":       ("🔀 声明/实现不符",    "🔀 Declaration Mismatch"),
            "INFO":           ("ℹ️ 信息",             "ℹ️ Info"),
        }

        RISK_TO_TYPE = {
            "CRITICAL": "HIGH",
            "HIGH":     "HIGH",
            "MEDIUM":   "MEDIUM",
            "LOW":      "LOW",
            "SAFE":     "INFO",
        }

        for skill in skills:
            s_name  = skill.get("name", "Unknown Skill")
            s_file  = skill.get("file", "")
            s_line  = skill.get("line")
            s_risk  = skill.get("risk_level", "LOW")
            issues  = skill.get("issues", [])
            good    = skill.get("good_practices", [])

            if s_risk == "CRITICAL":
                critical_count += 1
            elif s_risk == "HIGH":
                high_count += 1
            elif s_risk == "MEDIUM":
                medium_count += 1

            # File link
            file_link = ""
            if s_file:
                base_url = f"https://github.com/{self.owner}/{self.repo}/blob/{branch}/{s_file}"
                anchor   = f"#L{s_line}" if s_line else ""
                file_link = f' — <a href="{base_url}{anchor}" target="_blank">{s_file}</a>'

            for issue in issues:
                i_type    = issue.get("type", "INFO")
                i_title   = issue.get("title", "")
                i_detail  = issue.get("detail", "")
                i_evidence= issue.get("evidence", "")
                label_idx = 1 if en else 0
                type_label = ISSUE_TYPE_LABEL.get(i_type, ("", ""))[label_idx]
                finding_type = RISK_TO_TYPE.get(s_risk, "LOW")

                detail_html = (
                    f"<b>Skill:</b> {s_name}{file_link}<br/>"
                    f"<b>Issue:</b> {type_label} {i_title}<br/>"
                    f"<b>Detail:</b> {i_detail}"
                ) if en else (
                    f"<b>Skill：</b>{s_name}{file_link}<br/>"
                    f"<b>问题：</b>{type_label} {i_title}<br/>"
                    f"<b>说明：</b>{i_detail}"
                )
                if i_evidence:
                    detail_html += f"<br/><code style='font-size:11px;background:#f3f4f6;padding:2px 4px;border-radius:3px'>{i_evidence[:200]}</code>"

                findings.append({
                    "type":    finding_type,
                    "title":   f"[{s_risk}] {s_name}: {i_title}",
                    "detail":  detail_html,
                    "is_html": True,
                })

            # Good practices as INFO
            for gp in good:
                findings.append({
                    "type":  "INFO",
                    "title": f"✅ {s_name}: {gp}" if en else f"✅ {s_name}: {gp}",
                    "detail": gp,
                })

        # Compute final score
        base_score  = 100
        final_score = max(0, min(100, base_score + score_delta))
        if   critical_count > 0:
            risk_level = "CRITICAL"
        elif high_count > 0:
            risk_level = "HIGH"
        elif medium_count > 0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # Summary finding
        files_count = len(file_contents)
        sum_title = (
            f"🔍 {skills_total} skills analyzed across {files_count} files · "
            f"{critical_count} critical · {high_count} high · {medium_count} medium"
        ) if en else (
            f"🔍 {skills_total} 个 Skill 已分析（{files_count} 个文件）· "
            f"{critical_count} 严重 · {high_count} 高危 · {medium_count} 中危"
        )
        findings.insert(0, {
            "type":  "INFO",
            "title": sum_title,
            "detail": summary,
        })

        return {
            "score":      final_score,
            "risk_level": risk_level,
            "summary":    summary,
            "findings":   findings,
            "metrics": {
                "skill_files_found": files_count,
                "skills_analyzed":   skills_total,
                "critical":          critical_count,
                "high":              high_count,
                "medium":            medium_count,
                "llm_model":         self.QWEN_MODEL,
            },
        }

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _error_result(self, msg: str, en: bool) -> dict:
        return {
            "score":      50,
            "risk_level": "UNKNOWN",
            "summary":    msg,
            "findings":   [{"type": "INFO", "title": "Skill analysis error" if en else "Skill 分析错误", "detail": msg}],
            "metrics":    {"skill_files_found": 0, "skills_analyzed": 0},
        }
