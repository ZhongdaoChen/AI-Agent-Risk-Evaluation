"""
Skill Malicious Behavior Detector
Detects intentionally malicious operations in AI Agent skill/tool definitions.

Focus: deliberate harmful intent, NOT accidental code vulnerabilities.

Detects:
  1. Data exfiltration    — read sensitive files + send to hardcoded external URL
  2. Destructive ops      — DROP TABLE, DELETE without WHERE, rm -rf, disk wipe
  3. Backdoor / C2        — reverse shell, hardcoded remote IP, encoded payloads
  4. Credential harvesting— read .env / SSH keys / tokens + transmit outbound
  5. Stealth operations   — clear logs, hide audit trails, modify timestamps
  6. Supply chain attack  — obfuscated/encoded code, eval(base64decode(...))
"""
import asyncio
import base64
import json
import re
from typing import Dict, List, Optional, Tuple

import httpx

# ── LLM Prompt ────────────────────────────────────────────────────────────────

SYSTEM_PROMPT_ZH = """你是一名专门识别恶意代码的安全研究员，负责审查 AI Agent Skill/Tool 定义中是否存在**故意植入的恶意行为**。

⚠️ 重要前提：你的任务不是找代码质量问题或无意的漏洞，而是识别**开发者故意写入的恶意逻辑**。

判断标准——以下组合是高度可疑的：
1. **数据窃取**：读取敏感文件（.env、id_rsa、*.key、credentials、数据库文件）+ 向硬编码的外部 URL/IP 发送请求
2. **破坏性操作**：DROP TABLE、DELETE FROM（无 WHERE 条件）、rm -rf /、格式化磁盘、批量删除
3. **后门/C2 通信**：反向 shell、硬编码的远程 IP/域名、eval(base64decode(...))、混淆代码
4. **凭证收割**：读取 SSH 密钥、API token、密码文件 + 外传
5. **隐匿行为**：清除日志、修改审计记录、隐藏进程、删除自身
6. **供应链攻击**：base64 编码的可执行 payload、动态 import 外部恶意包

判断原则：
- 单独的"读文件"或"发 HTTP 请求"不可疑，两者组合 + 目标是敏感文件/凭证才可疑
- 硬编码的非知名外部 IP/域名（非 API 服务商）是强信号
- 故意混淆（base64、rot13、字符串拼接绕过检测）是强信号
- 业务正常逻辑（如上传用户选择的文件到 S3）不算恶意

返回严格 JSON，不要任何 Markdown：
{
  "malicious_findings": [
    {
      "skill_name": "<skill/函数名>",
      "file": "<文件路径>",
      "line": <行号或 null>,
      "severity": "CRITICAL" | "HIGH" | "MEDIUM",
      "pattern": "EXFILTRATION" | "DESTRUCTIVE" | "BACKDOOR" | "CREDENTIAL_HARVEST" | "STEALTH" | "OBFUSCATION",
      "title": "<一句话描述恶意行为，≤60字>",
      "intent": "<说明为什么判断这是故意的而非偶然：哪些特征组合让你怀疑>",
      "evidence": "<关键代码片段，≤250字符，保留原始代码>"
    }
  ],
  "clean": <true 如果没有发现任何可疑恶意行为>,
  "summary": "<2-3句总结：是否发现恶意行为，主要风险点，整体判断>",
  "score_delta": <整数，范围 -50 到 0>
}

评分参考：
- 发现 CRITICAL（明确数据窃取/后门/破坏）：-40 ~ -50
- 发现 HIGH（强可疑组合）：-20 ~ -35
- 发现 MEDIUM（弱信号，需人工复核）：-5 ~ -15
- 未发现恶意行为：0
"""

SYSTEM_PROMPT_EN = """You are a malicious code detection specialist reviewing AI Agent Skill/Tool definitions for **deliberately planted malicious behavior**.

⚠️ Key premise: Your job is NOT to find code quality issues or accidental vulnerabilities — only identify **intentionally malicious logic written by the developer**.

Suspicious patterns (combinations are key):
1. **Data exfiltration**: Read sensitive files (.env, id_rsa, *.key, credentials, DB files) + send to hardcoded external URL/IP
2. **Destructive ops**: DROP TABLE, DELETE FROM (no WHERE), rm -rf /, disk wipe, mass deletion
3. **Backdoor/C2**: Reverse shell, hardcoded remote IP/domain, eval(base64decode(...)), obfuscated code
4. **Credential harvesting**: Read SSH keys, API tokens, password files + exfiltrate
5. **Stealth ops**: Clear logs, tamper audit records, hide processes, self-deletion
6. **Supply chain attack**: base64-encoded executable payloads, dynamic import of external malicious packages

Judgment principles:
- "Read a file" OR "make HTTP request" alone is NOT suspicious — the combination targeting sensitive files IS
- Hardcoded non-service-provider external IPs/domains are a strong signal
- Intentional obfuscation (base64, rot13, string concatenation to bypass detection) is a strong signal
- Normal business logic (e.g., upload user-selected file to S3) is NOT malicious

Return strict JSON only, no Markdown:
{
  "malicious_findings": [
    {
      "skill_name": "<skill/function name>",
      "file": "<file path>",
      "line": <line number or null>,
      "severity": "CRITICAL" | "HIGH" | "MEDIUM",
      "pattern": "EXFILTRATION" | "DESTRUCTIVE" | "BACKDOOR" | "CREDENTIAL_HARVEST" | "STEALTH" | "OBFUSCATION",
      "title": "<one-line description of the malicious behavior, ≤60 chars>",
      "intent": "<explain why this appears intentional, not accidental: what combination of signals>",
      "evidence": "<key code snippet, ≤250 chars, keep original code>"
    }
  ],
  "clean": <true if no suspicious malicious behavior found>,
  "summary": "<2-3 sentence summary: whether malicious behavior found, main risks, overall verdict>",
  "score_delta": <integer, range -50 to 0>
}

Scoring:
- CRITICAL found (clear exfiltration/backdoor/destruction): -40 ~ -50
- HIGH found (strong suspicious combination): -20 ~ -35
- MEDIUM found (weak signal, needs human review): -5 ~ -15
- Nothing found: 0
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
            f"Analyze the following skill/tool files from repo `{self.owner}/{self.repo}` "
            f"for deliberately malicious behavior.\n\n"
            f"Remember: only flag intentional malice (data theft, destruction, backdoors), "
            f"NOT accidental code quality issues.\n\n"
            f"{context}"
        ) if en else (
            f"请分析仓库 `{self.owner}/{self.repo}` 中以下 Skill/Tool 文件，"
            f"识别其中是否存在**故意植入的恶意行为**。\n\n"
            f"注意：只标记故意的恶意逻辑（数据窃取、破坏操作、后门），不标记无意的代码质量问题。\n\n"
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

        mal_findings = data.get("malicious_findings", [])
        is_clean     = data.get("clean", len(mal_findings) == 0)
        summary      = data.get("summary", "")
        score_delta  = max(-50, min(0, int(data.get("score_delta", 0))))

        PATTERN_LABEL = {
            "EXFILTRATION":       ("📤 数据窃取外传",    "📤 Data Exfiltration"),
            "DESTRUCTIVE":        ("💣 破坏性操作",       "💣 Destructive Operation"),
            "BACKDOOR":           ("🚪 后门/C2 通信",     "🚪 Backdoor / C2"),
            "CREDENTIAL_HARVEST": ("🔑 凭证收割",         "🔑 Credential Harvesting"),
            "STEALTH":            ("👻 隐匿行为",          "👻 Stealth Operation"),
            "OBFUSCATION":        ("🎭 代码混淆",          "🎭 Code Obfuscation"),
        }

        SEV_TO_TYPE = {"CRITICAL": "HIGH", "HIGH": "HIGH", "MEDIUM": "MEDIUM"}

        findings: List[dict] = []
        critical_count = 0
        high_count     = 0
        medium_count   = 0

        for f in mal_findings:
            skill_name = f.get("skill_name", "Unknown")
            f_file     = f.get("file", "")
            f_line     = f.get("line")
            severity   = f.get("severity", "MEDIUM")
            pattern    = f.get("pattern", "")
            title      = f.get("title", "")
            intent     = f.get("intent", "")
            evidence   = f.get("evidence", "")

            if severity == "CRITICAL":
                critical_count += 1
            elif severity == "HIGH":
                high_count += 1
            else:
                medium_count += 1

            # File link
            file_link = ""
            if f_file:
                base_url  = f"https://github.com/{self.owner}/{self.repo}/blob/{branch}/{f_file}"
                anchor    = f"#L{f_line}" if f_line else ""
                file_link = f' — <a href="{base_url}{anchor}" target="_blank">{f_file}</a>'

            label_idx   = 1 if en else 0
            pat_label   = PATTERN_LABEL.get(pattern, ("⚠️ 可疑行为", "⚠️ Suspicious"))[label_idx]
            finding_type = SEV_TO_TYPE.get(severity, "MEDIUM")

            detail_html = (
                f"<b>Skill:</b> {skill_name}{file_link}<br/>"
                f"<b>Pattern:</b> {pat_label}<br/>"
                f"<b>Why intentional:</b> {intent}"
            ) if en else (
                f"<b>Skill：</b>{skill_name}{file_link}<br/>"
                f"<b>模式：</b>{pat_label}<br/>"
                f"<b>判断依据：</b>{intent}"
            )
            if evidence:
                detail_html += f"<br/><code style='font-size:11px;background:#fee2e2;padding:2px 4px;border-radius:3px'>{evidence[:250]}</code>"

            findings.append({
                "type":    finding_type,
                "title":   f"[{severity}] {pat_label} — {title}",
                "detail":  detail_html,
                "is_html": True,
            })

        # Compute final score
        final_score = max(0, min(100, 100 + score_delta))
        if   critical_count > 0:
            risk_level = "CRITICAL"
        elif high_count > 0:
            risk_level = "HIGH"
        elif medium_count > 0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        files_count = len(file_contents)
        if is_clean:
            clean_msg = (
                f"✅ No malicious behavior detected across {files_count} skill files"
            ) if en else (
                f"✅ 已扫描 {files_count} 个 Skill 文件，未发现恶意行为"
            )
            findings.insert(0, {"type": "INFO", "title": clean_msg, "detail": summary})
        else:
            warn_title = (
                f"🚨 {len(mal_findings)} malicious pattern(s) found · "
                f"{critical_count} critical · {high_count} high · {medium_count} medium"
            ) if en else (
                f"🚨 发现 {len(mal_findings)} 个恶意行为 · "
                f"{critical_count} 严重 · {high_count} 高危 · {medium_count} 中危"
            )
            findings.insert(0, {"type": "HIGH", "title": warn_title, "detail": summary})

        return {
            "score":      final_score,
            "risk_level": risk_level,
            "summary":    summary,
            "findings":   findings,
            "metrics": {
                "skill_files_scanned":   files_count,
                "malicious_findings":    len(mal_findings),
                "critical":              critical_count,
                "high":                  high_count,
                "medium":                medium_count,
                "clean":                 is_clean,
                "llm_model":             self.QWEN_MODEL,
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
