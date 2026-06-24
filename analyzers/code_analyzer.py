"""
Agent Capability Analyzer — LLM Edition
Enumerates what operations an AI agent can potentially perform:
what it can DO to your system, not traditional code vulnerabilities.
"""
import asyncio
import httpx
import base64
import json
import os
import re
from typing import List, Dict, Tuple
from analyzers.utils import smart_truncate, boost_imports, ENTRY_NAMES

def _esc(s: str) -> str:
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

# ── Risk weight per capability category ──────────────────────────────────────
CATEGORY_RISK = {
    "terminal":       {"label": "终端 / Shell 执行",          "label_en": "Terminal / Shell Execution",   "icon": "💻", "weight": 25},
    "code_execution": {"label": "代码解释器 / REPL",           "label_en": "Code Interpreter / REPL",      "icon": "⚙️",  "weight": 22},
    "computer_use":   {"label": "计算机 / 桌面控制",           "label_en": "Computer / Desktop Control",   "icon": "🖥️",  "weight": 22},
    "file_write":     {"label": "文件系统写入 / 删除",         "label_en": "File System Write / Delete",   "icon": "✏️",  "weight": 18},
    "database_write": {"label": "数据库写入",                  "label_en": "Database Write",               "icon": "🗄️",  "weight": 18},
    "email":          {"label": "邮件 / 消息发送",             "label_en": "Email / Message Sending",      "icon": "📧",  "weight": 15},
    "cloud_services": {"label": "云服务（AWS/GCP/Azure）",     "label_en": "Cloud Services (AWS/GCP/Azure)","icon": "☁️", "weight": 15},
    "external_api":   {"label": "外部 API 调用",               "label_en": "External API Calls",           "icon": "🌐",  "weight": 12},
    "browser":        {"label": "网页浏览器自动化",            "label_en": "Browser Automation",           "icon": "🌍",  "weight": 12},
    "file_read":      {"label": "文件系统读取",                "label_en": "File System Read",             "icon": "📂",  "weight": 8},
    "database_read":  {"label": "数据库读取",                  "label_en": "Database Read",                "icon": "🔍",  "weight": 8},
    "web_search":     {"label": "网络 / 互联网搜索",           "label_en": "Web / Internet Search",        "icon": "🔎",  "weight": 5},
    "memory":         {"label": "长期记忆 / 存储",             "label_en": "Long-term Memory / Storage",   "icon": "🧠",  "weight": 5},
    "auth":           {"label": "凭证 / 认证访问",             "label_en": "Credentials / Auth Access",    "icon": "🔑",  "weight": 10},
    "other":          {"label": "其他能力",                    "label_en": "Other Capabilities",           "icon": "🔧",  "weight": 5},
}

# Map LLM severity to display type
SEV_TYPE = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "INFO": "LOW"}

SYSTEM_PROMPT = """You are an AI agent security analyst. Your job is NOT to find code bugs.

THREAT MODEL — read carefully, this defines what matters:
The risk we care about comes from the NON-DETERMINISM of the LLM. An attacker who manipulates the model's output (via prompt injection, jailbreak, poisoned content) can make the agent autonomously CALL ITS TOOLS to do unexpected, harmful things. Therefore a capability is security-relevant ONLY if the LLM can actually trigger it.

You must distinguish two kinds of capabilities:
  • LLM-INVOCABLE: the capability is exposed to the model as a callable tool/function (e.g. @tool / function_tool decorator, OpenAI function-calling schema, MCP inputSchema, a tool passed in tools=[...] / functions=[...], LangChain Tool()/StructuredTool, an agent action/executor the model selects), OR it is reached from inside such a tool's implementation.
  • DETERMINISTIC: fixed-code paths the LLM cannot steer — startup/config code, deploy scripts, business logic, framework/infra plumbing, CLI utilities run by humans. List them but mark them as NOT llm-invocable; they do NOT count toward AI blast radius.

Only LLM-invocable capabilities with high/medium controllability count toward AI blast radius. If a tool is LLM-invocable but all key parameters/targets are hardcoded, validated, or constrained to a safe enum/allowlist the LLM cannot expand, set controllability="low"; it should be listed for transparency but excluded from blast-radius scoring.

IMPORTANT — STANDALONE SKILLS / TOOLS LIBRARIES:
A repo can be a *collection of skills/tools/plugins/MCP tools* with NO LLM driver of its own. This IS a tool surface: those skills are meant to be loaded into an agent and invoked by an LLM. In that case set has_tool_surface=true (even though is_ai_agent may be false), set project_type="skills_library" (or "tool"), and mark the skills as llm_invocable=true. The blast radius is exactly what an LLM could do by calling them. Do NOT declare such a repo "not applicable".

Only set has_tool_surface=false when the repo neither drives an LLM nor exposes ANY LLM-invocable tools/skills — i.e. a pure deterministic application, library, or CLI.

Enumerate EVERY operation, but tag each one honestly.

Return ONLY valid JSON — no markdown, no text outside the JSON:
{
  "agent_assessment": {
    "project_type": "agent" | "skills_library" | "tool" | "library" | "application" | "other",
    "is_ai_agent": true | false,
    "has_tool_surface": true | false,
    "reasoning": "<1 sentence: what kind of project is this, and does it expose tools/skills an LLM can invoke? cite the evidence>"
  },
  "capabilities": [
    {
      "category": "<one of the categories below>",
      "name": "<short capability name, max 60 chars, e.g. 'Execute arbitrary shell commands via bash tool'>",
      "severity": "HIGH" | "MEDIUM" | "LOW",
      "llm_invocable": true | false,
      "invocation_evidence": "<short: HOW the LLM can trigger this (e.g. 'registered via @tool', 'in tools=[] passed to the agent', 'called inside the shell tool'), OR why it is deterministic (e.g. 'only in deploy.py run by humans')>",
      "controllability": "high" | "medium" | "low",
      "description": "<1-2 sentences: what exactly can the agent do, AND the concrete blast radius if this capability is abused (what damage/scope of impact is possible)>",
      "evidence": "<exact code snippet proving this capability exists, max 180 chars>",
      "file": "<filename>",
      "line": <integer or null>
    }
  ],
  "capability_summary": "<A cohesive overall summary of what this project/agent does — its purpose, main workflow, and the general scope of what it operates on. Synthesize the whole picture, do NOT just list capabilities. Length MUST be ≤500 characters.>"
}

CONTROLLABILITY GUIDE (how much of the dangerous operation the LLM's output controls):
- "high":   the model supplies the key parameter/target — e.g. the shell command string, the file path, the SQL, the email recipient/body, the URL
- "medium": the model chooses among constrained options or supplies partial parameters
- "low":    parameters are hardcoded/validated/whitelisted; the model only triggers a fixed action. These are fixed/constrained capabilities and do NOT count toward blast-radius scoring.

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
- LOW:    Informational — the agent uses memory, search, other benign capabilities, or fixed/constrained actions whose parameters are not dynamically controlled by the LLM

RULES:
- Report each DISTINCT capability once — do not duplicate
- Only report capabilities backed by actual code evidence (tool definitions, function calls, imports, configurations)
- Be specific: "reads files from any path" is better than "reads files"
- Set llm_invocable=true ONLY when there is evidence the model can reach it (exposed tool, or code inside a tool). When unsure and it is plainly fixed infra/deploy/config code, set llm_invocable=false
- If a tool is defined but appears disabled or gated, note that in the description
- Do not inflate severity for fixed/constrained actions. If the LLM can only trigger a fixed action with no dynamic control over targets/parameters, use controllability="low" even when the deterministic action itself writes files or calls external APIs.
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
    STAGE1_MAX_CANDIDATES = 80    # candidate files sent to stage 1 ranker (single-call ceiling)
    STAGE2_PRIORITY_HINT  = 25    # how many files stage 1 is asked to rank as highest-priority
    MAX_LINES_PER_FILE    = 600   # deep scan lines in stage 2
    MAX_BATCH_CHARS       = 14000 # max context chars per stage-2 LLM call; larger sets are split into batches

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

            # ── Import tracking: 2-level deep from entry files ────────────────
            entry_contents: Dict[str, str] = {}
            for path in all_files:
                if path.split("/")[-1] in ENTRY_NAMES:
                    c = await self._fetch_file(gh, path, default_branch)
                    if c:
                        entry_contents[path] = c

            if entry_contents:
                candidates = boost_imports(entry_contents, all_files, candidates, self.STAGE1_MAX_CANDIDATES)
                # Level 2: also trace imports of the newly boosted files
                level1_paths = [p for p in candidates if p not in entry_contents][:15]
                level1_contents: Dict[str, str] = {}
                for path in level1_paths:
                    c = await self._fetch_file(gh, path, default_branch)
                    if c:
                        level1_contents[path] = c
                if level1_contents:
                    candidates = boost_imports(level1_contents, all_files, candidates, self.STAGE1_MAX_CANDIDATES)

            # ── Stage 1: fetch 50-line previews of all candidates ─────────────
            previews: Dict[str, str] = {}
            for path in candidates:
                content = await self._fetch_file(gh, path, default_branch)
                if content:
                    snippet = "\n".join(content.splitlines()[:self.STAGE1_PREVIEW_LINES])
                    previews[path] = snippet

            # ── Stage 1: cheap LLM ranks all candidates (priority-first) ─────
            if not self.qwen_key:
                return self._error_result("QWEN_API_KEY not configured")

            selected_paths = await self._stage1_rank_files(previews, readme_path)

            # ── Stage 2: fetch all ranked files (no fixed file cap) ───────────
            file_contents: Dict[str, str] = {}
            for path in selected_paths:
                content = await self._fetch_file(gh, path, default_branch)
                if content:
                    file_contents[path] = content

        # Deep LLM analysis, batched when the combined context is too large.
        raw_caps, summary, batches, agent_info = await self._call_llm_batched(file_contents)

        return self._build_result(raw_caps, summary, default_branch, len(file_contents), batches, agent_info)

    # ── Stage 1: file ranker (qwen-turbo) ────────────────────────────────────

    async def _stage1_rank_files(self, previews: Dict[str, str], readme_path: str) -> List[str]:
        """Use a cheap model to RANK candidate files by relevance.

        Returns every candidate (no hard cap) ordered priority-first, so stage 2
        deep-analyzes all of them while still processing the most relevant first.
        """
        preview_text = ""
        for path, snippet in previews.items():
            preview_text += f"\n--- {path} ---\n{snippet}\n"

        if self.lang == "en":
            prompt = f"""You are a code file relevance ranker.

Task: From the candidate file previews below, identify the most relevant files for analyzing "what operations can this AI Agent perform (blast radius)". List the top {self.STAGE2_PRIORITY_HINT} (or fewer) in descending relevance order.

Prioritize:
- Files that define tools/skills/actions/executors
- Files containing shell/bash/file/database/cloud/email/browser operations
- Agent entry files (main.py, app.py, agent.py, etc.)
- README (if it exists)

Deprioritize (but you do not need to list): test files, config-only files, documentation files, empty files.

Candidate file previews:
{preview_text}

Return in JSON format with only the file path list, most relevant first:
{{"selected_files": ["path1", "path2", ...]}}"""
            sys_content = "You are a code file relevance ranking expert. Output strict JSON."
        else:
            prompt = f"""你是一个代码文件相关性排序器。

任务：从下列候选文件的预览中，找出最适合用来分析「AI Agent 具备哪些操作能力（爆炸半径）」的文件，按相关性从高到低列出最重要的 {self.STAGE2_PRIORITY_HINT} 个（或更少）。

优先选择：
- 定义了工具/tool/skill/action/executor 的文件
- 包含 shell/bash/file/database/cloud/email/browser 等操作的文件
- Agent 的主入口文件（main.py、app.py、agent.py 等）
- README（如果存在）

可降低优先级（无需列出）：测试文件、配置文件、文档文件、空文件。

候选文件预览：
{preview_text}

以 JSON 格式返回，只包含文件路径列表，相关性高的排在前面：
{{"selected_files": ["path1", "path2", ...]}}"""
            sys_content = "你是代码文件相关性排序专家，输出严格的 JSON。"

        payload = {
            "model": self.QWEN_TURBO_MODEL,
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
                # Keep ranker order, but only paths that actually exist in previews.
                ordered = [p for p in selected if p in previews]
                # Append every remaining candidate so nothing is dropped from deep analysis.
                for p in previews:
                    if p not in ordered:
                        ordered.append(p)
                return ordered
        except Exception:
            # Fallback to original keyword-based ordering — still covers all candidates.
            return list(previews.keys())

    # ── LLM call ──────────────────────────────────────────────────────────────

    def _build_batches(self, file_contents: Dict[str, str]) -> List[str]:
        """Split files into combined-source batches under MAX_BATCH_CHARS."""
        batches: List[str] = []
        current: List[str] = []
        current_size = 0
        for path, content in file_contents.items():
            truncated = smart_truncate(content, self.MAX_LINES_PER_FILE, mode="capability")
            block = f"=== FILE: {path} ===\n{truncated}"
            # A single oversized file is truncated and placed in its own batch.
            if len(block) > self.MAX_BATCH_CHARS:
                block = block[: self.MAX_BATCH_CHARS] + "\n...(truncated)"
            if current and current_size + len(block) > self.MAX_BATCH_CHARS:
                batches.append("\n\n".join(current))
                current = []
                current_size = 0
            current.append(block)
            current_size += len(block)
        if current:
            batches.append("\n\n".join(current))
        return batches

    async def _call_llm_batched(self, file_contents: Dict[str, str]) -> Tuple[list, str, int, dict]:
        """Run the deep capability LLM over all files, splitting into batches as needed."""
        if not file_contents:
            return [], "", 0, {}

        batches = self._build_batches(file_contents)
        results = await asyncio.gather(
            *[self._call_llm(b) for b in batches],
            return_exceptions=True,
        )

        all_caps: list = []
        summaries: List[str] = []
        seen = set()
        is_ai_agent = False
        has_tool_surface = False
        reasonings: List[str] = []
        project_types: List[str] = []
        for r in results:
            if isinstance(r, Exception):
                continue
            caps, summary, assessment = r
            for cap in caps or []:
                # Dedupe identical capabilities reported across batches.
                key = (cap.get("category", "other"), (cap.get("name") or "").strip().lower())
                if key in seen:
                    continue
                seen.add(key)
                all_caps.append(cap)
            if summary:
                summaries.append(summary)
            # Project-level assessment: OR across batches (any batch seeing an
            # LLM/tool surface means the project has one).
            if isinstance(assessment, dict):
                if assessment.get("is_ai_agent"):
                    is_ai_agent = True
                if assessment.get("has_tool_surface"):
                    has_tool_surface = True
                if assessment.get("reasoning"):
                    reasonings.append(assessment["reasoning"])
                if assessment.get("project_type"):
                    project_types.append(assessment["project_type"])

        # One coherent overall summary. For multi-batch repos the partial summaries
        # are re-synthesized into a single ≤500-char overview instead of concatenated.
        if len(summaries) <= 1:
            final_summary = summaries[0] if summaries else ""
        else:
            final_summary = await self._synthesize_summary(summaries)

        # Pick the most agent-like project type seen across batches.
        TYPE_PRIORITY = ["agent", "skills_library", "tool", "application", "library", "other"]
        project_type = next((t for t in TYPE_PRIORITY if t in project_types), "")

        agent_info = {
            "is_ai_agent": is_ai_agent,
            "has_tool_surface": has_tool_surface,
            "project_type": project_type,
            "reasoning": reasonings[0] if reasonings else "",
        }
        return all_caps, final_summary, len(batches), agent_info

    async def _synthesize_summary(self, summaries: List[str]) -> str:
        """Merge partial per-batch summaries into one coherent overall summary (≤500 chars)."""
        joined = "\n".join(f"- {s}" for s in summaries)
        if self.lang == "en":
            prompt = (
                "Merge the following partial summaries of one project into a single coherent "
                "overall summary of what the project/agent does (purpose, main workflow, scope). "
                "Do NOT list capabilities. Length MUST be ≤500 characters.\n\n" + joined
            )
            sys_content = "You summarize software projects concisely. Output plain text only."
        else:
            prompt = (
                "下面是对同一个项目的多段局部总结，请合并成一段连贯的「总体功能」总结，"
                "说明该项目/Agent 的用途、主要工作流程与作用范围。不要罗列能力清单，字数必须小于等于 500 字。\n\n" + joined
            )
            sys_content = "你负责简洁地总结软件项目，只输出纯文本。"

        payload = {
            "model": self.QWEN_TURBO_MODEL,
            "temperature": 0.2,
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
                return r.json()["choices"][0]["message"]["content"].strip()
        except Exception:
            # Fallback: concatenate; the renderer caps length at 500 chars.
            return " ".join(summaries)

    async def _call_llm(self, combined_source: str):
        sys_prompt = SYSTEM_PROMPT
        if self.lang == "en":
            sys_prompt = SYSTEM_PROMPT.replace(
                "- All text fields (name, description) MUST be written in Chinese (Simplified Chinese). Evidence should keep the original code snippet.",
                "IMPORTANT: Output ALL text fields (name, description, capability_summary) in English only. Evidence should keep the original code snippet."
            )
        payload = {
            "model": self.QWEN_MODEL,
            "temperature": 0.05,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": sys_prompt},
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
                return (
                    data.get("capabilities", []),
                    data.get("capability_summary", ""),
                    data.get("agent_assessment", {}) or {},
                )
        except Exception as e:
            return [], f"LLM error: {e}", {}

    # ── Build result ──────────────────────────────────────────────────────────

    def _build_result(self, raw_caps: list, summary: str, branch: str, files_scanned: int,
                      batches: int = 1, agent_info: dict = None) -> dict:
        en = self.lang == "en"
        agent_info = agent_info or {}
        is_ai_agent      = agent_info.get("is_ai_agent", True)
        has_tool_surface = agent_info.get("has_tool_surface", True)
        project_type     = agent_info.get("project_type", "")

        # ── D: applicable whenever there is an LLM-invocable tool/skill surface.
        #        A standalone skills/tools library counts — those skills ARE the
        #        surface an LLM would invoke. Only truly tool-less projects are N/A. ──
        if not has_tool_surface:
            return self._not_applicable_result(summary, raw_caps, agent_info, branch,
                                                files_scanned, batches, en)

        # ── A: only LLM-invocable capabilities whose parameters/targets are
        #        dynamically controlled by the LLM count toward AI blast radius.
        #        Fixed/constrained tools are shown for transparency but not scored. ──
        reachable = [c for c in raw_caps if c.get("llm_invocable", True)]
        controlled = [
            c for c in reachable
            if (c.get("controllability") or "").lower() != "low"
        ]
        fixed_constrained = [
            c for c in reachable
            if (c.get("controllability") or "").lower() == "low"
        ]
        deterministic = [c for c in raw_caps if not c.get("llm_invocable", True)]

        # Group LLM-controlled capabilities by category
        grouped: Dict[str, list] = {}
        for cap in controlled:
            cat = cap.get("category", "other")
            grouped.setdefault(cat, []).append(cap)

        # Score: start at 100, deduct by capability risk weights
        score = 100
        score_steps = [("Baseline (no LLM-controlled capabilities)" if en else "基准分（无 LLM 动态管控能力）", 100, 100)]
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
            cat_label = meta["label_en"] if en else meta["label"]
            score_steps.append((f'{meta["icon"]} {cat_label}', -deduct, score))

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

                # Controllability badge — how much of the operation the LLM steers
                ctrl = (cap.get("controllability") or "").lower()
                ctrl_meta = {
                    "high":   ("#dc2626", "LLM 完全控制参数" if not en else "LLM controls params"),
                    "medium": ("#ca8a04", "LLM 部分控制" if not en else "LLM partial control"),
                    "low":    ("#6b7280", "参数固定/受限" if not en else "fixed/constrained"),
                }.get(ctrl)
                ctrl_badge = ""
                if ctrl_meta:
                    ctrl_badge = (
                        f' <span style="font-size:10px;color:white;background:{ctrl_meta[0]};'
                        f'padding:1px 6px;border-radius:8px;">🎮 {ctrl_meta[1]}</span>'
                    )
                inv_ev = cap.get("invocation_evidence", "")
                inv_html = (
                    f'<div style="color:#475569;font-size:10px;margin:2px 0;">🤖 {("LLM 可触发" if not en else "LLM-invocable")}: {_esc(inv_ev)}</div>'
                    if inv_ev else ""
                )
                detail_html = (
                    f'<div style="color:{sev_color};font-weight:500;margin-bottom:4px;">{_esc(desc)}</div>'
                    + inv_html
                    + (f'<div style="color:#6b7280;font-size:10px;margin:2px 0;">📍 Source: {file_link}</div>' if file_link else "")
                    + evidence_html
                )

                icon = {"HIGH":"⚠️","MEDIUM":"🔍","LOW":"ℹ️"}.get(sev,"🔍")
                findings.append({
                    "type":    ftype,
                    "title":   f'{icon} {meta["icon"]} {_esc(name)}{ctrl_badge}{inline_evidence}',
                    "detail":  detail_html,
                    "is_html": True,
                })

        score = max(0, min(100, score))

        # ── LLM-triggered but fixed/constrained capabilities — informational only ──
        if fixed_constrained:
            fixed_rows = []
            for cap in fixed_constrained:
                cat   = cap.get("category", "other")
                meta  = CATEGORY_RISK.get(cat, CATEGORY_RISK["other"])
                name  = cap.get("name", "Unknown capability")
                desc  = cap.get("description", "")
                why   = cap.get("invocation_evidence", "")
                evidence = cap.get("evidence", "")
                file_link = self._make_file_link(cap.get("file", ""), cap.get("line"), branch)
                evidence_html = ""
                if evidence:
                    evidence_html = (
                        f'<div style="font-family:monospace;font-size:10px;color:#64748b;'
                        f'background:#f8fafc;border:1px solid #e2e8f0;border-radius:4px;'
                        f'padding:4px 6px;margin-top:3px;white-space:pre-wrap;word-break:break-all;">'
                        f'{_esc(evidence[:180])}</div>'
                    )
                fixed_rows.append(
                    f'<div style="padding:5px 0;border-bottom:1px solid #f1f5f9;">'
                    f'<div style="font-weight:600;color:#475569;">{meta["icon"]} {_esc(name)}</div>'
                    f'<div style="color:#64748b;font-size:11px;line-height:1.5;margin-top:2px;">{_esc(desc)}</div>'
                    + (f'<div style="color:#94a3b8;font-size:10px;margin-top:1px;">🎮 {("参数固定/受限，LLM 只能触发固定动作" if not en else "fixed/constrained; LLM only triggers a fixed action")}: {_esc(why)}</div>' if why else "")
                    + (f'<div style="color:#94a3b8;font-size:10px;">📍 {file_link}</div>' if file_link else "")
                    + evidence_html
                    + '</div>'
                )
            fixed_title = (
                f'🎮 {len(fixed_constrained)} Fixed/constrained LLM-triggered capabilities — excluded from blast radius (click to expand)'
                if en else
                f'🎮 {len(fixed_constrained)} 项参数固定/受限的 LLM 可触发能力 — 不计入爆炸半径（点击展开）'
            )
            findings.append({
                "type":    "POSITIVE",
                "title":   fixed_title,
                "detail":  f'<div style="line-height:1.5;">{"".join(fixed_rows)}</div>',
                "is_html": True,
                "control_relevant": False,
            })

        # ── Deterministic capabilities (not LLM-invocable) — informational only ──
        if deterministic:
            det_rows = []
            for cap in deterministic:
                cat   = cap.get("category", "other")
                meta  = CATEGORY_RISK.get(cat, CATEGORY_RISK["other"])
                name  = cap.get("name", "Unknown capability")
                desc  = cap.get("description", "")
                why   = cap.get("invocation_evidence", "")
                file_link = self._make_file_link(cap.get("file", ""), cap.get("line"), branch)
                det_rows.append(
                    f'<div style="padding:5px 0;border-bottom:1px solid #f1f5f9;">'
                    f'<div style="font-weight:600;color:#475569;">{meta["icon"]} {_esc(name)}</div>'
                    f'<div style="color:#64748b;font-size:11px;line-height:1.5;margin-top:2px;">{_esc(desc)}</div>'
                    + (f'<div style="color:#94a3b8;font-size:10px;margin-top:1px;">🔒 {("固定代码，LLM 无法触发" if not en else "deterministic, not LLM-triggered")}: {_esc(why)}</div>' if why else "")
                    + (f'<div style="color:#94a3b8;font-size:10px;">📍 {file_link}</div>' if file_link else "")
                    + '</div>'
                )
            det_title = (
                f'🔒 {len(deterministic)} Deterministic capabilities — NOT LLM-invocable, excluded from blast radius (click to expand)'
                if en else
                f'🔒 {len(deterministic)} 项确定性能力 — 非 LLM 可触发，不计入爆炸半径（点击展开）'
            )
            findings.append({
                "type":    "POSITIVE",
                "title":   det_title,
                "detail":  f'<div style="line-height:1.5;">{"".join(det_rows)}</div>',
                "is_html": True,
                "control_relevant": False,
            })

        # NOTE: the capability summary card is inserted LAST (below) so it renders
        # first; the fixed/deterministic sections above are collapsible and sort
        # before the dynamically LLM-controlled capabilities.

        # Score breakdown
        criteria_rows = "".join([
            f'<tr style="border-bottom:1px solid #f1f5f9;">'
            f'<td style="padding:3px 8px;color:#374151;">{_esc(str(label))}</td>'
            f'<td style="padding:3px 8px;text-align:right;font-weight:bold;color:{"#16a34a" if d>=0 else "#dc2626"};">{"+" if d>=0 else ""}{d}</td>'
            f'<td style="padding:3px 8px;text-align:right;color:#6b7280;">{total}</td>'
            f'</tr>'
            for label, d, total in score_steps
        ])
        if en:
            score_html = f"""<div style="font-size:11px;">
  <div style="margin-bottom:6px;color:#6b7280;">
    Score reflects <b>LLM-controlled blast radius</b>: only capabilities whose parameters/targets are dynamically controlled by the LLM are counted. Fixed/constrained and deterministic capabilities are excluded.<br/>
    Terminal/Shell <b>−25</b> · Code Exec/Computer Control <b>−22</b> · File Write/DB Write <b>−18</b> ·
    Email/Cloud <b>−15</b> · Credentials <b>−10</b> · External API/Browser <b>−12</b> · File Read <b>−8</b> · Search <b>−5</b>
  </div>
  <table style="width:100%;border-collapse:collapse;background:#f8fafc;border-radius:6px;overflow:hidden;border:1px solid #e2e8f0;">
    <thead><tr style="background:#e2e8f0;font-weight:600;color:#475569;">
      <th style="padding:4px 8px;text-align:left;">Detected Capability</th>
      <th style="padding:4px 8px;text-align:right;">Score Change</th>
      <th style="padding:4px 8px;text-align:right;">Running Total</th>
    </tr></thead>
    <tbody>{criteria_rows}</tbody>
    <tfoot><tr style="background:#1e1b4b;color:white;font-weight:bold;">
      <td style="padding:4px 8px;">Final Score (capped 0–100)</td>
      <td></td>
      <td style="padding:4px 8px;text-align:right;font-size:13px;">{score}</td>
    </tr></tfoot>
  </table>
</div>"""
        else:
            score_html = f"""<div style="font-size:11px;">
  <div style="margin-bottom:6px;color:#6b7280;">
    分数反映<b>LLM 动态管控的爆炸半径</b>：只有参数/目标由 LLM 输出动态控制的能力才计分。参数固定/受限能力和确定性能力均排除。<br/>
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

        # Clarify when the repo is a skills/tools library rather than a full agent.
        if not is_ai_agent or project_type in ("skills_library", "tool"):
            banner_title = (
                "🧩 Skills/Tools library — evaluated as the tool surface an LLM would invoke"
                if en else
                "🧩 Skill/工具库 — 按「被 LLM 调用的工具面」评估"
            )
            banner_body = (
                "This repo is a collection of skills/tools with no LLM driver of its own. The blast radius below "
                "reflects what an LLM could do once these skills are loaded into an agent and invoked."
                if en else
                "该仓库是一组 Skill/工具，本身不含 LLM 驱动。下面的爆炸半径反映的是：当这些 Skill 被装载进 Agent 并由 LLM 调用后，可能造成的影响。"
            )
            findings.insert(0, {
                "type":    "INFO",
                "title":   banner_title,
                "detail":  f'<div style="line-height:1.6;color:#374151;">{_esc(banner_body)}</div>',
                "is_html": True,
            })

        # ── Capability summary card — inserted LAST so it renders at the very top ──
        summary_html = self._render_summary_card(summary, raw_caps, branch, en)
        if summary_html:
            findings.insert(0, {
                "type":    "INFO",
                "title":   "📋 Capability Summary" if en else "📋 能力摘要",
                "detail":  summary_html,
                "is_html": True,
            })

        det_count = len(deterministic)
        fixed_count = len(fixed_constrained)
        controlled_count = high_count + med_count + low_count
        summary_str = (
            f"{controlled_count} LLM-controlled capabilities · {high_count} high-impact · {fixed_count} fixed/constrained (excluded) · {det_count} deterministic (excluded) · {files_scanned} files scanned"
            if en else
            f"{controlled_count} 项 LLM 动态管控能力 · {high_count} 高影响 · {fixed_count} 项参数固定/受限（已排除）· {det_count} 项确定性能力（已排除）· {files_scanned} 个文件已扫描"
        )
        return {
            "score":      score,
            "risk_level": self._score_to_risk(score),
            "summary":    summary_str,
            "findings":   findings,
            "metrics": {
                "files_scanned":   files_scanned,
                "total_capabilities": len(raw_caps),
                "llm_invocable_capabilities": len(reachable),
                "llm_controlled_capabilities": controlled_count,
                "fixed_constrained_capabilities": fixed_count,
                "deterministic_capabilities": det_count,
                "high_impact":     high_count,
                "medium_impact":   med_count,
                "low_impact":      low_count,
                "is_ai_agent":     is_ai_agent,
                "has_tool_surface": has_tool_surface,
                "project_type":    project_type,
                "llm_model":       self.QWEN_MODEL,
                "llm_batches":     batches,
            },
        }

    def _not_applicable_result(self, summary: str, raw_caps: list, agent_info: dict,
                               branch: str, files_scanned: int, batches: int, en: bool) -> dict:
        """No LLM/tool surface detected → AI blast-radius dimension does not apply.

        Returned with risk_level UNKNOWN so it is excluded from the overall weighted score.
        """
        reasoning = agent_info.get("reasoning", "")
        title = (
            "🚫 No LLM-invocable tool/skill surface — capability blast radius N/A"
            if en else
            "🚫 未发现面向 LLM 的工具/Skill 接口 — 能力爆炸半径不适用"
        )
        body = (
            "This repo neither drives an LLM nor exposes any tools/skills an LLM could invoke "
            "(no function-calling tools, @tool/MCP definitions, agent tool registry, or skills library). "
            "Any capabilities here are plain deterministic code, so this AI-specific dimension is not scored "
            "and is excluded from the overall risk."
            if en else
            "该仓库既不驱动 LLM，也未暴露任何可被 LLM 调用的工具/Skill（无 function-calling 工具、@tool/MCP 定义、Agent 工具注册或 Skill 库）。"
            "此处的能力均为普通确定性代码，因此该 AI 专属维度不计分，并已从总体风险中排除。"
        )
        findings = [{
            "type":   "INFO",
            "title":  title,
            "detail": f'<div style="line-height:1.6;color:#374151;">{_esc(body)}'
                      + (f'<div style="color:#64748b;font-size:11px;margin-top:6px;">🔎 {_esc(reasoning)}</div>' if reasoning else "")
                      + '</div>',
            "is_html": True,
        }]
        summary_html = self._render_summary_card(summary, raw_caps, branch, en)
        if summary_html:
            findings.append({
                "type":    "POSITIVE",
                "title":   "📋 Capability Summary" if en else "📋 能力摘要",
                "detail":  summary_html,
                "is_html": True,
            })
        return {
            "score":      100,
            "risk_level": "UNKNOWN",
            "summary":    ("AI capability dimension not applicable (no LLM tool surface)"
                           if en else "AI 能力维度不适用（无 LLM 工具面）"),
            "findings":   findings,
            "metrics": {
                "files_scanned":   files_scanned,
                "is_ai_agent":     agent_info.get("is_ai_agent", False),
                "has_tool_surface": agent_info.get("has_tool_surface", False),
                "project_type":    agent_info.get("project_type", ""),
                "applicable":      False,
                "llm_model":       self.QWEN_MODEL,
                "llm_batches":     batches,
            },
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _select_files(self, files: List[str]) -> List[str]:
        skip = {"node_modules", ".git", "dist", "build", "__pycache__", "venv", ".venv",
                "site-packages", "test", "tests", "spec", "specs", "fixtures", "mocks",
                "migrations", "assets", "static", "public", "i18n", "locale", "docs"}
        src_ext = {".py", ".ts", ".js", ".go", ".rs", ".java", ".kt", ".rb", ".php"}

        # Directories that almost certainly contain agent capabilities — include ALL files inside
        priority_dirs = {"tool", "tools", "action", "actions", "skill", "skills",
                         "agent", "agents", "plugin", "plugins", "capability", "capabilities",
                         "executor", "executors", "handler", "handlers", "command", "commands",
                         "workflow", "workflows", "task", "tasks", "function", "functions",
                         "service", "services", "api", "integration", "integrations"}

        # Keywords scored against filename (higher signal than directory match)
        filename_kw = {"tool", "agent", "skill", "action", "executor", "capability", "plugin",
                       "command", "handler", "workflow", "bash", "shell", "email", "browser",
                       "search", "memory", "database", "file", "cloud", "aws", "gcp",
                       "azure", "api", "runner", "step", "hook", "trigger"}
        # Keywords scored against directory path
        dir_kw = {"tool", "agent", "skill", "action", "executor", "plugin", "command",
                  "handler", "workflow", "service", "integration", "function"}
        # High-value entry file names
        entry_kw = {"main", "app", "index", "run", "start", "entry", "server", "cli",
                    "agent", "pipeline", "orchestrat", "graph", "chain"}

        scored: list[tuple[int, str]] = []

        for f in files:
            parts = f.split("/")
            if any(p in skip for p in parts):
                continue
            name = parts[-1].lower()
            ext = ("." + name.split(".")[-1]) if "." in name else ""
            if ext not in src_ext:
                continue
            stem = name.rsplit(".", 1)[0] if "." in name else name
            dir_path = "/".join(parts[:-1]).lower()

            score = 0

            # +40 if file is directly inside a priority directory
            if parts[:-1] and parts[-2].lower() in priority_dirs:
                score += 40

            # +20 if any ancestor directory matches priority dirs
            elif any(p.lower() in priority_dirs for p in parts[:-1]):
                score += 20

            # +30 if filename matches capability keywords
            fname_hits = sum(1 for k in filename_kw if k in stem)
            score += fname_hits * 30

            # +15 if directory path matches capability keywords
            dir_hits = sum(1 for k in dir_kw if k in dir_path)
            score += dir_hits * 15

            # +20 for entry-point files near root
            if any(k in stem for k in entry_kw):
                score += 20

            # Prefer shallow files (root / 1 dir deep) for secondary coverage
            depth_bonus = max(0, 10 - len(parts) * 2)
            score += depth_bonus

            # Must have at least minimal signal (skip pure config/boilerplate)
            if score > 0:
                scored.append((score, f))

        # Sort by score descending, take top N
        scored.sort(key=lambda x: -x[0])
        return [f for _, f in scored[:self.STAGE1_MAX_CANDIDATES]]

    def _render_summary_card(self, summary: str, raw_caps: list, branch: str, en: bool) -> str:
        """Build the capability-summary card: a concise overall function summary (≤500 chars)."""
        if not summary:
            return ""

        summary = summary.strip()
        if len(summary) > 500:
            summary = summary[:500].rstrip() + "…"

        sec_title = "🧭 Overall Function" if en else "🧭 总体功能"
        return (
            f'<div style="line-height:1.6;">'
            f'<div style="font-size:11px;font-weight:700;color:#1e293b;margin-bottom:3px;">{sec_title}</div>'
            f'<div style="color:#374151;line-height:1.6;">{_esc(summary)}</div>'
            f'</div>'
        )

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
