"""
AI Agent Risk Evaluator - Main FastAPI Application
Streams analysis results via Server-Sent Events (SSE)
"""
import asyncio
import json
import os
import re
from typing import AsyncGenerator, Optional

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Query
from pydantic import BaseModel

load_dotenv()
DEFAULT_TOKEN = os.getenv("GITHUB_DEFAULT_TOKEN", "")
QWEN_API_KEY  = os.getenv("QWEN_API_KEY", "")

from openai import AsyncOpenAI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from analyzers.github_analyzer import GitHubAnalyzer
from analyzers.scorecard_analyzer import ScorecardAnalyzer
from analyzers.code_analyzer import CodeAnalyzer
from analyzers.license_analyzer import LicenseAnalyzer
from analyzers.deps_analyzer import DepsAnalyzer
from analyzers.depsdev_analyzer import DepsDotDevAnalyzer
from analyzers.ai_safety_analyzer import AISafetyAnalyzer
from analyzers.privacy_analyzer import PrivacyAnalyzer
from analyzers.supply_chain_analyzer import SupplyChainAnalyzer
from analyzers.runtime_analyzer import RuntimeAnalyzer
from analyzers.skill_analyzer import SkillAnalyzer
from translations import translate_result

app = FastAPI(title="AI Agent Risk Evaluator", version="1.0.0")

ANALYZER_ORDER = [
    "github",
    "depsdev",
    "code",
    "deps",
    "ai_safety",
    "skill",
    "privacy",
    "supply_chain",
    "runtime",
]

SCORING_WEIGHTS = {
    "github":       0.12,
    "depsdev":      0.05,
    "code":         0.23,
    "deps":         0.13,
    "ai_safety":    0.18,
    "skill":        0.12,
    "privacy":      0.08,
    "supply_chain": 0.05,
    "runtime":      0.04,
}

INTERNAL_PROJECT_SCORE_EXCLUDED_MODULES = {
    "github",
    "depsdev",
    "deps",
    "supply_chain",
    "runtime",
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")


def parse_github_url(url: str) -> tuple[str, str]:
    url = url.strip().rstrip("/")
    # Remove .git suffix
    if url.endswith(".git"):
        url = url[:-4]
    patterns = [
        r"github\.com/([^/\s]+)/([^/\s]+)",
        r"^([^/\s]+)/([^/\s]+)$",
    ]
    for pattern in patterns:
        m = re.search(pattern, url)
        if m:
            return m.group(1), m.group(2)
    raise ValueError(f"无法解析 GitHub 链接: {url}")


async def check_public_repo_access(owner: str, repo: str) -> dict:
    """Check whether the repository is publicly reachable without credentials."""
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "AI-Risk-Evaluator/1.0",
    }
    api_check = "github_api:not_checked"

    async with httpx.AsyncClient(headers=headers, timeout=10, follow_redirects=True) as client:
        try:
            response = await client.get(f"https://api.github.com/repos/{owner}/{repo}")
            api_check = f"github_api:{response.status_code}"
            if response.status_code == 200 and response.json().get("private") is False:
                return {
                    "public_accessible": True,
                    "project_type": "public_github_repository",
                    "access_check": api_check,
                }
        except httpx.HTTPError as e:
            api_check = f"github_api_failed:{type(e).__name__}"

        try:
            web_response = await client.get(f"https://github.com/{owner}/{repo}")
            web_check = f"github_web:{web_response.status_code}"
        except httpx.HTTPError as e:
            web_check = f"github_web_failed:{type(e).__name__}"
        else:
            if web_response.status_code == 200:
                return {
                    "public_accessible": True,
                    "project_type": "public_github_repository",
                    "access_check": f"{api_check};{web_check}",
                }

    return {
        "public_accessible": False,
        "project_type": "company_employee_developed",
        "access_check": f"{api_check};{web_check}",
    }


def calculate_overall(results: dict, excluded_modules: Optional[set[str]] = None) -> dict:
    excluded_modules = excluded_modules or set()
    total_w, weighted = 0.0, 0.0
    scored_modules = []
    score_excluded_modules = sorted(key for key in excluded_modules if key in results)

    for key, w in SCORING_WEIGHTS.items():
        if key in excluded_modules:
            continue
        if key in results and isinstance(results[key].get("score"), (int, float)):
            score = results[key]["score"]
            if results[key].get("risk_level") != "UNKNOWN":
                weighted += score * w
                total_w += w
                scored_modules.append(key)

    if total_w == 0:
        return {
            "score": 50.0,
            "risk_level": "UNKNOWN",
            "emoji": "⚪",
            "label": "Not Scored",
            "scored_modules": scored_modules,
            "excluded_modules": score_excluded_modules,
        }

    final = round(weighted / total_w, 1)

    if final >= 75:
        risk = "LOW"
        emoji = "🟢"
        label = "Low Risk"
    elif final >= 55:
        risk = "MEDIUM"
        emoji = "🟡"
        label = "Medium Risk"
    elif final >= 35:
        risk = "HIGH"
        emoji = "🔴"
        label = "High Risk"
    else:
        risk = "CRITICAL"
        emoji = "⚫"
        label = "Critical Risk"

    return {
        "score": final,
        "risk_level": risk,
        "emoji": emoji,
        "label": label,
        "scored_modules": scored_modules,
        "excluded_modules": score_excluded_modules,
    }


def normalize_selected_modules(modules: Optional[str]) -> list[str]:
    if not modules:
        return ANALYZER_ORDER[:]

    requested = [m.strip() for m in modules.split(",") if m.strip()]
    selected = [key for key in ANALYZER_ORDER if key in requested]
    return selected


async def stream_analysis(url: str, token: Optional[str], lang: str = "zh",
                          selected_modules: Optional[list[str]] = None) -> AsyncGenerator[str, None]:
    def sse(data: dict) -> str:
        return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"

    try:
        owner, repo = parse_github_url(url)
    except ValueError as e:
        yield sse({"type": "error", "message": str(e)})
        return

    repo_access = await check_public_repo_access(owner, repo)
    score_excluded_modules = (
        INTERNAL_PROJECT_SCORE_EXCLUDED_MODULES
        if not repo_access["public_accessible"]
        else set()
    )

    yield sse({"type": "start", "owner": owner, "repo": repo, "repo_access": repo_access})

    analyzers = [
        ("github",        "⭐ Open-source Reputation & Activity", GitHubAnalyzer(owner, repo, token)),
        ("depsdev",       "🌐 deps.dev Package Health",          DepsDotDevAnalyzer(owner, repo, token)),
        ("code",          "🤖 Agent Capability / Blast Radius",      CodeAnalyzer(owner, repo, token, lang=lang)),
        ("deps",          "📦 Dependency Vulnerability Scan",    DepsAnalyzer(owner, repo, token)),
        ("ai_safety",     "🛡️ Agent Guardrails",                 AISafetyAnalyzer(owner, repo, token, lang=lang)),
        ("skill",         "🔧 Skill Security Quality",           SkillAnalyzer(owner, repo, token, lang=lang)),
        ("privacy",       "🔒 Data Privacy",                     PrivacyAnalyzer(owner, repo, token)),
        ("supply_chain",  "⛓️ Supply Chain Integrity",           SupplyChainAnalyzer(owner, repo, token)),
        ("runtime",       "🐳 Runtime Isolation",                RuntimeAnalyzer(owner, repo, token)),
    ]
    if selected_modules is not None:
        analyzers = [item for item in analyzers if item[0] in set(selected_modules)]

    # Non-LLM analyzers that need translation
    NON_LLM = {"github", "depsdev", "deps", "privacy", "supply_chain", "runtime"}

    results = {}

    for key, name, analyzer in analyzers:
        yield sse({"type": "progress", "phase": key, "name": name, "status": "running"})
        try:
            result = await analyzer.analyze()
        except asyncio.CancelledError:
            # CancelledError is BaseException in Python 3.8+ — must catch explicitly
            cancelled_msg = "Analysis cancelled (asyncio timeout/cancel)" if lang == "en" else "分析被取消 (asyncio timeout/cancel)"
            timeout_title = "Analysis timed out" if lang == "en" else "分析超时"
            result = {
                "score": 50,
                "risk_level": "UNKNOWN",
                "summary": cancelled_msg,
                "findings": [{"type": "INFO", "title": timeout_title, "detail": f"{key} analyzer was cancelled"}],
                "metrics": {},
            }
        except Exception as e:
            failed_msg = f"Analysis failed: {str(e)[:120]}" if lang == "en" else f"分析失败: {str(e)[:120]}"
            error_title = "Analysis error" if lang == "en" else "分析出错"
            result = {
                "score": 50,
                "risk_level": "UNKNOWN",
                "summary": failed_msg,
                "findings": [{"type": "INFO", "title": error_title, "detail": str(e)[:200]}],
                "metrics": {},
            }
        if key in NON_LLM:
            result = translate_result(result, lang)
        results[key] = result
        yield sse({"type": "result", "phase": key, "name": name, "data": result})
        await asyncio.sleep(0.05)

    overall = calculate_overall(results, excluded_modules=score_excluded_modules)
    overall.update(repo_access)
    yield sse({"type": "complete", "overall": overall})


@app.get("/")
async def root():
    with open("static/index.html", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/api/config")
async def config():
    """Tell the frontend whether a default token is configured."""
    return {"has_default_token": bool(DEFAULT_TOKEN)}


@app.get("/api/analyze")
async def analyze(
    url: str = Query(..., description="GitHub repository URL"),
    token: Optional[str] = Query(None, description="GitHub PAT (optional, increases rate limit)"),
    lang: str = Query("zh", description="Output language: 'zh' (default) or 'en'"),
    modules: Optional[str] = Query(None, description="Comma-separated analyzer keys to run"),
):
    effective_token = token or DEFAULT_TOKEN or None
    selected_modules = normalize_selected_modules(modules)
    if not selected_modules:
        return StreamingResponse(
            iter([
                f"data: {json.dumps({'type': 'error', 'message': 'No valid analysis modules selected'}, ensure_ascii=False)}\n\n"
            ]),
            media_type="text/event-stream",
        )
    return StreamingResponse(
        stream_analysis(url, effective_token, lang=lang, selected_modules=selected_modules),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}


# ── Security Controls Recommendation ──────────────────────────────────────────

class ControlsRequest(BaseModel):
    repo: str
    overall: dict
    code_result: dict = {}
    ai_safety_result: dict = {}
    runtime_result: dict = {}
    lang: str = "zh"


def _build_controls_prompt(req: ControlsRequest) -> str:
    def fmt_findings(result: dict, max_items: int = 15) -> str:
        findings = result.get("findings", [])
        lines = []
        for f in findings[:max_items]:
            if f.get("type") == "INFO" or f.get("control_relevant") is False:
                continue
            lines.append(f"  [{f.get('type','?')}] {f.get('title','')}：{f.get('detail','')[:150]}")
        return "\n".join(lines) if lines else ("  No findings" if req.lang == "en" else "  无特殊发现")

    cap_summary    = req.code_result.get("summary", "N/A")
    safety_summary = req.ai_safety_result.get("summary", "N/A")
    cap_findings    = fmt_findings(req.code_result)
    safety_findings = fmt_findings(req.ai_safety_result)
    runtime_findings = fmt_findings(req.runtime_result)

    if req.lang == "en":
        return f"""You are a senior AI security advisor at the adidas AppSec team.

Below are the security assessment results for the open-source AI Agent: "{req.repo}"

== Overall Risk ==
Risk Level: {req.overall.get('risk_level')} | Score: {req.overall.get('score')} / 100

== Agent Capabilities (Blast Radius) ==
{cap_summary}
Detected capabilities:
{cap_findings}

== Agent Guardrails (what exists / what's missing) ==
{safety_summary}
Findings:
{safety_findings}

== Runtime Isolation ==
{runtime_findings}

---

Based on the above, generate actionable security control recommendations for teams deploying this Agent internally.

【Threat Model】
- Users are normal employees — not attackers. Risk comes from the Agent hallucinating, misjudging scope, or exceeding expected boundaries.
- Goal: constrain each detected capability to its intended scope; ensure no single action is irreversible without human awareness.

【Output Requirements】
Generate recommendations across up to these 4 categories:

1. **Capability Boundary Controls** — Only for LLM-controllable capabilities: the LLM can trigger the capability AND the LLM output dynamically controls execution parameters or targets such as commands, file paths, URLs, SQL, request bodies, recipients, cloud resources, or API arguments. For each HIGH/MEDIUM LLM-controllable capability, provide a specific control that restricts it to expected scope. Example: "Agent has shell execution where the LLM controls command text → restrict to a whitelist of allowed commands, block destructive flags". Exclude deterministic capabilities and capabilities whose parameters are fixed, hard-coded, or constrained to a safe enum/allowlist that the LLM cannot expand; their blast radius is already clear and they do not need Capability Boundary Controls.

2. **Guardrail Configuration** — For each POSITIVE guardrail already present, explain how to properly configure it for production. For example: if human approval exists, specify which capability categories must trigger it.

3. **Missing Guardrails** — For each dangerous capability that lacks a corresponding guardrail (no step limit, no approval, no allowlist), specify exactly what to add and how to implement it.

4. **Ops & Deployment** — Infrastructure-level controls: container hardening, IAM least-privilege, network egress restrictions, resource quotas tied to detected capabilities.

Rules:
- Every recommendation must reference a specific detected capability or guardrail finding ("Because this agent has X / lacks Y...")
- Do not generate Capability Boundary Controls for findings marked deterministic, not LLM-invocable, fixed/constrained, or where no evidence shows LLM-controlled parameters. If there are no LLM-controllable capabilities, omit this category rather than filling it with generic controls.
- Each item must include: title (≤8 words), precondition, reason (why, what could go wrong), implementation, example, priority (MUST/RECOMMEND/OPTIONAL), category
- `precondition` must state the concrete condition under which this control is necessary, so teams whose environment doesn't meet it can safely skip the control. Example: "Restrict file operation permissions" → precondition: "If the environment where the agent runs contains other sensitive files". If a control always applies regardless of environment, set precondition to "Applies unconditionally".
- `implementation` must be a concrete, deploy-time runbook the team can follow as-is — NOT generic advice. It must:
  · Say exactly WHERE to make the change (e.g. the agent's tool-registration code / the container Dockerfile / K8s SecurityContext / NetworkPolicy / an environment variable)
  · Give the actual values or list (e.g. exactly which commands belong on the allowlist, which destructive flags to block)
  · State how to VERIFY the control works (e.g. how to test that a command outside the allowlist is rejected)
- `example` field: provide a ready-to-copy config or code snippet (e.g. an allowlist array, a wrapper function, a Dockerfile fragment, a K8s/seccomp config, iptables egress rules). Preserve newlines and indentation. If no code example genuinely applies, use an empty string.
- Worked example (format reference only): Shell execution detected with LLM-controlled command text → implementation explains "add an allowlist check in the function that runs shell commands; permit only git/ls/cat, reject rm/curl/chmod and shell metacharacters", and `example` contains the corresponding allowlist-check code snippet.
- Prefer 8-12 high-signal items total. Do not pad categories with generic recommendations; include fewer items when the scan evidence does not support more.
- Output in English
- Return valid JSON: {{"controls": [{{"category": "Capability Boundary Controls", "title": "...", "precondition": "...", "reason": "...", "implementation": "...", "example": "...", "priority": "MUST"}}]}}"""

    return f"""你是 adidas AppSec 团队的高级 AI 安全顾问。

以下是开源 AI Agent「{req.repo}」的安全评估结果：

== 总体风险 ==
风险等级：{req.overall.get('risk_level')} | 综合评分：{req.overall.get('score')} / 100

== Agent能力/爆炸半径分析 ==
{cap_summary}
检测到的能力：
{cap_findings}

== Agent安全护栏（已有 / 缺失）==
{safety_summary}
发现项：
{safety_findings}

== 运行时隔离 ==
{runtime_findings}

---

请基于以上结果，为内部部署此 Agent 的团队生成安全管控建议。

【威胁模型】
- 使用者是正常员工，不是攻击者。风险来自 Agent 幻觉、误判、超出预期的能力边界。
- 目标：将每类检测到的能力限制在预期范围内；确保没有单次操作在用户不知情的情况下造成不可逆影响。

【输出要求】
按以下最多 4 个维度生成建议：

1. **能力边界管控** — 只针对「LLM 可管控能力」：LLM 可以触发该能力，并且 LLM 输出会动态影响执行参数或目标，例如命令、文件路径、URL、SQL、请求体、收件人、云资源或 API 参数。针对每一条 HIGH/MEDIUM 的 LLM 可管控能力，给出具体限制措施，将其约束在预期范围内。例如："Agent 具备 Shell 执行能力，且命令文本由 LLM 输出控制 → 限制为允许命令白名单，屏蔽破坏性参数"。排除确定性能力，以及参数固定、硬编码、或被安全枚举/白名单约束且 LLM 无法扩展的能力；这类能力爆炸半径清晰，不需要生成能力边界管控。

2. **护栏配置建议** — 针对已检测到存在的安全护栏（POSITIVE），说明在生产环境中应如何正确配置。例如：已有人工审批 → 明确哪些能力类别必须触发审批。

3. **缺失护栏补齐** — 针对有高危能力但缺乏对应护栏的情况（无步骤限制、无审批、无白名单），明确需要新增什么，并给出具体实施方式。

4. **运维部署管控** — 基础设施层面：容器加固、IAM 最小权限、网络出口限制、资源配额，结合检测到的能力定制。

规则：
- 每条建议必须引用具体的能力或护栏发现项（"因为该 Agent 具备 X / 缺少 Y..."）
- 不要为标记为确定性、非 LLM 可触发、参数固定/受限，或没有证据表明参数由 LLM 输出控制的发现项生成「能力边界管控」。如果没有 LLM 可管控能力，应省略该维度，而不是用泛泛建议凑数。
- 每条包含：title（8字以内）、precondition（前提条件）、reason、implementation、example、priority（MUST/RECOMMEND/OPTIONAL）、category
- precondition 必须写明「在什么前提条件下，这条管控才是必要的」，以便不满足该前提的团队可以安全地跳过此条。例如："限制文件操作权限" → precondition："如果 Agent 运行的环境中存在其他敏感文件"。若该条管控在任何环境下都必须执行，则 precondition 填"无条件适用"。
- implementation 必须是「部署该 Agent 时可直接照做的落地步骤」，而不是泛泛而谈。要求：
  · 指明在哪里改（如：Agent 的工具注册/调用代码、容器 Dockerfile、K8s SecurityContext、网络策略 NetworkPolicy、环境变量）
  · 给出具体取值或清单（如：命令白名单到底包含哪些命令、需要屏蔽哪些破坏性参数/元字符）
  · 说明如何验证该管控已生效（如：如何测试一条不在白名单内的命令会被拒绝）
- example 字段：给出一段可直接复制使用的配置或代码片段（如白名单数组、命令校验封装函数、Dockerfile 片段、K8s/seccomp 配置、iptables 出口规则等），保留换行与缩进；若该条确实无法给出代码示例，则用空字符串。
- 范例（仅作格式参考）：检测到 Shell 执行能力且命令文本由 LLM 控制 → implementation 说明"在 Agent 执行 shell 命令的封装函数处加入命令白名单校验，仅放行 git/ls/cat，拒绝 rm/curl/chmod 及 shell 元字符"，example 给出对应的白名单校验代码片段。
- 优先输出 8-12 条高信号建议。不要用泛泛建议凑满类别；扫描证据不足时可以少于 8 条。
- 全部中文输出
- 返回合法 JSON：{{"controls": [{{"category": "能力边界管控", "title": "...", "precondition": "...", "reason": "...", "implementation": "...", "example": "...", "priority": "MUST"}}]}}"""


def _extract_controls(data: dict) -> list:
    """Tolerate LLM key variations; return a list of control items or []."""
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        return []
    for key in ("controls", "recommendations", "items", "results", "data"):
        val = data.get(key)
        if isinstance(val, list):
            return val
    # Fallback: first list value in the dict
    for val in data.values():
        if isinstance(val, list) and val and isinstance(val[0], dict):
            return val
    return []


def _normalize_controls(controls: list, lang: str = "zh") -> list:
    """Normalize LLM control items so the frontend never renders undefined."""
    if lang == "en":
        defaults = {
            "category": "Other",
            "title": "Untitled control",
            "precondition": "Applies unconditionally",
            "reason": "No reason provided.",
            "implementation": "Implement this control based on the referenced finding and verify it after deployment.",
            "example": "",
        }
    else:
        defaults = {
            "category": "其他",
            "title": "未命名管控",
            "precondition": "无条件适用",
            "reason": "未提供原因。",
            "implementation": "请结合对应发现项实施该管控，并在部署后验证控制有效。",
            "example": "",
        }

    priority_map = {
        "MUST": "MUST",
        "REQUIRED": "MUST",
        "必须": "MUST",
        "强制": "MUST",
        "RECOMMEND": "RECOMMEND",
        "RECOMMENDED": "RECOMMEND",
        "建议": "RECOMMEND",
        "推荐": "RECOMMEND",
        "OPTIONAL": "OPTIONAL",
        "可选": "OPTIONAL",
    }

    normalized = []
    for item in controls:
        if not isinstance(item, dict):
            continue
        required_values = [
            str(item.get(field, "")).strip()
            for field in ("title", "reason", "implementation")
        ]
        if not all(required_values):
            continue
        control = {}
        for field in ("category", "title", "precondition", "reason", "implementation", "example"):
            value = item.get(field)
            control[field] = str(value).strip() if value not in (None, "") else defaults[field]
        raw_priority = str(item.get("priority", "RECOMMEND")).strip().upper()
        control["priority"] = priority_map.get(raw_priority, "RECOMMEND")
        normalized.append(control)
    return normalized


@app.post("/api/security-controls")
async def security_controls(req: ControlsRequest):
    client = AsyncOpenAI(
        api_key=QWEN_API_KEY,
        base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
    )
    prompt = _build_controls_prompt(req)
    sys_prompt = "You are an enterprise AI security advisor. Output strict JSON." if req.lang == "en" else "你是企业 AI 安全顾问，输出严格的 JSON。"

    async def _call_llm():
        resp = await asyncio.wait_for(
            client.chat.completions.create(
                model="qwen-max",
                temperature=0.3,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": sys_prompt},
                    {"role": "user",   "content": prompt},
                ],
            ),
            timeout=150.0,
        )
        return resp.choices[0].message.content

    last_err: Optional[Exception] = None
    for attempt in range(2):
        try:
            raw = await _call_llm()
            data = json.loads(raw)
            controls = _extract_controls(data)
            if not controls:
                last_err = ValueError("empty")
                continue
            return {"controls": _normalize_controls(controls, req.lang)}
        except (asyncio.TimeoutError, json.JSONDecodeError) as e:
            last_err = e
            continue
        except Exception as e:
            return {"controls": [], "error": str(e)[:200]}

    if isinstance(last_err, asyncio.TimeoutError):
        msg = "LLM response timed out after retry, please try again later" if req.lang == "en" else "LLM 响应超时（已重试），请稍后重试"
    elif isinstance(last_err, json.JSONDecodeError):
        msg = f"LLM returned invalid JSON: {str(last_err)[:120]}" if req.lang == "en" else f"LLM 返回的 JSON 无法解析: {str(last_err)[:120]}"
    else:
        msg = "LLM returned no recommendations, please try again" if req.lang == "en" else "LLM 未返回任何建议，请重试"
    return {"controls": [], "error": msg}
