"""
AI Agent Risk Evaluator - Main FastAPI Application
Streams analysis results via Server-Sent Events (SSE)
"""
import asyncio
import json
import os
import re
from typing import AsyncGenerator, Optional

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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


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


def calculate_overall(results: dict) -> dict:
    weights = {
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
    total_w, weighted = 0.0, 0.0
    for key, w in weights.items():
        if key in results and isinstance(results[key].get("score"), (int, float)):
            score = results[key]["score"]
            if results[key].get("risk_level") != "UNKNOWN":
                weighted += score * w
                total_w += w

    final = round(weighted / total_w, 1) if total_w > 0 else 50.0

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

    return {"score": final, "risk_level": risk, "emoji": emoji, "label": label}


async def stream_analysis(url: str, token: Optional[str], lang: str = "zh") -> AsyncGenerator[str, None]:
    def sse(data: dict) -> str:
        return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"

    try:
        owner, repo = parse_github_url(url)
    except ValueError as e:
        yield sse({"type": "error", "message": str(e)})
        return

    yield sse({"type": "start", "owner": owner, "repo": repo})

    analyzers = [
        ("github",        "⭐ Reputation & Activity",            GitHubAnalyzer(owner, repo, token)),
        ("depsdev",       "🌐 deps.dev Package Health",          DepsDotDevAnalyzer(owner, repo, token)),
        ("code",          "🤖 Agent Capability Analysis",            CodeAnalyzer(owner, repo, token, lang=lang)),
        ("deps",          "📦 Dependency Vulnerability Scan",    DepsAnalyzer(owner, repo, token)),
        ("ai_safety",     "🛡️ AI Safety Guardrails",             AISafetyAnalyzer(owner, repo, token, lang=lang)),
        ("skill",         "🔧 Skill Security Quality",           SkillAnalyzer(owner, repo, token, lang=lang)),
        ("privacy",       "🔒 Data Privacy",                     PrivacyAnalyzer(owner, repo, token)),
        ("supply_chain",  "⛓️ Supply Chain Integrity",           SupplyChainAnalyzer(owner, repo, token)),
        ("runtime",       "🐳 Runtime Isolation",                RuntimeAnalyzer(owner, repo, token)),
    ]

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

    overall = calculate_overall(results)
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
):
    effective_token = token or DEFAULT_TOKEN or None
    return StreamingResponse(
        stream_analysis(url, effective_token, lang=lang),
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
            if f.get("type") == "INFO":
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

== AI Safety Guardrails (what exists / what's missing) ==
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
Generate recommendations across exactly these 3 categories:

1. **Capability Boundary Controls** — For each HIGH/MEDIUM capability detected, provide a specific control that restricts it to expected scope. Example: "Agent has shell execution → restrict to a whitelist of allowed commands, block destructive flags".

2. **Guardrail Configuration** — For each POSITIVE guardrail already present, explain how to properly configure it for production. For example: if human approval exists, specify which capability categories must trigger it.

3. **Missing Guardrails** — For each dangerous capability that lacks a corresponding guardrail (no step limit, no approval, no allowlist), specify exactly what to add and how to implement it.

4. **Ops & Deployment** — Infrastructure-level controls: container hardening, IAM least-privilege, network egress restrictions, resource quotas tied to detected capabilities.

Rules:
- Every recommendation must reference a specific detected capability or guardrail finding ("Because this agent has X / lacks Y...")
- Each item must include: title (≤8 words), reason (why, what could go wrong), implementation (≥3 concrete steps with examples), priority (MUST/RECOMMEND/OPTIONAL), category
- At least 3 items per category; total ≥ 12
- Output in English
- Return valid JSON: {{"controls": [{{"category": "Capability Boundary Controls", "title": "...", "reason": "...", "implementation": "...", "priority": "MUST"}}]}}"""

    return f"""你是 adidas AppSec 团队的高级 AI 安全顾问。

以下是开源 AI Agent「{req.repo}」的安全评估结果：

== 总体风险 ==
风险等级：{req.overall.get('risk_level')} | 综合评分：{req.overall.get('score')} / 100

== Agent 能力分析（爆炸半径）==
{cap_summary}
检测到的能力：
{cap_findings}

== AI 安全护栏（已有 / 缺失）==
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
严格按以下 3 个维度生成建议：

1. **能力边界管控** — 针对每一条检测到的 HIGH/MEDIUM 能力，给出具体的限制措施，将其约束在预期范围内。例如："Agent 具备 Shell 执行能力 → 限制为允许命令白名单，屏蔽破坏性参数"。

2. **护栏配置建议** — 针对已检测到存在的安全护栏（POSITIVE），说明在生产环境中应如何正确配置。例如：已有人工审批 → 明确哪些能力类别必须触发审批。

3. **缺失护栏补齐** — 针对有高危能力但缺乏对应护栏的情况（无步骤限制、无审批、无白名单），明确需要新增什么，并给出具体实施方式。

4. **运维部署管控** — 基础设施层面：容器加固、IAM 最小权限、网络出口限制、资源配额，结合检测到的能力定制。

规则：
- 每条建议必须引用具体的能力或护栏发现项（"因为该 Agent 具备 X / 缺少 Y..."）
- 每条包含：title（8字以内）、reason（为什么，可能触发什么后果）、implementation（≥3步骤，含示例）、priority（MUST/RECOMMEND/OPTIONAL）、category
- 每个维度至少 3 条，总计不少于 12 条
- 全部中文输出
- 返回合法 JSON：{{"controls": [{{"category": "能力边界管控", "title": "...", "reason": "...", "implementation": "...", "priority": "MUST"}}]}}"""


@app.post("/api/security-controls")
async def security_controls(req: ControlsRequest):
    client = AsyncOpenAI(
        api_key=QWEN_API_KEY,
        base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
    )
    prompt = _build_controls_prompt(req)
    sys_prompt = "You are an enterprise AI security advisor. Output strict JSON." if req.lang == "en" else "你是企业 AI 安全顾问，输出严格的 JSON。"
    try:
        resp = await asyncio.wait_for(
            client.chat.completions.create(
                model="qwen-plus",
                temperature=0.3,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": sys_prompt},
                    {"role": "user",   "content": prompt},
                ],
            ),
            timeout=120.0,
        )
        raw = resp.choices[0].message.content
        data = json.loads(raw)
        return data
    except asyncio.TimeoutError:
        timeout_msg = "LLM response timed out, please try again later" if req.lang == "en" else "LLM 响应超时，请稍后重试"
        return {"controls": [], "error": timeout_msg}
    except Exception as e:
        return {"controls": [], "error": str(e)[:200]}
