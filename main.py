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
        "github":       0.15,
        "depsdev":      0.05,
        "code":         0.25,
        "deps":         0.15,
        "ai_safety":    0.20,
        "privacy":      0.10,
        "supply_chain": 0.05,
        "runtime":      0.05,
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


async def stream_analysis(url: str, token: Optional[str]) -> AsyncGenerator[str, None]:
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
        ("code",          "🤖 Agent Capability Analysis",            CodeAnalyzer(owner, repo, token)),
        ("deps",          "📦 Dependency Vulnerability Scan",    DepsAnalyzer(owner, repo, token)),
        ("ai_safety",     "🛡️ AI Safety Guardrails",             AISafetyAnalyzer(owner, repo, token)),
        ("privacy",       "🔒 Data Privacy",                     PrivacyAnalyzer(owner, repo, token)),
        ("supply_chain",  "⛓️ Supply Chain Integrity",           SupplyChainAnalyzer(owner, repo, token)),
        ("runtime",       "🐳 Runtime Isolation",                RuntimeAnalyzer(owner, repo, token)),
    ]

    results = {}

    for key, name, analyzer in analyzers:
        yield sse({"type": "progress", "phase": key, "name": name, "status": "running"})
        try:
            result = await analyzer.analyze()
        except asyncio.CancelledError:
            # CancelledError is BaseException in Python 3.8+ — must catch explicitly
            result = {
                "score": 50,
                "risk_level": "UNKNOWN",
                "summary": "分析被取消 (asyncio timeout/cancel)",
                "findings": [{"type": "INFO", "title": "分析超时", "detail": f"{key} analyzer was cancelled"}],
                "metrics": {},
            }
        except Exception as e:
            result = {
                "score": 50,
                "risk_level": "UNKNOWN",
                "summary": f"分析失败: {str(e)[:120]}",
                "findings": [{"type": "INFO", "title": "分析出错", "detail": str(e)[:200]}],
                "metrics": {},
            }
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
):
    effective_token = token or DEFAULT_TOKEN or None
    return StreamingResponse(
        stream_analysis(url, effective_token),
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
    privacy_result: dict = {}
    supply_chain_result: dict = {}


def _build_controls_prompt(req: ControlsRequest) -> str:
    def fmt_findings(result: dict, max_items: int = 10) -> str:
        findings = result.get("findings", [])
        lines = []
        for f in findings[:max_items]:
            if f.get("type") in ("INFO",):
                continue
            lines.append(f"  [{f.get('type','?')}] {f.get('title','')}：{f.get('detail','')[:120]}")
        return "\n".join(lines) if lines else "  无特殊发现"

    cap_summary   = req.code_result.get("summary", "未获取")
    safety_summary = req.ai_safety_result.get("summary", "未获取")

    cap_findings    = fmt_findings(req.code_result)
    safety_findings = fmt_findings(req.ai_safety_result)
    runtime_findings = fmt_findings(req.runtime_result)
    privacy_findings = fmt_findings(req.privacy_result)
    sc_findings      = fmt_findings(req.supply_chain_result)

    return f"""你是 adidas AppSec 团队的高级 AI 安全顾问。

以下是对开源 AI Agent 仓库「{req.repo}」的安全评估结果：

== 总体风险 ==
风险等级：{req.overall.get('risk_level')} RISK
综合评分：{req.overall.get('score')} / 100

== Agent 能力分析（爆炸半径）==
{cap_summary}
发现项：
{cap_findings}

== AI 安全护栏 ==
{safety_summary}
发现项：
{safety_findings}

== 运行时隔离 ==
{runtime_findings}

== 数据隐私 ==
{privacy_findings}

== 供应链完整性 ==
{sc_findings}

---

请基于以上评估结果，为企业内部计划部署此 Agent 的开发与运维团队，生成**详尽、可操作**的安全管控建议。

【重要前提】本场景的威胁模型是：
- Agent 的使用者是**正常员工或业务用户，不会主动尝试攻击或绕过系统**
- 风险来源是：AI Agent 自身的幻觉、误判、能力边界不清，导致用户**在毫不知情的情况下**触发了超出预期的操作
- 典型场景：用户让 Agent 帮忙整理文件，Agent 误删了不该删的内容；用户让 Agent 发邮件，Agent 发给了错误的收件人；Agent 调用了用户未预期的云 API
- 管控目标：**为 Agent 的每一类能力设置合理的边界和兜底机制，防止意外造成不可逆影响**
- 不需要考虑主动攻击、渗透测试、恶意提示注入等对抗性场景

要求：
1. 覆盖以下四个维度（每个维度至少 2-3 条，总计不少于 10 条）：
   - 调用方代码（开发者在集成代码中实现的边界和兜底）
   - 运维部署（基础设施层面的能力限制与资源保护）
   - 监控与审计（感知 Agent 做了什么，发现意外行为）
   - 数据安全（防止 Agent 误操作导致数据泄露或损坏）

2. 每条建议必须包含：
   - title：简短有力的建议名称（10字以内）
   - reason：为什么需要，结合该 Agent 具体发现的能力，说明"如果不做，用户在正常使用时可能意外触发什么后果"
   - implementation：详细的实施步骤，包括伪代码、配置示例或命令，不少于 3 个具体步骤
   - priority：MUST（该能力存在时必须实施）/ RECOMMEND（强烈建议）/ OPTIONAL（锦上添花）
   - category：对应维度名称（如"调用方代码"）

3. 建议要针对此 Agent 的具体能力定制，直接说明"因为该 Agent 具备 X 能力，所以需要..."
4. implementation 字段使用换行分隔步骤，可包含代码块
5. 全部使用中文输出
6. 以合法 JSON 格式返回，结构如下：
{{"controls": [{{"category": "调用方代码", "title": "...", "reason": "...", "implementation": "...", "priority": "MUST"}}]}}"""


@app.post("/api/security-controls")
async def security_controls(req: ControlsRequest):
    client = AsyncOpenAI(
        api_key=QWEN_API_KEY,
        base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
    )
    prompt = _build_controls_prompt(req)
    try:
        resp = await asyncio.wait_for(
            client.chat.completions.create(
                model="qwen-plus",
                temperature=0.3,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": "你是企业 AI 安全顾问，输出严格的 JSON。"},
                    {"role": "user",   "content": prompt},
                ],
            ),
            timeout=120.0,
        )
        raw = resp.choices[0].message.content
        data = json.loads(raw)
        return data
    except asyncio.TimeoutError:
        return {"controls": [], "error": "LLM 响应超时，请稍后重试"}
    except Exception as e:
        return {"controls": [], "error": str(e)[:200]}
