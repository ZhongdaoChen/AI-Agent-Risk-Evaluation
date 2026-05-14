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

load_dotenv()
DEFAULT_TOKEN = os.getenv("GITHUB_DEFAULT_TOKEN", "")
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
