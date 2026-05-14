"""
Data Privacy Analyzer
Checks for data privacy risks in AI agent projects:
- Privacy policy / data handling documentation
- Logging of user inputs / prompts to persistent storage
- Telemetry opt-in vs opt-out behavior
- PII patterns appearing in log / print statements
- Data anonymization / pseudonymization mechanisms
"""
import re
import base64
import httpx
from typing import List, Tuple

# Documentation file checks: (filename, title, detail, score_delta)
PRIVACY_DOCS = [
    ("PRIVACY.md",          "隐私政策文档 (PRIVACY.md)",       "项目包含明确的隐私政策说明",   15),
    ("DATA_HANDLING.md",    "数据处理说明 (DATA_HANDLING.md)", "项目说明了数据处理方式",       10),
    ("PRIVACY_POLICY.md",   "隐私政策 (PRIVACY_POLICY.md)",   "项目包含明确的隐私政策",       10),
    ("docs/privacy.md",     "隐私文档 (docs/privacy.md)",      "文档目录包含隐私说明",          5),
]

# Code patterns: (regex, title, detail, is_positive, score_delta)
PRIVACY_PATTERNS: List[Tuple[str, str, str, bool, int]] = [
    # ── Positive ────────────────────────────────────────────────────────────
    (
        r'(?i)(anonymi[sz]e?|pseudonymiz|redact|mask[_\s]?(pii|data|field)'
        r'|pii[_\s]?remov|scrub[_\s]?(pii|data))',
        "数据匿名化 / 脱敏处理",
        "代码包含 PII 数据匿名化或脱敏机制，保护用户隐私",
        True, 10,
    ),
    (
        r'(?i)(telemetry[_\s]?=\s*False'
        r'|TELEMETRY_ENABLED\s*=\s*False'
        r'|disable[_\s]?telemetry|no[_\s]?telemetry'
        r'|opt[_\s]?out.*telemetry)',
        "遥测默认关闭",
        "遥测 / 数据收集默认处于关闭状态，保护用户隐私",
        True, 10,
    ),
    (
        r'(?i)(data[_\s]?retention|retention[_\s]?policy'
        r'|delete[_\s]?after|expire[_\s]?after|ttl\s*=)',
        "数据留存策略",
        "代码实现了数据过期 / 删除机制，避免无限期留存用户数据",
        True, 5,
    ),
    (
        r'(?i)(encrypt[_\s]?(at[_\s]?rest|storage|data)'
        r'|aes[_\s]?(256|128)|fernet|nacl|cryptograph)',
        "静态数据加密",
        "用户数据在存储时经过加密处理",
        True, 5,
    ),
    # ── Negative ────────────────────────────────────────────────────────────
    (
        r'(?i)(logging\.(debug|info|warning|error|critical)\s*\('
        r'[^)]*\b(prompt|user[_\s]?input|user[_\s]?message|query|conversation)\b)',
        "将用户输入 / 对话写入日志",
        "代码将用户的 prompt 或消息内容写入日志，存在隐私泄露风险",
        False, -20,
    ),
    (
        r'(?i)(print\s*\([^)]*\b(prompt|user[_\s]?input|user[_\s]?message|query)\b)',
        "print 输出用户输入",
        "代码将用户输入 print 到标准输出，可能被持久化到日志文件",
        False, -10,
    ),
    (
        r'(?i)(posthog\.capture|mixpanel\.track|segment\.track'
        r'|analytics\.track|amplitude\.track)',
        "第三方行为分析追踪",
        "代码集成了第三方分析平台，可能将用户行为数据发送至外部服务",
        False, -10,
    ),
    (
        r'(?i)(telemetry[_\s]?=\s*True'
        r'|TELEMETRY_ENABLED\s*=\s*True'
        r'|enable[_\s]?telemetry\s*=\s*True)',
        "遥测默认开启",
        "遥测 / 数据收集默认处于开启状态，用户需主动关闭",
        False, -15,
    ),
    (
        r'(?i)(open\s*\([^)]+["\']a["\']\s*\)[^)]*\b(prompt|user[_\s]?input|message)\b'
        r'|write\s*\([^)]*\b(prompt|user[_\s]?input|user_message)\b)',
        "将用户输入写入文件",
        "代码将用户输入直接追加写入文件，存在对话内容持久化风险",
        False, -15,
    ),
]


class PrivacyAnalyzer:
    BASE = "https://api.github.com"

    def __init__(self, owner: str, repo: str, token: str = None):
        self.owner = owner
        self.repo = repo
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "AI-Risk-Evaluator/1.0",
        }
        if token:
            self.headers["Authorization"] = f"token {token}"

    async def analyze(self) -> dict:
        async with httpx.AsyncClient(headers=self.headers, timeout=20) as client:
            repo_r = await client.get(f"{self.BASE}/repos/{self.owner}/{self.repo}")
            repo_r.raise_for_status()
            default_branch = repo_r.json().get("default_branch", "main")

            tree_r = await client.get(
                f"{self.BASE}/repos/{self.owner}/{self.repo}/git/trees/{default_branch}",
                params={"recursive": "1"},
            )
            if tree_r.status_code != 200:
                return self._error_result("无法获取代码树")

            files = [f["path"] for f in tree_r.json().get("tree", []) if f.get("type") == "blob"]
            file_set_lower = {f.lower() for f in files}

            # ── Check documentation files ───────────────────────────────────
            found_privacy_doc = False
            score = 70
            score_steps = [("Baseline", 70, 70)]
            findings = []

            for filename, title, detail, delta in PRIVACY_DOCS:
                if filename.lower() in file_set_lower:
                    found_privacy_doc = True
                    score += delta
                    score_steps.append((f"Privacy doc: {filename}", delta, score))
                    findings.append({
                        "type": "POSITIVE",
                        "title": f"✅ {title}",
                        "detail": detail,
                    })

            if not found_privacy_doc:
                score -= 10
                score_steps.append(("No privacy documentation found", -10, score))
                findings.append({
                    "type": "WARNING",
                    "title": "⚠️ 缺少隐私政策文档",
                    "detail": "未找到 PRIVACY.md / DATA_HANDLING.md，用户无法了解数据处理方式",
                })

            # ── Scan source files for privacy patterns ──────────────────────
            scan_files = self._select_files(files)
            matches: dict = {}

            for path in scan_files[:12]:
                content = await self._fetch_file(client, path, default_branch)
                if not content:
                    continue
                base_url = f"https://github.com/{self.owner}/{self.repo}/blob/{default_branch}/{path}"
                lines = content.splitlines()

                for pattern, title, detail, is_pos, delta in PRIVACY_PATTERNS:
                    if title in matches:
                        continue
                    m = re.search(pattern, content, re.MULTILINE)
                    if m:
                        line_no = content[: m.start()].count("\n") + 1
                        snippet = lines[line_no - 1].strip()[:100] if lines else ""
                        matches[title] = (is_pos, delta, path, line_no, snippet, detail, base_url)

        # ── Build score & findings ──────────────────────────────────────────
        positive_count = int(found_privacy_doc)
        negative_count = 0

        for title, (is_pos, delta, path, line_no, snippet, detail, base_url) in matches.items():
            score += delta
            score_steps.append((title, delta, score))
            detail_html = detail
            if base_url and line_no:
                url = f"{base_url}#L{line_no}"
                link = f'<a href="{url}" target="_blank" class="underline text-indigo-600 font-mono">{path}:{line_no}</a>'
                detail_html += f'<br/><span class="text-gray-400">📍 发现于</span> {link}'
            if snippet:
                color = "text-green-700" if is_pos else "text-red-700"
                code = f'<code class="bg-gray-100 {color} px-1 rounded font-mono">{self._esc(snippet)}</code>'
                detail_html += f'<br/><span class="text-gray-400">📝 匹配代码</span> {code}'

            if is_pos:
                positive_count += 1
                findings.append({"type": "POSITIVE", "title": f"✅ {title}", "detail": detail_html, "is_html": True})
            else:
                negative_count += 1
                sev = "CRITICAL" if delta <= -15 else "WARNING"
                icon = "🚨" if sev == "CRITICAL" else "⚠️"
                findings.append({"type": sev, "title": f"{icon} {title}", "detail": detail_html, "is_html": True})

        score = max(0, min(100, score))
        findings.insert(0, {
            "type": "INFO",
            "title": f"📊 Score Breakdown — Final: <b>{score}</b> / 100",
            "detail": self._score_breakdown_html(score_steps, score),
            "is_html": True,
        })
        return {
            "score": score,
            "risk_level": self._score_to_risk(score),
            "summary": f"{positive_count} 项隐私保护，{negative_count} 项隐私风险",
            "findings": findings,
            "metrics": {
                "has_privacy_doc": found_privacy_doc,
                "positive_controls": positive_count,
                "negative_patterns": negative_count,
                "files_scanned": len(scan_files),
            },
        }

    def _select_files(self, files: List[str]) -> List[str]:
        priority, secondary = [], []
        skip = {"node_modules", ".git", "dist", "build", "__pycache__", "venv", ".venv"}
        src_ext = {".py", ".ts", ".js", ".go"}
        focus_kw = ["telemetry", "analytics", "track", "log", "privacy", "data", "main", "app", "agent", "config"]

        for f in files:
            parts = f.split("/")
            if any(p in skip for p in parts):
                continue
            name = parts[-1].lower()
            ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
            if any(kw in f.lower() for kw in focus_kw) and ext in src_ext:
                priority.append(f)
            elif ext in src_ext and len(parts) <= 3:
                secondary.append(f)
        return (priority + secondary)[:12]

    async def _fetch_file(self, client: httpx.AsyncClient, path: str, branch: str) -> str:
        try:
            r = await client.get(
                f"{self.BASE}/repos/{self.owner}/{self.repo}/contents/{path}",
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

    def _score_breakdown_html(self, score_steps, final_score):
        rows = "".join([
            f'<tr style="border-bottom:1px solid #f1f5f9;">'
            f'<td style="padding:3px 8px;color:#374151;">{self._esc(str(label))}</td>'
            f'<td style="padding:3px 8px;text-align:right;font-weight:bold;color:{"#16a34a" if d >= 0 else "#dc2626"};">'
            f'{"+" if d >= 0 else ""}{d}</td>'
            f'<td style="padding:3px 8px;text-align:right;color:#6b7280;">{total}</td>'
            f'</tr>'
            for label, d, total in score_steps
        ])
        return f"""<div style="font-size:11px;">
  <div style="font-weight:600;color:#374151;margin-bottom:4px;">📊 评分明细</div>
  <table style="width:100%;border-collapse:collapse;background:#f8fafc;border-radius:6px;overflow:hidden;border:1px solid #e2e8f0;">
    <thead>
      <tr style="background:#e2e8f0;font-weight:600;color:#475569;">
        <th style="padding:4px 8px;text-align:left;">评分项</th>
        <th style="padding:4px 8px;text-align:right;">分值变化</th>
        <th style="padding:4px 8px;text-align:right;">累计得分</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
    <tfoot>
      <tr style="background:#1e1b4b;color:white;font-weight:bold;">
        <td style="padding:4px 8px;">最终得分（0-100封顶）</td>
        <td></td>
        <td style="padding:4px 8px;text-align:right;font-size:13px;">{final_score}</td>
      </tr>
    </tfoot>
  </table>
</div>"""

    def _esc(self, s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    def _error_result(self, msg: str) -> dict:
        return {
            "score": 50, "risk_level": "UNKNOWN", "summary": msg,
            "findings": [{"type": "INFO", "title": "无法分析", "detail": msg}],
            "metrics": {},
        }

    def _score_to_risk(self, score: int) -> str:
        if score >= 75: return "LOW"
        elif score >= 55: return "MEDIUM"
        elif score >= 35: return "HIGH"
        return "CRITICAL"
