"""
GitHub Reputation & Activity Analyzer
Evaluates: stars, forks, last commit, contributor count, SECURITY.md, CI/CD
"""
import httpx
from datetime import datetime, timezone
import math


class GitHubAnalyzer:
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
            # Fetch core repo data
            r = await client.get(f"{self.BASE}/repos/{self.owner}/{self.repo}")
            r.raise_for_status()
            repo = r.json()

            # Fetch contributors (get count via pagination header)
            cr = await client.get(
                f"{self.BASE}/repos/{self.owner}/{self.repo}/contributors",
                params={"per_page": 1, "anon": "false"},
            )
            contrib_count = self._parse_total_from_link(cr)

            # Check SECURITY.md
            sec_r = await client.get(
                f"{self.BASE}/repos/{self.owner}/{self.repo}/contents/SECURITY.md"
            )
            has_security_md = sec_r.status_code == 200

            # Check CI workflows
            wf_r = await client.get(
                f"{self.BASE}/repos/{self.owner}/{self.repo}/contents/.github/workflows"
            )
            has_ci = wf_r.status_code == 200 and isinstance(wf_r.json(), list) and len(wf_r.json()) > 0

        stars = repo.get("stargazers_count", 0)
        forks = repo.get("forks_count", 0)
        open_issues = repo.get("open_issues_count", 0)
        pushed_at = repo.get("pushed_at", "")
        created_at = repo.get("created_at", "")
        description = repo.get("description") or "无描述"
        license_name = (repo.get("license") or {}).get("spdx_id", "NONE")
        is_archived = repo.get("archived", False)
        is_fork = repo.get("fork", False)
        topics = repo.get("topics", [])

        # Calculate days since last commit
        days_since_commit = 9999
        if pushed_at:
            last_push = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
            days_since_commit = (datetime.now(timezone.utc) - last_push).days

        # Calculate repo age in days
        repo_age_days = 0
        if created_at:
            created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            repo_age_days = (datetime.now(timezone.utc) - created).days

        # --- Scoring ---
        score = 0
        findings = []
        score_steps = [("Baseline", 0, 0)]

        # Stars (0-25)
        if stars >= 10000:
            _delta = 25
        elif stars >= 1000:
            _delta = 20
        elif stars >= 100:
            _delta = 15
        elif stars >= 10:
            _delta = 10
        else:
            _delta = 5
            findings.append({"type": "WARNING", "title": f"⭐ Stars 数量较少 ({stars})", "detail": "项目知名度较低，社区验证不足"})
        score += _delta
        score_steps.append((f"Stars: {stars:,}", _delta, score))

        # Last commit recency (0-25)
        if days_since_commit <= 30:
            _delta = 25
        elif days_since_commit <= 90:
            _delta = 20
        elif days_since_commit <= 180:
            _delta = 15
        elif days_since_commit <= 365:
            _delta = 8
            findings.append({"type": "WARNING", "title": f"🕐 最后提交 {days_since_commit} 天前", "detail": "项目活跃度下降，可能缺乏维护"})
        else:
            _delta = 0
            findings.append({"type": "DANGER", "title": f"💀 项目超过 {days_since_commit} 天未更新", "detail": "项目可能已停止维护，存在未修复漏洞风险"})
        score += _delta
        score_steps.append((f"Last commit: {days_since_commit}d ago", _delta, score))

        # Contributor count (0-20)
        if contrib_count >= 20:
            _delta = 20
        elif contrib_count >= 10:
            _delta = 15
        elif contrib_count >= 5:
            _delta = 10
        elif contrib_count >= 2:
            _delta = 7
        else:
            _delta = 3
            findings.append({"type": "WARNING", "title": f"👤 贡献者仅 {contrib_count} 人", "detail": "单人维护项目风险较高，存在'bus factor'问题"})
        score += _delta
        score_steps.append((f"Contributors: {contrib_count}", _delta, score))

        # SECURITY.md (0-15)
        if has_security_md:
            score += 15
            score_steps.append(("SECURITY.md present", 15, score))
            findings.append({"type": "POSITIVE", "title": "✅ 存在 SECURITY.md", "detail": "项目有明确的安全漏洞披露流程"})
        else:
            score_steps.append(("SECURITY.md missing", 0, score))
            findings.append({"type": "WARNING", "title": "⚠️ 缺少 SECURITY.md", "detail": "无安全漏洞报告渠道，漏洞可能得不到及时处理"})

        # CI/CD (0-15)
        if has_ci:
            score += 15
            score_steps.append(("CI/CD workflows present", 15, score))
            findings.append({"type": "POSITIVE", "title": "✅ 存在 CI/CD 工作流", "detail": "自动化测试和发布流程，代码质量有保障"})
        else:
            score_steps.append(("CI/CD workflows missing", 0, score))
            findings.append({"type": "WARNING", "title": "⚠️ 未发现 CI/CD 配置", "detail": "缺少自动化测试，代码质量无法保证"})

        # Archived / Fork penalties
        if is_archived:
            _before = score
            score = max(0, score - 30)
            _actual_delta = score - _before
            score_steps.append(("Archived repository penalty", _actual_delta, score))
            findings.append({"type": "DANGER", "title": "🚫 项目已归档", "detail": "已归档项目不再接受更新，安全漏洞将无法修复"})

        if is_fork:
            findings.append({"type": "INFO", "title": "🍴 这是一个 Fork", "detail": "需确认与上游是否保持同步"})

        # Cap score at 100
        score = min(100, score)
        risk_level = self._score_to_risk(score)

        # Score breakdown finding
        findings.insert(0, {
            "type": "INFO",
            "title": f"📊 Score Breakdown — Final: <b>{score}</b> / 100",
            "detail": self._score_breakdown_html(score_steps, score),
            "is_html": True,
        })

        return {
            "score": score,
            "risk_level": risk_level,
            "summary": f"{stars:,} Stars · {contrib_count} 贡献者 · {days_since_commit} 天前更新",
            "findings": findings,
            "metrics": {
                "stars": stars,
                "forks": forks,
                "open_issues": open_issues,
                "contributors": contrib_count,
                "days_since_commit": days_since_commit,
                "repo_age_days": repo_age_days,
                "has_security_md": has_security_md,
                "has_ci": has_ci,
                "is_archived": is_archived,
                "is_fork": is_fork,
                "topics": topics,
                "description": description,
                "license": license_name,
            },
        }

    def _esc(self, s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

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

    def _parse_total_from_link(self, response: httpx.Response) -> int:
        """Parse total count from GitHub Link header pagination."""
        link = response.headers.get("link", "")
        if 'rel="last"' in link:
            import re
            match = re.search(r'page=(\d+)>; rel="last"', link)
            if match:
                return int(match.group(1))
        # If no pagination, count from response body
        try:
            data = response.json()
            if isinstance(data, list):
                return len(data)
        except Exception:
            pass
        return 1

    def _score_to_risk(self, score: int) -> str:
        if score >= 75:
            return "LOW"
        elif score >= 55:
            return "MEDIUM"
        elif score >= 35:
            return "HIGH"
        return "CRITICAL"
