"""
deps.dev Analyzer (6th Dimension)
Uses https://api.deps.dev to evaluate:
- Package health (is the package published & actively maintained?)
- Dependency graph (how many packages depend on this one → criticality)
- Cross-validation of license & known vulnerabilities
"""
import httpx
import urllib.parse
import re
from typing import Optional


ECOSYSTEMS = [
    ("PyPI",    ["requirements.txt", "pyproject.toml", "setup.py"]),
    ("npm",     ["package.json"]),
    ("Go",      ["go.mod"]),
    ("Maven",   ["pom.xml"]),
    ("Cargo",   ["Cargo.toml"]),
]


class DepsDotDevAnalyzer:
    DEPSDEV = "https://api.deps.dev/v3alpha"
    GITHUB  = "https://api.github.com"

    def __init__(self, owner: str, repo: str, token: str = None):
        self.owner = owner
        self.repo  = repo
        self.gh_headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "AI-Risk-Evaluator/1.0",
        }
        if token:
            self.gh_headers["Authorization"] = f"token {token}"

    async def analyze(self) -> dict:
        async with httpx.AsyncClient(timeout=20) as client:
            # 1. Get project data from deps.dev
            project_data = await self._get_project(client)

            # 2. Detect ecosystem and package name from repo files
            ecosystem, pkg_name = await self._detect_package(client)

            # 3. Get package details if we found one
            pkg_data = None
            pkg_versions = []
            dependents_count = 0
            if ecosystem and pkg_name:
                pkg_data, pkg_versions, dependents_count = await self._get_package_info(client, ecosystem, pkg_name)

        findings = []
        score = 100
        score_steps = [("Baseline", 100, 100)]

        # --- Project-level checks ---
        if project_data:
            open_issues = project_data.get("openIssuesCount", 0)
            depsdev_license = project_data.get("license", "")

            if open_issues > 500:
                findings.append({
                    "type": "WARNING",
                    "title": f"⚠️ 积压 Issue 过多 ({open_issues:,} open)",
                    "detail": "大量未关闭 Issue 可能表明维护响应迟缓",
                })
                score -= 8
                score_steps.append((f"High open issues: {open_issues:,}", -8, score))
            elif open_issues > 200:
                findings.append({
                    "type": "INFO",
                    "title": f"ℹ️ Open Issues: {open_issues:,}",
                    "detail": "Issue 数量较多，关注维护团队响应速度",
                })

            if depsdev_license:
                findings.append({
                    "type": "POSITIVE",
                    "title": f"✅ deps.dev 确认 License: {depsdev_license}",
                    "detail": "deps.dev 独立确认了仓库的许可证类型",
                })
        else:
            findings.append({
                "type": "INFO",
                "title": "ℹ️ deps.dev 暂无此项目记录",
                "detail": "项目可能较新，或尚未被 deps.dev 索引",
            })
            score -= 10
            score_steps.append(("No deps.dev project record", -10, score))

        # --- Package-level checks ---
        if pkg_data and pkg_name:
            latest_version = pkg_data.get("latestVersion", "未知")
            versions_count = len(pkg_versions)

            findings.append({
                "type": "POSITIVE",
                "title": f"✅ 已发布到 {ecosystem}: {pkg_name} v{latest_version}",
                "detail": f"共 {versions_count} 个历史版本，说明项目有规范的发版流程",
            })

            # Dependents (how many packages depend on this)
            if dependents_count > 1000:
                findings.append({
                    "type": "INFO",
                    "title": f"📦 被 {dependents_count:,} 个包依赖（高影响力）",
                    "detail": "该包被大量项目依赖，供应链攻击影响面极大，需严格审查",
                })
                score -= 5  # high criticality = higher risk if compromised
                score_steps.append((f"High dependents count: {dependents_count:,}", -5, score))
            elif dependents_count > 100:
                findings.append({
                    "type": "INFO",
                    "title": f"📦 被 {dependents_count:,} 个包依赖",
                    "detail": "中等影响力，仍需关注供应链安全",
                })
            elif dependents_count > 0:
                findings.append({
                    "type": "POSITIVE",
                    "title": f"📦 被 {dependents_count} 个包依赖",
                    "detail": "依赖范围有限，供应链攻击影响面较小",
                })

            # Check for package vulnerabilities via deps.dev
            pkg_vulns = pkg_data.get("advisoryKeys", [])
            if pkg_vulns:
                score -= len(pkg_vulns) * 10
                score_steps.append((f"Package advisories: {len(pkg_vulns)}", -len(pkg_vulns) * 10, score))
                findings.append({
                    "type": "DANGER",
                    "title": f"🚨 deps.dev 记录 {len(pkg_vulns)} 个安全公告",
                    "detail": f"Advisory IDs: {', '.join(v.get('id','') for v in pkg_vulns[:5])}",
                })
            else:
                findings.append({
                    "type": "POSITIVE",
                    "title": f"✅ deps.dev 未发现包级别安全公告",
                    "detail": f"针对 {ecosystem}/{pkg_name} 最新版本无已知 advisory",
                })

        elif ecosystem:
            # We detected the ecosystem but couldn't find the package on deps.dev
            findings.append({
                "type": "INFO",
                "title": f"ℹ️ 检测到 {ecosystem} 项目，但未在 deps.dev 找到对应包",
                "detail": "项目可能尚未发布到包管理器，或包名与仓库名不同",
            })
        else:
            findings.append({
                "type": "INFO",
                "title": "ℹ️ 未检测到已发布的包",
                "detail": "项目可能是应用程序而非可复用的库，无包级别评估",
            })

        score = max(0, min(100, score))
        risk_level = self._score_to_risk(score)

        findings.insert(0, {
            "type": "INFO",
            "title": f"📊 Score Breakdown — Final: <b>{score}</b> / 100",
            "detail": self._score_breakdown_html(score_steps, score),
            "is_html": True,
        })

        pkg_summary = f"{ecosystem}/{pkg_name} · {dependents_count:,} 个下游依赖" if pkg_name else "未发布为独立包"
        summary = pkg_summary if project_data or pkg_data else "deps.dev 暂无数据"

        return {
            "score": score,
            "risk_level": risk_level,
            "summary": summary,
            "findings": findings,
            "metrics": {
                "has_project_data": bool(project_data),
                "ecosystem": ecosystem,
                "package_name": pkg_name,
                "dependents_count": dependents_count,
                "open_issues_depsdev": project_data.get("openIssuesCount") if project_data else None,
                "depsdev_license": project_data.get("license") if project_data else None,
            },
        }

    async def _get_project(self, client: httpx.AsyncClient) -> Optional[dict]:
        try:
            project_id = urllib.parse.quote(f"github.com/{self.owner}/{self.repo}", safe="")
            r = await client.get(f"{self.DEPSDEV}/projects/{project_id}")
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return None

    async def _detect_package(self, client: httpx.AsyncClient):
        """Try to detect ecosystem and package name from repo files."""
        import base64

        # First try to find the package name from common config files
        for ecosystem, filenames in ECOSYSTEMS:
            for filename in filenames:
                try:
                    r = await client.get(
                        f"{self.GITHUB}/repos/{self.owner}/{self.repo}/contents/{filename}",
                        headers=self.gh_headers,
                    )
                    if r.status_code != 200:
                        continue
                    data = r.json()
                    content = ""
                    if data.get("encoding") == "base64":
                        content = base64.b64decode(data["content"]).decode("utf-8", errors="ignore")

                    pkg_name = self._extract_package_name(content, filename, ecosystem)
                    if pkg_name:
                        return ecosystem, pkg_name
                except Exception:
                    continue

        # Fallback: use repo name as package name guess
        return None, None

    def _extract_package_name(self, content: str, filename: str, ecosystem: str) -> Optional[str]:
        """Extract the primary package name from a dependency file."""
        if filename == "pyproject.toml":
            m = re.search(r'name\s*=\s*["\']([^"\']+)["\']', content)
            if m:
                return m.group(1)
        elif filename == "setup.py":
            m = re.search(r'name\s*=\s*["\']([^"\']+)["\']', content)
            if m:
                return m.group(1)
        elif filename == "package.json":
            import json
            try:
                d = json.loads(content)
                name = d.get("name", "")
                if name and not name.startswith("@") or "/" not in name:
                    return name
                return name
            except Exception:
                pass
        elif filename == "go.mod":
            m = re.match(r'^module\s+(\S+)', content, re.MULTILINE)
            if m:
                return m.group(1)
        elif filename == "pom.xml":
            m = re.search(r'<artifactId>([^<]+)</artifactId>', content)
            if m:
                return m.group(1)
        elif filename == "Cargo.toml":
            m = re.search(r'name\s*=\s*"([^"]+)"', content)
            if m:
                return m.group(1)
        return None

    async def _get_package_info(self, client: httpx.AsyncClient, ecosystem: str, pkg_name: str):
        """Get package details and dependent count from deps.dev."""
        try:
            encoded = urllib.parse.quote(pkg_name, safe="")
            r = await client.get(f"{self.DEPSDEV}/systems/{ecosystem}/packages/{encoded}")
            if r.status_code != 200:
                # Try with repo name as fallback
                encoded = urllib.parse.quote(self.repo, safe="")
                r = await client.get(f"{self.DEPSDEV}/systems/{ecosystem}/packages/{encoded}")
                if r.status_code != 200:
                    return None, [], 0

            pkg_data = r.json()
            versions = pkg_data.get("versions", [])

            # Get dependent count for the latest version
            latest = pkg_data.get("latestVersion", "")
            dependents_count = 0
            if latest:
                dep_r = await client.get(
                    f"{self.DEPSDEV}/systems/{ecosystem}/packages/{encoded}/versions/{urllib.parse.quote(latest, safe='')}/dependents"
                )
                if dep_r.status_code == 200:
                    dependents_count = dep_r.json().get("totalCount", 0) or len(dep_r.json().get("dependents", []))

            return pkg_data, versions, dependents_count
        except Exception:
            return None, [], 0

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

    def _score_to_risk(self, score: int) -> str:
        if score >= 75:
            return "LOW"
        elif score >= 55:
            return "MEDIUM"
        elif score >= 35:
            return "HIGH"
        return "CRITICAL"
