"""
Dependency Vulnerability Analyzer
- Fetches dependency files (requirements.txt, package.json, go.mod, etc.)
- Queries OSV.dev API (https://osv.dev) for known CVEs - no auth required
"""
import httpx
import re
import json
from typing import List, Dict, Tuple


ECOSYSTEM_MAP = {
    "requirements.txt": "PyPI",
    "pyproject.toml": "PyPI",
    "setup.py": "PyPI",
    "package.json": "npm",
    "go.mod": "Go",
    "Gemfile": "RubyGems",
    "Cargo.toml": "crates.io",
    "pom.xml": "Maven",
}

SEVERITY_SCORE = {"CRITICAL": -25, "HIGH": -12, "MODERATE": -5, "MEDIUM": -5, "LOW": -2}


class DepsAnalyzer:
    BASE = "https://api.github.com"
    OSV = "https://api.osv.dev/v1"

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
        packages = []
        dep_files_found = []

        async with httpx.AsyncClient(headers=self.headers, timeout=20) as client:
            # Try GitHub vulnerability alerts first (requires token + repo permission)
            if "Authorization" in self.headers:
                vuln_r = await client.get(
                    f"{self.BASE}/repos/{self.owner}/{self.repo}/vulnerability-alerts",
                    headers={**self.headers, "Accept": "application/vnd.github.v4+json"},
                )
                if vuln_r.status_code == 204:
                    # No vulnerabilities reported via Dependabot
                    pass

            # Fetch dependency files
            for filename, ecosystem in ECOSYSTEM_MAP.items():
                content = await self._fetch_file_content(client, filename)
                if content:
                    dep_files_found.append(filename)
                    parsed = self._parse_deps(content, filename, ecosystem)
                    packages.extend(parsed)

        if not packages:
            return {
                "score": 70,
                "risk_level": "UNKNOWN",
                "summary": "未找到可识别的依赖文件",
                "findings": [
                    {
                        "type": "INFO",
                        "title": "📦 未找到依赖清单",
                        "detail": "未找到 requirements.txt / package.json / go.mod 等文件",
                    }
                ],
                "metrics": {"dep_files": [], "packages_checked": 0},
            }

        # Query OSV.dev for vulnerabilities (batch, max 100 at a time)
        vulns = await self._query_osv(packages[:50])

        # Build findings
        findings = []
        score = 100
        score_steps = [("Baseline", 100, 100)]
        vuln_packages = set()
        critical_count = 0
        high_count = 0
        medium_count = 0
        critical_applied = high_applied = medium_applied = 0

        for pkg_name, ecosystem, source_file, advisories in vulns:
            for adv in advisories:
                severity = adv.get("severity", "MEDIUM").upper()
                if severity == "CRITICAL":
                    critical_count += 1
                    if critical_applied < 2:
                        score -= 25
                        score_steps.append((f"CVE CRITICAL: {pkg_name}", -25, score))
                        critical_applied += 1
                elif severity == "HIGH":
                    high_count += 1
                    if high_applied < 4:
                        score -= 12
                        score_steps.append((f"CVE HIGH: {pkg_name}", -12, score))
                        high_applied += 1
                else:
                    medium_count += 1
                    if medium_applied < 6:
                        score -= 5
                        score_steps.append((f"CVE MEDIUM: {pkg_name}", -5, score))
                        medium_applied += 1
                vuln_packages.add(pkg_name)

                icon = "🚨" if severity == "CRITICAL" else "⚠️" if severity == "HIGH" else "⚠️"
                sev_color = {"CRITICAL": "#dc2626", "HIGH": "#ea580c"}.get(severity, "#ca8a04")

                osv_id      = adv.get("id", "")
                cve_ids     = adv.get("cve_ids", [])
                summary     = adv.get("summary", "暂无摘要")
                published   = adv.get("published", "")
                cwe_ids     = adv.get("cwe_ids", [])
                fixed_ver   = adv.get("fixed_version")
                intro_ver   = adv.get("affected_intro")
                ref_url     = adv.get("ref_url")
                nvd_url     = adv.get("nvd_url")

                # Build ID badges: OSV + CVEs
                id_parts = [f'<a href="https://osv.dev/vulnerability/{osv_id}" target="_blank" class="underline font-mono text-indigo-600">{osv_id}</a>']
                for cve in cve_ids:
                    nvd = f"https://nvd.nist.gov/vuln/detail/{cve}"
                    id_parts.append(f'<a href="{nvd}" target="_blank" class="underline font-mono text-red-600">{cve}</a>')
                ids_html = " &nbsp;|&nbsp; ".join(id_parts)

                # Affected / fixed version range
                ver_parts = []
                if intro_ver:
                    ver_parts.append(f"引入版本 ≥ {intro_ver}")
                if fixed_ver:
                    ver_parts.append(f'<span class="text-green-700 font-semibold">修复版本: {fixed_ver}</span>')
                else:
                    ver_parts.append('<span class="text-red-600 font-semibold">⚠ 暂无修复版本</span>')
                ver_html = " &nbsp;·&nbsp; ".join(ver_parts) if ver_parts else ""

                # CWE
                cwe_html = ""
                if cwe_ids:
                    cwes = " ".join(
                        f'<a href="https://cwe.mitre.org/data/definitions/{c.replace("CWE-","")}.html" target="_blank" class="underline text-purple-600">{c}</a>'
                        for c in cwe_ids
                    )
                    cwe_html = f'<span class="text-gray-400">漏洞类型</span> {cwes} &nbsp;·&nbsp; '

                # External ref
                ref_html = ""
                if ref_url:
                    ref_html = f'<a href="{ref_url}" target="_blank" class="underline text-blue-500">📎 详情链接</a>'

                detail_html = (
                    f'<div class="font-medium text-gray-600 mb-1">{summary}</div>'
                    f'<div class="text-gray-400 text-xs space-y-0.5">'
                    f'  <div>{ids_html}</div>'
                    f'  <div>{cwe_html}{ref_html}'
                    + (f' &nbsp;·&nbsp; <span class="text-gray-400">发布 {published}</span>' if published else "")
                    + f'</div>'
                    + (f'  <div>{ver_html}</div>' if ver_html else "")
                    + f'</div>'
                )

                # --- Title: 模块名：CVE链接，源代码出处 ---
                # CVE links (prefer CVE IDs, fallback to OSV ID)
                if cve_ids:
                    cve_links_html = "、".join(
                        f'<a href="https://nvd.nist.gov/vuln/detail/{c}" target="_blank" class="underline font-mono text-red-600 hover:text-red-800">{c}</a>'
                        for c in cve_ids
                    )
                else:
                    cve_links_html = f'<a href="https://osv.dev/vulnerability/{osv_id}" target="_blank" class="underline font-mono text-indigo-600 hover:text-indigo-800">{osv_id}</a>'

                # Source file link on GitHub
                src_url = f"https://github.com/{self.owner}/{self.repo}/blob/HEAD/{source_file}"
                src_html = f'<a href="{src_url}" target="_blank" class="underline text-gray-500 hover:text-gray-700">{source_file}</a>' if source_file else ""

                title_html = (
                    f"{icon} <span class='font-mono font-bold text-gray-800'>{pkg_name}</span>"
                    f"：{cve_links_html}"
                    + (f"，{src_html}" if src_html else "")
                    + f" &nbsp;<span style='color:{sev_color}' class='text-xs font-semibold'>[{severity}]</span>"
                )

                findings.append({
                    "type": "CRITICAL" if severity == "CRITICAL" else "DANGER" if severity == "HIGH" else "WARNING",
                    "title": title_html,
                    "detail": detail_html,
                    "is_html": True,
                })

        # Cap deductions to avoid overly punishing repos with many medium CVEs
        score = max(0, min(100, score))

        if not findings:
            findings.append({
                "type": "POSITIVE",
                "title": f"✅ 已检查 {len(packages)} 个依赖包，未发现已知 CVE",
                "detail": f"通过 OSV.dev 数据库查询，依赖文件: {', '.join(dep_files_found)}",
            })
            summary = f"检查 {len(packages)} 个依赖，未发现 CVE"
        else:
            summary = f"检查 {len(packages)} 个依赖，{len(vuln_packages)} 个存在已知漏洞"

        risk_level = self._score_to_risk(score)

        findings.insert(0, {
            "type": "INFO",
            "title": f"📊 Score Breakdown — Final: <b>{score}</b> / 100",
            "detail": self._score_breakdown_html(score_steps, score),
            "is_html": True,
        })

        return {
            "score": score,
            "risk_level": risk_level,
            "summary": summary,
            "findings": findings,
            "metrics": {
                "dep_files": dep_files_found,
                "packages_checked": len(packages),
                "vulnerable_packages": list(vuln_packages),
            },
        }

    async def _fetch_file_content(self, client: httpx.AsyncClient, filename: str) -> str:
        import base64
        try:
            r = await client.get(
                f"{self.BASE}/repos/{self.owner}/{self.repo}/contents/{filename}"
            )
            if r.status_code != 200:
                return ""
            data = r.json()
            if data.get("encoding") == "base64":
                return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
            return ""
        except Exception:
            return ""

    def _parse_deps(self, content: str, filename: str, ecosystem: str) -> List[Dict]:
        packages = []
        if filename == "requirements.txt":
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                match = re.match(r"^([A-Za-z0-9_\-\.]+)", line)
                if match:
                    packages.append({"name": match.group(1), "ecosystem": ecosystem, "source_file": filename})

        elif filename == "package.json":
            try:
                data = json.loads(content)
                for section in ("dependencies", "devDependencies"):
                    for pkg in (data.get(section) or {}).keys():
                        packages.append({"name": pkg, "ecosystem": ecosystem, "source_file": filename})
            except Exception:
                pass

        elif filename == "go.mod":
            for line in content.splitlines():
                match = re.match(r"^\s+([^\s]+)\s+v([^\s]+)", line)
                if match:
                    packages.append({"name": match.group(1), "ecosystem": ecosystem, "version": match.group(2), "source_file": filename})

        elif filename == "pyproject.toml":
            for line in content.splitlines():
                match = re.search(r'["\']([A-Za-z0-9_\-\.]+)[>=<!]', line)
                if match:
                    packages.append({"name": match.group(1), "ecosystem": ecosystem, "source_file": filename})

        return packages

    async def _query_osv(self, packages: List[Dict]) -> List[Tuple[str, str, List]]:
        """Query OSV.dev batch API and extract rich CVE details."""
        if not packages:
            return []

        queries = [{"package": {"name": p["name"], "ecosystem": p["ecosystem"]}} for p in packages]

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.post(
                    f"{self.OSV}/querybatch",
                    json={"queries": queries},
                    headers={"Content-Type": "application/json"},
                )
                if r.status_code != 200:
                    return []

                results = r.json().get("results", [])
                vulns = []
                for i, result in enumerate(results):
                    advisories = result.get("vulns", [])
                    if advisories and i < len(packages):
                        pkg = packages[i]
                        enriched = [self._enrich_vuln(v) for v in advisories]
                        vulns.append((pkg["name"], pkg["ecosystem"], pkg.get("source_file", ""), enriched))
                return vulns
        except Exception:
            return []

    def _enrich_vuln(self, v: dict) -> dict:
        """Extract all useful fields from a single OSV vulnerability entry."""
        osv_id   = v.get("id", "")
        aliases  = v.get("aliases", [])
        summary  = v.get("summary", "暂无摘要")
        severity = self._get_severity(v)
        published = (v.get("published") or "")[:10]
        db_specific = v.get("database_specific", {})
        cwe_ids  = db_specific.get("cwe_ids", [])

        # CVE IDs from aliases
        cve_ids = [a for a in aliases if a.startswith("CVE-")]

        # Fixed version: look in affected[].ranges events
        fixed_version = None
        affected_intro = None
        for aff in v.get("affected", []):
            for rng in aff.get("ranges", []):
                if rng.get("type") == "ECOSYSTEM":
                    for evt in rng.get("events", []):
                        if "fixed" in evt:
                            fixed_version = evt["fixed"]
                        if "introduced" in evt and evt["introduced"] != "0":
                            affected_intro = evt["introduced"]

        # Best reference URL: prefer ADVISORY > WEB
        ref_url = None
        for ref in v.get("references", []):
            if ref.get("type") == "ADVISORY":
                ref_url = ref.get("url")
                break
        if not ref_url:
            for ref in v.get("references", []):
                if ref.get("type") == "WEB":
                    ref_url = ref.get("url")
                    break

        # NVD link for CVE IDs
        nvd_url = None
        if cve_ids:
            nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_ids[0]}"

        return {
            "id": osv_id,
            "cve_ids": cve_ids,
            "summary": summary,
            "severity": severity,
            "published": published,
            "cwe_ids": cwe_ids,
            "fixed_version": fixed_version,
            "affected_intro": affected_intro,
            "ref_url": ref_url or nvd_url,
            "nvd_url": nvd_url,
        }

    def _get_severity(self, vuln: dict) -> str:
        """Extract highest severity from OSV vulnerability."""
        # Try database_specific.severity first (cleaner string like HIGH/CRITICAL)
        db_sev = vuln.get("database_specific", {}).get("severity", "")
        if isinstance(db_sev, str) and db_sev.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "MODERATE"):
            return db_sev.upper()

        # Try affected[].ecosystem_specific
        for aff in vuln.get("affected", []):
            es = aff.get("ecosystem_specific", {}).get("severity", "")
            if es.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                return es.upper()

        # Fallback: parse CVSS vector - look for base score in CVSS string
        # Format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (no base score) 
        # or just a float string
        for s in vuln.get("severity", []):
            raw = s.get("score", "")
            # Try direct float
            try:
                val = float(raw)
                if val >= 9.0: return "CRITICAL"
                if val >= 7.0: return "HIGH"
                if val >= 4.0: return "MEDIUM"
                return "LOW"
            except ValueError:
                pass
            # CVSS vector string - estimate from C/I/A components
            if "C:H" in raw and "I:H" in raw:
                return "CRITICAL"
            if "C:H" in raw or "I:H" in raw:
                return "HIGH"
            if "C:L" in raw or "I:L" in raw:
                return "MEDIUM"

        return "MEDIUM"

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
        if score >= 80:
            return "LOW"
        elif score >= 60:
            return "MEDIUM"
        elif score >= 40:
            return "HIGH"
        return "CRITICAL"
