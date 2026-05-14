"""
OpenSSF Scorecard Analyzer
Uses the public Scorecard API: https://api.securityscorecards.dev
"""
import httpx


CHECK_DESCRIPTIONS = {
    "Code-Review": "代码审查 - 提交是否经过评审",
    "Maintained": "维护状态 - 项目是否在活跃维护",
    "CII-Best-Practices": "CII 最佳实践徽章",
    "License": "许可证 - 是否有明确的 License",
    "Signed-Releases": "签名发布 - 发布是否有加密签名",
    "Binary-Artifacts": "二进制产物 - 是否包含不明二进制文件",
    "Branch-Protection": "分支保护 - 主分支是否有保护规则",
    "Dangerous-Workflow": "危险工作流 - CI 是否存在注入风险",
    "Dependency-Update-Tool": "依赖更新工具 - 是否使用 Dependabot 等",
    "Fuzzing": "模糊测试",
    "Packaging": "打包发布",
    "Pinned-Dependencies": "依赖锁定 - CI 依赖是否固定版本",
    "SAST": "静态分析 - 是否使用 SAST 工具",
    "Security-Policy": "安全策略 - 是否有 SECURITY.md",
    "Token-Permissions": "Token 权限 - CI 是否遵循最小权限原则",
    "Vulnerabilities": "已知漏洞 - 是否有未修复 CVE",
    "Webhooks": "Webhook 安全",
}


class ScorecardAnalyzer:
    API = "https://api.securityscorecards.dev"

    def __init__(self, owner: str, repo: str):
        self.owner = owner
        self.repo = repo

    async def analyze(self) -> dict:
        url = f"{self.API}/projects/github.com/{self.owner}/{self.repo}"
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(url)

            if r.status_code == 404:
                # Fallback: try deps.dev which has broader Scorecard coverage
                depsdev_result = await self._try_depsdev(client)
                if depsdev_result:
                    return depsdev_result
                return {
                    "score": 50,
                    "risk_level": "UNKNOWN",
                    "summary": "OpenSSF Scorecard 及 deps.dev 均暂无此仓库数据",
                    "findings": [
                        {
                            "type": "INFO",
                            "title": "📊 无 Scorecard 数据",
                            "detail": "该仓库未被收录，项目可能较新或知名度较低，建议手动运行 scorecard CLI",
                        }
                    ],
                    "metrics": {"available": False},
                }

        r.raise_for_status()
        data = r.json()

        raw_score = data.get("score", 0)  # 0-10 scale
        score = round(raw_score * 10)  # normalize to 0-100

        checks = data.get("checks", [])
        findings = []
        check_details = {}

        for check in checks:
            name = check.get("name", "")
            check_score = check.get("score", -1)  # -1 means N/A
            reason = check.get("reason", "")
            desc = CHECK_DESCRIPTIONS.get(name, name)
            check_details[name] = check_score

            if check_score == -1:
                continue

            normalized = check_score * 10

            if normalized < 30:
                findings.append({
                    "type": "DANGER",
                    "title": f"❌ {desc} ({check_score}/10)",
                    "detail": reason,
                })
            elif normalized < 60:
                findings.append({
                    "type": "WARNING",
                    "title": f"⚠️ {desc} ({check_score}/10)",
                    "detail": reason,
                })
            elif normalized >= 80:
                findings.append({
                    "type": "POSITIVE",
                    "title": f"✅ {desc} ({check_score}/10)",
                    "detail": reason,
                })

        # Special attention to critical checks
        vuln_score = check_details.get("Vulnerabilities", -1)
        dangerous_wf = check_details.get("Dangerous-Workflow", -1)

        if vuln_score == 0:
            findings.insert(0, {
                "type": "CRITICAL",
                "title": "🚨 存在已知漏洞 (Vulnerabilities: 0/10)",
                "detail": "仓库依赖存在未修复的公开 CVE 漏洞",
            })

        if dangerous_wf == 0:
            findings.insert(0, {
                "type": "CRITICAL",
                "title": "🚨 CI 工作流存在注入风险 (Dangerous-Workflow: 0/10)",
                "detail": "CI 脚本可能被恶意 PR 注入执行任意代码",
            })

        risk_level = self._score_to_risk(score)

        return {
            "score": score,
            "risk_level": risk_level,
            "summary": f"OpenSSF Scorecard 综合评分 {raw_score:.1f}/10",
            "findings": findings[:15],  # cap at 15 findings
            "metrics": {
                "available": True,
                "raw_score": raw_score,
                "check_details": check_details,
                "date": data.get("date", ""),
            },
        }

    def _score_to_risk(self, score: int) -> str:
        if score >= 70:
            return "LOW"
        elif score >= 50:
            return "MEDIUM"
        elif score >= 30:
            return "HIGH"
        return "CRITICAL"

    async def _try_depsdev(self, client: httpx.AsyncClient) -> dict | None:
        """Fallback: fetch Scorecard data from deps.dev, which has broader coverage."""
        try:
            import urllib.parse
            project_id = urllib.parse.quote(f"github.com/{self.owner}/{self.repo}", safe="")
            r = await client.get(f"https://api.deps.dev/v3alpha/projects/{project_id}")
            if r.status_code != 200:
                return None
            data = r.json()
            sc = data.get("scorecard", {})
            checks = sc.get("checks", [])
            if not checks:
                return None

            # Parse checks identical to the main flow
            findings = []
            check_details = {}
            total, count = 0, 0
            for check in checks:
                name = check.get("name", "")
                check_score = check.get("score", -1)
                reason = check.get("reason", "")
                desc = CHECK_DESCRIPTIONS.get(name, name)
                check_details[name] = check_score
                if check_score == -1:
                    continue
                total += check_score
                count += 1
                normalized = check_score * 10
                if normalized < 30:
                    findings.append({"type": "DANGER",    "title": f"❌ {desc} ({check_score}/10)", "detail": reason})
                elif normalized < 60:
                    findings.append({"type": "WARNING",   "title": f"⚠️ {desc} ({check_score}/10)", "detail": reason})
                elif normalized >= 80:
                    findings.append({"type": "POSITIVE",  "title": f"✅ {desc} ({check_score}/10)", "detail": reason})

            raw_score = round(total / count, 1) if count else 0
            score = round(raw_score * 10)
            date = sc.get("date", "")[:10] if sc.get("date") else ""

            if check_details.get("Vulnerabilities") == 0:
                findings.insert(0, {"type": "CRITICAL", "title": "🚨 存在已知漏洞 (Vulnerabilities: 0/10)", "detail": "仓库依赖存在未修复的公开 CVE 漏洞"})
            if check_details.get("Dangerous-Workflow") == 0:
                findings.insert(0, {"type": "CRITICAL", "title": "🚨 CI 工作流存在注入风险 (Dangerous-Workflow: 0/10)", "detail": "CI 脚本可能被恶意 PR 注入执行任意代码"})

            return {
                "score": score,
                "risk_level": self._score_to_risk(score),
                "summary": f"Scorecard {raw_score:.1f}/10（数据来自 deps.dev）",
                "findings": findings[:15],
                "metrics": {"available": True, "raw_score": raw_score, "check_details": check_details, "date": date, "source": "deps.dev"},
            }
        except Exception:
            return None
