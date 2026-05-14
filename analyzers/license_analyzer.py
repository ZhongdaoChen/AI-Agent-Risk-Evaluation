"""
License Compliance Analyzer
Evaluates license risk for commercial/enterprise usage
"""
import httpx


LICENSE_RISK = {
    # Low risk - permissive
    "MIT": (100, "LOW", "宽松许可证，商业使用无限制"),
    "Apache-2.0": (100, "LOW", "宽松许可证，含专利保护条款"),
    "BSD-2-Clause": (95, "LOW", "宽松许可证，商业使用无限制"),
    "BSD-3-Clause": (95, "LOW", "宽松许可证，商业使用无限制"),
    "ISC": (95, "LOW", "MIT 等价，商业使用无限制"),
    "Unlicense": (90, "LOW", "公共域，无任何限制"),
    "CC0-1.0": (90, "LOW", "公共域献出"),
    "MPL-2.0": (80, "MEDIUM", "文件级 Copyleft，修改的文件需开源，独立模块可闭源"),
    "LGPL-2.1": (70, "MEDIUM", "弱 Copyleft，动态链接无需开源，静态链接需开源"),
    "LGPL-3.0": (70, "MEDIUM", "弱 Copyleft，动态链接无需开源，静态链接需开源"),
    "LGPL-2.0": (70, "MEDIUM", "弱 Copyleft"),
    # High risk - Copyleft
    "GPL-2.0": (50, "HIGH", "强 Copyleft，分发时衍生作品必须开源，商业产品风险高"),
    "GPL-3.0": (50, "HIGH", "强 Copyleft，分发时衍生作品必须开源，商业产品风险高"),
    "GPL-2.0-only": (50, "HIGH", "强 Copyleft，商业产品风险高"),
    "GPL-3.0-only": (50, "HIGH", "强 Copyleft，商业产品风险高"),
    # Critical - Network Copyleft
    "AGPL-3.0": (25, "CRITICAL", "网络 Copyleft，通过网络提供服务也必须开源，SaaS 场景高危"),
    "AGPL-3.0-only": (25, "CRITICAL", "网络 Copyleft，SaaS 场景高危"),
    "SSPL-1.0": (20, "CRITICAL", "超级 Copyleft (MongoDB)，整个软件栈都需开源"),
    # Unknown
    "NOASSERTION": (30, "HIGH", "许可证未明确声明，法律风险高"),
    "NONE": (10, "CRITICAL", "无任何许可证，默认版权保留，使用即侵权"),
}


class LicenseAnalyzer:
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
        async with httpx.AsyncClient(headers=self.headers, timeout=15) as client:
            r = await client.get(f"{self.BASE}/repos/{self.owner}/{self.repo}/license")

        if r.status_code == 404:
            spdx = "NONE"
            license_name = "无许可证"
            license_url = None
        elif r.status_code == 200:
            data = r.json()
            license_info = data.get("license", {})
            spdx = license_info.get("spdx_id", "NOASSERTION")
            license_name = license_info.get("name", spdx)
            license_url = data.get("html_url")
        else:
            spdx = "NOASSERTION"
            license_name = "未知"
            license_url = None

        if spdx in LICENSE_RISK:
            score, risk_level, detail = LICENSE_RISK[spdx]
        else:
            score, risk_level, detail = 40, "MEDIUM", f"自定义或未识别许可证 ({spdx})，需法务评估"

        findings = []

        if risk_level == "CRITICAL":
            findings.append({
                "type": "CRITICAL",
                "title": f"🚨 {license_name} - 高风险许可证",
                "detail": detail,
            })
        elif risk_level == "HIGH":
            findings.append({
                "type": "DANGER",
                "title": f"⚠️ {license_name} - 商业使用受限",
                "detail": detail,
            })
        elif risk_level == "MEDIUM":
            findings.append({
                "type": "WARNING",
                "title": f"⚠️ {license_name} - 使用时需注意",
                "detail": detail,
            })
        else:
            findings.append({
                "type": "POSITIVE",
                "title": f"✅ {license_name} - 商业友好",
                "detail": detail,
            })

        # Additional guidance
        if spdx in ("AGPL-3.0", "AGPL-3.0-only", "SSPL-1.0"):
            findings.append({
                "type": "CRITICAL",
                "title": "🚨 SaaS/云服务场景特别警告",
                "detail": "在云环境部署此 Agent 对外提供服务，可能触发开源义务，需在使用前咨询法务",
            })

        if spdx == "NONE":
            findings.append({
                "type": "CRITICAL",
                "title": "🚨 无许可证即版权保留",
                "detail": "根据著作权法，无许可证代码的版权归作者所有，未经授权使用属于侵权",
            })

        return {
            "score": score,
            "risk_level": risk_level,
            "summary": f"{license_name} ({spdx})",
            "findings": findings,
            "metrics": {
                "spdx_id": spdx,
                "license_name": license_name,
                "license_url": license_url,
            },
        }
