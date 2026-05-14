"""
Supply Chain Integrity Analyzer
Evaluates the integrity and trustworthiness of the project's supply chain:
- Dependency lock files (poetry.lock, package-lock.json, etc.)
- Pinned vs unpinned version specifiers in requirements.txt
- SHA256 / hash verification for model weight downloads
- GitHub releases with checksum / SBOM assets
- HuggingFace model usage with pinned revisions
"""
import re
import base64
import json
import httpx
from typing import Optional


LOCK_FILES = [
    "poetry.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Pipfile.lock",
    "requirements.lock",
    "uv.lock",
    "pdm.lock",
]

SBOM_FILES = [
    "sbom.json",
    "sbom.xml",
    "cyclonedx.json",
    "cyclonedx.xml",
    "spdx.json",
    "bom.json",
    "bom.xml",
]


class SupplyChainAnalyzer:
    BASE = "https://api.github.com"
    HF_API = "https://huggingface.co/api"

    def __init__(self, owner: str, repo: str, token: str = None):
        self.owner = owner
        self.repo = repo
        self.gh_headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "AI-Risk-Evaluator/1.0",
        }
        if token:
            self.gh_headers["Authorization"] = f"token {token}"

    async def analyze(self) -> dict:
        async with httpx.AsyncClient(headers=self.gh_headers, timeout=20) as client:
            # File tree
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

            # ── Lock file check ─────────────────────────────────────────────
            found_lock = None
            for lf in LOCK_FILES:
                if lf.lower() in file_set_lower:
                    found_lock = lf
                    break

            # ── SBOM check ──────────────────────────────────────────────────
            found_sbom = None
            for sb in SBOM_FILES:
                if sb.lower() in file_set_lower:
                    found_sbom = sb
                    break
            # Also check releases folder
            if not found_sbom:
                sbom_in_releases = any(
                    "sbom" in f.lower() or "cyclonedx" in f.lower() or "spdx" in f.lower()
                    for f in files
                )
                if sbom_in_releases:
                    found_sbom = next(
                        f for f in files if "sbom" in f.lower() or "cyclonedx" in f.lower()
                    )

            # ── requirements.txt pin analysis ──────────────────────────────
            req_pin_ratio, req_total, req_pinned = None, 0, 0
            req_content = await self._fetch_file(client, "requirements.txt", default_branch)
            if req_content:
                req_total, req_pinned = self._analyze_pins(req_content)
                if req_total > 0:
                    req_pin_ratio = req_pinned / req_total

            # Also check pyproject.toml for dev deps
            pyproject_content = await self._fetch_file(client, "pyproject.toml", default_branch)

            # ── Model download hash verification ────────────────────────────
            model_hash_verified = False
            model_hash_risky = False
            hf_model_pinned = False
            hf_model_id: Optional[str] = None

            # Scan a few key source files for model download patterns
            src_files = [f for f in files if f.endswith((".py", ".ts", ".js")) and
                         any(kw in f.lower() for kw in ["model", "download", "load", "main", "app"]) and
                         not any(skip in f for skip in ["node_modules", ".git", "__pycache__", "venv"])][:6]

            for path in src_files:
                content = await self._fetch_file(client, path, default_branch)
                if not content:
                    continue
                # Hash verification patterns
                if re.search(r'(?i)(sha256|md5|hash[_\s]?check|verify[_\s]?hash|checksum)', content):
                    model_hash_verified = True
                # Unsafe model download patterns (wget/curl without verification)
                if re.search(r'(?i)(wget|curl|requests\.get)\s*\([^)]*\.(bin|pt|safetensors|gguf|onnx)', content):
                    model_hash_risky = True
                # HuggingFace model with pinned revision
                hf_match = re.search(
                    r'(?i)from_pretrained\s*\(\s*["\']([a-zA-Z0-9_\-/\.]+)["\']'
                    r'.*?revision\s*=\s*["\']([a-f0-9]{7,40}|[^\s"\']+)["\']',
                    content, re.DOTALL,
                )
                if hf_match:
                    hf_model_pinned = True
                    hf_model_id = hf_match.group(1)
                elif not hf_model_id:
                    hf_id_match = re.search(
                        r'(?i)from_pretrained\s*\(\s*["\']([a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-\.]+)["\']',
                        content,
                    )
                    if hf_id_match:
                        hf_model_id = hf_id_match.group(1)

            # ── Check GitHub releases for checksum assets ───────────────────
            release_has_checksums = False
            try:
                rel_r = await client.get(
                    f"{self.BASE}/repos/{self.owner}/{self.repo}/releases/latest"
                )
                if rel_r.status_code == 200:
                    assets = rel_r.json().get("assets", [])
                    for asset in assets:
                        name = asset.get("name", "").lower()
                        if any(kw in name for kw in ["sha256", "checksum", "hash", "sbom", ".sig"]):
                            release_has_checksums = True
                            break
            except Exception:
                pass

            # ── HuggingFace model card check ────────────────────────────────
            hf_has_model_card = False
            hf_model_card_detail = ""
            if hf_model_id:
                try:
                    hf_r = await client.get(
                        f"{self.HF_API}/models/{hf_model_id}",
                        headers={"User-Agent": "AI-Risk-Evaluator/1.0"},
                        timeout=10,
                    )
                    if hf_r.status_code == 200:
                        hf_data = hf_r.json()
                        card_data = hf_data.get("cardData", {})
                        hf_has_model_card = bool(card_data)
                        base_model = card_data.get("base_model", "")
                        license_id = card_data.get("license", "")
                        if base_model:
                            hf_model_card_detail = f"基础模型: {base_model}，许可证: {license_id or '未知'}"
                        else:
                            hf_model_card_detail = f"许可证: {license_id or '未知'}"
                except Exception:
                    pass

        # ── Score & findings ────────────────────────────────────────────────
        score = 60  # neutral baseline
        score_steps = [("Baseline", 60, 60)]
        findings = []

        # Lock file
        if found_lock:
            score += 20
            score_steps.append((f"Lock file: {found_lock}", 20, score))
            findings.append({
                "type": "POSITIVE",
                "title": f"✅ 依赖锁文件: {found_lock}",
                "detail": "锁文件确保所有环境使用完全一致的依赖版本，防止隐式升级引入恶意代码",
            })
        else:
            score -= 15
            score_steps.append(("Lock file missing", -15, score))
            findings.append({
                "type": "WARNING",
                "title": "⚠️ 缺少依赖锁文件",
                "detail": f"未找到 {' / '.join(LOCK_FILES[:4])} 等锁文件，依赖版本可能不一致，存在供应链攻击风险",
            })

        # requirements.txt pin ratio
        if req_total > 0:
            if req_pin_ratio >= 0.9:
                score += 10
                score_steps.append((f"Pinned deps ratio {int(req_pin_ratio*100)}%", 10, score))
                findings.append({
                    "type": "POSITIVE",
                    "title": f"✅ 依赖版本精确锁定 ({req_pinned}/{req_total} 个使用 ==)",
                    "detail": "requirements.txt 中绝大多数依赖使用精确版本号，减少供应链风险",
                })
            elif req_pin_ratio < 0.3:
                score -= 10
                score_steps.append((f"Unpinned deps ratio {int((1-req_pin_ratio)*100)}%", -10, score))
                findings.append({
                    "type": "WARNING",
                    "title": f"⚠️ 大量依赖版本未固定 ({req_total - req_pinned}/{req_total} 个未用 ==)",
                    "detail": "requirements.txt 中多数依赖使用宽松版本约束，新版本可能引入漏洞",
                })

        # SBOM
        if found_sbom:
            score += 10
            score_steps.append((f"SBOM: {found_sbom}", 10, score))
            findings.append({
                "type": "POSITIVE",
                "title": f"✅ 软件物料清单 (SBOM): {found_sbom}",
                "detail": "SBOM 提供完整的依赖组件清单，便于漏洞追踪和合规审计",
            })

        # Release checksums
        if release_has_checksums:
            score += 10
            score_steps.append(("Release checksums present", 10, score))
            findings.append({
                "type": "POSITIVE",
                "title": "✅ GitHub Release 包含校验文件",
                "detail": "发布版本附带 SHA256 / 签名文件，用户可验证下载完整性",
            })

        # Model hash verification
        if model_hash_verified:
            score += 5
            score_steps.append(("Model hash verification", 5, score))
            findings.append({
                "type": "POSITIVE",
                "title": "✅ 模型文件哈希校验",
                "detail": "代码在下载模型权重时验证了哈希值，防止被篡改的模型文件",
            })
        if model_hash_risky:
            score -= 10
            score_steps.append(("Model download without hash check", -10, score))
            findings.append({
                "type": "WARNING",
                "title": "⚠️ 模型文件下载未见校验逻辑",
                "detail": "检测到直接通过 wget/curl/requests 下载模型权重，未发现哈希验证步骤",
            })

        # HuggingFace model info
        if hf_model_id:
            if hf_model_pinned:
                score += 5
                score_steps.append((f"HuggingFace model pinned: {hf_model_id}", 5, score))
                findings.append({
                    "type": "POSITIVE",
                    "title": f"✅ HuggingFace 模型版本已固定: {hf_model_id}",
                    "detail": "使用了带 revision 的 from_pretrained()，模型版本可追溯",
                })
            else:
                findings.append({
                    "type": "INFO",
                    "title": f"ℹ️ HuggingFace 模型未固定版本: {hf_model_id}",
                    "detail": "建议在 from_pretrained() 中指定 revision= 参数以锁定模型版本",
                })

            if hf_has_model_card:
                findings.append({
                    "type": "POSITIVE",
                    "title": f"✅ HuggingFace Model Card 存在",
                    "detail": hf_model_card_detail or "模型有完整的 Model Card，包含训练数据和使用说明",
                })
            elif hf_model_id:
                findings.append({
                    "type": "WARNING",
                    "title": f"⚠️ 模型 {hf_model_id} 缺少 Model Card",
                    "detail": "无 Model Card 意味着模型的训练数据、能力和限制均不透明",
                })

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
            "summary": self._build_summary(found_lock, req_total, req_pin_ratio, hf_model_id),
            "findings": findings,
            "metrics": {
                "lock_file": found_lock,
                "sbom_file": found_sbom,
                "req_total": req_total,
                "req_pinned": req_pinned,
                "release_has_checksums": release_has_checksums,
                "model_hash_verified": model_hash_verified,
                "hf_model_id": hf_model_id,
                "hf_model_pinned": hf_model_pinned,
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

    def _analyze_pins(self, content: str):
        total = pinned = 0
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            total += 1
            if "==" in line:
                pinned += 1
        return total, pinned

    def _build_summary(self, lock, req_total, pin_ratio, hf_model):
        parts = []
        parts.append("🔒 锁文件 ✅" if lock else "🔒 锁文件 ❌")
        if req_total > 0 and pin_ratio is not None:
            pct = int(pin_ratio * 100)
            parts.append(f"版本固定 {pct}%")
        if hf_model:
            parts.append(f"模型: {hf_model}")
        return " · ".join(parts)

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
