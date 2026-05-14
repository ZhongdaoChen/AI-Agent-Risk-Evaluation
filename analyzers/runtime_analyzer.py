"""
Runtime Isolation Analyzer
Checks whether the AI agent provides runtime isolation and container security:
- Dockerfile presence and configuration
  - Non-root USER instruction
  - No dangerous volume mounts (docker socket)
  - No --privileged flag in docker-compose
  - Resource limits (memory/CPU)
- .devcontainer support
- E2B / Modal / sandbox platform integrations
- docker-compose security settings
"""
import re
import base64
import httpx


class RuntimeAnalyzer:
    BASE = "https://api.github.com"

    # Pairs of (filename_patterns, fetch_path)
    CONTAINER_FILES = [
        "Dockerfile",
        "dockerfile",
        "Dockerfile.dev",
        "Dockerfile.prod",
        "docker-compose.yml",
        "docker-compose.yaml",
        "docker-compose.prod.yml",
        ".devcontainer/devcontainer.json",
        ".devcontainer.json",
    ]

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

            # ── Locate container / isolation files ─────────────────────────
            dockerfile_path = None
            compose_path = None
            devcontainer_path = None

            for f in files:
                fl = f.lower()
                if fl in ("dockerfile", "dockerfile.dev", "dockerfile.prod") or fl.endswith("/dockerfile"):
                    dockerfile_path = f
                elif fl in ("docker-compose.yml", "docker-compose.yaml",
                            "docker-compose.prod.yml", "docker-compose.prod.yaml"):
                    compose_path = f
                elif fl in (".devcontainer/devcontainer.json", ".devcontainer.json", "devcontainer.json"):
                    devcontainer_path = f

            # ── Fetch contents ──────────────────────────────────────────────
            dockerfile_content = ""
            compose_content = ""
            devcontainer_content = ""
            req_content = ""

            if dockerfile_path:
                dockerfile_content = await self._fetch_file(client, dockerfile_path, default_branch)
            if compose_path:
                compose_content = await self._fetch_file(client, compose_path, default_branch)
            if devcontainer_path:
                devcontainer_content = await self._fetch_file(client, devcontainer_path, default_branch)

            # Check requirements for sandbox integrations
            req_content = await self._fetch_file(client, "requirements.txt", default_branch)
            pyproject = await self._fetch_file(client, "pyproject.toml", default_branch)
            combined_deps = req_content + "\n" + pyproject

        # ── Evaluate ────────────────────────────────────────────────────────
        score = 50  # neutral baseline — many agent projects don't ship Docker
        score_steps = [("基准分（中性 — 很多Agent项目不含Docker）", 50, 50)]
        findings = []

        # ── Dockerfile analysis ─────────────────────────────────────────────
        if dockerfile_content:
            score += 15
            score_steps.append(("Dockerfile present", 15, score))
            findings.append({
                "type": "POSITIVE",
                "title": f"✅ 提供 Dockerfile: {dockerfile_path}",
                "detail": "容器化部署支持，有助于环境隔离",
            })

            # Non-root user
            user_instructions = re.findall(r'(?mi)^USER\s+(\S+)', dockerfile_content)
            if user_instructions:
                last_user = user_instructions[-1].lower()
                if last_user not in ("root", "0"):
                    score += 20
                    score_steps.append((f"Non-root user: USER {user_instructions[-1]}", 20, score))
                    findings.append({
                        "type": "POSITIVE",
                        "title": f"✅ 容器以非 root 用户运行 (USER {user_instructions[-1]})",
                        "detail": "遵循最小权限原则，容器以普通用户身份运行",
                    })
                else:
                    score -= 20
                    score_steps.append(("Container runs as root", -20, score))
                    findings.append({
                        "type": "DANGER",
                        "title": "🔴 容器以 root 用户运行",
                        "detail": "Dockerfile 中 USER 指令指定为 root，容器内进程拥有最高权限，存在提权风险",
                    })
            else:
                # No USER = defaults to root
                score -= 15
                score_steps.append(("No USER instruction (defaults to root)", -15, score))
                findings.append({
                    "type": "WARNING",
                    "title": "⚠️ Dockerfile 未指定非 root 用户",
                    "detail": "未找到 USER 指令，容器默认以 root 运行，建议添加 `USER nonroot` 或专用用户",
                })

            # Resource limits
            if re.search(r'(?i)(--memory|--cpus|ulimit|mem_limit)', dockerfile_content):
                score += 5
                score_steps.append(("Dockerfile resource limits", 5, score))
                findings.append({
                    "type": "POSITIVE",
                    "title": "✅ 设置了资源限制",
                    "detail": "容器有内存或 CPU 限制，防止资源耗尽攻击",
                })

            # Sensitive capabilities
            if re.search(r'(?i)--privileged', dockerfile_content):
                score -= 20
                score_steps.append(("Dockerfile --privileged flag", -20, score))
                findings.append({
                    "type": "CRITICAL",
                    "title": "🚨 Dockerfile 使用了 --privileged",
                    "detail": "--privileged 赋予容器几乎等同宿主机的权限，极度危险",
                })

        else:
            findings.append({
                "type": "INFO",
                "title": "ℹ️ 未提供 Dockerfile",
                "detail": "项目未包含容器化配置，运行环境隔离依赖用户自行处理",
            })

        # ── docker-compose analysis ─────────────────────────────────────────
        if compose_content:
            findings.append({
                "type": "POSITIVE" if not re.search(r'(?i)privileged\s*:\s*true', compose_content) else "DANGER",
                "title": "✅ 提供 docker-compose 配置" if not re.search(r'(?i)privileged\s*:\s*true', compose_content)
                         else "🚨 docker-compose 使用 privileged: true",
                "detail": "可通过 docker-compose 一键部署" if not re.search(r'(?i)privileged\s*:\s*true', compose_content)
                          else "privileged: true 赋予容器宿主机级别权限，高度危险",
            })

            # Docker socket mount
            if re.search(r'/var/run/docker\.sock', compose_content):
                score -= 20
                score_steps.append(("Docker socket mount (/var/run/docker.sock)", -20, score))
                findings.append({
                    "type": "CRITICAL",
                    "title": "🚨 挂载了 Docker socket (/var/run/docker.sock)",
                    "detail": "挂载 Docker socket 等同于给容器宿主机 root 权限，可完全逃逸容器隔离",
                })

            # Privileged in compose
            if re.search(r'(?i)privileged\s*:\s*true', compose_content):
                score -= 20
                score_steps.append(("docker-compose privileged: true", -20, score))

            # Resource limits in compose
            if re.search(r'(?i)(mem_limit|memory:|cpus:)', compose_content):
                score += 5
                score_steps.append(("docker-compose resource limits", 5, score))
                findings.append({
                    "type": "POSITIVE",
                    "title": "✅ docker-compose 设置了资源限制",
                    "detail": "Compose 配置中包含内存或 CPU 限制",
                })

        # ── devcontainer ────────────────────────────────────────────────────
        if devcontainer_path:
            score += 10
            score_steps.append(("Dev Container configuration", 10, score))
            findings.append({
                "type": "POSITIVE",
                "title": "✅ 提供 Dev Container 配置",
                "detail": "VS Code Dev Container 确保开发环境标准化，减少环境差异带来的安全风险",
            })

        # ── Sandbox platform integrations ───────────────────────────────────
        sandbox_found = []
        if re.search(r'(?i)\be2b\b|e2b[_\-]sdk', combined_deps):
            sandbox_found.append("E2B")
        if re.search(r'(?i)\bmodal\b', combined_deps):
            sandbox_found.append("Modal")
        if re.search(r'(?i)(pyodide|webassembly|wasm)', combined_deps):
            sandbox_found.append("WebAssembly")
        if re.search(r'(?i)(firejail|bubblewrap|nsjail|seccomp)', combined_deps):
            sandbox_found.append("Linux 沙箱")

        if sandbox_found:
            score += 10
            score_steps.append((f"Sandbox integrations: {', '.join(sandbox_found)}", 10, score))
            findings.append({
                "type": "POSITIVE",
                "title": f"✅ 集成沙箱平台: {', '.join(sandbox_found)}",
                "detail": f"项目使用 {', '.join(sandbox_found)} 提供代码执行隔离，降低逃逸风险",
            })

        # ── Summary bonus/penalty ───────────────────────────────────────────
        has_any_isolation = bool(dockerfile_content or devcontainer_path or sandbox_found)
        if not has_any_isolation:
            score -= 10
            score_steps.append(("No runtime isolation found", -10, score))
            findings.append({
                "type": "WARNING",
                "title": "⚠️ 无运行时隔离配置",
                "detail": "未发现 Dockerfile、Dev Container 或沙箱集成，AI Agent 直接在宿主环境运行",
            })

        score = max(0, min(100, score))
        findings.insert(0, {
            "type": "INFO",
            "title": f"📊 Score Breakdown — Final: <b>{score}</b> / 100",
            "detail": self._score_breakdown_html(score_steps, score),
            "is_html": True,
        })
        summary_parts = []
        if dockerfile_path:
            summary_parts.append("Docker ✅")
        if devcontainer_path:
            summary_parts.append("DevContainer ✅")
        if sandbox_found:
            summary_parts.append(f"Sandbox: {', '.join(sandbox_found)}")
        if not summary_parts:
            summary_parts.append("无容器 / 沙箱配置")

        return {
            "score": score,
            "risk_level": self._score_to_risk(score),
            "summary": " · ".join(summary_parts),
            "findings": findings,
            "metrics": {
                "has_dockerfile": bool(dockerfile_content),
                "dockerfile_path": dockerfile_path,
                "has_compose": bool(compose_content),
                "has_devcontainer": bool(devcontainer_path),
                "sandbox_integrations": sandbox_found,
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
