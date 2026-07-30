from __future__ import annotations

import argparse
import asyncio
import html
import json
import os
import sys
from pathlib import Path
from typing import Any

from dotenv import dotenv_values

from analyzers.skill_analyzer import SkillAnalyzer


DOTENV_ALLOWLIST = {"QWEN_API_KEY"}


def main(argv: list[str] | None = None) -> int:
    _load_allowed_dotenv(Path.cwd() / ".env")
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return asyncio.run(_run_scan(args))
    parser.print_help()
    return 2


def _load_allowed_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for key, value in dotenv_values(path).items():
        if key in DOTENV_ALLOWLIST and value is not None:
            os.environ.setdefault(key, value)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="appsec-skill-security-checker",
        description="Run the Skill Security Quality scanner against a local checkout.",
    )
    subparsers = parser.add_subparsers(dest="command")
    scan = subparsers.add_parser("scan", help="Scan local skill directories")
    scan.add_argument("--repo", default=".", help="Local repository checkout path")
    scan.add_argument("--skills", nargs="*", default=None, help="Skill paths relative to --repo")
    scan.add_argument("--output", help="Write machine-readable JSON to this path")
    scan.add_argument("--summary-output", help="Write Markdown summary to this path")
    scan.add_argument("--lang", choices=("en", "zh"), default="en", help="Output language")
    scan.add_argument(
        "--fail-on",
        choices=("LOW", "MEDIUM", "HIGH", "CRITICAL"),
        help="Return exit 1 when risk is at or above this level",
    )
    return parser


async def _run_scan(args: argparse.Namespace) -> int:
    repo_path = str(Path(args.repo).resolve())
    skill_paths = [path for path in (args.skills or []) if path]
    analyzer = SkillAnalyzer("local", Path(repo_path).name, lang=args.lang)
    result = await analyzer.analyze_local(repo_path, skill_paths or None)
    exit_code = _exit_code_for_result(result, args.fail_on)
    payload = _build_payload(repo_path, skill_paths, result, exit_code)

    json_text = json.dumps(payload, ensure_ascii=False, indent=2)
    if args.output:
        _write_text(args.output, json_text + "\n")
        _write_text(str(Path(args.output).with_suffix(".html")), _render_html_details(result))
    else:
        print(json_text)

    if args.summary_output:
        _write_text(args.summary_output, _render_markdown(payload))

    return exit_code


def _exit_code_for_result(result: dict[str, Any], fail_on: str | None) -> int:
    risk_level = str(result.get("risk_level", "UNKNOWN")).upper()
    if risk_level == "UNKNOWN":
        return 3
    if fail_on and _risk_rank(risk_level) >= _risk_rank(fail_on):
        return 1
    return 0


def _risk_rank(risk_level: str) -> int:
    return {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }.get(str(risk_level).upper(), 0)


def _build_payload(repo_path: str, skill_paths: list[str], result: dict[str, Any], exit_code: int) -> dict[str, Any]:
    raw_result = {
        key: value
        for key, value in result.items()
        if key != "findings"
    }
    return {
        "schema_version": "1.0",
        "tool": "appsec-skill-security-checker",
        "scan": {
            "mode": "local",
            "repo_path": repo_path,
            "skills": skill_paths,
        },
        "result": {
            "score": result.get("score"),
            "risk_level": result.get("risk_level"),
            "summary": result.get("summary"),
            "metrics": result.get("metrics", {}),
        },
        "issues": result.get("issues", []),
        "raw_result": raw_result,
        "exit_code": exit_code,
    }


def _render_html_details(result: dict[str, Any]) -> str:
    blocks = []
    for finding in result.get("findings", []) or []:
        if not isinstance(finding, dict):
            continue
        title = html.escape(str(finding.get("title") or "Details"))
        detail = str(finding.get("detail") or "")
        if not finding.get("is_html"):
            detail = f"<pre>{html.escape(detail)}</pre>"
        blocks.append(f"<section><h2>{title}</h2>\n{detail}\n</section>")

    body = "\n".join(blocks) if blocks else "<p>No HTML details were produced.</p>"
    return "\n".join([
        "<!doctype html>",
        "<html lang=\"en\">",
        "<head>",
        "  <meta charset=\"utf-8\">",
        "  <title>Skill Risk Scan Details</title>",
        "  <style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:24px;color:#0f172a;}section{margin-bottom:24px;}h1{font-size:24px;}h2{font-size:18px;margin-top:24px;}</style>",
        "</head>",
        "<body>",
        "<h1>Skill Risk Scan Details</h1>",
        body,
        "</body>",
        "</html>",
        "",
    ])


def _render_markdown(payload: dict[str, Any]) -> str:
    result = payload["result"]
    metrics = result.get("metrics", {})
    lines = [
        "## Skill Risk Scan",
        "",
        f"Risk: {result.get('risk_level', 'UNKNOWN')}",
        f"Score: {result.get('score', 'n/a')} / 100",
        f"Summary: {result.get('summary', '')}",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Components scanned | {metrics.get('components_scanned', 0)} |",
        f"| Raw SkillSpector findings | {metrics.get('raw_issues_found', 0)} |",
        f"| Counted malicious High/Critical findings | {metrics.get('counted_high_critical_issues', 0)} |",
        f"| Recommendation | {metrics.get('recommendation', '')} |",
        "",
        "### Findings",
        "",
    ]

    issues = payload.get("issues", [])
    if not issues:
        lines.append("No malicious High/Critical skill findings were retained.")
        return "\n".join(lines) + "\n"

    lines.extend([
        "| Severity | Rule | File | Summary |",
        "|---|---|---|---|",
    ])
    for issue in issues:
        location = str(issue.get("file") or "")
        if issue.get("line"):
            location = f"{location}:{issue['line']}"
        lines.append(
            "| "
            f"{_md_cell(issue.get('severity', ''))} | "
            f"{_md_cell(issue.get('id', ''))} | "
            f"{_md_cell(location)} | "
            f"{_md_cell(issue.get('finding', ''))} |"
        )
    return "\n".join(lines) + "\n"


def _md_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


def _write_text(path: str, content: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
