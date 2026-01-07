#!/usr/bin/env python3
"""Fetch a HackerOne report and render it to Markdown."""
from __future__ import annotations

import argparse
import os
import re
from typing import Any, Dict, Optional, Tuple

try:
    import requests
except ImportError as exc:
    raise SystemExit("Missing dependency: requests. Install with `pip install requests`.") from exc

PUBLIC_JSON_URL = "https://hackerone.com/reports/{id}.json"
CUSTOMER_API_URL = "https://api.hackerone.com/v1/reports/{id}"
HACKER_API_URL = "https://api.hackerone.com/v1/hackers/reports/{id}"

UA = "h1_to_md/1.1 (+https://hackerone.com/)"
REPORT_ID_RE = re.compile(r"/reports/(\d+)(?:\b|/|$)")


def parse_report_id(s: str) -> Optional[str]:
    m = REPORT_ID_RE.search(s)
    if m:
        return m.group(1)
    return s if s.isdigit() else None


def http_get_json(url: str, auth: Optional[Tuple[str, str]] = None, timeout: int = 30) -> Dict[str, Any]:
    headers = {"Accept": "application/json", "User-Agent": UA}
    r = requests.get(url, headers=headers, auth=auth, timeout=timeout)
    if r.status_code != 200:
        raise RuntimeError(f"GET {url} failed: {r.status_code} {r.reason}\nBody: {r.text[:400]}")
    return r.json()


def safe_get(d: Dict[str, Any], path: str, default: Any = None) -> Any:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def normalize_public(j: Dict[str, Any]) -> Dict[str, Any]:
    team = j.get("team") or {}
    reporter = j.get("reporter") or {}
    severity = j.get("severity") or {}

    return {
        "source": "hackerone_public_json",
        "id": j.get("id"),
        "url": j.get("url"),
        "title": j.get("title"),
        "state": j.get("state"),
        "substate": j.get("readable_substate") or j.get("substate"),
        "created_at": j.get("created_at"),
        "submitted_at": j.get("submitted_at"),
        "disclosed_at": j.get("disclosed_at"),
        "public": j.get("public"),
        "visibility": j.get("visibility"),
        "team_handle": team.get("handle"),
        "team_name": safe_get(team, "profile.name"),
        "reporter_username": reporter.get("username"),
        "severity_rating": j.get("severity_rating") or safe_get(severity, "rating"),
        "weakness": safe_get(j, "weakness.name"),
        "cve_ids": j.get("cve_ids") or [],
        "structured_scope": safe_get(j, "structured_scope.asset_identifier"),
        "body_md": j.get("vulnerability_information") or "",
    }


def normalize_official_api(j: Dict[str, Any]) -> Dict[str, Any]:
    data = j.get("data") or {}
    attrs = data.get("attributes") or {}
    rels = data.get("relationships") or {}

    title = attrs.get("title") or attrs.get("name")
    body = attrs.get("vulnerability_information") or attrs.get("description") or ""

    return {
        "source": "hackerone_official_api",
        "id": data.get("id"),
        "url": attrs.get("url") or "",
        "title": title,
        "state": attrs.get("state"),
        "substate": attrs.get("substate"),
        "created_at": attrs.get("created_at"),
        "submitted_at": attrs.get("submitted_at"),
        "disclosed_at": attrs.get("disclosed_at"),
        "public": attrs.get("public"),
        "visibility": attrs.get("visibility"),
        "team_handle": safe_get(rels, "program.data.id") or safe_get(rels, "program.data.attributes.handle"),
        "team_name": "",
        "reporter_username": safe_get(rels, "reporter.data.attributes.username") or "",
        "severity_rating": safe_get(rels, "severity.data.attributes.rating") or attrs.get("severity_rating"),
        "weakness": safe_get(rels, "weakness.data.attributes.name") or "",
        "cve_ids": attrs.get("cve_ids") or [],
        "structured_scope": "",
        "body_md": body,
    }


def render_markdown(r: Dict[str, Any]) -> str:
    def fmt_dt(s: Any) -> str:
        return "" if not s else str(s)

    lines = [
        "---",
        "source: HackerOne",
        f"report_id: {r.get('id') or ''}",
        f"report_url: {r.get('url') or ''}",
    ]
    if r.get("team_handle"):
        lines.append(f"team: {r.get('team_handle')}")
    if r.get("reporter_username"):
        lines.append(f"reporter: {r.get('reporter_username')}")
    if r.get("severity_rating"):
        lines.append(f"severity: {r.get('severity_rating')}")
    lines.append(f"created_at: {fmt_dt(r.get('created_at'))}")
    if r.get("disclosed_at"):
        lines.append(f"disclosed_at: {fmt_dt(r.get('disclosed_at'))}")
    lines.append("---\n")

    title = r.get("title") or f"HackerOne Report {r.get('id')}"
    lines.append(f"# {title}\n")

    lines.append("## Metadata\n")
    meta = {
        "Report URL": r.get("url"),
        "Team": r.get("team_handle") or r.get("team_name"),
        "Reporter": r.get("reporter_username"),
        "Severity": r.get("severity_rating"),
        "Weakness": r.get("weakness"),
        "CVE IDs": ", ".join(r.get("cve_ids") or []) if isinstance(r.get("cve_ids"), list) else (r.get("cve_ids") or ""),
        "State": r.get("state"),
        "Substate": r.get("substate"),
        "Created": fmt_dt(r.get("created_at")),
        "Submitted": fmt_dt(r.get("submitted_at")),
        "Disclosed": fmt_dt(r.get("disclosed_at")),
        "Scope/Asset": r.get("structured_scope"),
        "Visibility": r.get("visibility"),
    }
    for k, v in meta.items():
        if v:
            lines.append(f"- **{k}:** {v}")
    lines.append("")

    body = (r.get("body_md") or "").strip()
    lines.append("## Report\n")
    lines.append(body if body else "(No report body was available in the fetched data.)")
    lines.append("")

    return "\n".join(lines)


def fetch_from_url(url_or_id: str, api_mode: str, username: str, token: str) -> Dict[str, Any]:
    rid = parse_report_id(url_or_id)
    if not rid:
        raise RuntimeError("Could not parse report id. Use https://hackerone.com/reports/<id> or a numeric id.")

    public_error: Optional[Exception] = None
    if api_mode in ("auto", "public"):
        try:
            j = http_get_json(PUBLIC_JSON_URL.format(id=rid))
            return normalize_public(j)
        except Exception as exc:
            public_error = exc
            if api_mode == "public":
                raise

    if not (username and token):
        hint = "Provide credentials via --username/--token or H1_USER/H1_TOKEN."
        msg = "Public fetch failed or report is not public, and no API credentials were provided."
        if public_error:
            msg = f"{msg}\nPublic fetch error: {public_error}\n{hint}"
        else:
            msg = f"{msg}\n{hint}"
        raise RuntimeError(msg)

    if api_mode in ("auto", "customer"):
        j = http_get_json(CUSTOMER_API_URL.format(id=rid), auth=(username, token))
        return normalize_official_api(j)

    if api_mode == "hacker":
        j = http_get_json(HACKER_API_URL.format(id=rid), auth=(username, token))
        return normalize_official_api(j)

    raise RuntimeError(f"Unknown api_mode: {api_mode}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate report.md from a HackerOne report URL/ID.")
    ap.add_argument("input", help="HackerOne report URL or numeric id")
    ap.add_argument("-o", "--output", default="report.md", help="Output markdown filename (default: report.md)")
    ap.add_argument("--api-mode", choices=["auto", "public", "customer", "hacker"], default="auto")
    ap.add_argument("--username", default=os.getenv("H1_USER", ""))
    ap.add_argument("--token", default=os.getenv("H1_TOKEN", ""))
    args = ap.parse_args()

    r = fetch_from_url(args.input, args.api_mode, args.username, args.token)
    md = render_markdown(r)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(md)

    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
