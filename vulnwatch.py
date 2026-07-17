#!/usr/bin/env python3
"""Build a ranked cross-platform vulnerability report from public security feeds."""

from __future__ import annotations

import argparse
import csv
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
UA = "VulnWatch/1.0 defensive-vulnerability-report"

PLATFORMS = {
    "Windows": ("microsoft:windows", "windows 10", "windows 11", "windows server"),
    "macOS": ("apple:macos", "apple:mac_os_x", "macos", "mac os x"),
    "Linux": ("linux:linux_kernel", "linux kernel", "ubuntu", "debian", "red hat", "fedora"),
    "Android": ("google:android", "android"),
    "iOS/iPadOS": ("apple:iphone_os", "apple:ipados", "ios", "ipados", "iphone os"),
}


@dataclass
class Finding:
    cve: str
    platforms: list[str]
    title: str
    description: str
    published: str
    modified: str
    cvss: float
    severity: str
    epss: float
    epss_percentile: float
    known_exploited: bool
    ransomware_use: bool
    cisa_due_date: str
    risk_score: float
    solution: str
    vendor_advisory: str
    nvd_url: str


def get_json(url: str, params: dict[str, Any] | None = None, api_key: str = "", retries: int = 4) -> Any:
    if params:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    headers = {"User-Agent": UA, "Accept": "application/json"}
    if api_key and url.startswith(NVD_URL):
        headers["apiKey"] = api_key
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=45) as response:
                return json.load(response)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
            if attempt == retries - 1:
                raise RuntimeError(f"Request failed after {retries} attempts: {url}: {exc}") from exc
            retry_after = getattr(exc, "headers", {}).get("Retry-After") if hasattr(exc, "headers") else None
            time.sleep(float(retry_after or (2 ** attempt)))
    raise AssertionError("unreachable")


def iso_nvd(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def fetch_recent_nvd(days: int, api_key: str) -> list[dict[str, Any]]:
    """Fetch recently published CVEs in NVD's maximum 120-day windows."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    records: dict[str, dict[str, Any]] = {}
    cursor = start
    while cursor < end:
        window_end = min(cursor + timedelta(days=119), end)
        offset = 0
        while True:
            data = get_json(NVD_URL, {
                "pubStartDate": iso_nvd(cursor), "pubEndDate": iso_nvd(window_end),
                "startIndex": offset, "resultsPerPage": 2000,
            }, api_key)
            batch = data.get("vulnerabilities", [])
            for wrapper in batch:
                cve = wrapper.get("cve", {})
                if cve.get("id"):
                    records[cve["id"]] = cve
            offset += len(batch)
            if not batch or offset >= int(data.get("totalResults", 0)):
                break
            time.sleep(0.7 if api_key else 6.1)
        cursor = window_end + timedelta(milliseconds=1)
    return list(records.values())


def walk_cpe_strings(node: Any) -> Iterable[str]:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "criteria" and isinstance(value, str):
                yield value.lower()
            else:
                yield from walk_cpe_strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from walk_cpe_strings(value)


def english_description(cve: dict[str, Any]) -> str:
    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            return re.sub(r"\s+", " ", item.get("value", "")).strip()
    return ""


def detect_platforms(cve: dict[str, Any], kev: dict[str, Any] | None = None) -> list[str]:
    cpes = " ".join(walk_cpe_strings(cve.get("configurations", [])))
    evidence = " ".join((cpes, english_description(cve).lower(),
                         str((kev or {}).get("vendorProject", "")).lower(),
                         str((kev or {}).get("product", "")).lower()))
    matches = []
    for platform, needles in PLATFORMS.items():
        if any(needle in evidence for needle in needles):
            matches.append(platform)
    # Avoid treating Apple mobile CVEs as macOS solely because the vendor is Apple.
    if "iOS/iPadOS" in matches and "macOS" in matches and "macos" not in evidence and "mac_os_x" not in evidence:
        matches.remove("macOS")
    return matches


def cvss_info(cve: dict[str, Any]) -> tuple[float, str]:
    metrics = cve.get("metrics", {})
    for version in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(version, [])
        if entries:
            data = entries[0].get("cvssData", {})
            score = float(data.get("baseScore", 0) or 0)
            severity = entries[0].get("baseSeverity") or data.get("baseSeverity") or "UNKNOWN"
            return score, str(severity).upper()
    return 0.0, "UNKNOWN"


def references(cve: dict[str, Any]) -> tuple[str, str]:
    refs = cve.get("references", [])
    vendor = [r.get("url", "") for r in refs if "Vendor Advisory" in r.get("tags", [])]
    patch = [r.get("url", "") for r in refs if "Patch" in r.get("tags", [])]
    return (vendor or patch or [""])[0], (patch or vendor or [""])[0]


def risk_score(cvss: float, epss: float, kev: bool, ransomware: bool, published: str) -> float:
    age_bonus = 0.0
    try:
        published_at = datetime.fromisoformat(published.replace("Z", "+00:00"))
        # NVD normally returns UTC timestamps, but some records omit the offset.
        # Normalize both forms before doing arithmetic (required by Python 3.14).
        if published_at.tzinfo is None:
            published_at = published_at.replace(tzinfo=timezone.utc)
        else:
            published_at = published_at.astimezone(timezone.utc)
        age = (datetime.now(timezone.utc) - published_at).days
        age_bonus = max(0.0, 10.0 * (1.0 - age / 365.0))
    except (TypeError, ValueError):
        pass
    score = cvss * 3.5 + epss * 25.0 + (30.0 if kev else 0.0) + (8.0 if ransomware else 0.0) + age_bonus
    return round(min(100.0, score), 1)


def solution_for(cve: dict[str, Any], kev: dict[str, Any] | None) -> tuple[str, str]:
    vendor_url, patch_url = references(cve)
    if kev and kev.get("requiredAction"):
        action = str(kev["requiredAction"]).strip()
        if kev.get("dueDate"):
            action += f" CISA remediation due date: {kev['dueDate']}."
        return action, vendor_url or patch_url
    if patch_url:
        return "Apply the latest vendor security update or fixed release described in the linked advisory. Prioritize internet-facing and privileged systems, then verify the installed version.", vendor_url or patch_url
    return "Check the affected vendor's security advisory and upgrade to a confirmed fixed release. If no fix is available, remove or isolate the affected component and restrict network access until a patch is published.", vendor_url


def fetch_epss(cves: list[str]) -> dict[str, tuple[float, float]]:
    scores: dict[str, tuple[float, float]] = {}
    for pos in range(0, len(cves), 100):
        data = get_json(EPSS_URL, {"cve": ",".join(cves[pos:pos + 100]), "limit": 100})
        for row in data.get("data", []):
            scores[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
    return scores


def build_findings(cves: list[dict[str, Any]], kev_catalog: dict[str, dict[str, Any]]) -> list[Finding]:
    candidates = []
    for cve in cves:
        kev = kev_catalog.get(cve.get("id", ""))
        platforms = detect_platforms(cve, kev)
        if platforms and cve.get("vulnStatus") not in {"Rejected"}:
            candidates.append((cve, kev, platforms))
    epss = fetch_epss([cve["id"] for cve, _, _ in candidates])
    findings = []
    for cve, kev, platforms in candidates:
        cvss, severity = cvss_info(cve)
        probability, percentile = epss.get(cve["id"], (0.0, 0.0))
        ransomware = bool(kev and str(kev.get("knownRansomwareCampaignUse", "")).lower() == "known")
        solution, advisory = solution_for(cve, kev)
        description = english_description(cve)
        findings.append(Finding(
            cve=cve["id"], platforms=platforms, title=(kev or {}).get("vulnerabilityName") or description[:120],
            description=description, published=cve.get("published", ""), modified=cve.get("lastModified", ""),
            cvss=cvss, severity=severity, epss=round(probability, 5), epss_percentile=round(percentile, 5),
            known_exploited=bool(kev), ransomware_use=ransomware, cisa_due_date=(kev or {}).get("dueDate", ""),
            risk_score=risk_score(cvss, probability, bool(kev), ransomware, cve.get("published", "")),
            solution=solution, vendor_advisory=advisory,
            nvd_url=f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
        ))
    return sorted(findings, key=lambda x: (x.risk_score, x.known_exploited, x.cvss, x.epss), reverse=True)


def select_top(findings: list[Finding], limit: int, per_platform: bool) -> list[Finding]:
    if not per_platform:
        return findings[:limit]
    selected: dict[str, Finding] = {}
    for platform in PLATFORMS:
        for item in (f for f in findings if platform in f.platforms):
            if sum(platform in x.platforms for x in selected.values()) >= limit:
                break
            selected[item.cve] = item
    return sorted(selected.values(), key=lambda x: x.risk_score, reverse=True)


def write_reports(findings: list[Finding], output: Path, metadata: dict[str, Any]) -> None:
    output.mkdir(parents=True, exist_ok=True)
    rows = [asdict(f) for f in findings]
    (output / "top_vulnerabilities.json").write_text(json.dumps({"metadata": metadata, "vulnerabilities": rows}, indent=2), encoding="utf-8")
    with (output / "top_vulnerabilities.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]) if rows else list(Finding.__annotations__))
        writer.writeheader()
        for row in rows:
            row["platforms"] = "; ".join(row["platforms"])
            writer.writerow(row)
    cards = []
    for f in findings:
        links = f'<a href="{html.escape(f.nvd_url)}" target="_blank">NVD</a>'
        if f.vendor_advisory:
            links += f' · <a href="{html.escape(f.vendor_advisory)}" target="_blank">Vendor advisory</a>'
        badges = "".join(f'<span class="badge">{html.escape(p)}</span>' for p in f.platforms)
        exploited = '<span class="kev">ACTIVELY EXPLOITED</span>' if f.known_exploited else ""
        cards.append(f'''<article data-platform="{html.escape(' '.join(f.platforms))}" data-search="{html.escape((f.cve+' '+f.title+' '+f.description).lower())}">
          <header><div><strong>{html.escape(f.cve)}</strong> {badges} {exploited}</div><b class="score">{f.risk_score}</b></header>
          <h2>{html.escape(f.title)}</h2><p>{html.escape(f.description)}</p>
          <div class="metrics">CVSS {f.cvss:g} ({html.escape(f.severity)}) · EPSS {f.epss:.1%} · Published {html.escape(f.published[:10])}</div>
          <h3>Recommended solution</h3><p>{html.escape(f.solution)}</p><footer>{links}</footer></article>''')
    generated = html.escape(metadata["generated_at"])
    doc = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MOV Mobile IT — VulnWatch Report</title><style>
:root{{--bg:#081019;--panel:#101c29;--line:#21364a;--text:#e8f1f7;--muted:#9eb0bf;--cyan:#2dd4bf;--red:#fb7185}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:15px system-ui,sans-serif}}main{{max-width:1100px;margin:auto;padding:34px 20px}}h1{{margin:0;font-size:clamp(28px,5vw,48px)}}.sub,.metrics{{color:var(--muted)}}.controls{{position:sticky;top:0;background:#081019ee;padding:18px 0;display:flex;gap:10px;z-index:2}}input,select{{width:100%;padding:12px;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--text)}}select{{max-width:190px}}article{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px;margin:14px 0}}article header{{display:flex;justify-content:space-between;gap:12px}}h2{{font-size:18px}}h3{{font-size:14px;color:var(--cyan);margin-bottom:0}}.score{{font-size:27px;color:var(--cyan)}}.badge,.kev{{display:inline-block;padding:3px 7px;border-radius:12px;background:#17354a;font-size:11px;margin:2px}}.kev{{background:#5a1826;color:#fecdd3}}a{{color:var(--cyan)}}footer{{margin-top:12px}}@media(max-width:600px){{.controls{{flex-direction:column}}select{{max-width:none}}}}
</style></head><body><main><p class="sub" style="letter-spacing:.14em;color:var(--cyan);margin-bottom:5px">MOV MOBILE IT • DEFENSIVE SECURITY INTELLIGENCE</p><h1>VulnWatch</h1><p class="sub">Top {len(findings)} current cross-platform vulnerabilities · generated {generated} · risk score /100</p>
<div class="controls"><input id="q" placeholder="Search CVE, product, or description"><select id="platform"><option value="">All platforms</option>{''.join(f'<option>{p}</option>' for p in PLATFORMS)}</select></div>
<section>{''.join(cards) or '<p>No matching vulnerabilities were returned.</p>'}</section></main><script>
const q=document.querySelector('#q'),p=document.querySelector('#platform'),cards=[...document.querySelectorAll('article')];function filter(){{cards.forEach(c=>c.hidden=!(c.dataset.search.includes(q.value.toLowerCase())&&(!p.value||c.dataset.platform.split(' ').join(' ').includes(p.value))))}}q.oninput=filter;p.onchange=filter;
</script></body></html>'''
    (output / "index.html").write_text(doc, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Rank current Windows, macOS, Linux, Android, and iOS/iPadOS CVEs.")
    parser.add_argument("--limit", type=int, default=100, help="Number of results (default: 100)")
    parser.add_argument("--days", type=int, default=120, help="Published lookback, 1-730 days (default: 120)")
    parser.add_argument("--per-platform", action="store_true", help="Return up to --limit results for each platform")
    parser.add_argument("--output", type=Path, default=Path("report"))
    parser.add_argument("--nvd-api-key", default=os.getenv("NVD_API_KEY", ""))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not 1 <= args.days <= 730 or not 1 <= args.limit <= 1000:
        print("--days must be 1..730 and --limit must be 1..1000", file=sys.stderr)
        return 2
    try:
        print("Fetching CISA KEV catalog...", file=sys.stderr)
        kev_data = get_json(KEV_URL)
        kev = {x["cveID"]: x for x in kev_data.get("vulnerabilities", [])}
        print(f"Fetching NVD CVEs published in the last {args.days} days...", file=sys.stderr)
        cves = fetch_recent_nvd(args.days, args.nvd_api_key)
        findings = select_top(build_findings(cves, kev), args.limit, args.per_platform)
        metadata = {"generated_at": datetime.now(timezone.utc).isoformat(), "lookback_days": args.days,
                    "result_count": len(findings), "selection": "per-platform" if args.per_platform else "global",
                    "sources": [NVD_URL, KEV_URL, EPSS_URL]}
        write_reports(findings, args.output, metadata)
        print(f"Wrote {len(findings)} findings to {args.output.resolve()}")
        return 0
    except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"VulnWatch failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
