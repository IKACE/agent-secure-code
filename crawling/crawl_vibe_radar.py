#!/usr/bin/env python3
"""
Crawl CVE/GHSA entries from vibe-radar-ten.vercel.app/cves.

Step 1: Fetch the listing page and extract all CVE/GHSA identifiers.
Step 2: Fetch each detail page and extract structured vulnerability data.
Step 3: Write results to crawling/data/vibe_radar_cves.jsonl.

Usage:
    python crawl_vibe_radar.py [--output crawling/data/vibe_radar_cves.jsonl] [--delay 1.0]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.request import urlopen, Request
from html.parser import HTMLParser


BASE_URL = "https://vibe-radar-ten.vercel.app"
LISTING_URL = f"{BASE_URL}/cves"

DEFAULT_OUTPUT = Path(__file__).parent / "data" / "vibe_radar_cves.jsonl"


# ---------------------------------------------------------------------------
# HTML text extractor
# ---------------------------------------------------------------------------

class TextExtractor(HTMLParser):
    """Simple HTML→text converter that tracks tag context."""

    def __init__(self):
        super().__init__()
        self._pieces: list[str] = []
        self._skip = False

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript"):
            self._skip = True

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript"):
            self._skip = False

    def handle_data(self, data):
        if not self._skip:
            self._pieces.append(data)

    def get_text(self) -> str:
        return " ".join(self._pieces)


def fetch(url: str) -> str:
    """Fetch a URL and return the response body as a string."""
    req = Request(url, headers={"User-Agent": "Mozilla/5.0 (research crawler)"})
    with urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


def html_to_text(html: str) -> str:
    parser = TextExtractor()
    parser.feed(html)
    return parser.get_text()


# ---------------------------------------------------------------------------
# Listing page: extract all identifiers
# ---------------------------------------------------------------------------

def get_all_ids(html: str) -> List[str]:
    """Extract detail-page slugs (CVE-* or GHSA-*) from the listing page.

    The listing uses CVE IDs as the primary entry identifier. GHSAs appear as
    metadata within each card. Standalone GHSAs (no associated CVE nearby) also
    have their own detail pages.
    """
    cve_ids = list(dict.fromkeys(re.findall(r"CVE-\d{4}-\d+", html)))
    ghsa_ids = list(dict.fromkeys(re.findall(
        r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", html
    )))

    slugs = list(cve_ids)  # all CVEs get their own page

    # Add GHSAs that don't appear near any CVE (standalone entries)
    for ghsa in ghsa_ids:
        idx = html.find(ghsa)
        nearby = html[max(0, idx - 2000):idx + 200]
        if not re.search(r"CVE-\d{4}-\d+", nearby):
            slugs.append(ghsa)

    return slugs


# ---------------------------------------------------------------------------
# Detail page: extract structured fields
# ---------------------------------------------------------------------------

def strip_tags(html_fragment: str) -> str:
    """Remove HTML tags and decode entities from a fragment."""
    text = re.sub(r"<!--.*?-->", "", html_fragment)  # remove comments
    text = re.sub(r"<[^>]+>", "", text)
    text = text.replace("&#x27;", "'").replace("&amp;", "&").replace("&lt;", "<")
    text = text.replace("&gt;", ">").replace("&quot;", '"')
    return text.strip()


def extract_dl_fields(html_fragment: str) -> Dict[str, str]:
    """Extract <dt>/<dd> pairs from a definition list fragment."""
    fields = {}
    pairs = re.findall(r"<dt[^>]*>(.*?)</dt>\s*<dd[^>]*>(.*?)</dd>", html_fragment, re.DOTALL)
    for dt, dd in pairs:
        key = strip_tags(dt).strip()
        val = strip_tags(dd).strip()
        if key and val:
            fields[key] = val
    return fields


def extract_detail(html: str, slug: str) -> Dict[str, Any]:
    """Parse a detail page and return structured vulnerability data.

    Extracts: id, cve_id, ghsa_id, severity, cvss, cwes, published_date,
    verified_by, description, how_ai_introduced, causality_analysis (with
    status, vulnerability, root_cause, pattern, causal_chain, reasoning,
    verified_by), ai_signals, bug_commits, fix_commits, references.
    """
    record: Dict[str, Any] = {"id": slug}

    # ── Basic identifiers ──────────────────────────────────────────────
    cve_match = re.search(r"(CVE-\d{4}-\d+)", html)
    if cve_match:
        record["cve_id"] = cve_match.group(1)

    ghsa_match = re.search(r"(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})", html)
    if ghsa_match:
        record["ghsa_id"] = ghsa_match.group(1)

    # ── Severity & CVSS ────────────────────────────────────────────────
    sev_match = re.search(r">(CRITICAL|HIGH|MEDIUM|LOW)</span>", html, re.IGNORECASE)
    if sev_match:
        record["severity"] = sev_match.group(1).upper()

    cvss_match = re.search(r"CVSS\s*(?:<!--.*?-->)?\s*([\d.]+)", html)
    if cvss_match:
        record["cvss"] = float(cvss_match.group(1))

    # ── CWEs ───────────────────────────────────────────────────────────
    cwes = list(dict.fromkeys(re.findall(r"CWE-(\d+)", html)))
    if cwes:
        record["cwes"] = [f"CWE-{c}" for c in cwes]

    # ── Published date & verified_by ───────────────────────────────────
    pub_match = re.search(r"Published:\s*(?:<!--.*?-->)?\s*(\w+ \d{1,2},\s*\d{4})", html)
    if pub_match:
        record["published_date"] = pub_match.group(1)

    ver_match = re.search(r"Verified by:\s*(?:<!--.*?-->)?\s*([^<]+)", html)
    if ver_match:
        record["verified_by"] = [v.strip() for v in ver_match.group(1).split(",") if v.strip()]

    # ── Description ────────────────────────────────────────────────────
    # First <p> inside <main> after the header div
    desc_match = re.search(
        r"Description</div>\s*</div>\s*<div>\s*<p>(.*?)</p>", html, re.DOTALL
    )
    if desc_match:
        record["description"] = strip_tags(desc_match.group(1))
    else:
        meta_match = re.search(r'<meta\s+name="description"\s+content="([^"]+)"', html)
        if meta_match:
            record["description"] = strip_tags(meta_match.group(1))

    # ── How AI Introduced This ─────────────────────────────────────────
    # Extract the block between "How AI Introduced This" and the next <section
    how_start = html.find("How AI Introduced This")
    how_end_match = re.search(r"<section[\s>]", html[how_start:]) if how_start >= 0 else None
    how_end = how_start + how_end_match.start() if how_end_match else -1
    how_match = how_start >= 0 and how_end > how_start
    if how_match:
        how_block = html[how_start:how_end]

        # The intro paragraph (before Causality Analysis)
        intro_match = re.search(r"<p[^>]*>(.*?)</p>", how_block, re.DOTALL)
        if intro_match:
            record["how_ai_introduced"] = strip_tags(intro_match.group(1))

        # Causality Analysis block
        causality: Dict[str, Any] = {}

        # Status: CONFIRMED / LIKELY / etc + blamed commit SHA
        status_match = re.search(
            r"<span[^>]*>(CONFIRMED|LIKELY|POSSIBLE|UNLIKELY|NOT_CONFIRMED)</span>"
            r"\s*—\s*<a[^>]*href=\"([^\"]+)\"[^>]*>([^<]+)</a>",
            how_block
        )
        if status_match:
            causality["status"] = status_match.group(1)
            causality["blamed_commit_url"] = status_match.group(2)
            causality["blamed_commit_short"] = status_match.group(3)

        # dt/dd fields: Vulnerability, Root Cause, Pattern, Causal Chain, Reasoning
        dl_fields = extract_dl_fields(how_block)
        for key in ["Vulnerability", "Root Cause", "Pattern", "Causal Chain", "Reasoning"]:
            if key in dl_fields:
                causality[key.lower().replace(" ", "_")] = dl_fields[key]

        # Verified by (within causality block)
        caus_ver = re.search(r"Verified by\s*(?:<!--.*?-->)?\s*([a-z0-9._-]+(?:-[a-z0-9]+)*)", how_block)
        if caus_ver:
            causality["causality_verified_by"] = caus_ver.group(1)

        if causality:
            record["causality_analysis"] = causality

    # ── AI Signal Details ──────────────────────────────────────────────
    ai_section = re.search(
        r"<section[^>]*>\s*<h2[^>]*>AI Signal Details</h2>(.*?)</section>",
        html, re.DOTALL
    )
    if ai_section:
        sig_block = ai_section.group(1)
        signals = []

        # Each signal: tool name, detection method, evidence snippet, confidence %
        # Pattern: <span>GitHub Copilot</span><span>co author trailer generic</span><code>...</code><span>70%</span>
        sig_matches = re.findall(
            r"<span[^>]*>([^<]+)</span>\s*<span[^>]*>([^<]+)</span>\s*<code[^>]*>([^<]+)</code>\s*<span[^>]*>(\d+%)</span>",
            sig_block
        )
        for tool, method, evidence, confidence in sig_matches:
            signals.append({
                "tool": tool.strip(),
                "detection_method": method.strip(),
                "evidence": evidence.strip(),
                "confidence": confidence.strip(),
            })

        # Also capture the commit SHA the signals are for
        sig_commit = re.search(r"AI Signals in\s*(?:<!--.*?-->)?\s*<a[^>]*>([^<]+)</a>", sig_block)
        if signals or sig_commit:
            ai_signal_data: Dict[str, Any] = {}
            if sig_commit:
                ai_signal_data["commit_short"] = sig_commit.group(1).strip()
            if signals:
                ai_signal_data["signals"] = signals
            record["ai_signals"] = ai_signal_data

    # ── Bug-Introducing Commits ────────────────────────────────────────
    bug_section = re.search(
        r"<section[^>]*>\s*<h2[^>]*>Bug-Introducing Commits.*?</h2>(.*?)</section>",
        html, re.DOTALL
    )
    if bug_section:
        bug_block = bug_section.group(1)
        bug_commits = []

        # Each commit block has: short SHA link, commit message <p>, author, date, blamed file, blame %
        commit_blocks = re.findall(
            r'<a[^>]*href="(https://github\.com/[^"]+/commit/[0-9a-f]+)"[^>]*>([^<]+)</a>'
            r'(?:\s*<span[^>]*>AI</span>)?'
            r'\s*</div>\s*<div[^>]*>\s*<p[^>]*>([^<]*)</p>'
            r'\s*<div[^>]*>\s*<span[^>]*>([^<]*)</span>\s*<span[^>]*>([^<]*)</span>'
            r'\s*<span[^>]*>([^<]*)</span>'
            r'\s*<span[^>]*>Blame:\s*(?:<!--.*?-->)?\s*(\d+%)</span>',
            bug_block
        )
        for url, sha_short, msg, author, date, blamed_file, blame_pct in commit_blocks:
            bug_commits.append({
                "url": url,
                "sha_short": sha_short.strip(),
                "message": strip_tags(msg),
                "author": author.strip(),
                "date": date.strip(),
                "blamed_file": blamed_file.strip(),
                "blame_confidence": blame_pct.strip(),
            })

        # Fallback: at least capture commit URLs
        if not bug_commits:
            urls = re.findall(
                r'href="(https://github\.com/[^"]+/commit/[0-9a-f]+)"', bug_block
            )
            for url in urls:
                sha = url.rsplit("/", 1)[-1]
                bug_commits.append({"url": url, "sha_short": sha[:7]})

        if bug_commits:
            record["bug_commits"] = bug_commits

    # ── Fix Commits ────────────────────────────────────────────────────
    fix_section = re.search(
        r"<section[^>]*>\s*<h2[^>]*>Fix Commits.*?</h2>(.*?)</section>",
        html, re.DOTALL
    )
    if fix_section:
        fix_block = fix_section.group(1)
        fix_commits = []

        # Each fix: <code>sha</code><a href="url">repo/sha</a><span>source</span>
        fix_matches = re.findall(
            r'<code[^>]*>([^<]+)</code>\s*<a[^>]*href="(https://github\.com/[^"]+/commit/[0-9a-f]+)"[^>]*>'
            r'.*?</a>\s*<span[^>]*>([^<]*)</span>',
            fix_block, re.DOTALL
        )
        for sha_short, url, source in fix_matches:
            fix_commits.append({
                "sha_short": sha_short.strip(),
                "url": url,
                "source": source.strip(),
            })

        # Fallback
        if not fix_commits:
            urls = re.findall(
                r'href="(https://github\.com/[^"]+/commit/[0-9a-f]+)"', fix_block
            )
            for url in urls:
                sha = url.rsplit("/", 1)[-1]
                fix_commits.append({"url": url, "sha_short": sha[:7]})

        if fix_commits:
            record["fix_commits"] = fix_commits

    # ── References ─────────────────────────────────────────────────────
    ref_section = re.search(r"References</div>\s*</div>\s*<div[^>]*>\s*<ul[^>]*>(.*?)</ul>", html, re.DOTALL)
    if ref_section:
        refs = re.findall(r'href="([^"]+)"', ref_section.group(1))
        if refs:
            record["references"] = refs

    # ── Repo (from commit URLs) ────────────────────────────────────────
    repo_match = re.search(
        r"github\.com/([^/]+/[^/]+)/(?:commit|security)", html
    )
    if repo_match:
        record["repo"] = repo_match.group(1)

    return record


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Crawl vibe-radar CVE database")
    parser.add_argument("--output", "-o", type=Path, default=DEFAULT_OUTPUT,
                        help="Output JSONL path")
    parser.add_argument("--delay", type=float, default=1.0,
                        help="Delay between requests in seconds")
    parser.add_argument("--limit", type=int, default=None,
                        help="Max entries to crawl (for testing)")
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)

    print(f"Fetching listing page: {LISTING_URL}")
    listing_html = fetch(LISTING_URL)

    slugs = get_all_ids(listing_html)
    print(f"Found {len(slugs)} vulnerability entries")

    if args.limit:
        slugs = slugs[:args.limit]
        print(f"  (limited to {args.limit})")

    results = []
    for i, slug in enumerate(slugs):
        detail_url = f"{BASE_URL}/cves/{slug}"
        print(f"  [{i+1}/{len(slugs)}] Fetching {slug} ...", end=" ", flush=True)

        try:
            detail_html = fetch(detail_url)
            record = extract_detail(detail_html, slug)
            results.append(record)
            print(f"OK ({record.get('severity', '?')})")
        except Exception as e:
            print(f"FAILED: {e}")
            results.append({"id": slug, "error": str(e)})

        if i < len(slugs) - 1:
            time.sleep(args.delay)

    # Write output
    with open(args.output, "w") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"\nWrote {len(results)} records to {args.output}")

    # Summary
    severities = {}
    for r in results:
        sev = r.get("severity", "UNKNOWN")
        severities[sev] = severities.get(sev, 0) + 1
    print("Severity breakdown:", json.dumps(severities, indent=2))


if __name__ == "__main__":
    main()
