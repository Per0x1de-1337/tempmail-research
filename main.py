#!/usr/bin/env python3
"""
Live temp-email infrastructure research via MX fingerprinting + blocklist git analysis.

Defensive research only — measures the gap between MX/CT detection and public
blocklist inclusion for disposable email domains.

Usage:
  python3 temp_email_ct_research.py
  python3 temp_email_ct_research.py --skip-certstream --gap-limit 25
"""

from __future__ import annotations

import argparse
import json
import random
import re
import smtplib
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import certstream
except ImportError:
    certstream = None  # type: ignore

ROOT = Path(__file__).resolve().parent
OUTPUTS_DIR = ROOT / "outputs"
BLOCKLIST_REPO = ROOT / "blocklist-repo"
BLOCKLIST_FILE = "disposable_email_blocklist.conf"
BLOCKLIST_REMOTE = (
    "https://github.com/disposable-email-domains/disposable-email-domains.git"
)

REFERENCE_PROVIDERS = [
    "guerrillamail.com",
    "mailinator.com",
    "tempmail.com",
    "yopmail.com",
    "getnada.com",
    "maildrop.cc",
    "temp-mail.org",
    "sharklasers.com",
    "dispostable.com",
    "mailnesia.com",
    "trashmail.com",
    "mintemail.com",
    "mytemp.email",
    "tempail.com",
    "guerrillamailblock.com",
    "emailondeck.com",
    "mailcatch.com",
    "tempinbox.com",
    "mailsac.com",
    "inboxkitten.com",
    "dropmail.me",
    "tempmailo.com",
    "emailfake.com",
    "crazymailing.com",
    "mail.tm",
    "tempmail.ninja",
    "internxt.com",
]

CLUSTER_MX = {"mail.wabblywabble.com", "mail.wallywatts.com"}

WHOIS_CREATED = re.compile(
    r"Creation Date|Created On|created:|Registration Time|Registered on",
    re.I,
)


def ensure_blocklist_repo() -> Path:
    if (BLOCKLIST_REPO / ".git").is_dir():
        subprocess.run(
            ["git", "-C", str(BLOCKLIST_REPO), "fetch", "--depth", "1", "origin"],
            check=False,
            capture_output=True,
        )
        return BLOCKLIST_REPO
    BLOCKLIST_REPO.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "clone", "--depth", "200", BLOCKLIST_REMOTE, str(BLOCKLIST_REPO)],
        check=True,
    )
    return BLOCKLIST_REPO


def load_blocklist_at_commit(repo: Path, commit: str) -> set[str]:
    raw = subprocess.check_output(
        ["git", "-C", str(repo), "show", f"{commit}:{BLOCKLIST_FILE}"],
        text=True,
    )
    return {
        line.strip().lower()
        for line in raw.splitlines()
        if line.strip() and not line.startswith("#")
    }


def period_additions(repo: Path, since: str, until: str) -> list[tuple[str, str]]:
    log = subprocess.check_output(
        [
            "git",
            "-C",
            str(repo),
            "log",
            f"--since={since}",
            f"--until={until}",
            "--format=%aI",
            "-p",
            "--",
            BLOCKLIST_FILE,
        ],
        text=True,
    )
    entries: list[tuple[str, str]] = []
    current_date: str | None = None
    for chunk in log.split("\n\n"):
        lines = chunk.splitlines()
        if not lines:
            continue
        if lines[0].startswith("20"):
            current_date = lines[0][:10]
        for line in lines[1:]:
            if line.startswith("+") and not line.startswith("+++"):
                domain = line[1:].strip().lower()
                if domain and "." in domain and not domain.startswith("#"):
                    entries.append((current_date or since, domain))
    seen: set[str] = set()
    unique: list[tuple[str, str]] = []
    for date, domain in entries:
        if domain not in seen:
            seen.add(domain)
            unique.append((date, domain))
    return unique


def dig_mx(domain: str) -> list[str]:
    try:
        out = subprocess.check_output(
            ["dig", "+short", "MX", domain],
            timeout=8,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        return []
    hosts: list[str] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            hosts.append(parts[-1].rstrip(".").lower())
    return sorted(set(hosts))


def build_reference_mx(providers: list[str]) -> set[str]:
    hosts: set[str] = set()
    for domain in providers:
        hosts.update(dig_mx(domain))
    return hosts


def whois_created(domain: str) -> str | None:
    try:
        out = subprocess.check_output(
            ["whois", domain], timeout=12, text=True, stderr=subprocess.DEVNULL
        )
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        return None
    dates: list[str] = []
    for line in out.splitlines():
        if WHOIS_CREATED.search(line):
            for match in re.finditer(r"(\d{4}-\d{2}-\d{2})", line):
                dates.append(match.group(1))
    return min(dates) if dates else None


def test_catch_all(domain: str, timeout: int = 8) -> bool | None:
    mx_hosts = dig_mx(domain)
    if not mx_hosts:
        return None
    probe = f"probe-{int(time.time())}@{domain}"
    for mx in mx_hosts[:2]:
        try:
            with smtplib.SMTP(timeout=timeout) as smtp:
                smtp.connect(mx, 25)
                smtp.helo("infrawatch-research.local")
                smtp.mail("research@infrawatch.local")
                code, _ = smtp.rcpt(probe)
                if 200 <= code < 300:
                    return True
                if 500 <= code < 600:
                    return False
        except (socket.timeout, socket.error, smtplib.SMTPException, OSError):
            continue
    return None


def ct_first_seen(domain: str) -> str | None:
    import urllib.parse

    url = f"https://crt.sh/?q={urllib.parse.quote(domain)}&output=json"
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "InfraWatch-TempEmail-Research/1.0"}
        )
        data = urllib.request.urlopen(req, timeout=25).read()
        if data[:1] != b"[":
            return None
        certs = json.loads(data)
        if not certs:
            return None
        earliest = min(c.get("entry_timestamp", "") for c in certs if c.get("entry_timestamp"))
        return earliest[:10] if earliest else None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
        return None


def collect_certstream(seconds: int) -> list[dict[str, Any]]:
    if certstream is None:
        raise RuntimeError("certstream package required: pip install certstream")

    events: list[dict[str, Any]] = []

    def on_message(message: dict[str, Any], _context: Any) -> None:
        if message.get("message_type") != "certificate_update":
            return
        leaf = message["data"]["leaf_cert"]
        for raw in leaf.get("all_domains", []):
            name = raw.strip().lower().lstrip("*.")
            if name and "*" not in name and name.count(".") >= 1:
                events.append({"domain": name, "source": "certstream"})

    thread = threading.Thread(
        target=lambda: certstream.listen_for_events(
            on_message, url="wss://certstream.calidog.io/"
        ),
        daemon=True,
    )
    thread.start()
    time.sleep(seconds)
    return events


def median(values: list[int]) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[len(ordered) // 2]


def analyze_mx_sample(
    blocklist: set[str],
    additions: list[str],
    reference_mx: set[str],
    sample_size: int,
    seed: int,
) -> dict[str, Any]:
    rng = random.Random(seed)
    sample = list(dict.fromkeys(additions + rng.sample(list(blocklist), min(sample_size, len(blocklist)))))

    mx_cluster: dict[str, list[str]] = defaultdict(list)
    ref_hits: list[dict[str, str]] = []

    for domain in additions:
        hosts = dig_mx(domain)
        for host in hosts:
            if host in reference_mx:
                ref_hits.append({"domain": domain, "mx": host})
                break

    for domain in sample:
        for host in dig_mx(domain):
            mx_cluster[host].append(domain)

    shared = {mx: doms for mx, doms in mx_cluster.items() if len(doms) >= 3}
    top_counts = {mx: len(doms) for mx, doms in sorted(shared.items(), key=lambda x: -len(x[1]))[:8]}

    def examples_for(hosts: set[str], limit: int = 3) -> list[str]:
        out: list[str] = []
        for host in hosts:
            out.extend(mx_cluster.get(host, [])[:limit])
        return list(dict.fromkeys(out))[:6]

    return {
        "sample_size": len(sample),
        "reference_mx_hits": len(ref_hits),
        "reference_mx_hit_rate_pct": round(100 * len(ref_hits) / max(1, len(additions)), 1),
        "top_mx_clusters": top_counts,
        "cluster_examples": {
            "wabblywabble_wallywatts": examples_for(CLUSTER_MX),
            "yopmail_satellites": mx_cluster.get("smtp.yopmail.com", [])[:3],
            "cloudflare_route": mx_cluster.get("route2.mx.cloudflare.net", [])[:3],
        },
        "ref_hits": ref_hits,
        "mx_cluster": mx_cluster,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Temp email MX / blocklist gap research")
    parser.add_argument("--blocklist-commit", default="523cca1")
    parser.add_argument("--since", default="2026-02-01")
    parser.add_argument("--until", default="2026-03-01")
    parser.add_argument("--research-date", default="2026-02-25")
    parser.add_argument("--sample-size", type=int, default=300)
    parser.add_argument("--sample-seed", type=int, default=202602)
    parser.add_argument("--gap-limit", type=int, default=25)
    parser.add_argument("--validate-cluster-limit", type=int, default=6)
    parser.add_argument("--ct-domain", default="imashr.com")
    parser.add_argument("--certstream-seconds", type=int, default=75)
    parser.add_argument("--skip-certstream", action="store_true", default=True)
    parser.add_argument("--with-certstream", action="store_true")
    args = parser.parse_args()
    if args.with_certstream:
        args.skip_certstream = False

    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    if args.since.startswith("2026-02"):
        findings_path = OUTPUTS_DIR / "temp_email_feb2026_findings.json"
        gap_path = OUTPUTS_DIR / "detection_gap_feb2026.json"
    else:
        period_tag = args.since[:7].replace("-", "")
        findings_path = OUTPUTS_DIR / f"temp_email_{period_tag}_findings.json"
        gap_path = OUTPUTS_DIR / f"detection_gap_{period_tag}.json"

    print("[1/6] Loading blocklist snapshot from git...")
    repo = ensure_blocklist_repo()
    blocklist = load_blocklist_at_commit(repo, args.blocklist_commit)
    print(f"      commit {args.blocklist_commit}: {len(blocklist):,} domains")

    print("[2/6] Reading blocklist additions from git history...")
    dated_additions = period_additions(repo, args.since, args.until)
    additions = [domain for _, domain in dated_additions]
    print(f"      {len(additions)} domains added between {args.since} and {args.until}")

    print("[3/6] Building reference MX fingerprint...")
    reference_mx = build_reference_mx(REFERENCE_PROVIDERS)
    print(f"      {len(reference_mx)} MX hosts from {len(REFERENCE_PROVIDERS)} providers")

    print("[4/6] Analyzing MX clusters on blocklist sample...")
    analysis = analyze_mx_sample(
        blocklist, additions, reference_mx, args.sample_size, args.sample_seed
    )
    print(f"      reference MX hits in period additions: {analysis['reference_mx_hits']}/{len(additions)}")

    cluster_domains = [
        domain
        for domain in additions
        if CLUSTER_MX.intersection(dig_mx(domain))
    ][: args.validate_cluster_limit]

    print(f"[5/6] Catch-all validation on {len(cluster_domains)} cluster domains...")
    catch_all_rows: list[dict[str, Any]] = []
    for domain in cluster_domains:
        catch_all_rows.append(
            {"domain": domain, "mx": dig_mx(domain), "catch_all": test_catch_all(domain)}
        )
        time.sleep(0.3)

    print(f"[6/6] Measuring whois gap for up to {args.gap_limit} additions...")
    gap_rows: list[dict[str, Any]] = []
    for blocklist_date, domain in dated_additions[: args.gap_limit]:
        created = whois_created(domain)
        gap_days = None
        if created and blocklist_date:
            gap_days = (datetime.fromisoformat(blocklist_date) - datetime.fromisoformat(created)).days
        gap_rows.append(
            {
                "domain": domain,
                "created": created,
                "blocklist_date": blocklist_date,
                "gap_days": gap_days,
            }
        )

    gap_path.write_text(json.dumps(gap_rows, indent=2) + "\n", encoding="utf-8")

    spinup_gaps = {
        row["domain"]: row["gap_days"]
        for row in gap_rows
        if row["gap_days"] is not None
        and row["created"]
        and row["created"].startswith("2025")
        and 0 <= row["gap_days"] < 2000
    }
    spinup_values = list(spinup_gaps.values())

    ct_first = ct_first_seen(args.ct_domain) if args.ct_domain else None
    ct_example: dict[str, Any] | None = None
    if args.ct_domain:
        ct_example = {
            "domain": args.ct_domain,
            "ct_first_seen": ct_first,
            "on_blocklist_at_research_time": args.ct_domain not in blocklist,
            "mx": dig_mx(args.ct_domain),
        }

    certstream_events = 0
    if not args.skip_certstream:
        print("      (optional) listening to Certstream...")
        try:
            certstream_events = len(collect_certstream(args.certstream_seconds))
        except Exception as exc:
            print(f"      Certstream failed: {exc}", file=sys.stderr)

    findings = {
        "research_date": args.research_date,
        "blocklist_snapshot_commit": args.blocklist_commit,
        "blocklist_size_end_feb": len(blocklist),
        "feb_2026_additions": len(additions),
        "reference_mx_hits": analysis["reference_mx_hits"],
        "reference_mx_hit_rate_pct": analysis["reference_mx_hit_rate_pct"],
        "top_mx_clusters": analysis["top_mx_clusters"],
        "cluster_examples": analysis["cluster_examples"],
        "catch_all_validation": catch_all_rows,
        "proactive_ct_example": ct_example,
        "detection_gap_2025_spinups_days": {
            **spinup_gaps,
            "median": median(spinup_values),
        },
        "certstream_events": certstream_events,
    }
    findings_path.write_text(json.dumps(findings, indent=2) + "\n", encoding="utf-8")

    print("\n=== RESEARCH SUMMARY ===")
    print(f"Blocklist snapshot:           {len(blocklist):,}")
    print(f"Period additions:             {len(additions)}")
    print(f"Reference MX hits:            {analysis['reference_mx_hits']} ({analysis['reference_mx_hit_rate_pct']}%)")
    print(f"2025 spin-up median gap:      {median(spinup_values)} days")
    print(f"Findings:                     {findings_path}")
    print(f"Detection gap:                {gap_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
