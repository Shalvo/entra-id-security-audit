#!/usr/bin/env python3
"""
entra_audit: a read-only identity security health check for Microsoft Entra ID.

Pulls users and authentication-method registration details from Microsoft Graph
and flags common identity risks:

  CRITICAL  administrators with no MFA method registered
  HIGH      enabled member accounts with no MFA method registered
  MEDIUM    enabled accounts with no sign-in for STALE_DAYS (members and guests)
  MEDIUM    enabled accounts that were created long ago and have never signed in

Run with --demo to use the bundled sample tenant; no credentials needed.
The tool only reads data. It never changes anything in the tenant.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

GRAPH = "https://graph.microsoft.com/v1.0"
USER_SELECT = "id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,signInActivity"
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SAMPLE_FILE = Path(__file__).with_name("sample_tenant.json")


@dataclass
class Finding:
    severity: str
    check: str
    user: str
    detail: str


# ---------------------------------------------------------------- helpers

_FRACTION = re.compile(r"\.(\d+)")


def parse_graph_time(value: str | None) -> datetime | None:
    """Parse Graph timestamps such as 2026-03-13T19:15:41.6195833Z (7 fractional digits)."""
    if not value:
        return None
    value = value.replace("Z", "+00:00")
    value = _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), value, count=1)
    dt = datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def last_sign_in(user: dict) -> datetime | None:
    """Most recent sign-in of any kind recorded for the user."""
    activity = user.get("signInActivity") or {}
    stamps = [
        parse_graph_time(activity.get(k))
        for k in ("lastSignInDateTime", "lastNonInteractiveSignInDateTime", "lastSuccessfulSignInDateTime")
    ]
    stamps = [s for s in stamps if s]
    return max(stamps) if stamps else None


# ---------------------------------------------------------------- checks

def run_checks(users: list[dict], registration: list[dict], now: datetime, stale_days: int = 90) -> list[Finding]:
    """Apply every check and return findings sorted by severity. Pure function: easy to test."""
    reg_by_id = {r.get("id"): r for r in registration}
    stale = timedelta(days=stale_days)
    findings: list[Finding] = []

    for u in users:
        if not u.get("accountEnabled", False):
            continue  # disabled accounts cannot sign in; out of scope
        upn = u.get("userPrincipalName", u.get("id", "?"))
        is_guest = (u.get("userType") or "").lower() == "guest"
        reg = reg_by_id.get(u.get("id"))

        if reg is not None and not reg.get("isMfaRegistered", False):
            if reg.get("isAdmin"):
                findings.append(Finding("CRITICAL", "admin-without-mfa", upn,
                                        "Holds an admin role but has no MFA method registered"))
            elif not is_guest:
                findings.append(Finding("HIGH", "user-without-mfa", upn,
                                        "Enabled member account with no MFA method registered"))

        last = last_sign_in(u)
        kind = "guest" if is_guest else "member"
        if last is None:
            created = parse_graph_time(u.get("createdDateTime"))
            if created and now - created > stale:
                findings.append(Finding("MEDIUM", f"{kind}-never-signed-in", upn,
                                        f"Created {(now - created).days} days ago and never signed in"))
        elif now - last > stale:
            findings.append(Finding("MEDIUM", f"stale-{kind}", upn,
                                    f"Last sign-in {(now - last).days} days ago"))

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.check, f.user))
    return findings


def summarise(users: list[dict], findings: list[Finding]) -> dict:
    enabled = [u for u in users if u.get("accountEnabled")]
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] += 1
    return {
        "users_total": len(users),
        "users_enabled": len(enabled),
        "findings": len(findings),
        "by_severity": counts,
    }


# ---------------------------------------------------------------- data sources

def load_demo(path: Path = SAMPLE_FILE) -> tuple[list[dict], list[dict], datetime]:
    data = json.loads(path.read_text(encoding="utf-8"))
    # The sample is frozen at a point in time so the demo output never drifts.
    return data["users"], data["registrationDetails"], parse_graph_time(data["generatedAt"])


class GraphClient:
    """Minimal app-only Microsoft Graph client (client credentials flow)."""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        import msal  # imported here so --demo and the tests need no extra packages
        import requests

        app = msal.ConfidentialClientApplication(
            client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_secret,
        )
        result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        if "access_token" not in result:
            raise SystemExit(f"Could not get a token: {result.get('error_description', result)}")
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {result['access_token']}"

    def get_all(self, url: str) -> list[dict]:
        """Follow @odata.nextLink paging and back off politely on throttling (HTTP 429)."""
        items: list[dict] = []
        while url:
            resp = self.session.get(url, timeout=30)
            if resp.status_code == 429:
                time.sleep(int(resp.headers.get("Retry-After", "5")))
                continue
            resp.raise_for_status()
            data = resp.json()
            items.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
        return items


def load_live() -> tuple[list[dict], list[dict], datetime]:
    missing = [v for v in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET") if not os.environ.get(v)]
    if missing:
        raise SystemExit(f"Missing environment variables: {', '.join(missing)}. See README, or use --demo.")
    client = GraphClient(os.environ["AZURE_TENANT_ID"], os.environ["AZURE_CLIENT_ID"], os.environ["AZURE_CLIENT_SECRET"])
    users = client.get_all(f"{GRAPH}/users?$select={USER_SELECT}")
    registration = client.get_all(f"{GRAPH}/reports/authenticationMethods/userRegistrationDetails")
    return users, registration, datetime.now(timezone.utc)


# ---------------------------------------------------------------- output

def format_report(summary: dict, findings: list[Finding], stale_days: int) -> str:
    s = summary
    out = [
        "Entra ID security audit",
        f"Users: {s['users_total']} total, {s['users_enabled']} enabled   Stale threshold: {stale_days} days",
        "Findings: " + ", ".join(f"{k} {v}" for k, v in s["by_severity"].items() if v) if findings else "Findings: none",
        "",
    ]
    if findings:
        w = max(len(f.user) for f in findings)
        out.append(f"{'SEVERITY':<9} {'CHECK':<24} {'USER':<{w}}  DETAIL")
        for f in findings:
            out.append(f"{f.severity:<9} {f.check:<24} {f.user:<{w}}  {f.detail}")
    return "\n".join(out)


def write_csv(path: str, findings: list[Finding]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["severity", "check", "user", "detail"])
        writer.writeheader()
        writer.writerows(asdict(f) for f in findings)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Read-only identity security audit for Microsoft Entra ID.")
    p.add_argument("--demo", action="store_true", help="use the bundled sample tenant instead of Microsoft Graph")
    p.add_argument("--stale-days", type=int, default=90, help="days without sign-in before an account is stale (default 90)")
    p.add_argument("--csv", metavar="PATH", help="also write findings to a CSV file")
    p.add_argument("--json", action="store_true", help="print summary and findings as JSON")
    p.add_argument("--fail-on-critical", action="store_true", help="exit with code 1 if any CRITICAL finding exists")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    users, registration, now = load_demo() if args.demo else load_live()
    findings = run_checks(users, registration, now, args.stale_days)
    summary = summarise(users, findings)

    if args.json:
        print(json.dumps({"summary": summary, "findings": [asdict(f) for f in findings]}, indent=2))
    else:
        print(format_report(summary, findings, args.stale_days))
    if args.csv:
        write_csv(args.csv, findings)
        if not args.json:
            print(f"\nCSV written to {args.csv}")

    return 1 if (args.fail_on_critical and summary["by_severity"]["CRITICAL"]) else 0


if __name__ == "__main__":
    sys.exit(main())
