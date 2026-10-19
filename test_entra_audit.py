"""Tests for entra_audit. Run with: pytest -v (no tenant or credentials needed)."""
import csv
import json
from datetime import datetime, timezone

import entra_audit as ea

NOW = datetime(2026, 10, 19, 8, 0, tzinfo=timezone.utc)


def user(uid, enabled=True, kind="Member", created="2024-01-01T00:00:00Z", last=None):
    return {
        "id": uid,
        "userPrincipalName": f"{uid}@contoso.onmicrosoft.com",
        "accountEnabled": enabled,
        "userType": kind,
        "createdDateTime": created,
        "signInActivity": {"lastSignInDateTime": last} if last else None,
    }


def reg(uid, mfa, admin=False):
    return {"id": uid, "isMfaRegistered": mfa, "isAdmin": admin}


def checks(users, regs, days=90):
    return [(f.severity, f.check, f.user.split("@")[0]) for f in ea.run_checks(users, regs, NOW, days)]


def test_parses_graph_timestamp_with_seven_fraction_digits():
    dt = ea.parse_graph_time("2023-03-13T19:15:41.6195833Z")
    assert dt == datetime(2023, 3, 13, 19, 15, 41, 619583, tzinfo=timezone.utc)


def test_parse_graph_time_handles_empty():
    assert ea.parse_graph_time(None) is None and ea.parse_graph_time("") is None


def test_last_sign_in_uses_most_recent_of_all_types():
    u = {"signInActivity": {"lastSignInDateTime": "2026-01-01T00:00:00Z",
                            "lastNonInteractiveSignInDateTime": "2026-10-01T00:00:00Z"}}
    assert ea.last_sign_in(u) == datetime(2026, 10, 1, tzinfo=timezone.utc)


def test_admin_without_mfa_is_critical():
    assert checks([user("admin", last="2026-10-18T00:00:00Z")], [reg("admin", False, admin=True)]) == [
        ("CRITICAL", "admin-without-mfa", "admin")
    ]


def test_member_without_mfa_is_high():
    assert checks([user("bob", last="2026-10-18T00:00:00Z")], [reg("bob", False)]) == [
        ("HIGH", "user-without-mfa", "bob")
    ]


def test_guest_without_mfa_is_not_flagged_for_mfa():
    # guests authenticate in their home tenant, so their MFA is not registered here
    assert checks([user("guest", kind="Guest", last="2026-10-18T00:00:00Z")], [reg("guest", False)]) == []


def test_user_with_mfa_and_recent_sign_in_is_clean():
    assert checks([user("ok", last="2026-10-18T00:00:00Z")], [reg("ok", True)]) == []


def test_disabled_accounts_are_skipped():
    assert checks([user("gone", enabled=False, last="2020-01-01T00:00:00Z")], [reg("gone", False, admin=True)]) == []


def test_stale_member_and_guest():
    users = [user("old", last="2026-05-01T00:00:00Z"), user("ext", kind="Guest", last="2026-01-01T00:00:00Z")]
    regs = [reg("old", True), reg("ext", False)]
    assert sorted(checks(users, regs)) == [("MEDIUM", "stale-guest", "ext"), ("MEDIUM", "stale-member", "old")]


def test_stale_threshold_is_configurable():
    users = [user("u", last="2026-09-01T00:00:00Z")]  # 48 days ago
    assert checks(users, [reg("u", True)], days=90) == []
    assert checks(users, [reg("u", True)], days=30) == [("MEDIUM", "stale-member", "u")]


def test_never_signed_in_only_flagged_when_account_is_old():
    users = [user("fresh", created="2026-10-15T00:00:00Z"), user("ghost", created="2025-01-01T00:00:00Z")]
    regs = [reg("fresh", True), reg("ghost", True)]
    assert checks(users, regs) == [("MEDIUM", "member-never-signed-in", "ghost")]


def test_findings_sorted_by_severity():
    users = [user("stale", last="2026-01-01T00:00:00Z"), user("nomfa", last="2026-10-18T00:00:00Z"),
             user("adm", last="2026-10-18T00:00:00Z")]
    regs = [reg("stale", True), reg("nomfa", False), reg("adm", False, admin=True)]
    assert [s for s, _, _ in checks(users, regs)] == ["CRITICAL", "HIGH", "MEDIUM"]


def test_demo_tenant_end_to_end(capsys):
    assert ea.main(["--demo", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["summary"]["by_severity"] == {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 4, "LOW": 0}
    assert out["summary"]["users_enabled"] == 10


def test_fail_on_critical_exit_code():
    assert ea.main(["--demo", "--fail-on-critical"]) == 1


def test_csv_export(tmp_path):
    path = tmp_path / "findings.csv"
    ea.main(["--demo", "--csv", str(path)])
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    assert len(rows) == 9 and rows[0]["severity"] == "CRITICAL"


def test_live_mode_without_credentials_exits_cleanly(monkeypatch):
    for v in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"):
        monkeypatch.delenv(v, raising=False)
    try:
        ea.load_live()
    except SystemExit as exc:
        assert "Missing environment variables" in str(exc)
    else:
        raise AssertionError("expected SystemExit")
