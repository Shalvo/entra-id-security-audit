# entra-id-security-audit

![CI](https://github.com/Shalvo/entra-id-security-audit/actions/workflows/ci.yml/badge.svg)

A read-only Python tool that checks a Microsoft Entra ID (Azure AD) tenant for
the identity weaknesses attackers go after first, using the Microsoft Graph API.

| Check | Severity | Why it matters |
|---|---|---|
| Admin with no MFA registered | CRITICAL | One phished password gives tenant-wide control |
| Enabled member with no MFA registered | HIGH | Easy target for password spraying |
| Stale member or guest (no sign-in for N days) | MEDIUM | Forgotten accounts are rarely monitored |
| Account created long ago and never used | MEDIUM | Often shared, test or orphaned accounts |

Disabled accounts are skipped. Guests are not flagged for MFA because they
authenticate in their home tenant. The tool never writes to the tenant.

## Try it without a tenant

```bash
pip install -r requirements.txt
python entra_audit.py --demo
```

```text
Entra ID security audit
Users: 11 total, 10 enabled   Stale threshold: 90 days
Findings: CRITICAL 2, HIGH 3, MEDIUM 4

SEVERITY  CHECK                    USER                                    DETAIL
CRITICAL  admin-without-mfa        exchange.admin@contoso.onmicrosoft.com  Holds an admin role but has no MFA method registered
CRITICAL  admin-without-mfa        it.admin@contoso.onmicrosoft.com        Holds an admin role but has no MFA method registered
HIGH      user-without-mfa         new.starter@contoso.onmicrosoft.com     Enabled member account with no MFA method registered
...
```

The demo tenant (`sample_tenant.json`) is fictional and uses the same JSON
shape Microsoft Graph returns, so the code path is identical to a live run.

## Run it against a real tenant

Use a test or developer tenant first (the Microsoft 365 Developer Program
provides one).

1. **Register an app**: Entra admin centre → *App registrations* → *New registration*.
2. **Grant API permissions**: *API permissions* → *Add a permission* →
   *Microsoft Graph* → *Application permissions*:
   - `User.Read.All`
   - `AuditLog.Read.All` (needed for sign-in activity and the MFA registration report)

   Then click **Grant admin consent**.
3. **Create a client secret**: *Certificates & secrets* → *New client secret*.
   For anything beyond a lab, use a certificate instead of a secret.
4. **Set environment variables** (never commit these):

   ```bash
   export AZURE_TENANT_ID="<tenant-guid>"
   export AZURE_CLIENT_ID="<app-client-id>"
   export AZURE_CLIENT_SECRET="<secret-value>"
   python entra_audit.py --csv findings.csv
   ```

   PowerShell: `$env:AZURE_TENANT_ID="..."` and so on.

Sign-in activity and the authentication methods registration report need
Microsoft Entra ID P1 or P2 licensing. Check Microsoft Learn for the current
permission and licence requirements before relying on the output.

## Options

| Option | Default | Purpose |
|---|---|---|
| `--demo` | off | Use the bundled sample tenant |
| `--stale-days N` | 90 | Days without sign-in before an account is stale |
| `--csv PATH` | off | Also write findings to CSV for Excel or a ticket |
| `--json` | off | Machine-readable output |
| `--fail-on-critical` | off | Exit code 1 when a CRITICAL finding exists (for scheduled runs or pipelines) |

## How it works

- Authenticates with the OAuth 2.0 client credentials flow via MSAL.
- Calls `GET /users` (with `signInActivity`) and
  `GET /reports/authenticationMethods/userRegistrationDetails`, following
  `@odata.nextLink` paging and backing off when Graph throttles (HTTP 429).
- The checks live in one pure function, `run_checks()`, which takes plain
  dictionaries and a timestamp. That keeps the logic easy to unit test without
  a tenant.

## Tests

```bash
pytest -v
```

GitHub Actions runs the tests and the demo on Python 3.10, 3.11 and 3.12 on
every push.

## Roadmap

- [ ] Check Conditional Access policies for MFA coverage gaps
- [ ] Flag permanent (non-PIM) Global Administrator assignments
- [ ] Report on apps with expiring or long-lived client secrets
- [ ] HTML report output
- [ ] Run on a schedule as an Azure Function with a managed identity

## Background

I administered Microsoft 365 and Entra ID for a 3,500-user, multi-country
organisation, where MFA coverage and stale-account clean-up were recurring
pieces of work. This project automates those checks with Microsoft Graph and
Python as part of my security engineering practice.

## Licence

MIT
