# Security Policy

## Reporting a vulnerability

If you find a security issue in ScopeGuard itself — a way to bypass scope enforcement,
exfiltrate data, or cause harm outside the declared target list — please **do not**
open a public issue.

Email the maintainer (see the GitHub profile) with:

- Description of the issue
- Reproduction steps
- Affected version / commit
- Suggested mitigation

Expect an acknowledgment within 72 hours.

## In scope

- Bypasses of `scope.yaml` enforcement
- Path traversal in the report engine
- Injection in the web dashboard (XSS, template injection)
- Denial of service via scan inputs
- Anything that causes ScopeGuard to touch a host outside declared scope

## Out of scope

- Vulnerabilities in a target network you scanned. That's between you and the owner.
- Missing features (cracking, deauth, injection) — non-goals by design.

## Non-goals

ScopeGuard will never ship:

- WiFi password cracking
- WPA handshake capture
- Deauthentication attacks
- Packet injection
- Scanning without a valid, unexpired `scope.yaml`

## Using ScopeGuard responsibly

Intended for: auditing networks you own, lab/home environments, authorized engagements.

Not intended for: networks you do not own, public WiFi, corporate networks without
authorization, or any activity that violates local law.

You are responsible for what you scan.
