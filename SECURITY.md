# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✓ Active  |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in SwarmHawk itself (not a finding produced by SwarmHawk against a third-party target), please report it privately:

**Email:** security@swarmhawk.ai
**Subject:** `[SECURITY] <brief description>`

Include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Your suggested fix (optional)

We will acknowledge your report within 48 hours and aim to release a fix within 14 days for critical issues.

## Responsible Disclosure

We follow coordinated disclosure. We ask that you:

1. Give us reasonable time to fix the issue before public disclosure
2. Do not access, modify, or delete data beyond what is needed to demonstrate the vulnerability
3. Do not perform denial-of-service attacks

We will credit you in the release notes (unless you prefer to remain anonymous).

## Scope

In scope: the SwarmHawk CLI source code, its dependencies, and the PyPI package.

Out of scope: SwarmHawk's cloud platform (swarmhawk.ai) — please use the cloud platform's own responsible disclosure process at swarmhawk.ai/security.

## Ethical Use

SwarmHawk is a dual-use security tool. It is intended exclusively for:

- Authorized penetration testing (with a signed scope ledger)
- Security research on systems you own
- CTF competitions
- Defensive security monitoring of your own infrastructure

Using SwarmHawk against systems without explicit written authorization is illegal in most jurisdictions and violates this project's terms. The maintainers do not accept responsibility for unauthorized use.
