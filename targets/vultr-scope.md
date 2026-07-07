# Vultr — Bug Bounty Scope

Program page: https://www.vultr.com/ (public policy)
Rating: Bugcrowd Vulnerability Rating Taxonomy (VRT)
Transcribed: 2026-07-07 — **always re-verify against the live policy before testing.**

## In Scope (exact hosts only — no wildcards)

| Host | Notes |
|---|---|
| `www.vultr.com` | Marketing / main site |
| `console.vultr.com` | Customer control panel |
| `api.vultr.com` | Public API |
| `docs.vultr.com` | Documentation |
| `blogs.vultr.com` | Blog |
| `community.vultr.com` | Community |
| `discover.vultr.com` | Discover |
| `agent.vultr.com` | Agent |
| `creators.vultrdevrel.com` | DevRel creators (separate apex `vultrdevrel.com`) |

> Scope lists **individual hosts**, not a `*.vultr.com` wildcard. Only the hosts
> above are authorized. Do not test other subdomains, IP ranges, or customer VM
> workloads. `creators.vultrdevrel.com` lives on a different registered domain —
> confirm ownership/scope before testing.

## Accepted Categories (non-exhaustive)

- Injection Attacks
- Authentication or Authorization Flaws
- Cross-Site Scripting (XSS)
- Sensitive Data Exposure
- Privilege Escalation

"Include, but are not limited to" — other classes may be accepted, but the five
above are explicitly named.

## Rating & Payouts

- Assessment via **Bugcrowd VRT**.
- **P1–P4** eligible for payout. **P5** reportable but not compensated.

| Priority | Payout (USD) |
|---|---|
| P4 | $50 – $300 |
| P3 | $300 – $500 |
| P2 | $500 – $1,000 |
| P1 | $1,000 – $10,000 |

## Hunting Notes

- Highest-value surfaces: `console.vultr.com` (authZ / IDOR / privilege
  escalation across tenants) and `api.vultr.com` (authn, injection, data
  exposure). These map directly to the top payout tiers.
- Run scope-locked recon — no `*.vultr.com` enumeration is authorized:
  ```bash
  python3 tools/hunt.py --target console.vultr.com
  # or verify any asset first:
  /scope api.vultr.com
  ```
- Before submitting, run the 7-Question Gate (`/validate`) and confirm the
  VRT priority to set payout expectations.
