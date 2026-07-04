# Google VRP — `accounts.google.com` / OAuth Surface
## Recon + Testing Methodology (Bug Bounty Posture)

**Target program:** Google & Alphabet Web VRP → Identity / Account-boundary surface
**Report portal:** https://bughunters.google.com
**Author scope:** Solo researcher, low-noise, logic-first
**Version:** 1.0

---

## ⚠️ Rules of Engagement (READ FIRST — this is not a government engagement)

You do **not** have blanket authorization here. Authorization is bounded by the VRP rules. Violating them risks profile ban, forfeited rewards, and legal exposure.

**Hard PROHIBITED (will get you banned):**
- No DoS / stress / volumetric testing.
- No automated high-volume traffic — this kills your default `nuclei`, `sqlmap --batch`, `gobuster -t 50`, `ffuf` mass-fuzz, `hydra` login brute-force sequences. Do **not** point them at Google.
- No login/OTP brute-force or credential stuffing against real accounts.
- No black-hat SEO, no spam, no social engineering / phishing Google employees, no physical access.
- No testing `*.appspot.com`, `*.bc.googleusercontent.com` (Cloud customer apps — unauthorized).
- No pivoting into other users' real data. Use **only accounts you control** (register 2–3 test Google accounts; label them clearly).

**ALLOWED:**
- Manual testing of your own accounts and OAuth flows.
- Low-rate, targeted requests via Burp (manual repeater, not Intruder mass-payload runs).
- Passive recon (DNS, CT logs, JS analysis, public docs).
- Building your own OAuth **client** to test Google-as-IdP behavior.

**Rule of thumb:** if a human couldn't plausibly generate the traffic by hand in a browser session, throttle it or don't send it.

---

## Scope Definition

### In scope (where undiscovered bugs realistically live)
Google's core OAuth code-exchange and token-signing paths are among the most-tested code on earth — don't expect low-hanging fruit there. Realistic surface:

1. **Account lifecycle & identity linking** — linking/unlinking third-party identities, "Sign in with Google" as consumer, recovery flows, secondary email/phone binding. *Pre-account-takeover and identity-confusion bugs cluster here.*
2. **Cross-product authorization boundaries** — a token/session scoped to product A that reads product B's data (your IDOR-across-ecosystem angle).
3. **Consent & authorization edge cases** — silent re-authorization, consent bypass for new scopes, `prompt`/`login_hint` handling.
4. **`redirect_uri` / client-registration validation** — especially on newer or acquired products and first-party clients with permissive registration.
5. **Session management on `accounts.google.com`** — multi-login (`/u/0`, `/u/1`), session fixation, logout completeness, cookie scoping across `*.google.com`.
6. **New / recently-integrated products** consuming the Google account — least-tested surface. Track Google product launches and integrations.

### Out of scope (don't waste cycles)
- Core `/o/oauth2/token` code→token exchange crypto — hardened.
- `id_token` signature forgery — hardened (but **client-side** validation flaws in Google's own consumer apps are fair game).
- Sandbox-domain XSS (`*.googleusercontent.com`) unless sensitive-data impact.
- Blogger / `*.blogspot.com` owner-supplied JS.
- Known non-qualifying findings — **read Bug Hunter University first** to avoid dupes/N/A.

---

## Phase 1 — Passive Recon (OAuth-Specific)

Goal: map Google's OAuth/OIDC surface and endpoint inventory without touching auth logic.

**OIDC discovery documents** (fetch, read, diff over time):
- `https://accounts.google.com/.well-known/openid-configuration`
- `https://www.googleapis.com/oauth2/v3/certs` (JWKS — note key rotation, `kid`s, algs)
- Enumerate every endpoint the discovery doc exposes: `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `revocation_endpoint`, `device_authorization_endpoint`, supported `scopes_supported`, `response_types_supported`, `grant_types_supported`, `code_challenge_methods_supported`.

**Client & integration inventory:**
- CT logs / `crt.sh` for Google auth-adjacent subdomains (passive only).
- Wayback Machine + public JS for historical OAuth client IDs, deprecated `redirect_uri`s, old scopes, legacy endpoints.
- Google's own product docs (Identity, Sign-In, Workspace, Cloud OAuth) — map documented vs undocumented `prompt`, `access_type`, `include_granted_scopes`, `hd`, `login_hint` params.
- GitHub search for leaked first-party client IDs / config and integration quirks (public repos only; do not use leaked secrets).

**Deliverable:** an endpoint + parameter inventory sheet. This is your test matrix input for Phase 3.

---

## Phase 2 — Active Enumeration (Flow Mapping)

Goal: capture and diagram every auth flow variant with Burp, using **your own** test accounts. Low rate, manual.

**Capture each flow end-to-end in Burp:**
- Authorization Code + PKCE (standard "Sign in with Google").
- Implicit / hybrid `response_type` variants (if still accepted anywhere).
- Device code flow.
- Account linking flow (link a third-party identity to your Google account, and Google identity to a third-party app).
- Re-authentication / step-up / consent-again flows.
- Multi-account (`/u/0`, `/u/1`) and account switch.
- Logout / session revocation.

**For each flow, record every parameter and its role:**
`client_id`, `redirect_uri`, `response_type`, `response_mode`, `scope`, `state`, `nonce`, `code_challenge`/`code_challenge_method`, `prompt`, `access_type`, `login_hint`, `hd`, `include_granted_scopes`, `continue`, `authuser`.

**Build the request-mutation baseline:** for each parameter you'll later drop, duplicate, swap, or corrupt one at a time (Repeater, not Intruder mass-runs).

**Deliverable:** annotated flow diagrams + a per-parameter "what happens if I tamper" hypothesis list.

---

## Phase 3 — Vulnerability Testing (OAuth/OIDC Attack Matrix)

Test each class manually against your own accounts/clients. Priority = impact × surface freshness. Skip anything you've confirmed hardened in Phase 1.

| # | Class | What to test | Impact if found |
|---|-------|--------------|-----------------|
| 1 | **`redirect_uri` validation** | Path append/traversal, subdomain/sibling-domain, trailing-slash/`@`/`#` tricks, param pollution (`redirect_uri` ×2), `localhost`/loopback rules, deprecated URIs from Wayback | Auth code / token exfil → **ATO** (Critical) |
| 2 | **Authorization code binding** | Reuse code, use one account's code in another's session, cross-client code use, code leak via `Referer`/`continue` | Code injection → ATO (Critical) |
| 3 | **PKCE integrity** | Downgrade (drop `code_challenge`), `plain` vs `S256` confusion, verifier reuse/omission at token endpoint | Code-interception ATO (High/Critical) |
| 4 | **`state` / CSRF** | Missing/echoed-not-validated `state`, cross-flow `state` reuse, forced login CSRF | OAuth-CSRF / account linking to attacker (High) |
| 5 | **Account linking / pre-ATO** | Link attacker identity to victim-email account before victim registers; unverified-email linking; merge/unlink race | **Pre-account takeover** (Critical) |
| 6 | **Scope escalation** | Add scopes at consent vs granted set, `include_granted_scopes=true` abuse, incremental-auth silent grants, downgrade then upgrade | Over-privileged token (High) |
| 7 | **Consent bypass / silent auth** | `prompt=none` on flows that shouldn't allow it, auto-approval for first-party-adjacent clients, re-consent skipped on scope change | Silent authorization (High) |
| 8 | **Cross-product authz boundary** | Token/session scoped to product A → call product B API; `authuser`/`/u/N` confusion returning wrong account's data | IDOR across ecosystem (High/Critical) — **your strongest angle** |
| 9 | **Session management** | Logout completeness (token still valid post-logout), session fixation, cookie scope across `*.google.com`, revocation propagation delay | Session hijack (High) |
| 10 | **`id_token` client-side validation** | In Google's own consumer apps: `aud`/`iss`/`nonce`/`exp` checks, `alg` handling on the *consumer* side | ATO if a first-party client mis-validates (High) |
| 11 | **IdP mix-up / response confusion** | `response_mode` swap (`query`→`fragment`→`form_post`), issuer confusion in multi-IdP flows | Token/code leak (High) |
| 12 | **Open redirect chaining** | `continue`, `redirect_uri`, `next` params as leak primitives to smuggle code/token off-origin | Amplifies #1/#2 (Medium→Critical when chained) |

**Method for each row:** one-variable mutation in Repeater → observe response, redirect, token/code placement → if anomalous, escalate manually.

---

## Phase 4 — Exploitation & PoC (to the 2026 Panel Bar)

Google's 2026 rules **deprioritize AI-style write-ups without proof** and reward **concrete, reproducible PoCs** (and, where relevant, suggested fixes). A theory-only report will be reduced or rejected.

For every confirmed finding:
1. **Reproduce** — full HTTP request/response pair(s), exact order, exact accounts (label test-account-A / test-account-B).
2. **Prove the boundary break** — show attacker-controlled account obtaining victim-account data/access. Screen-record the flow.
3. **Minimal PoC** — smallest curl/Burp sequence or a tiny HTML page (for redirect/CSRF chains) that a triager can run in <5 min.
4. **Impact statement** — concrete: "full account takeover of any user who clicks X," not "may lead to compromise."
5. **CVSS 3.1** vector + score.
6. **Suggested fix** — 1–2 lines (e.g., "enforce exact `redirect_uri` match; reject on param duplication").

**Escalation targets to always attempt:** authorization code → token → account takeover; scope creep → sensitive-API read; cross-product token → PII read.

---

## Phase 5 — Self-Learning Loop

After each finding (or each dead end):
1. `web_search`: `Google OAuth VRP writeup [class] account takeover` — study disclosed reports for what Google *paid* on vs marked dupe/N/A.
2. Review recent Bug Hunters leaderboard writeups + Google Security blog VRP posts for current focus areas and bugSWAT targets.
3. Re-read Bug Hunter University "non-qualifying" list — confirm your finding isn't there.
4. Update your parameter-mutation set with any new bypass primitive.
5. Re-test previously "clean" flows against the new primitive (esp. on newly-launched Google products).

---

## Phase 6 — Submission (VRP format, NOT LaTeX)

Do **not** use the CERT-UK/ITDA LaTeX report engine here — VRP wants a concise portal submission, not a government audit deliverable.

**Submission structure:**
- **Title:** `[Class] in [flow] leading to [impact]` — precise.
- **Bug location:** select the right VRP sub-program (Google & Alphabet Web).
- **Summary:** 2–3 sentences, attack scenario + who exploits it + what they gain.
- **Steps to reproduce:** numbered, exact, with your test-account labels.
- **PoC:** request/response, curl, and/or hosted HTML + screen recording link.
- **Impact:** concrete worst case.
- **Suggested remediation:** short.
- **Attachments:** video PoC, HAR (scrubbed), minimal exploit page.

**Pre-submit checklist:**
- [ ] Reproduced twice, from clean sessions.
- [ ] Only your own accounts touched — zero real-user data accessed.
- [ ] No prohibited tooling/volume used at any point.
- [ ] Checked Bug Hunter University — not a known non-qualifier.
- [ ] Impact escalated as far as it goes.
- [ ] First-reporter risk accepted (dupes happen — submit fast on strong findings).
- [ ] CVSS + suggested fix included.

---

## Quick-Start Sequence

1. Register test accounts A, B (+ a throwaway third-party OAuth client you control).
2. Fetch `.well-known/openid-configuration` + JWKS → build endpoint/param inventory.
3. Burp-capture all flows from Phase 2 with account A.
4. Work the Phase 3 matrix top-down, one variable at a time, manual/low-rate.
5. On any anomaly → Phase 4 escalation immediately (don't sit on redirect/code leaks).
6. Loop Phase 5 continuously; submit via Phase 6 the moment a boundary break is proven.

**Highest-EV focus for your profile:** rows **8 (cross-product authz)**, **5 (account-linking pre-ATO)**, and **1 (redirect_uri)** — logic-heavy, map to your VAPT strengths, and live on the fresher/less-fuzzed surface.
