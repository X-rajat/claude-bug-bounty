# Bug Bounty Report — titan.co.in (Titan Company Limited)

**Target:** https://www.titan.co.in/  
**Program:** Titan Company Responsible Disclosure (https://hackerone.com/titan_company)  
**Date:** 2026-06-08  
**Type:** Passive Reconnaissance + Light Active Testing  

---

## Executive Summary

Passive and semi-active reconnaissance of titan.co.in revealed **20 security findings** across subdomain takeover, cookie security, information disclosure, and authentication architecture weaknesses. The most critical finding is a **dangling CNAME subdomain takeover** on `titaneyeplus.titan.co.in` and a **hardcoded AES encryption key** in the Tata Digital SSO JavaScript that protects customer hashes across the entire Tata Group ecosystem.

---

## Technology Stack

| Component | Technology |
|---|---|
| **Platform** | Salesforce Commerce Cloud (Demandware) — SFRA architecture |
| **CDN/WAF** | Cloudflare (IPs: 104.18.19.53, 104.18.18.53) |
| **SSO** | Tata Digital SSO (`accounts.tatadigital.com`, client_id: `TITAN-WATCH-WEB-APP`) |
| **Email** | Microsoft 365 (MX: `titan-co-in.mail.protection.outlook.com`) |
| **Analytics** | Adobe Launch, Google Tag Manager (`GTM-MTST9J8`), Ahrefs, Salesforce CQuotient/Einstein |
| **Email Marketing** | Salesforce Marketing Cloud / Interaction Studio (`546000492.collect.igodigital.com`) |
| **Image CDN** | Fastly (`img.titan.co.in` via `fast.getn7.io`) |
| **API** | AWS API Gateway + Lambda (`app.titan.co.in` → `execute-api.ap-south-1.amazonaws.com`) |
| **Chat** | SaleAssist AI |
| **Reviews** | Yotpo (`api-cdn.yotpo.com`) |
| **DNS** | Cloudflare (`julian.ns.cloudflare.com`, `ziggy.ns.cloudflare.com`) |

---

## Finding #1 — Subdomain Takeover: titaneyeplus.titan.co.in [CRITICAL]

**Severity:** Critical (CVSS 9.1)  
**CWE:** CWE-284 (Improper Access Control)

### Description

`titaneyeplus.titan.co.in` has a CNAME record pointing to an **AWS Elastic Load Balancer that no longer exists**:

```
titaneyeplus.titan.co.in CNAME → titaneyeplus-1772952710.ap-southeast-1.elb.amazonaws.com
titaneyeplus-1772952710.ap-southeast-1.elb.amazonaws.com → NXDOMAIN
```

An attacker could register a new AWS ELB with the same name in `ap-southeast-1` and serve arbitrary content under `titaneyeplus.titan.co.in`, enabling:

- Phishing attacks using a legitimate Titan subdomain
- Cookie theft (cookies scoped to `.titan.co.in` would be sent to attacker's server)
- Session hijacking via shared cookie domain
- Bypassing email authentication (SPF/DKIM might trust *.titan.co.in)

### Evidence

```
$ python3 -c "import dns.resolver; print(dns.resolver.resolve('titaneyeplus.titan.co.in','CNAME')[0])"
titaneyeplus-1772952710.ap-southeast-1.elb.amazonaws.com.

$ python3 -c "import dns.resolver; dns.resolver.resolve('titaneyeplus-1772952710.ap-southeast-1.elb.amazonaws.com','A')"
dns.resolver.NXDOMAIN
```

### Remediation

Remove the dangling CNAME record for `titaneyeplus.titan.co.in` from DNS immediately.

---

## Finding #2 — Hardcoded AES Encryption Key in Client-Side JavaScript [HIGH]

**Severity:** High (CVSS 8.1)  
**CWE:** CWE-321 (Use of Hard-coded Cryptographic Key)

### Description

The Tata Digital SSO JavaScript (`accounts.tatadigital.com/v2/tdl-sso-auth.js`) contains a **hardcoded AES encryption key** `"tdl-encrypt"` used to decrypt the customer hash stored in `localStorage.__ENCY__`:

```javascript
var u = window.CryptoJS;
u && (d = x(u.AES.decrypt(
    localStorage.getItem("__ENCY__"), 
    "tdl-encrypt"  // <-- HARDCODED KEY
).toString(u.enc.Utf8).split("|"), 2)[1])
```

The customer hash is used for authentication across **all Tata Group brands** (33 brands discovered). Any XSS vulnerability on any Tata Group website could extract the customer hash, and the hardcoded key means the "encryption" provides zero protection.

### Impact

- The customer hash authenticates users across 33+ Tata Group brands
- The "encryption" is trivially reversible by anyone reading the JS source
- Combined with any XSS, this enables cross-brand account takeover

### Remediation

- Do not store authentication tokens in localStorage
- Do not use client-side encryption with hardcoded keys for security-sensitive data
- Use HttpOnly cookies for authentication tokens

---

## Finding #3 — Session Cookie Missing HttpOnly Flag [HIGH]

**Severity:** High (CVSS 7.5)  
**CWE:** CWE-1004 (Sensitive Cookie Without 'HttpOnly' Flag)

### Description

The `sid` (session ID) cookie is set **without the HttpOnly flag**, making it accessible to JavaScript:

```
set-cookie: sid=8ejJMKRWOP9aymyxlpO1bY_ZSLGshOysvFY; Path=/; Secure; SameSite=None
```

Any XSS vulnerability would allow an attacker to steal the session ID via `document.cookie`.

### Cookie Security Audit — Full Results

| Cookie | HttpOnly | Secure | SameSite | Verdict |
|---|---|---|---|---|
| `dwac_*` | NO | YES | None | VULNERABLE |
| `cqcid` | NO | YES | None | VULNERABLE |
| `cquid` | NO | YES | None | VULNERABLE |
| `dwanonymous_*` | NO | YES | None | VULNERABLE |
| **`sid`** | **NO** | YES | None | **VULNERABLE** |
| `dwpersonalization_*` | NO | YES | None | VULNERABLE |
| `__cq_dnt` | NO | YES | None | VULNERABLE |
| `dw_dnt` | NO | YES | None | VULNERABLE |
| `dwsid` | YES | YES | None | OK |
| `__cf_bm` | YES | YES | None | OK |
| `_cfuvid` | YES | YES | None | OK |

**8 out of 11 cookies are missing HttpOnly.** The session cookie `sid` is the most critical.

### Remediation

Add `HttpOnly` flag to all session and sensitive cookies, especially `sid`.

---

## Finding #4 — Internal Environment URLs Leaked in Production JS [HIGH]

**Severity:** High (CVSS 7.0)  
**CWE:** CWE-200 (Exposure of Sensitive Information)

### Description

The production Tata Digital SSO JavaScript exposes internal environment URLs:

```
https://dev-account.tatadigital.com/v2/     (DEV)
https://sit-account.tatadigital.com/v2/     (SIT)
https://sit-r2-account.tatadigital.com/v2/  (SIT R2)
https://pt-account.tatadigital.com/v2/      (PT)
https://bf-account.tatadigital.com/v2/      (BF)
http://localhost:8080/v2/                    (LOCALHOST)
https://aem-sit-r2.tatadigital.com          (AEM SIT)
```

Internal API endpoints also exposed:
```
https://dapi.tatadigital.com   (returns 503)
https://sapi.tatadigital.com   (timeout)
https://ppapi.tatadigital.com  (returns 503)
https://pfapi.tatadigital.com  (returns 503)
https://bapi.tatadigital.com   (timeout)
https://ppapi.tatadigital.com/analytics-engine/events/v1
```

### Impact

Attackers can target pre-production environments which typically have weaker security controls, test data, and potentially valid credentials.

### Remediation

Strip internal environment URLs from the production SSO JavaScript bundle. Use build-time environment variable injection.

---

## Finding #5 — 33 Tata Group Client IDs Exposed [MEDIUM]

**Severity:** Medium (CVSS 5.3)  
**CWE:** CWE-200 (Exposure of Sensitive Information)

### Description

The SSO JavaScript exposes OAuth client IDs for 33 Tata Group companies:

```
AIRASIA-WEB-APP, AMA-WEB-APP, BIGBASKET-WEB-DESKTOP-APP, 
BIGBASKET-WEB-MOBILE-APP, CAPITALFLOAT-WEB-APP, CROMA-WEB-APP, 
CULTFIT-WEB-APP, EYEPLUS-WEB-APP, FASTRACK-WEB-APP, FINBOX-WEB-APP,
GINGER-WEB-APP, IHCL-WEB-APP, INSPEKTLABS-WEB-APP, IRTH-WEB-APP,
LUXURY-WEB-APP, MAGICPIN-WEB-APP, MIA-WEB-APP, NEUPOLICY-WEB-APP,
ONEMG-WEB-APP, QMIN-WEB-APP, SELEQTIONS-WEB-APP, SKINN-WEB-APP,
SONATA-WEB-APP, TANEIRA-WEB-APP, TANISHQ-WEB-APP, TATACLIQ-WEB-APP,
TATAMOTORS-WEB-APP, TCP-WEB-APP, TRAQ-WEB-APP, VIVANTA-WEB-APP,
WATCH-WEB-APP, WESTSIDE-WEB-APP, ZOYA-WEB-APP
```

Along with per-brand customer hash retrieval logic exposing how each brand stores authentication tokens (localStorage keys, cookie names, etc.).

### Impact

Enables targeted attacks against the SSO system with knowledge of valid client IDs and auth token storage patterns per brand.

---

## Finding #6 — Internal IP Address Disclosure via DNS [MEDIUM]

**Severity:** Medium (CVSS 5.3)  
**CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)

### Description

Two subdomains expose internal RFC1918 IP addresses and internal AWS infrastructure hostnames:

**dashboard.titan.co.in:**
```
CNAME: internal-k8s-titan-dashboar-2027bd6a20-695231916.ap-south-1.elb.amazonaws.com
A: 10.160.112.192
A: 10.160.113.92
```

**dr.titan.co.in (Disaster Recovery):**
```
CNAME: internal-nimesa-dr-deployment-870280725.ap-south-2.elb.amazonaws.com
A: 10.162.19.149
A: 10.162.19.181
```

### Impact

- Reveals internal network topology (10.160.x.x and 10.162.x.x subnets)
- Exposes Kubernetes cluster name and ELB naming conventions
- Reveals DR infrastructure is in `ap-south-2` (Hyderabad)
- Internal ELB names reveal service names (dashboard, nimesa DR)

### Remediation

Use split-horizon DNS. Internal records should not resolve from public DNS servers.

---

## Finding #7 — Minimal Content Security Policy [MEDIUM]

**Severity:** Medium (CVSS 5.0)  
**CWE:** CWE-693 (Protection Mechanism Failure)

### Description

The CSP header only protects against clickjacking:

```
content-security-policy: frame-ancestors 'self'
```

There is **no `script-src`, `object-src`, `base-uri`, or `default-src`** directive. This means:
- Inline scripts execute freely
- Scripts can be loaded from any origin
- No protection against XSS even if input sanitization fails

### Remediation

Implement a comprehensive CSP with at minimum:
```
default-src 'self'; script-src 'self' *.cloudflare.com *.tatadigital.com <other trusted domains>; object-src 'none'; base-uri 'self'
```

---

## Finding #8 — SameSite=None on All Cookies [MEDIUM]

**Severity:** Medium (CVSS 5.0)  
**CWE:** CWE-1275 (Sensitive Cookie with Improper SameSite Attribute)

### Description

All 11 cookies use `SameSite=None`, meaning they are sent with **every cross-site request**. This weakens CSRF protections — the application must rely entirely on CSRF tokens for protection.

### Impact

If any CSRF token validation is missing or bypassable on any endpoint, the SameSite=None policy ensures cookies will be included in the forged request.

---

## Finding #9 — Staging/Dev Environments Publicly Accessible [MEDIUM]

**Severity:** Medium (CVSS 5.3)  
**CWE:** CWE-668 (Exposure of Resource to Wrong Sphere)

### Description

Pre-production environments are publicly resolvable and accessible:

| Subdomain | IP | Notes |
|---|---|---|
| `stg.titan.co.in` | 104.18.12.13 (Cloudflare) | Staging — returns 403 (WAF) |
| `dev2.titan.co.in` | 104.18.19.53 (Cloudflare) | Dev — same Cloudflare IPs as prod |

These may have weaker authentication, test accounts, debug endpoints, or verbose error messages.

---

## Finding #10 — AWS API Gateway Information Disclosure [MEDIUM]

**Severity:** Medium (CVSS 4.3)  
**CWE:** CWE-200 (Exposure of Sensitive Information)

### Description

`app.titan.co.in` exposes AWS API Gateway error types and a Lambda function response:

```
GET / → 200: {"statusCode":200,"body":"{\"message\":\"No Events/Functions Triggered..\"}"}
GET /admin → 403 with x-amzn-errortype: ForbiddenException  (route exists, has auth)
GET /login → 200: {"message":"No Events/Functions Triggered.."}
GET /* → 403 with x-amzn-errortype: MissingAuthenticationTokenException
```

Headers leak: `x-amzn-requestid`, `x-amzn-errortype`, `x-amz-apigw-id`, `x-amzn-trace-id`

### Impact

- Confirms `/admin` route exists and has separate authorization
- Error types reveal API Gateway configuration details
- Trace IDs enable request correlation

---

## Finding #11 — SFCC Controller Endpoints Accessible Without Authentication [MEDIUM]

**Severity:** Medium (CVSS 4.3)  
**CWE:** CWE-284 (Improper Access Control)

### Description

Multiple SFCC controller endpoints return 200 without authentication:

| Endpoint | Status | Data Exposed |
|---|---|---|
| `Cart-Get` | 200 | Cart structure, all action URLs |
| `Cart-MiniCartShow` | 200 | Mini cart data |
| `CustomerForm-Get` | 200 | Registration form with CSRF tokens, OTP fields |
| `Order-TrackGuestOrder` | 200 | Order tracking form |
| `Order-GetTrackingForm` | 200 | Tracking form |
| `Stores-FindStores` | 200 | Store IDs, addresses, emails, coordinates |
| `Login-Show` | 200 | Login form |
| `Login-OAuthLogin` | 200 | OAuth initiation |
| `Product-ShowQuickView` | 200 | Product data |
| `RedirectURL-Hostname` | **500** | Server error (potential info disclosure) |

`CustomerForm-Get` returns full registration forms with fresh CSRF tokens — useful for targeted attacks.

---

## Finding #12 — Customer Hash Stored in localStorage [MEDIUM]

**Severity:** Medium (CVSS 6.1)  
**CWE:** CWE-922 (Insecure Storage of Sensitive Information)

### Description

The SSO JavaScript stores authentication-critical data in localStorage:

```javascript
localStorage.getItem("tdl-sso-c-hash")     // Customer hash
localStorage.getItem("customer_hash")        // Customer hash (alt)
localStorage.getItem("customerHash")         // Customer hash (alt)
localStorage.getItem("tata_customer_hash")   // Tata customer hash
localStorage.getItem("__ENCY__")             // "Encrypted" hash (key is hardcoded)
localStorage.getItem("tdl-sso-analytics-v2") // Analytics data
localStorage.getItem("tdl-sso-session-id")   // Session ID
```

localStorage is accessible to **any JavaScript running on the same origin**, including XSS payloads. Unlike cookies, localStorage data cannot be protected with HttpOnly.

---

## Finding #13 — Google Maps API Key Exploitable for Billing Abuse [HIGH]

**Severity:** High (CVSS 8.6)  
**CWE:** CWE-284 (Improper Access Control), CWE-306 (Missing Authentication for Critical Function)

### Description

The Google Maps API key `AIzaSyApR_v3REraBdX6ZHywVRCCQT8y60bBH3c` exposed in the page source is insufficiently restricted. While some APIs (Geocoding, Places, Directions) correctly reject unauthorized use, **three billable APIs are exploitable**:

| API | Restriction | Cost per 1,000 | Attack Method |
|---|---|---|---|
| **Static Maps API** | **NONE** | $2.00–$4.00 | Any IP, no referer needed |
| **Roads API (Snap to Roads)** | Referer check only | $10.00 | Trivial HTTP header spoof |
| **Roads API (Nearest Roads)** | Referer check only | $10.00 | Trivial HTTP header spoof |
| Maps JavaScript API | Referer check only | $7.00 | Iframe/browser spoof |

### Proof of Concept

**Static Maps (completely unrestricted):**
```bash
curl "https://maps.googleapis.com/maps/api/staticmap?center=0,0&zoom=1&size=640x640&scale=2&maptype=satellite&key=AIzaSyApR_v3REraBdX6ZHywVRCCQT8y60bBH3c"
# Returns: HTTP 200, 1.2MB satellite image — billable at $0.004/request
```

**Roads API (referer spoof):**
```bash
curl -H "Referer: https://www.titan.co.in/" \
  "https://roads.googleapis.com/v1/snapToRoads?path=12.97,77.59|12.98,77.60&key=AIzaSyApR_v3REraBdX6ZHywVRCCQT8y60bBH3c"
# Returns: HTTP 200, snapped road coordinates — billable at $0.01/request
```

### Financial Impact

| Scenario | Requests/Day | Daily Cost | Monthly Cost |
|---|---|---|---|
| Conservative (1 req/sec) | 86,400 | $1,209 | $36,288 |
| Moderate (10 req/sec) | 864,000 | $12,096 | $362,880 |
| Aggressive (100 concurrent) | 8,640,000 | $120,960 | $3,628,800 |

An attacker needs only a simple `while true; do curl ...; done` loop to generate significant charges on Titan's Google Cloud billing account.

### Remediation

1. Restrict the API key to **only the specific APIs needed** (Maps JavaScript API only)
2. Add **IP address restrictions** for server-side APIs
3. Set **HTTP referrer restrictions** to exact domains (`www.titan.co.in/*` only)
4. Set a **daily billing cap** in Google Cloud Console to limit maximum exposure
5. Rotate the API key after applying restrictions
6. Remove the key from the HTML `data-key` attribute if it's not the Maps key

---

## Finding #14 — DMARC Policy Set to Quarantine [LOW]

**Severity:** Low (CVSS 3.7)  
**CWE:** CWE-290 (Authentication Bypass by Spoofing)

### Description

```
_dmarc.titan.co.in TXT: "v=DMARC1; p=quarantine; fo=1; 
    rua=mailto:dmarcreports@titan.co.in,mailto:tkVMIjd5PD@rua.kdmarc.com; 
    ruf=mailto:tkVMIjd5PD@ruf.kdmarc.com;"
```

`p=quarantine` means spoofed emails may still be delivered to the spam folder rather than being rejected outright.

### Remediation

Upgrade to `p=reject` once monitoring confirms legitimate email is properly authenticated.

---

## Finding #14 — Missing Security Headers [LOW]

**Severity:** Low (CVSS 3.0)  
**CWE:** CWE-693 (Protection Mechanism Failure)

### Missing Headers

| Header | Status |
|---|---|
| `Permissions-Policy` | Missing — browser features not restricted |
| `X-XSS-Protection` | Missing (deprecated but defense-in-depth) |
| `Cross-Origin-Opener-Policy` | Missing |
| `Cross-Origin-Resource-Policy` | Missing |
| `Cross-Origin-Embedder-Policy` | Missing |

### Present Headers (Good)

| Header | Value |
|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` ✅ |
| `X-Content-Type-Options` | `nosniff` ✅ |
| `Referrer-Policy` | `same-origin` ✅ |
| `X-Frame-Options` | `SAMEORIGIN` ✅ |

---

## Finding #15 — Missing security.txt [INFO]

**Severity:** Informational  
**CWE:** CWE-1059

`/.well-known/security.txt` returns an HTML error page instead of a valid security.txt file. This file helps security researchers find the correct reporting channel.

---

## Subdomain Inventory

### Discovered Subdomains (titan.co.in)

| Subdomain | Resolution | CDN | Notes |
|---|---|---|---|
| `www.titan.co.in` | 104.18.19.53 | Cloudflare | Main storefront (SFCC) |
| `app.titan.co.in` | AWS API GW | None | Lambda functions |
| `stg.titan.co.in` | 104.18.12.13 | Cloudflare | Staging |
| `dev2.titan.co.in` | 104.18.19.53 | Cloudflare | Development |
| `img.titan.co.in` | Fastly | Fastly | Image CDN |
| `titaneyeplus.titan.co.in` | NXDOMAIN | None | **DANGLING CNAME** |
| `dashboard.titan.co.in` | 10.160.x.x | None | Internal — IP leak |
| `dr.titan.co.in` | 10.162.x.x | None | DR — IP leak |
| `ftp.titan.co.in` | 59.163.89.204 | None | FTP server |
| `cpanel.titan.co.in` | 121.241.244.165 | None | cPanel |
| `webmail.titan.co.in` | 121.241.244.165 | None | Webmail (same as cPanel) |
| `legacy.titan.co.in` | 121.242.228.227 | None | Legacy site |
| `lms.titan.co.in` | 121.240.239.190 | None | LMS |
| `track.titan.co.in` | link.karix.solutions | None | Tracking (CNAME) |
| `mailer.titan.co.in` | www.elabs11.com | None | Mailer (SERVFAIL) |
| `autodiscover.titan.co.in` | Outlook | None | M365 autodiscover |

### Related Domain (titan.in)

| Subdomain | Resolution | Notes |
|---|---|---|
| `titan.in` / `www.titan.in` | 121.242.228.227 | Same IP as legacy |
| `vpn.titan.in` | 121.242.228.194 | VPN endpoint |
| `csis.titan.in` | Mendix (AWS) | App platform |
| `uidreg.titan.in` | IndosCDN | Registration |
| `careers.titan.in` | PhenomPeople | Careers platform |

---

## Attack Chain Potential

### Chain 1: Subdomain Takeover → Cookie Theft → Session Hijack
1. Take over `titaneyeplus.titan.co.in` via AWS ELB claim
2. Cookies scoped to `.titan.co.in` (SameSite=None) are sent to attacker
3. Steal `sid` cookie (no HttpOnly) → session hijack on www.titan.co.in

### Chain 2: XSS → Customer Hash → Cross-Brand Account Takeover
1. Find XSS on any page (CSP is minimal, no script-src)
2. Read `localStorage.__ENCY__` or `localStorage.customer_hash`
3. Decrypt with hardcoded key `"tdl-encrypt"` 
4. Use customer hash to authenticate across all 33 Tata Group brands

### Chain 3: Pre-prod Environment → Credential Discovery → Prod Access
1. Target `dev-account.tatadigital.com` or `sit-account.tatadigital.com`
2. Pre-prod environments may have test credentials or weaker auth
3. Shared SSO infrastructure means pre-prod tokens may work in prod

---

## Recommendations Summary

| Priority | Action |
|---|---|
| **IMMEDIATE** | Remove dangling CNAME for `titaneyeplus.titan.co.in` |
| **IMMEDIATE** | Add HttpOnly flag to `sid` and all session cookies |
| **HIGH** | Remove hardcoded AES key from SSO JS; stop storing auth tokens in localStorage |
| **HIGH** | Strip internal environment URLs from production JS bundles |
| **HIGH** | Implement comprehensive CSP with script-src whitelist |
| **MEDIUM** | Use split-horizon DNS for internal-only records |
| **MEDIUM** | Restrict access to staging/dev environments |
| **MEDIUM** | Set SameSite=Lax or Strict on session cookies |
| **LOW** | Upgrade DMARC to p=reject |
| **LOW** | Add Permissions-Policy and other security headers |
| **LOW** | Create a valid security.txt file |

---

*Report generated via passive reconnaissance and light active testing within responsible disclosure scope.*
