# Server-Side Request Forgery (SSRF) — Lab Report

**Author:**Muhammad Wasiq
**Environment:** PortSwigger Web Security Academy (authorized training labs)
**Scope:** 5 SSRF labs — Basic (local server), Basic (back-end system), Blacklist bypass, Open-redirect bypass, Whitelist bypass (Expert)
**Tools used:** Burp Suite (Proxy, Repeater)


> Note: These are PortSwigger's own deliberately vulnerable training applications, tested with authorization inherent to the platform. This report documents methodology and findings in a professional pentest-report format for portfolio and learning purposes — it is not a client engagement.

---

## 1. Executive Summary

This report documents hands-on testing of five Server-Side Request Forgery (SSRF) scenarios, covering unfiltered SSRF, blacklist and whitelist filter bypasses, redirect-chain exploitation, and the underlying trust assumptions that make SSRF dangerous in real applications.

Across all five labs, the root cause was the same: **the application let user input decide the destination of a server-side request, and the validation in place did not match how the request was actually resolved and sent.** Filters failed in different, specific ways — a blacklist failed because it matched text, not addresses; a whitelist failed because its parser disagreed with the request library's parser; a redirect bypass failed because only the first hop was validated.

| # | Lab | Difficulty | Result | Key Takeaway |
|---|-----|-----------|--------|---------------|
| 1 | SSRF against the local server | Apprentice | Solved | Loopback requests often bypass auth entirely |
| 2 | SSRF against another back-end system | Apprentice | Solved | Internal IPs are weakly protected — network isolation is not a security control |
| 3 | SSRF with blacklist-based filter | Practitioner | Solved | Blacklists block spellings, not addresses |
| 4 | SSRF with filter bypass via open redirect | Practitioner | Solved | Allowlisting a host means nothing if that host can redirect |
| 5 | SSRF with whitelist-based filter | Expert | Solved | Parser mismatches break allowlists |

---

## 2. Scope and Methodology

- **Target:** PortSwigger Web Security Academy SSRF lab set (5 labs)
- **Method:** Manual testing via Burp Suite. Each request was intercepted in Proxy, sent to Repeater, and the vulnerable parameter (`stockApi`) was modified and resent to observe server behavior.
- **Approach per lab:**
  1. Identify the parameter carrying a URL or URL fragment
  2. Determine what the server does with it (fetches it, returns the response)
  3. Identify the defense in place, if any (filter, allowlist, redirect validation)
  4. Attempt to redirect the request to an unintended target
  5. Confirm impact via the returned response
- **Limitations:** Testing was confined to PortSwigger's lab environment. No real production systems, third parties, or customer data were involved.

---

## 3. Findings

### F-01: Basic SSRF Against the Local Server
**Severity:** Critical
**Lab:** Basic SSRF against the local server (Apprentice)

**Description:**
The stock-check feature accepted a full URL in the `stockApi` parameter and fetched it server-side. Pointing this at the server's own loopback address reached an administrative interface that is normally only accessible to authenticated users — but trusts any request originating from the local machine.

**Request (normal):**
```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded

stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1
```

**Request (exploited):**
```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded

stockApi=http://localhost/admin
```

**Result:** Server returned the full admin panel HTML in the response.

**Root cause:** Admin access control is only enforced at the network/front-end layer, implicitly trusting any request that originates from the local machine (common for disaster-recovery access or because the check lives in a separate front-end component).

**Fix:** Enforce authentication/authorization at the application layer regardless of request origin. Never treat "comes from localhost" as equivalent to "is authenticated."

---

### F-02: Basic SSRF Against Another Back-End System
**Severity:** Critical
**Lab:** Basic SSRF against another back-end system (Apprentice)

**Description:**
The same `stockApi` parameter was used to reach an internal, non-routable IP address hosting an unauthenticated admin interface.

**Request:**
```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded

stockApi=http://192.168.0.68/admin
```

**Result:** Admin interface on the internal host returned successfully, with no authentication required.

**Root cause:** The internal system relied entirely on network isolation as its security boundary. Once a request could originate from inside the network (via the vulnerable app acting as a proxy), there was no further control.

**Fix:** Internal services must enforce their own authentication regardless of network position. Network segmentation is not a substitute for access control.

---

### F-03: SSRF with Blacklist-Based Filter Bypass
**Severity:** High
**Lab:** SSRF with blacklist-based input filter (Practitioner)

**Description:**
The application blocked literal strings such as `127.0.0.1` and `localhost`. This was bypassed using an alternative representation of the same address.

**Bypass techniques used:**
```
http://2130706433/admin        # decimal form of 127.0.0.1
http://017700000001/admin      # octal form
http://127.1/admin             # shorthand form
```

**Result:** Filter did not recognize the alternate representation; request reached the loopback admin interface.

**Root cause:** The filter performed a string comparison against known-bad values instead of resolving and checking the actual destination address.

**Fix:** Resolve the hostname to an IP address server-side and validate the IP against a blocklist of private/loopback/link-local ranges — never match on raw input text.

---

### F-04: SSRF Filter Bypass via Open Redirection
**Severity:** High
**Lab:** SSRF with filter bypass via open redirection vulnerability (Practitioner)

**Description:**
The application validated that the `stockApi` URL belonged to an allowed domain. That allowed domain, however, contained an open redirect, which was chained to reach the real (internal) target.

**Request:**
```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded

stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin
```

**Result:** The allowed domain redirected the server's request to `192.168.0.68/admin`, which the server followed and returned.

**Root cause:** The validation only checked the first request's domain. Redirects issued by that domain were followed without being re-validated.

**Fix:** Either disable redirect-following on server-side HTTP requests, or re-validate the destination of every redirect hop against the same allowlist/IP checks used on the initial request.

---

### F-05: SSRF with Whitelist-Based Filter Bypass
**Severity:** High
**Lab:** SSRF with whitelist-based input filter (Expert)

**Description:**
The application only allowed URLs matching an expected host pattern. This was bypassed by exploiting inconsistencies between how the filter parsed the URL and how the back-end HTTP client parsed it.

**Bypass techniques used:**
```
https://expected-host:fakepassword@evil-host     # credentials syntax — real host is evil-host
https://evil-host#expected-host                  # fragment syntax — real host is evil-host
https://expected-host.evil-host                  # subdomain syntax — real host is evil-host
```
Combined with URL encoding to further confuse the filter's parsing logic.

**Result:** The filter matched on the presence of `expected-host` in the string, while the actual HTTP request was sent to `evil-host`.

**Root cause:** Ad-hoc URL validation (regex or substring matching) does not reliably agree with a full URL parser. The gap between the two was the exploitable surface.

**Fix:** Use a single, well-tested URL parser for both validation and the actual request. Validate the parsed `host` component specifically — never the raw string — and reject any credentials/fragment syntax in unexpected places.

---

## 4. Common Root Cause (All Findings)

Every finding traces back to one pattern: **the component that approves a URL is not the component that uses it, and the two disagree about what the URL actually points to.** Whether that's a loopback address in disguise, an internal IP with no further checks, a different address notation, a redirect chain, or a parser mismatch — the fix is always the same in principle: validate the final, resolved destination, not the input string, and re-validate at every hop.

---

## 5. Remediation Roadmap

| Priority | Action |
|---|---|
| 1 | Never let "request originates from localhost/internal network" imply "authenticated" |
| 2 | Enforce authentication on all internal/admin interfaces independent of network position |
| 3 | Replace blacklist/whitelist string matching with: resolve DNS → validate IP against private/loopback/link-local ranges |
| 4 | Disable automatic redirect-following on server-side requests, or re-validate every redirect hop |
| 5 | Add network-level egress controls (app servers should not reach internal ranges or metadata endpoints unless explicitly required) |
| 6 | Log and alert on outbound requests to private IP ranges or cloud metadata addresses |

---

## 6. Lessons Learned

1. Validate where a request actually lands after resolution — not how the input string looks.
2. A blacklist blocks known bad spellings; an attacker only needs one it missed.
3. A whitelist is only as strong as its URL parser; two different parsers in one code path is a vulnerability waiting to be found.
4. Every redirect is effectively a brand-new, unvalidated request.
5. Network isolation is not access control — internal systems need their own authentication.

## 7. References

- PortSwigger Web Security Academy — Server-side request forgery (SSRF)
- OWASP Top 10:2025 — A01: Broken Access Control (SSRF consolidated here)
- Capital One breach (2019) — public post-incident analyses on SSRF reaching cloud metadata services
