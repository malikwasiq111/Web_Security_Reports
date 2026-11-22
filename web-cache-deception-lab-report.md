# Web Cache Deception — Lab Report

**Author:** Muhammad Wasiq
**Environment:** PortSwigger Web Security Academy (authorized training labs)
**Scope:** 5 web cache deception labs — Path mapping, Path delimiters, Origin server normalization, Cache server normalization, Exact-match (file name) cache rules
**Tools used:** Burp Suite (Proxy, Repeater, Intruder, Param Miner extension)

> Note: These are PortSwigger's own deliberately vulnerable training applications. This report documents methodology and findings in a professional pentest-report format for portfolio and learning purposes — it is not a client engagement.

---

## 1. Executive Summary

This report documents hands-on testing of five web cache deception (WCD) scenarios. Web cache deception is distinct from web cache poisoning: poisoning manipulates the cache key to serve malicious content to *other* users, while deception tricks the cache into storing a *victim's own sensitive response* under a URL the attacker can later request.

Across all five labs, the root cause was the same: **the cache and the origin server parse the same URL path differently, and that gap lets a request for private data look like a request for a static file.** Each lab exploited a different point of disagreement — how paths map to resources, how delimiter characters are handled, and how each side normalizes encoded characters and dot-segments.

| # | Lab | Difficulty | Result | Key Takeaway |
|---|-----|-----------|--------|---------------|
| 1 | Exploiting path mapping for WCD | Apprentice | Solved | REST-style origin servers ignore trailing path segments; traditional-mapping caches don't |
| 2 | Exploiting path delimiters for WCD | Practitioner | Solved | A character treated as a delimiter by the origin but not the cache splits their interpretation of the path |
| 3 | Exploiting origin server normalization for WCD | Practitioner | Solved | If the origin resolves encoded dot-segments but the cache doesn't, path traversal reaches dynamic content under a static prefix |
| 4 | Exploiting cache server normalization for WCD | Practitioner | Solved | If the cache resolves dot-segments but the origin doesn't, traversal plus a delimiter is needed to land on both sides correctly |
| 5 | Exploiting exact-match cache rules for WCD | Expert | Solved | Even single, named static files (e.g. index.html) can be used as the cache-trigger via normalization discrepancies |

---

## 2. Scope and Methodology

- **Target:** PortSwigger Web Security Academy web cache deception lab set (5 labs)
- **Method:** Manual testing via Burp Suite Proxy and Repeater, with Param Miner's dynamic cachebuster to keep cache keys unique between test requests, and Burp Intruder to sweep delimiter characters.
- **General approach per lab:**
  1. Identify an endpoint returning sensitive, dynamic content via GET
  2. Confirm whether the response is cacheable (`X-Cache`, `Cache-Control` headers, response-time differences)
  3. Test how the **origin server** maps/normalizes the path (does an arbitrary suffix still return the same dynamic data?)
  4. Test how the **cache** maps/normalizes the path (does adding a static extension or prefix cause a cache hit?)
  5. Combine the discrepancy into one URL that the cache treats as static but the origin still treats as the dynamic endpoint
  6. Confirm by requesting the crafted URL as a second "attacker" request and checking for the victim's cached data
- **Limitations:** Testing was confined to PortSwigger's lab environment. No real production systems, CDNs, or customer data were involved.

---

## 3. Findings

### F-01: Path Mapping Discrepancy
**Severity:** High
**Lab:** Exploiting path mapping for web cache deception (Apprentice)

**Description:**
The application used REST-style URL mapping, where extra path segments are treated as ignorable parameters rather than literal file paths. The cache, by contrast, mapped the full path literally and matched on file extension.

**Testing:**
```
/my-account/foo           → still returns account page (origin ignores "foo")
/my-account/foo.js        → response is cached (cache matches on .js extension)
```

**Result:** Requesting `/my-account/anything.js` returned the authenticated user's private account page, and the response was stored by the cache. A follow-up request to the same URL (simulating the attacker) returned the victim's cached account data.

**Root cause:** The origin server abstracts the URL into a logical endpoint and ignores trailing segments; the cache has a rule to store any path ending in a static extension, and interprets the full literal path.

**Fix:** Configure the origin to return an explicit error (404) for unexpected path segments instead of silently ignoring them, and ensure cache rules key on actual `Content-Type`, not just URL extension.

---

### F-02: Delimiter Discrepancy
**Severity:** High
**Lab:** Exploiting path delimiters for web cache deception (Practitioner)

**Description:**
The origin server treated a specific character as a path delimiter (truncating everything after it), while the cache did not recognize that character and treated it as part of the literal path.

**Testing approach:**
```
/settings/users/list          → baseline response
/settings/users/listaaa       → reference response for "unrecognized segment"
/settings/users/list;aaa      → matches baseline → ';' is a delimiter for the origin
/settings/users/list;aaa.js   → cached → cache does not treat ';' as a delimiter
```

**Result:** The crafted URL `/settings/users/list;aaa.js` was interpreted by the origin as `/settings/users/list` (returning sensitive user-list data) and by the cache as a static `.js` file, which it stored.

**Root cause:** Delimiter handling is framework-specific (e.g. `;` for matrix parameters in some frameworks) and is not consistently applied across the cache layer, which has no awareness of the origin's routing conventions.

**Fix:** Mark dynamic, authenticated endpoints with `Cache-Control: no-store, private` so the cache never stores them regardless of how the path is parsed. Don't rely on path-based cache rules alone for distinguishing static from dynamic content.

---

### F-03: Origin Server Normalization Discrepancy
**Severity:** High
**Lab:** Exploiting origin server normalization for web cache deception (Practitioner)

**Description:**
The origin server decoded URL-encoded characters and resolved dot-segment path traversal (`..`) during normalization; the cache did neither, and instead matched on a static directory prefix.

**Testing:**
```
/aaa/..%2fprofile             → origin returns profile data (resolves to /profile)
/static/..%2fprofile          → cached under /static prefix, but origin still serves /profile
```

**Result:** The payload `/static/..%2fprofile` was interpreted by the cache as a request under the cacheable `/static` prefix, while the origin server decoded and resolved it down to `/profile`, returning the authenticated user's dynamic profile data — which the cache then stored.

**Root cause:** Only the origin server normalizes the encoded traversal sequence; the cache treats the raw, un-normalized path as the cache key, so the two disagree on what resource is actually being requested.

**Fix:** The cache should normalize paths (decode and resolve dot-segments) using the same logic as the origin before applying cache rules, or cache rules should not be based purely on a directory prefix without confirming the resource actually served from that directory.

---

### F-04: Cache Server Normalization Discrepancy
**Severity:** High
**Lab:** Exploiting cache server normalization for web cache deception (Practitioner)

**Description:**
This was the inverse of F-03: the **cache** resolved encoded dot-segments while the **origin** did not. Path traversal alone was not enough here, since the origin would simply error out on the un-resolved traversal sequence — an additional delimiter (recognized by the origin but not the cache) was needed to make both sides agree on different resources.

**Testing:**
```
/profile%2f%2e%2e%2fstatic         → cache resolves to /static (cached); origin returns error for literal path
/profile;%2f%2e%2e%2fstatic        → origin truncates at ';' and returns /profile data; cache still resolves to /static
```

**Result:** The payload `/profile;%2f%2e%2e%2fstatic` caused the cache to normalize and key the response under `/static` (triggering the static-directory cache rule), while the origin server truncated the path at the delimiter and returned the dynamic `/profile` content — which was then cached under the `/static` key.

**Root cause:** Normalization was asymmetric between cache and origin, and exploiting it required chaining two separate discrepancies (normalization plus delimiter handling) rather than one.

**Fix:** Same as F-03 — align normalization behavior between cache and origin, and never let a static-prefix rule alone decide cacheability without verifying the response's actual content type.

---

### F-05: Exact-Match (File Name) Cache Rule via Normalization
**Severity:** Medium-High
**Lab:** Exploiting exact-match cache rules for web cache deception (Expert)

**Description:**
Unlike directory-prefix or extension rules, this cache rule matched one exact file name (e.g. `index.html`). The same cache-side normalization discrepancy from F-03 was reused, but the payload had to resolve to the exact matched file name instead of a directory prefix.

**Testing:**
```
/profile%2f%2e%2e%2findex.html     → cached (cache normalizes to /index.html); origin's handling confirmed separately
```

**Result:** By normalizing the crafted path down to the exact cached file name, the cache stored the dynamic profile response under that file name's cache entry, which the origin server had actually served from the unresolved dynamic path.

**Root cause:** Exact-match rules are assumed "safe" because they target one specific, known-static file name, but they are equally vulnerable if the cache's path normalization can be tricked into mapping an arbitrary path onto that exact name.

**Fix:** Exact-match cache rules need the same protections as prefix/extension rules: verify `Content-Type` and `Cache-Control` on the actual response before storing, don't assume a filename match is inherently safe from normalization abuse.

---

## 4. Common Root Cause (All Findings)

Every finding comes from the same underlying gap: **the cache and the origin server each build their own idea of "what resource does this path point to," and nothing guarantees those two ideas match.** Whether the mismatch comes from REST-style abstraction, framework-specific delimiters, or inconsistent decoding of dot-segments and encoded characters, the result is the same — a URL that looks static to the cache but resolves to private, dynamic content at the origin.

---

## 5. Remediation Roadmap

| Priority | Action |
|---|---|
| 1 | Set `Cache-Control: no-store, private` explicitly on all dynamic/authenticated responses — don't rely on the cache to infer this from the URL |
| 2 | Configure the CDN/cache so caching rules cannot override an explicit `Cache-Control` header from the origin |
| 3 | Enable CDN protections that verify response `Content-Type` matches the requested URL's extension before caching (e.g. cache deception armor features) |
| 4 | Align URL normalization (decoding, dot-segment resolution, delimiter handling) between cache and origin wherever possible |
| 5 | Have the origin return explicit errors for unexpected trailing path segments instead of silently ignoring them |
| 6 | Periodically audit cache rules (extension, directory-prefix, exact-match) against actual origin routing behavior |

---

## 6. Lessons Learned

1. Web cache deception and web cache poisoning are different bugs with different mechanisms — don't conflate them in a report.
2. Always use a cache-buster (unique query string per request) while testing, or results get contaminated by your own cached responses.
3. Response headers (`X-Cache`, `Cache-Control`) and response-time differences are the main signals for detecting caching behavior.
4. A discrepancy almost never needs to be "found once" — it tends to generalize across many endpoints on the same origin/cache pair, since delimiter and normalization behavior is usually consistent platform-wide.
5. Defenses that look safe in isolation (an exact file-name rule, a directory prefix) are only as safe as the normalization logic behind them.

## 7. References

- PortSwigger Web Security Academy — Web cache deception
- PortSwigger Black Hat USA 2024 research: *Gotta Cache 'em all: bending the rules of web cache exploitation*
- OWASP Top 10:2025 — A02: Security Misconfiguration (caching-related misconfigurations fall under this category)
