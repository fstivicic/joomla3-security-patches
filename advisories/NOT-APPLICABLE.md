# Investigated and not patched

Two advisories from the same disclosure rounds are **not** in the patch set. Both
decisions are recorded here with their reasoning, because "we looked and decided no"
is useful information and an unexplained gap is not.

---

## CVE-2026-92232 — XSS filter bypass via whitespace in HTML data URIs

| | |
|---|---|
| **Upstream advisory** | [20260916](https://developer.joomla.org/security-centre/1096-20260916-core-xss-filter-bypass-in-inputfilter-via-whitespace-characters-in-html-data-uris.html) · [GHSA-943m-2293-5c6p](https://github.com/advisories/GHSA-943m-2293-5c6p) |
| **Claimed affected** | Joomla 1.5.0 – 5.4.8, 6.0.0 – 6.1.3 |
| **Verdict** | **Does not apply to 3.10.12 as described** |

The advisory states: *"The cleanAttribute method removes HTML data URIs, however
injected whitespace characters could circumvent that cleanup."*

Joomla 3.10.12 has no such method and no such cleanup. Searching both filter
implementations finds no `cleanAttribute` (singular) and no `data:` URI handling at
all:

```
$ grep -rn "cleanAttribute" libraries/
libraries/src/Filter/InputFilter.php:1082:   protected function _cleanAttributes($attrSet)
libraries/vendor/joomla/filter/src/InputFilter.php:607:  protected function cleanAttributes($attrSet)

$ grep -n "data:" libraries/vendor/joomla/filter/src/InputFilter.php libraries/src/Filter/InputFilter.php
(no matches)
```

`cleanAttributes` (plural) is a different, pre-existing method. The data-URI stripping
that this CVE describes bypassing was added to Joomla after the 3.x line, so there is
no vulnerable code path to patch. The published version range appears to be a
conservative "all versions up to the fix" rather than a verified lower bound.

### The part that is worth knowing

3.10 is not *safer* for lacking the cleanup — it simply never filtered `data:` URIs in
attributes in the first place. That is a pre-existing weakness in Joomla 3, not this
CVE, and it is deliberately **not** patched here, for two reasons:

1. Adding data-URI stripping to 3.10 is a behaviour change, not a backport. Sites
   legitimately embed inline `data:image/...` content, and silently dropping it would
   break working pages.
2. Doing it properly means writing new filtering logic rather than porting a reviewed
   upstream fix, which is exactly the kind of change most likely to introduce a new
   bug into a security patch set.

If you accept untrusted HTML into content, consider a Content-Security-Policy that
restricts `img-src` and forbids inline script, which addresses the class rather than
one instance of it.

---

## CVE-2026-92222 — SSRF vectors in core extensions

| | |
|---|---|
| **Upstream advisory** | [20260909](https://developer.joomla.org/security-centre/1089-20260909-core-ssrf-vectors-in-various-core-extensions.html) · [GHSA-47wr-m8j6-xmcq](https://github.com/advisories/GHSA-47wr-m8j6-xmcq) |
| **Claimed affected** | **Disputed — see below** |
| **Severity** | High (upstream rating) |
| **Verdict** | **Unresolved. Needs investigation before any patch.** |

This is the one genuine loose end, and the highest-severity item in the set.

The two authoritative sources disagree about whether Joomla 3 is affected:

| Source | Affected range |
|---|---|
| Joomla security centre listing | **3.0.0** – 5.4.8, 6.0.0 – 6.1.3 |
| GitHub advisory GHSA-47wr-m8j6-xmcq | **4.0.0** – 5.4.8, 6.0.0 – 6.1.3 |

If the security centre is right, Joomla 3.10 carries an unpatched High-severity SSRF.
If the GitHub advisory is right, it does not apply at all.

The advisory text — *"URLs used for serverside requests were improperly validated"* —
does not name a method or file, and "various core extensions" could cover several
subsystems whose 3.x and 4.x implementations differ substantially. Resolving it means
identifying the specific upstream fix commits, mapping each to its 3.x equivalent (if
one exists), and confirming the validation gap is present.

**No patch is offered on a guess.** Writing an SSRF fix against an unidentified code
path is how a patch set acquires a regression that is worse than the vulnerability.

This is the top item on the list for the next round, and help identifying the
upstream commits would be genuinely useful — open an issue if you have them.
