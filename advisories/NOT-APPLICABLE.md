# Investigated and not patched

One advisory from the same disclosure rounds is **not** in the patch set. The decision
is recorded here with its reasoning, because "we looked and decided no" is useful
information and an unexplained gap is not.

> **Resolved since the first revision:** CVE-2026-92222 (SSRF in core extensions) was
> listed here as unresolved while the published version ranges disagreed about Joomla 3.
> It has been investigated and **does affect 3.10.12**, despite the advisory's stated
> 4.0.0 lower bound — that bound reflects which branches Joomla still assesses, not the
> extent of the bug. It is now patched as [JSEC-0005](JSEC-0005.md).

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

## Policy: going beyond upstream

This patch set backports **reviewed upstream fixes**. It does not invent new ones.

That rule has teeth, and JSEC-0005 is where it bites. Upstream's scheme restriction is
input-time only, so a hostile feed URL already in the database is still fetched. A
fetch-time scheme check in `FeedFactory::getFeed()` would close that, and is only a few
lines — but it is unreviewed code written against an EOL branch by one person, in the
exact function that every feed on the site flows through. A regression there breaks feeds
silently, because the call site suppresses errors with `@`.

So it is documented in the advisory, with SQL to audit existing values, rather than
patched. If someone wants it, it belongs in an `optional/` directory with its own tests
and a loud warning, not in the default set.

The same reasoning keeps data-URI filtering out of JSEC-0004 and the permissive
`UrlRule` default out of JSEC-0005.
