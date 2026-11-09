# Live site verification

The automated suites (`tests/probe.php`, `tests/regression.php`) run against the files
on disk. They never start Joomla. A patch set can pass both and still break a running
site, so this records an end-to-end check on a real installation.

**Date:** 9 November 2026
**Environment:** Joomla 3.10.12, PHP 8.2.15, MySQL 8.0.35, PHP built-in server,
"Default English (GB)" sample data, patches applied with `bin/apply.sh`.

Everything below was done through a browser against a running site, not simulated.

---

## Install

Joomla 3.10.12 installed cleanly on PHP 8.2 — all three installer steps, sample data,
and the post-install screen. The admin Control Panel and the front end both render
without PHP errors.

Worth noting for anyone running 3.10 on modern PHP: it works, but Joomla displays its
own banner, *"Support has ended for your version of Joomla 3.10"*. That is Joomla's
notice, not a patch artefact.

One environment gotcha unrelated to Joomla: if `session.save_path` points at a Redis
instance that is not running, Joomla fails with a bare "Failed to start the session".

## JSEC-0001 — `HTMLHelper::link()` escaping

This was the highest regression risk in the set, because `link()` is called all over
core and the patch changes its output.

**Print and email icons.** `components/com_content/helpers/icon.php` passes an
`onclick` handler full of single quotes. After patching, the rendered attribute is:

```html
onclick="window.open(this.href,&#039;win2&#039;,&#039;status=no,toolbar=no,...&#039;); return false;"
```

The single quotes became `&#039;`. That *looks* broken, so it was checked in the
browser rather than reasoned about. Reading the parsed DOM for both icon links:

| Check | Result |
|---|---|
| Browser compiled `onclick` into a function | **true** (both links) |
| Compiled JS contains a real `'win2'` apostrophe | **true** (both links) |
| Compiled JS still contains `&#039;` | **false** |
| `href` double-encoded (`&amp;amp;`) | **false** |

The HTML parser decodes entities in attribute values before the JS engine sees them,
so the handlers work. Confirmed, not assumed.

**Double-encoding.** `JRoute::_()` already HTML-escapes ampersands, so re-encoding
would turn every paginated and routed link into `&amp;amp;`. Across the home page, an
article page and a contact page, occurrences of `amp;amp;`: **0**.

## JSEC-0005 — feed URL scheme restriction

Exercised through the real admin UI, not the validator in isolation.

| Action | Result |
|---|---|
| Create news feed with `https://example.com/feed.xml` | **"News feed saved."** |
| Change the same feed's link to `file:///C:/Windows/win.ini` | **"Warning: Invalid field: Link"** |

The News Feed edit form also renders normally, which confirms the patched form XML is
still well-formed and the manifest parses.

## JSEC-0004 — `checkAttribute()` false positives

`administrator/components/com_contact/tables/contact.php` calls `checkAttribute()` on
**every contact save** and rejects the save when it returns true. A false positive here
would make contacts unsavable, so this was tested with a realistic URL containing a
query string:

- Saved a contact with website `https://example.com/about?a=1&b=2` → **"Contact saved."**
- The contact then renders on the front end with its link intact.

## JSEC-0003 — upload filtering

Verified at function level against real files written to disk (see `tests/probe.php`
and `tests/regression.php`): `.shtml`, `.shtm`, `.sht`, `.stm`, `.asp`, `.aspx` blocked;
`.jpg`, `.png`, `.pdf`, `.xlsx`, `.txt`, `.css`, `.js`, `.zip`, `.woff2`, `.mp4` still
allowed.

**Not** exercised through the Media Manager UI. The patch only adds entries to a deny
list consulted by `isSafeFile()`, which is the function tested, but the UI path itself
is unverified.

## Front-end sweep

Fourteen URLs fetched on the patched site and scanned for `fatal error`, `parse error`,
`uncaught exception`, `call to undefined` and memory exhaustion:

```
/                                                200
article view                                     200
featured / categories / contact / newsfeeds      200
login, search, tag view                          200
print view (tmpl=component&print=1)              200
component/mailto                                 200

pages with PHP errors: 0
```

Two non-200s, both normal and unrelated: the registration view 303-redirects because
public registration is off by default, and `?format=feed` 404s because no feed menu
item exists.

## JavaScript console

No errors or exceptions on the patched article page (the one carrying the modified
`onclick` handlers) or in the admin.

---

## What this does *not* prove

- **Only the default `protostar` template and core extensions.** Third-party templates
  and extensions that call `HTMLHelper::link()` with unusual attribute arrays are
  untested, and the attribute-name whitelist added by JSEC-0001 will silently drop
  names that are not valid HTML attribute names.
- **Media Manager upload UI not exercised**, as above.
- **PHP 8.2 only.** The automated suites run on 7.4, 8.0, 8.2 and 8.3 in CI, but the
  live site was only driven on 8.2.
- **MySQL only.** PostgreSQL was not tested.
- **A sample-data site, not a real one.** Real Joomla 3 sites carry years of
  third-party extensions, and that is where a patch set is most likely to surprise you.
  Test on a staging copy of *your* site.
