# J3-SEC — unofficial security patches for Joomla 3.10

[![verify patch set](https://github.com/fstivicic/joomla3-security-patches/actions/workflows/verify.yml/badge.svg)](https://github.com/fstivicic/joomla3-security-patches/actions/workflows/verify.yml)
[![licence: GPL-2.0-or-later](https://img.shields.io/badge/licence-GPL--2.0--or--later-blue)](LICENSE.txt)

Free, source-available security patches for **Joomla 3.10.12**, the final release of
the Joomla 3 series.

Every push and every month, CI fetches a stock 3.10.12, confirms the probe **finds**
vulnerabilities before patching, applies the set, and confirms the probe comes back
clean — on PHP 7.4, 8.0, 8.2 and 8.3. The badge above is that job.

Joomla 3 reached end of life on **17 August 2023**. The Joomla project's own paid
Extended Long Term Support (eLTS) programme, which backported security fixes to the
3.x branch, **ended on 17 February 2025**.

This repository publishes backports for vulnerabilities disclosed since then, derived
from the public fixes in current Joomla and in the Joomla Framework packages.

### Prior art — read this before assuming this repo is the only option

It is not, and you should know the landscape before trusting anyone's patches,
including mine.

- **[PhilETaylor/Joomla3.10.999](https://github.com/PhilETaylor/Joomla3.10.999)** is a
  public GPL-2.0 collection of Joomla 3.10 plus community hot fixes, with branches
  mirroring the eLTS releases up to `3.10.20-elts`. Its last commit is **17 February
  2025** — the day eLTS ended — so it does not cover anything disclosed afterwards.
- **[mySites.guru](https://mysites.guru/)** (Phil Taylor) maintains an ongoing Joomla 3
  patch tool, free to its subscribers, which as of October 2026 covered 85 files
  including 2026 CVEs. It is delivered inside their commercial monitoring product
  rather than as a standalone download, and they state they reproduce each issue on a
  stock 3.10.12 install before including it. **If you already use mySites.guru, use
  their tool — it has broader coverage than this repository.**

What this repo adds is a *standalone, publicly downloadable* patch set with its own
vulnerability probe and CI, for people who are not mySites.guru customers and want
something they can read, verify and apply themselves. It is narrower in coverage and
makes no claim to be first.

> **Not affiliated with the Joomla project or Open Source Matters, Inc.** Joomla is a
> trademark of Open Source Matters, Inc. This is an independent, unofficial effort and
> carries no endorsement. If you can upgrade to a supported Joomla release, do that
> instead — these patches are for sites that cannot, yet.

---

## What is patched

Five advisories, all disclosed after the ELTS programme closed, all verified against
the 3.10.12 source rather than taken on trust from the published version ranges.

| ID | CVE | Issue | Severity | Status |
|----|-----|-------|----------|--------|
| [JSEC-0001](advisories/JSEC-0001.md) | CVE-2026-90906 | XSS in `HTMLHelper::link()` and `::iframe()` | Medium | Patched |
| [JSEC-0002](advisories/JSEC-0002.md) | CVE-2026-90907 | Unauthorised account creation via `profile.save` | Medium | Patched |
| [JSEC-0003](advisories/JSEC-0003.md) | CVE-2026-73373 | Unrestricted upload of `.shtml` and other executables | High | Patched |
| [JSEC-0004](advisories/JSEC-0004.md) | CVE-2026-92231 | XSS filter bypass via HTML5 entity decode mismatch | High | Patched |
| [JSEC-0005](advisories/JSEC-0005.md) | CVE-2026-92222 | SSRF and local file read via unrestricted feed URL schemes | High | Patched |

**JSEC-0005 is not in the advisory's published version range**, and is the clearest
argument for checking code rather than version tables. Joomla lists CVE-2026-92222 as
affecting 4.0.0 and later — but Joomla does not assess EOL branches, so that bound
describes the scope of their review, not the extent of the bug. Three of the four
fields they fixed exist in 3.10 in identical form, the validator that would constrain
them already supports the fix, and the dangerous schemes are demonstrably accepted.

One further advisory was investigated and is **not** patched here: CVE-2026-92232 does
not apply to the 3.x codebase as described, because the data-URI cleanup it describes
bypassing was never in Joomla 3. See
[advisories/NOT-APPLICABLE.md](advisories/NOT-APPLICABLE.md), which also records the
policy on when a gap is left open rather than filled with unreviewed code.

## Verifying before you trust it

Do not take the table above on faith. The repository ships a probe that reports,
for each known attack vector, whether a given Joomla root is vulnerable or fixed:

```sh
php tests/probe.php /path/to/your/joomla
```

On an unpatched 3.10.12 tree it reports **19 vulnerable vectors**. After applying the
patch set it reports **0**, with control cases (a benign URL, a legitimate `.jpg`
upload, an ordinary `https://` feed URL) still behaving correctly. The probe needs no
database and no web server, and touches nothing in your installation.

Both suites run against files on disk and never start Joomla. A patch set can pass
them and still break a running site, so the set was also installed and driven through
a browser on a real Joomla 3.10.12 / PHP 8.2 / MySQL 8 install — see
[VERIFICATION.md](VERIFICATION.md) for what was checked and, more importantly, what
that still does not prove.

It also prints a short **Notes** section for observations the patch set deliberately
does not change — currently `UrlRule`'s permissive default scheme list, which is the
reason JSEC-0005 is needed but which cannot be tightened globally without breaking
every other url-validated field in core and in third-party extensions. Notes do not
count toward the vulnerable total and do not affect the exit code.

## Applying the patches

Back up first. Then use the wrapper — it checks that every patch applies before
changing anything, and verifies afterwards that each one actually landed:

```sh
bin/apply.sh /path/to/your/joomla              # Linux, macOS, WSL, Git Bash
bin/apply.sh /path/to/your/joomla --check      # dry run, changes nothing

bin\apply.ps1 C:\path\to\your\joomla           # Windows PowerShell
bin\apply.ps1 C:\path\to\your\joomla -Check
```

To apply by hand, the patch files are standard unified diffs rooted at your
Joomla directory:

```sh
cd /path/to/your/joomla
for p in /path/to/j3-sec/patches/*.patch; do patch -p1 -F0 -i "$p"; done
```

`-F0` matters. GNU patch defaults to a fuzz factor of 2, which lets context
match at a shifted offset — so running the same patch twice can insert the same
code twice. With zero fuzz, context must match exactly or the patch is refused.

> **Do not use `git apply` for this.** Inside a git repository, `git apply`
> resolves paths relative to the **repository root** rather than your working
> directory, and silently ignores paths outside it. If your Joomla install sits
> anywhere inside a git work tree — a versioned site, or a checkout one level up
> — `git apply` exits 0 having changed nothing at all. The wrapper scripts
> handle this (they prefer GNU patch, and pin `GIT_WORK_TREE` when they must use
> git), which is the main reason to use them rather than patching by hand.

If your installation has modified core files — and many long-lived Joomla 3 sites
have — a hunk may fail. The patches are small and the advisories describe each change
in full, so applying by hand is realistic. Do not use `--force` or `-R`.

### Files touched

```
libraries/src/HTML/HTMLHelper.php                                    JSEC-0001
components/com_users/controllers/profile.php                         JSEC-0002
libraries/src/Filter/InputFilter.php                                 JSEC-0003
libraries/vendor/joomla/filter/src/InputFilter.php                   JSEC-0004
administrator/components/com_newsfeeds/models/forms/newsfeed.xml     JSEC-0005
modules/mod_feed/mod_feed.xml                                        JSEC-0005
administrator/modules/mod_feed/mod_feed.xml                          JSEC-0005
```

`libraries/vendor/` is a Composer-vendored dependency. Nothing in a normal Joomla 3
site regenerates it, but if you ever run `composer install` against this tree, the
JSEC-0004 change will be reverted. Re-apply it afterwards.

## Behaviour changes you should know about

These are deliberate, and they match upstream. They are listed here because a
security patch that silently changes behaviour is how people lose trust in a patch
set.

- **JSEC-0003** blocks `.asp`, `.aspx`, `.sht`, `.shtm`, `.shtml` and `.stm` uploads.
  A site that legitimately accepts any of these must override
  `forbidden_extensions` at the call site rather than reverting the patch.
- **JSEC-0004** strips whitespace from attribute values before testing them for
  dangerous URL schemes, so a value that genuinely reads `java script:` is now
  treated as hostile and the attribute is dropped.
- **JSEC-0001** escapes URLs passed to `HTMLHelper::link()`. Callers that were
  passing pre-built markup through the `$url` argument — which was never supported —
  will see it escaped. The link *text* is still not escaped, matching upstream, since
  callers legitimately pass markup there.
- **JSEC-0005** rejects feed URLs whose scheme is not `http` or `https`. A site
  deliberately pointing `mod_feed` or a news feed at an `ftp://` source will have to
  change it; saving such a value now fails validation.

## Honest limits

- **Not a complete audit.** This covers advisories published since the ELTS shutdown
  that I verified against the 3.10 source. Joomla 3.10.12 certainly contains other
  unpatched issues, including any that were only ever fixed in paid ELTS releases.
  JSEC-0005 is a warning about method as much as a fix: it was found only by reading
  the release diff, because the advisory's version range said 3.x was unaffected.
  Other advisories dismissed on the same basis may deserve the same treatment.
- **JSEC-0005 does not stop SSRF over HTTP.** Restricting schemes removes `file://`,
  `gopher://` and friends, but `http://169.254.169.254/` remains a valid feed URL and
  Joomla will still fetch it. That matches upstream. Internal-address blocking belongs
  in egress firewall rules, not a form validation rule. It is also input-time only, so
  audit values already in your database — the advisory has the SQL.
- **JSEC-0004's end-to-end impact is unproven.** The unit-level filter bypass is
  real and reproducible, but in both filter configurations I tested, `InputFilter::clean()`
  dropped the hostile anchor through unrelated attribute handling. The patch is
  correct and matches upstream; I could not construct a working end-to-end exploit,
  and I would rather say so than imply more urgency than I demonstrated.
- **No warranty.** See the licence. Test on a staging copy.
- **Third-party extensions are out of scope.** On a typical Joomla 3 site they are a
  larger risk surface than core.

## Who maintains this, and how to get help

Maintained by one person. That is the main risk of relying on it, and it is stated here
rather than buried.

**Something wrong with a patch?** [Open an issue](../../issues). No email needed, and a
public report gets fixed faster.

**Stuck on an EOL platform and want someone to look at it properly?**

I do paid work on exactly this problem: software that still runs the business but is out
of support, undocumented, or dependent on one person's knowledge. The usual starting
point is a short fixed-fee audit that produces a written risk assessment and costed
options, with automated tests demonstrating that behaviour is preserved before and after
any change.

To get in touch, [open an issue](../../issues) or use the contact details on
[my GitHub profile](https://github.com/fstivicic). No email address is printed here on
purpose — this page gets scraped, and a profile link is something I can change.

This repository is the unpaid half of that, and it stays unpaid. Nothing here is a
teaser for a paid tier, there is no "pro" version, and the patches will not start
expiring. If that ever changes it will be announced loudly and the existing patches will
stay under the GPL they were published under.

## Related work

- [`writeups/version-ranges-lie.md`](writeups/version-ranges-lie.md) — how JSEC-0005 was
  found: an advisory listed Joomla 3 as unaffected, and the release diff showed otherwise.
  Also the general lesson about trusting affected-version ranges on EOL software.

## Licence

The patches are derivative works of Joomla and are published under the
**GNU General Public License version 2 or later**, the same terms as Joomla itself.
See [LICENSE.txt](LICENSE.txt). The probe and tooling in `tests/` and `bin/` are
under the same licence for simplicity.

Because the GPL is copyleft, anyone may use, modify and redistribute these patches,
including commercially. Nobody can make them proprietary — including me.

## Reporting a problem

If a patch breaks something, or a backport is wrong, open an issue with your PHP
version, your Joomla version, and the probe output. Reports that a patch is
*incomplete* are especially welcome: a backport that looks right and isn't is worse
than no patch.

Do not report vulnerabilities in Joomla itself here. Those go to the Joomla
project's own security team, via <https://developer.joomla.org/security/report-issue.html>.
