# J3-SEC — unofficial security patches for Joomla 3.10

Free, source-available security patches for **Joomla 3.10.12**, the final release of
the Joomla 3 series.

Joomla 3 reached end of life on **17 August 2023**. The Joomla project's own paid
Extended Long Term Support programme, which backported security fixes to the 3.x
branch, **ended on 17 February 2025**. Since then, vulnerabilities disclosed against
the 3.x line have had no patch source at all.

This repository publishes backports for those vulnerabilities, derived from the
public fixes in current Joomla and in the Joomla Framework packages.

> **Not affiliated with the Joomla project or Open Source Matters, Inc.** Joomla is a
> trademark of Open Source Matters, Inc. This is an independent, unofficial effort and
> carries no endorsement. If you can upgrade to a supported Joomla release, do that
> instead — these patches are for sites that cannot, yet.

---

## What is patched

Four advisories, all disclosed after the ELTS programme closed, all verified against
the 3.10.12 source rather than taken on trust from the published version ranges.

| ID | CVE | Issue | Severity | Status |
|----|-----|-------|----------|--------|
| [JSEC-0001](advisories/JSEC-0001.md) | CVE-2026-90906 | XSS in `HTMLHelper::link()` and `::iframe()` | Medium | Patched |
| [JSEC-0002](advisories/JSEC-0002.md) | CVE-2026-90907 | Unauthorised account creation via `profile.save` | Medium | Patched |
| [JSEC-0003](advisories/JSEC-0003.md) | CVE-2026-73373 | Unrestricted upload of `.shtml` and other executables | High | Patched |
| [JSEC-0004](advisories/JSEC-0004.md) | CVE-2026-92231 | XSS filter bypass via HTML5 entity decode mismatch | High | Patched |

Two further advisories were investigated and are **not** patched here. See
[advisories/NOT-APPLICABLE.md](advisories/NOT-APPLICABLE.md) for the reasoning —
one does not apply to the 3.x codebase as described, and one has a disputed
version range that needs confirmation before any patch is written.

## Verifying before you trust it

Do not take the table above on faith. The repository ships a probe that reports,
for each known attack vector, whether a given Joomla root is vulnerable or fixed:

```sh
php tests/probe.php /path/to/your/joomla
```

On an unpatched 3.10.12 tree it reports **16 vulnerable vectors**. After applying the
patch set it reports **0**, with control cases (a benign URL, a legitimate `.jpg`
upload) still behaving correctly. The probe needs no database and no web server, and
touches nothing in your installation.

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
libraries/src/HTML/HTMLHelper.php                     JSEC-0001
components/com_users/controllers/profile.php          JSEC-0002
libraries/src/Filter/InputFilter.php                  JSEC-0003
libraries/vendor/joomla/filter/src/InputFilter.php    JSEC-0004
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

## Honest limits

- **Not a complete audit.** This covers advisories published since the ELTS shutdown
  that I verified against the 3.10 source. Joomla 3.10.12 certainly contains other
  unpatched issues, including any that were only ever fixed in paid ELTS releases.
- **JSEC-0004's end-to-end impact is unproven.** The unit-level filter bypass is
  real and reproducible, but in both filter configurations I tested, `InputFilter::clean()`
  dropped the hostile anchor through unrelated attribute handling. The patch is
  correct and matches upstream; I could not construct a working end-to-end exploit,
  and I would rather say so than imply more urgency than I demonstrated.
- **No warranty.** See the licence. Test on a staging copy.
- **Third-party extensions are out of scope.** On a typical Joomla 3 site they are a
  larger risk surface than core.

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
