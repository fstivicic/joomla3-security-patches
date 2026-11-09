# Security policy

## This project is not the Joomla security team

Vulnerabilities in **Joomla itself** go to the Joomla project, not here:
<https://developer.joomla.org/security/report-issue.html>

Report here only problems with **these patches**: a backport that is wrong,
incomplete, breaks a site, or claims to fix something it does not.

## Reporting a problem with a patch

Open a public issue. These patches address already-public CVEs, so there is
nothing to coordinate and a public report gets fixed faster.

Include your PHP version, your Joomla version, and the output of:

```sh
php tests/probe.php /path/to/your/joomla
```

**Reports that a patch is incomplete are the most valuable kind.** A backport
that looks right and is not is worse than no patch, because it buys a false
sense of safety. If you can show a bypass, please do.

## What is and is not covered

See the table in [README.md](README.md) and the per-advisory notes in
`advisories/`. In particular:

- Only advisories published after the official ELTS programme ended on
  17 February 2025, and only those verified present in 3.10.12.
- `advisories/NOT-APPLICABLE.md` records what was investigated and skipped,
  and why.
- Third-party extensions are out of scope. On a typical Joomla 3 site they are
  a bigger risk surface than core.

## No warranty

GPL-2.0-or-later, as-is, no warranty. Test on a staging copy. If you need a
support commitment, you need a commercial vendor with a contract, not a free
patch set from a stranger.
