# An advisory said Joomla 3 wasn't affected. The release diff said otherwise.

*November 2026*

Joomla 3 reached end of life on 17 August 2023. The Joomla project ran a paid Extended
Long Term Support programme that kept backporting security fixes to the 3.x branch, and
that programme ended on 17 February 2025. Joomla's own usage statistics have put 3.10.x
at over a third of all reporting installations.

So there is a large population of sites running an unpatched CMS. I set out to build a
free, standalone patch set for the advisories published since eLTS closed.

The interesting part was not the patching. It was discovering that one of the
vulnerabilities I'd written off as "not applicable" was applicable after all — and that
the reason I'd written it off was a published version range that was, for my purposes,
wrong.

> **Credit where it is due, and a correction to an earlier draft of this post.**
> I am not the first person to reach this conclusion about CVE-2026-92222. Phil Taylor's
> [mySites.guru](https://mysites.guru/blog/joomla-3-security-fixes-verified-on-3-10-12/)
> published a Joomla 3 patch round in **October 2026** — a month before this — that
> already included CVE-2026-92222 alongside CVE-2026-90907 and others, each reproduced
> on a stock 3.10.12 install. An earlier version of this post said Joomla 3 had "no
> patch source at all" since February 2025. That was wrong: the public
> [Joomla3.10.999](https://github.com/PhilETaylor/Joomla3.10.999) repo collects fixes up
> to the end of eLTS, and mySites.guru has continued backporting since, inside their
> commercial product.
>
> I found this while fact-checking my own claims before contacting anyone about the
> work — which is the only reason you are reading an accurate version. The method below
> still holds, and the lesson about version ranges is if anything strengthened by
> someone else having independently had to learn it. But the discovery is not mine, and
> presenting it as novel would have been false.

## The first pass

I pulled every Joomla advisory published after the ELTS shutdown and filtered for ones
whose affected-version range reached back into 3.x. Six looked relevant. I checked each
against the actual 3.10.12 source rather than trusting the range, which caught one
immediately:

**CVE-2026-92232** is described as a bypass of data-URI stripping in
`InputFilter::cleanAttribute()`. Its range says it affects Joomla 1.5.0 onward. But
3.10.12 has no `cleanAttribute()` method and no `data:` URI handling anywhere in either
of its filter implementations:

```
$ grep -rn "cleanAttribute" libraries/
libraries/src/Filter/InputFilter.php:1082:   protected function _cleanAttributes($attrSet)
libraries/vendor/joomla/filter/src/InputFilter.php:607:  protected function cleanAttributes($attrSet)

$ grep -n "data:" libraries/vendor/joomla/filter/src/InputFilter.php libraries/src/Filter/InputFilter.php
(no matches)
```

`cleanAttributes` — plural — is a different, older method. The cleanup this CVE describes
bypassing was added after the 3.x line. There is no vulnerable code path to patch. The
"1.5.0" lower bound is a conservative "everything up to the fix", not a verified claim.

That is the failure mode everyone expects from version ranges: **too wide**. A range that
over-claims wastes your time and inflates your patch count.

Four others checked out as genuinely present, and I patched them. Which left one.

## The one I got wrong

**CVE-2026-92222** — "SSRF vectors in various core extensions", rated High. Two sources
disagreed about it. One listing appeared to show a lower bound of 3.0.0; the advisory
detail page and the GitHub advisory both said **4.0.0**.

I wrote it up as unresolved and moved on, with a note that the detail page was probably
authoritative. That was the right instinct about the documents and the wrong conclusion
about the code.

Because here is what "affected: 4.0.0 and later" actually means: **it is the range the
vendor assessed.** Joomla does not evaluate end-of-life branches. Nobody tested 3.10
against this bug, because testing 3.10 is not something anyone is paid or obliged to do.
The lower bound of a version range on an EOL-adjacent advisory is a statement about
*review scope*, not about *where the bug lives*.

The only way to settle it was to find the fix.

## Finding a fix that isn't in the commit log

Joomla develops security fixes privately and squashes them into the release commit, so
the public commit list between 5.4.8 and 5.4.9 contains translation updates, template
manager fixes, and nothing resembling a security patch. Reading commit subjects gets you
nowhere.

The release *diff*, though, is public. 268 files changed. Filtering the filenames for
anything URL- or HTTP-shaped produced a very short list, and one pattern jumped out:

```
+1  -0   administrator/components/com_newsfeeds/forms/newsfeed.xml
+1  -0   administrator/modules/mod_feed/mod_feed.xml
+1  -0   modules/mod_feed/mod_feed.xml
+1  -0   plugins/task/requests/forms/get_requests.xml
```

Exactly one line added to each of four files — and those four are precisely the core
extensions that fetch a URL server-side. That is the SSRF fix. The added line, in all
four cases:

```xml
 			validate="url"
+			schemes="http,https"
```

Two near-misses worth naming, because both would have sent me down the wrong path. The
same release changed `libraries/src/Uri/Uri.php` (+5 lines) with a new unit test — that
looks like a URL-validation security fix and is actually a different one, an XSS
plausibility check in `isInternal()`. And `MediaHelper::isImage()` changed from
`return preg_match(...)` to `return (bool) preg_match(...)`, which looks like input
hardening and is a phpstan cast. Attributing either to this CVE would have produced a
confident, wrong patch.

## So is 3.10 affected?

Three of those four form fields exist in 3.10 with identical markup — `validate="url"`,
no `schemes` attribute. The fourth, the task-scheduler plugin, is Joomla 4.1+ and has no
3.x analogue.

The question then becomes whether 3.10's validator even honours a `schemes` attribute,
because if it ignores it, adding one is theatre. It honours it:

```php
if ($element['schemes'] == '')
{
    $scheme = array('http', 'https', 'ftp', 'ftps', 'gopher', 'mailto', 'news', 'prospero',
        'telnet', 'rlogin', 'sftp', 'tn3270', 'wais', 'mid', 'cid', 'nntp', 'tel', 'urn',
        'ldap', 'file', 'fax', 'modem', 'git');
}
else
{
    $scheme = explode(',', $element['schemes']);
}
```

That default list is the vulnerability. `file`, `gopher`, `ldap`, `telnet` — all accepted
when a field declares no constraint. I tested it directly rather than reasoning about it:

```
no schemes attr    file:///etc/passwd                         ACCEPTED
no schemes attr    gopher://127.0.0.1:6379/_SET               ACCEPTED
no schemes attr    ldap://127.0.0.1/                          ACCEPTED

schemes=http,https file:///etc/passwd                         rejected
schemes=http,https gopher://127.0.0.1:6379/_SET               rejected
schemes=http,https http://example.com/feed.xml                ACCEPTED
```

## It's worse than SSRF on 3.x

Where that stored URL ends up matters. `FeedFactory::getFeed()` does this *before* any
HTTP client is involved:

```php
$reader = new \XMLReader;

if (!@$reader->open($uri, null, LIBXML_NOERROR | LIBXML_ERR_NONE | LIBXML_NOWARNING))
{
    // ... only now fall back to an HTTP client
}
```

`XMLReader::open()` resolves its argument through **PHP's stream wrappers**, not through
an HTTP transport. So on Joomla 3:

- `file:///etc/passwd` is a local file read, not a request.
- `gopher://host:port/_PAYLOAD` hands an attacker control of the bytes written to an
  arbitrary TCP port — the standard pivot to an unauthenticated Redis or SMTP service on
  localhost.
- `php://`, `compress.zlib://`, and any other registered wrapper are in scope too.

And the `@` means every failure is silent, which makes blind probing comfortable.

It needs an authenticated user, but not an administrator: module edit rights, or create
rights on news feeds, which plenty of sites hand to editor-level groups.

## The fix, and what it doesn't fix

The patch is the same one upstream made — `schemes="http,https"` on three fields, no code
change, because the validator already supported it.

What it does *not* do is stop SSRF over HTTP. After patching,
`http://169.254.169.254/latest/meta-data/` is still a perfectly valid feed URL and Joomla
will still fetch it. Upstream left that too, and correctly: you cannot filter internal
addresses in a form validation rule — DNS rebinding and redirects defeat it — and blocking
private ranges would break the entirely legitimate case of an intranet feed. That belongs
in egress firewall rules.

It is also input-time only. A hostile URL already sitting in the database is still
fetched, so after patching you have to go look:

```sql
SELECT id, name, link FROM #__newsfeeds
WHERE link NOT LIKE 'http://%' AND link NOT LIKE 'https://%';
```

## The general lesson

If you run out-of-support software, the affected-version range on a new advisory is not
evidence about you. It tells you which branches the vendor still reviews. Your branch
stopped being reviewed on a date you can look up, and after that date the ranges silently
stop meaning what they look like they mean.

Ranges over-claim in the obvious direction, and CVE-2026-92232 is a clean example — a
1.5.0 lower bound on a bug that cannot exist in 1.5.0. Everyone expects that one and
handles it by checking.

They also under-claim, and that direction is the dangerous one, because it produces a
*reassuring* false negative. There is nothing to check if you have already concluded the
advisory doesn't apply to you.

The only reliable procedure I know is unglamorous: find the actual fix, read it, and look
for the same construct in your own tree. And then check whether somebody has already done
it, which is the step I did last and should have done first. For this advisory that took about an hour,
mostly spent filtering a 268-file diff. It is the difference between a High-severity local
file read being patched and being filed under "doesn't affect us".

---

The patch set, the per-advisory write-ups including the two I decided *not* to patch, and
a probe that reports whether a given Joomla root is vulnerable, are in this repository.
All GPL-2.0-or-later, same as Joomla.

Not affiliated with the Joomla project or Open Source Matters, Inc. If you can upgrade to
a supported release, do that instead.
