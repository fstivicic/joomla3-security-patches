#!/usr/bin/env python3
"""
Generate the JSEC patch set against a pristine Joomla 3.10.12 tree.

Each fix is applied as a separate commit so that `git format-patch` produces
clean, individually-appliable unified diffs. Anchors are matched exactly; any
anchor that is not found aborts the run rather than silently skipping a fix.
"""
import os
import shutil
import stat
import subprocess
import sys


def _force_remove(func, path, _exc):
    """Windows leaves .git objects read-only; clear the flag and retry."""
    os.chmod(path, stat.S_IWRITE)
    func(path)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.path.join(REPO, ".work")
SRC = os.path.join(WORK, "joomla-cms-3.10.12")
OUT = os.path.join(REPO, "patches")
TARBALL_URL = "https://github.com/joomla/joomla-cms/archive/refs/tags/3.10.12.tar.gz"


# Pinned so regenerating the set produces byte-identical patch files. Without
# this, git format-patch stamps each commit with the generation time and every
# rebuild churns all the patches.
FIXED_DATE = "2026-11-09T12:00:00+00:00"


def sh(*args, **kw):
    kw.setdefault("cwd", SRC)
    kw.setdefault("check", True)
    env = dict(os.environ)
    env.setdefault("GIT_AUTHOR_DATE", FIXED_DATE)
    env.setdefault("GIT_COMMITTER_DATE", FIXED_DATE)
    env["GIT_AUTHOR_DATE"] = FIXED_DATE
    env["GIT_COMMITTER_DATE"] = FIXED_DATE
    kw.setdefault("env", env)
    return subprocess.run(args, **kw)


def edit(relpath, old, new, count=1):
    """Replace `old` with `new` in relpath, asserting the anchor is unique."""
    path = os.path.join(SRC, relpath)
    with open(path, "r", encoding="utf-8", newline="") as fh:
        body = fh.read()
    found = body.count(old)
    if found != count:
        sys.exit(
            "ANCHOR FAIL in %s: expected %d occurrence(s), found %d\n--- anchor ---\n%s"
            % (relpath, count, found, old[:400])
        )
    body = body.replace(old, new, count)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(body)
    print("  patched %s" % relpath)


def commit(msg):
    sh("git", "add", "-A")
    sh("git", "commit", "-q", "-m", msg)
    print("  committed: %s" % msg.splitlines()[0])


# --------------------------------------------------------------------------
# Repo setup
# --------------------------------------------------------------------------
print("== preparing pristine tree ==")

# Always re-extract from the tarball. Reusing a checked-out git tree is not safe
# here: on Windows, `git reset --hard` rewrites the files through autocrlf and
# every LF anchor below stops matching.
TARBALL = os.path.join(WORK, "j3.tar.gz")

if not os.path.isdir(WORK):
    os.makedirs(WORK)

# Fetch the pristine release if it is not cached, so this runs from a clean clone.
if not os.path.isfile(TARBALL):
    print("  downloading Joomla 3.10.12 ...")
    import urllib.request
    urllib.request.urlretrieve(TARBALL_URL, TARBALL)

if os.path.isdir(SRC):
    shutil.rmtree(SRC, onerror=_force_remove)

os.makedirs(SRC)
subprocess.run(
    ["tar", "xzf", TARBALL, "-C", SRC, "--strip-components=1"],
    cwd=WORK, check=True,
)
print("  extracted pristine 3.10.12")

# core.autocrlf=false keeps the working tree byte-identical to the tarball, so
# anchors match and the emitted diffs use LF.
sh("git", "init", "-q")
sh("git", "config", "core.autocrlf", "false")
sh("git", "config", "core.eol", "lf")
sh("git", "config", "user.email", "patches@example.invalid")
sh("git", "config", "user.name", "JSEC Patch Set")
sh("git", "add", "-A")
sh("git", "commit", "-q", "-m", "pristine Joomla 3.10.12")
print("  baseline commit created")

base = subprocess.run(
    ["git", "rev-list", "--max-parents=0", "HEAD"],
    cwd=SRC, check=True, capture_output=True, text=True,
).stdout.strip()

# --------------------------------------------------------------------------
# JSEC-0001 / CVE-2026-90906 - XSS in HTMLHelper::link (and ::iframe)
# --------------------------------------------------------------------------
print("\n== JSEC-0001 CVE-2026-90906 HTMLHelper::link ==")
H = "libraries/src/HTML/HTMLHelper.php"

edit(H, """	public static function link($url, $text, $attribs = null)
	{
		if (is_array($attribs))
		{
			$attribs = ArrayHelper::toString($attribs);
		}

		return '<a href="' . $url . '" ' . $attribs . '>' . $text . '</a>';
	}""", """	public static function link($url, $text, $attribs = null)
	{
		if (is_array($attribs))
		{
			$attribs = ArrayHelper::toString(self::escapeAttributesArray($attribs));
		}

		$url = htmlspecialchars((string) $url, ENT_QUOTES, 'UTF-8', false);

		return '<a href="' . $url . '" ' . $attribs . '>' . $text . '</a>';
	}""")

edit(H, """	public static function iframe($url, $name, $attribs = null, $noFrames = '')
	{
		if (is_array($attribs))
		{
			$attribs = ArrayHelper::toString($attribs);
		}

		return '<iframe src="' . $url . '" ' . $attribs . ' name="' . $name . '">' . $noFrames . '</iframe>';
	}""", """	public static function iframe($url, $name, $attribs = null, $noFrames = '')
	{
		if (is_array($attribs))
		{
			$attribs = ArrayHelper::toString(self::escapeAttributesArray($attribs));
		}

		$url  = htmlspecialchars((string) $url, ENT_QUOTES, 'UTF-8', false);
		$name = htmlspecialchars((string) $name, ENT_QUOTES, 'UTF-8', false);

		return '<iframe src="' . $url . '" ' . $attribs . ' name="' . $name . '">' . $noFrames . '</iframe>';
	}""")

# Append the helper immediately before the final closing brace of the class.
edit(H, """		return '{' . implode(',', $elements) . '}';
	}
}""", """		return '{' . implode(',', $elements) . '}';
	}

	/**
	 * Escape the values of an attributes array and drop entries whose name is not a
	 * syntactically valid HTML attribute name.
	 *
	 * Backported from Joomla 5.4.9 for CVE-2026-90906. Kept PHP 5.3 compatible: no
	 * scalar type hints and no return type declaration.
	 *
	 * @param   array  $attributes  Attribute name => value pairs.
	 *
	 * @return  array  The escaped attributes.
	 *
	 * @since   3.10.12-jsec1
	 */
	protected static function escapeAttributesArray(array $attributes)
	{
		foreach ($attributes as $attributeName => $attributeValue)
		{
			// Skip invalid attribute names
			if (!preg_match('/^[a-zA-Z][a-zA-Z0-9_:.-]*$/', (string) $attributeName))
			{
				unset($attributes[$attributeName]);

				continue;
			}

			if (is_array($attributeValue))
			{
				$attributes[$attributeName] = self::escapeAttributesArray($attributeValue);

				continue;
			}

			$attributes[$attributeName] = htmlspecialchars((string) $attributeValue, ENT_QUOTES, 'UTF-8', false);
		}

		return $attributes;
	}
}""")

commit("""JSEC-0001: fix XSS in HTMLHelper::link and ::iframe (CVE-2026-90906)

The link() and iframe() methods interpolated $url, $name and array attribute
values into markup without escaping, so any caller passing unsanitised input
produced an XSS vector.

Escape the URL and name with htmlspecialchars(), and escape attribute values
via a new escapeAttributesArray() helper that also drops syntactically invalid
attribute names.

Backported from upstream Joomla 5.4.9. The helper is rewritten without the
scalar type hints and return type used upstream, to preserve PHP 5.3
compatibility for the 3.10 branch.

Advisory: https://developer.joomla.org/security-centre/1081-20260901-core-xss-in-htmlhelper-link-method.html""")

# --------------------------------------------------------------------------
# JSEC-0002 / CVE-2026-90907 - Unauthorized account creation via profile.save
# --------------------------------------------------------------------------
print("\n== JSEC-0002 CVE-2026-90907 profile.save guest check ==")
P = "components/com_users/controllers/profile.php"

edit(P, """		$app    = JFactory::getApplication();
		$model  = $this->getModel('Profile', 'UsersModel');
		$user   = JFactory::getUser();
		$userId = (int) $user->get('id');

		// Get the user data.""", """		$app    = JFactory::getApplication();
		$model  = $this->getModel('Profile', 'UsersModel');
		$user   = JFactory::getUser();
		$userId = (int) $user->get('id');

		// Only allow logged in users. A guest reaching this point would be saved as a
		// new record because $userId is 0, creating an account without registration.
		if ($user->get('guest'))
		{
			$app->enqueueMessage(JText::_('JERROR_ALERTNOAUTHOR'), 'error');
			$app->setHeader('status', 403, true);

			return false;
		}

		// Get the user data.""")

commit("""JSEC-0002: require an authenticated user in profile.save (CVE-2026-90907)

UsersControllerProfile::save() checked the CSRF token but never checked the
login state. For a guest, $userId is 0, so forcing $requestData['id'] = 0 made
the profile model treat the submission as a new record and create an account,
bypassing the site's registration setting.

Add an explicit guest check before any data is read, matching the guard added
upstream in Joomla 5.4.9.

Advisory: https://developer.joomla.org/security-centre/1082-20260902-core-unauthorized-user-account-creation-via-profile-save-controller.html""")

# --------------------------------------------------------------------------
# JSEC-0003 / CVE-2026-73373 - Unrestricted uploads of SHTML files
# --------------------------------------------------------------------------
print("\n== JSEC-0003 CVE-2026-73373 forbidden extensions ==")
F = "libraries/src/Filter/InputFilter.php"

edit(F, """			'forbidden_extensions'       => array(
				'php', 'phps', 'pht', 'phtml', 'php3', 'php4', 'php5', 'php6', 'php7',
				'php8', 'phar', 'inc', 'pl', 'cgi', 'fcgi', 'java', 'jar', 'py',
			),""", """			'forbidden_extensions'       => array(
				'asp', 'aspx', 'cgi', 'fcgi', 'inc', 'jar', 'java', 'phar', 'php', 'php3', 'php4', 'php5', 'php6',
				'php7', 'php8', 'php9', 'phps', 'pht', 'phtml', 'pl', 'py', 'sht', 'shtm', 'shtml', 'stm',
			),""")

commit("""JSEC-0003: block SHTML and other executable uploads (CVE-2026-73373)

The default forbidden extension list omitted server-parsed HTML (.shtml, .shtm,
.sht, .stm) and classic ASP (.asp, .aspx). On a server configured to execute
those handlers, an upload passing InputFilter::isSafeFile() could lead to code
execution.

Replace the list with the full set used upstream as
InputFilter::FORBIDDEN_FILE_EXTENSIONS in Joomla 5.4.9, which adds asp, aspx,
php9, sht, shtm, shtml and stm.

Note for integrators: this is deliberately a behaviour change. Sites that
legitimately accept any of these extensions through the media manager must
override 'forbidden_extensions' at the call site rather than reverting this
patch.

Advisory: https://developer.joomla.org/security-centre/1077-20260810-core-unrestricted-uploads-of-shtml-files.html""")

# --------------------------------------------------------------------------
# JSEC-0004 / CVE-2026-92231 - InputFilter HTML5 entity decode mismatch
# --------------------------------------------------------------------------
print("\n== JSEC-0004 CVE-2026-92231 checkAttribute entity decoding ==")
I = "libraries/vendor/joomla/filter/src/InputFilter.php"

edit(I, """	public static function checkAttribute($attrSubSet)
	{
		$quoteStyle = version_compare(\\PHP_VERSION, '5.4', '>=') ? \\ENT_QUOTES | \\ENT_HTML401 : \\ENT_QUOTES;

		$attrSubSet[0] = strtolower($attrSubSet[0]);
		$attrSubSet[1] = html_entity_decode(strtolower($attrSubSet[1]), $quoteStyle, 'UTF-8');

		return (strpos($attrSubSet[1], 'expression') !== false && $attrSubSet[0] === 'style')
			|| preg_match('/(?:(?:java|vb|live)script|behaviour|mocha)(?::|&colon;|&column;)/', $attrSubSet[1]) !== 0;
	}""", """	public static function checkAttribute($attrSubSet)
	{
		$attrSubSet[0] = strtolower($attrSubSet[0]);

		/*
		 * Decode the value the same way a browser would before looking for a dangerous scheme.
		 *
		 * This has to happen BEFORE lowercasing: PHP's entity tables are case sensitive, so
		 * lowercasing first would turn the HTML5 entity `&NewLine;` into the unknown `&newline;`
		 * and it would survive decoding untouched.
		 *
		 * ENT_HTML5 requires PHP 5.4; on 5.3 we fall back to the default table and rely on the
		 * numeric-reference pass and whitespace stripping below.
		 */
		$quoteStyle = defined('ENT_HTML5') ? \\ENT_QUOTES | \\ENT_HTML5 : \\ENT_QUOTES;
		$decoded    = html_entity_decode($attrSubSet[1], $quoteStyle, 'UTF-8');

		/*
		 * html_entity_decode() only resolves numeric character references that are properly
		 * terminated with a semicolon. Browsers are more forgiving and also consume unterminated
		 * references such as `java&#10script:`, so resolve those here as well.
		 */
		$decoded = preg_replace_callback(
			'/&#(x[0-9a-f]+|[0-9]+);?/i',
			array(__CLASS__, 'decodeNumericReference'),
			$decoded
		);

		// Now that everything is decoded, normalise the value for the checks below
		$attrSubSet[1] = strtolower($decoded);

		// Remove common XSS-evasion characters
		$attrSubSet[1] = str_replace(array("\\t", "\\n", "\\r", " ", "\\0", "\\v", "\\f"), '', $attrSubSet[1]);

		return (strpos($attrSubSet[1], 'expression') !== false && $attrSubSet[0] === 'style')
			|| preg_match('/(?:(?:java|vb|live)script|behaviour|mocha)(?::|&colon;|&column;)/', $attrSubSet[1]) !== 0;
	}

	/**
	 * Resolve a single numeric character reference, terminated or not, to its UTF-8 character.
	 *
	 * Helper for checkAttribute(). Implemented as a named static method rather than the closure
	 * used upstream so that the 3.10 branch keeps PHP 5.3 compatibility.
	 *
	 * @param   array  $matches  Match set from preg_replace_callback().
	 *
	 * @return  string
	 *
	 * @since   3.10.12-jsec1
	 */
	public static function decodeNumericReference($matches)
	{
		$reference = $matches[1];

		if ($reference[0] === 'x' || $reference[0] === 'X')
		{
			$codepoint = (int) hexdec(substr($reference, 1));
		}
		else
		{
			$codepoint = (int) $reference;
		}

		// Ignore anything that is not a scalar Unicode value and keep the raw match instead.
		// Surrogates (U+D800 - U+DFFF) are excluded as they are not encodable on their own.
		if ($codepoint > 0x10FFFF || ($codepoint >= 0xD800 && $codepoint <= 0xDFFF))
		{
			return $matches[0];
		}

		// mb_chr() is used over chr() so codepoints above U+00FF are not truncated.
		if (function_exists('mb_chr'))
		{
			return mb_chr($codepoint, 'UTF-8');
		}

		// Fallback for PHP < 7.2 or builds without mbstring: a terminated numeric reference
		// is something html_entity_decode() will resolve on its own.
		return html_entity_decode('&#' . $codepoint . ';', \\ENT_QUOTES, 'UTF-8');
	}""")

commit("""JSEC-0004: decode HTML5 entities before scheme check in InputFilter (CVE-2026-92231)

checkAttribute() decoded attribute values with ENT_HTML401 and lowercased them
*before* decoding. Both choices defeat the javascript: scheme regex:

  * ENT_HTML401 leaves HTML5-only entities such as &NewLine; and &Tab; intact,
    so `java&Tab;script:` never matched, while a browser collapses the tab and
    executes it.
  * Lowercasing first mangles the case-sensitive entity names, turning
    &NewLine; into the unknown &newline; so it survives decoding untouched.

Decode first with ENT_HTML5, additionally resolve unterminated numeric
references (`java&#10script:`), then lowercase and strip whitespace and control
characters before matching.

Backported from joomla-framework/filter. The upstream closure is replaced with
a named static method, and mb_chr() is guarded with an html_entity_decode()
fallback, both to keep PHP 5.3/no-mbstring targets working.

Behaviour change: attribute values are now whitespace-stripped before the
check, so a value that genuinely reads "java script:" is treated as hostile and
the attribute is dropped. This matches upstream and is considered acceptable.

Advisory: https://developer.joomla.org/security-centre/1095-20260915-core-xss-filter-bypass-in-inputfilter-via-html5-entity-decode-mismatch.html""")

# --------------------------------------------------------------------------
# JSEC-0005 / CVE-2026-92222 - SSRF via unrestricted URL schemes
# --------------------------------------------------------------------------
print("\n== JSEC-0005 CVE-2026-92222 feed URL schemes ==")

# Indentation differs per file; each file contains exactly one validate="url".
for relpath, indent in (
    ("administrator/components/com_newsfeeds/models/forms/newsfeed.xml", "\t\t\t"),
    ("modules/mod_feed/mod_feed.xml", "\t\t\t\t\t"),
    ("administrator/modules/mod_feed/mod_feed.xml", "\t\t\t\t\t"),
):
    edit(
        relpath,
        indent + 'validate="url"\n',
        indent + 'validate="url"\n' + indent + 'schemes="http,https"\n',
    )

commit("""JSEC-0005: restrict feed URL schemes to http/https (CVE-2026-92222)

The three core form fields whose value is fetched server-side by
FeedFactory::getFeed() declared validate="url" without a schemes attribute.
UrlRule's default scheme list when the attribute is absent is extremely broad:

  http https ftp ftps gopher mailto news prospero telnet rlogin sftp tn3270
  wais mid cid nntp tel urn ldap file fax modem git

FeedFactory::getFeed() passes the stored value to XMLReader::open(), which
resolves it through PHP's stream wrappers. A value of file:///etc/passwd is
therefore a local file read rather than an HTTP request, and gopher:// or
ldap:// give an attacker control over the bytes sent to an arbitrary TCP port.

Add schemes="http,https" to the three affected fields. The 3.10 UrlRule
already honours the attribute, so no code change is required.

Upstream fixed the equivalent fields in Joomla 5.4.9 the same way. Upstream's
change set also covers plugins/task/requests, which has no analogue here: the
Task Scheduler was introduced in Joomla 4.1.

Note on the advisory's version range: Joomla lists this as affecting 4.0.0 and
later, but the vulnerable pattern and the permissive UrlRule default are both
present in 3.10.12 and the dangerous schemes are demonstrably accepted. The
published range reflects which branches Joomla still assesses, not an absence
of the bug here. See advisories/JSEC-0005.md.

Limitation: restricting the scheme does not prevent SSRF to internal hosts over
HTTP. http://169.254.169.254/ remains a valid feed URL after this patch, by
design and in line with upstream.

Advisory: https://developer.joomla.org/security-centre/1089-20260909-core-ssrf-vectors-in-various-core-extensions.html""")

# --------------------------------------------------------------------------
# Emit patches
# --------------------------------------------------------------------------
print("\n== writing patches ==")
if not os.path.isdir(OUT):
    os.makedirs(OUT)
for stale in os.listdir(OUT):
    if stale.endswith(".patch"):
        os.remove(os.path.join(OUT, stale))

sh("git", "format-patch", "-q", "--no-signature", "--zero-commit", "--no-numbered",
   "-o", OUT, base)
for name in sorted(os.listdir(OUT)):
    if name.endswith(".patch"):
        size = os.path.getsize(os.path.join(OUT, name))
        print("  %s (%d bytes)" % (name, size))

count = len([f for f in os.listdir(OUT) if f.endswith(".patch")])
print("\nDone. %d patches generated." % count)
