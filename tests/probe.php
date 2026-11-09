<?php
/**
 * Vulnerability probe for the JSEC Joomla 3.10 patch set.
 *
 * Run against a Joomla 3.10 root and it reports, for each known vector, whether
 * that root is VULNERABLE or FIXED. The same probe is run against a pristine
 * tree and a patched tree, so the patch set is proved by the change in output
 * rather than by assertion alone.
 *
 * Usage: php probe.php /path/to/joomla-root
 */

if ($argc < 2) {
	fwrite(STDERR, "usage: php probe.php /path/to/joomla-root\n");
	exit(2);
}

$root = rtrim($argv[1], "/\\");

if (!is_dir($root . '/libraries')) {
	fwrite(STDERR, "not a Joomla root: $root\n");
	exit(2);
}

// ---------------------------------------------------------------------------
// Minimal bootstrap. No autoloader: we require exactly the files under test.
// ---------------------------------------------------------------------------
// The CMS library files guard themselves with `defined('JPATH_PLATFORM') or die;`,
// which exits silently with status 0 if the constant is missing.
define('_JEXEC', 1);
define('JPATH_PLATFORM', $root . '/libraries');
define('JPATH_ROOT', $root);
define('JPATH_SITE', $root);

// HTMLHelper.php calls \JLoader::import() at file scope for three legacy packages
// that none of the methods under test touch. A no-op stub keeps the probe free of
// a full CMS bootstrap.
if (!class_exists('JLoader', false)) {
	class JLoader
	{
		public static function import($path, $base = null)
		{
			return true;
		}

		public static function register($class, $path, $force = true)
		{
			return true;
		}
	}
}

// StringHelper delegates to the bundled phputf8 functions, which Joomla normally
// pulls in through Composer's autoloader file map.
// utf8.php is the dispatcher: it loads either the mbstring or the native
// implementation itself, so everything here is require_once.
require_once $root . '/libraries/vendor/joomla/string/src/phputf8/utf8.php';
require_once $root . '/libraries/vendor/joomla/string/src/phputf8/ord.php';
require_once $root . '/libraries/vendor/joomla/string/src/phputf8/utils/validation.php';
require_once $root . '/libraries/vendor/joomla/string/src/StringHelper.php';
require $root . '/libraries/vendor/joomla/filter/src/InputFilter.php';
require $root . '/libraries/vendor/joomla/utilities/src/ArrayHelper.php';
require $root . '/libraries/src/HTML/HTMLHelper.php';
require $root . '/libraries/vendor/joomla/uri/src/UriHelper.php';
require $root . '/libraries/src/Form/FormRule.php';
require $root . '/libraries/src/Form/Rule/UrlRule.php';

use Joomla\CMS\HTML\HTMLHelper;
use Joomla\Filter\InputFilter;

$results = array();
$notes   = array();

function report($id, $vulnerable, $detail = '')
{
	global $results;
	$results[] = array($id, $vulnerable ? 'VULNERABLE' : 'FIXED', $detail);
}

/**
 * Record an observation that this patch set does not change and that therefore
 * must not count toward the vulnerable total — background evidence for an
 * advisory rather than a pass/fail criterion.
 */
function note($id, $detail = '')
{
	global $notes;
	$notes[] = array($id, $detail);
}

// ---------------------------------------------------------------------------
// CVE-2026-92231 - checkAttribute entity decode mismatch
//
// Each payload is one a browser resolves to `javascript:`. checkAttribute()
// returns true when it recognises the value as hostile, so false = bypass.
// ---------------------------------------------------------------------------
$filterVectors = array(
	'html5-entity-tab'        => 'java&Tab;script:alert(1)',
	'html5-entity-newline'    => 'java&NewLine;script:alert(1)',
	'unterminated-numeric'    => 'java&#10script:alert(1)',
	'unterminated-hex'        => 'java&#x0Ascript:alert(1)',
	'terminated-numeric'      => 'java&#10;script:alert(1)',
	'literal-whitespace'      => "java\tscript:alert(1)",
	'plain-control'           => 'javascript:alert(1)',
);

foreach ($filterVectors as $id => $payload) {
	$detected = InputFilter::checkAttribute(array('href', $payload));
	report('CVE-2026-92231/' . $id, !$detected, $detected ? 'detected' : 'bypass');
}

/*
 * End-to-end through clean(), in the configuration where the bypass actually
 * reaches output: a whitelist filter that deliberately permits <a href>, which
 * is what a site allowing restricted HTML in user content looks like.
 *
 * Under the default blacklist-plus-xssAuto configuration the anchor is dropped
 * by unrelated attribute handling, so that path is reported separately and is
 * not evidence either way.
 */
$allowHref = new InputFilter(array('a'), array('href'), 1, 1);
$cleaned   = $allowHref->clean('<a href="java&Tab;script:alert(1)">x</a>', 'html');
$normalise = function ($html) {
	return stripos(str_replace(array("\t", "\n", "\r", ' ', "\0"), '', html_entity_decode($html, ENT_QUOTES, 'UTF-8')), 'javascript:') !== false;
};
report('CVE-2026-92231/end-to-end-whitelist', $normalise($cleaned), trim($cleaned));

$defaults    = new InputFilter(array(), array(), 0, 0, 1);
$cleanedDef  = $defaults->clean('<a href="java&Tab;script:alert(1)">x</a>', 'html');
report('CVE-2026-92231/end-to-end-defaults', $normalise($cleanedDef), trim($cleanedDef));

// ---------------------------------------------------------------------------
// CVE-2026-90906 - XSS in HTMLHelper::link and ::iframe
// ---------------------------------------------------------------------------
$linkOut = HTMLHelper::link('" onmouseover="alert(1)', 'click');
report(
	'CVE-2026-90906/link-url-breakout',
	strpos($linkOut, 'onmouseover="alert(1)"') !== false || strpos($linkOut, '" onmouseover=') !== false,
	trim($linkOut)
);

$attrOut = HTMLHelper::link('https://example.test', 'click', array('title' => '" onfocus="alert(1)'));
report(
	'CVE-2026-90906/link-attr-breakout',
	strpos($attrOut, 'onfocus=') !== false && strpos($attrOut, '&quot;') === false,
	trim($attrOut)
);

$iframeOut = HTMLHelper::iframe('" onload="alert(1)', 'frame');
report(
	'CVE-2026-90906/iframe-url-breakout',
	strpos($iframeOut, 'onload="alert(1)"') !== false || strpos($iframeOut, '" onload=') !== false,
	trim($iframeOut)
);

// A legitimate URL with query separators must still render usefully.
$benign = HTMLHelper::link('index.php?a=1&b=2', 'ok');
report(
	'CVE-2026-90906/benign-url-preserved',
	strpos($benign, 'index.php?a=1') === false,
	trim($benign)
);

// ---------------------------------------------------------------------------
// CVE-2026-73373 - SHTML and friends missing from the forbidden list
// ---------------------------------------------------------------------------
require $root . '/libraries/src/Filter/InputFilter.php';

$cmsFilter = 'Joomla\\CMS\\Filter\\InputFilter';
$tmpDir    = sys_get_temp_dir() . '/jsec-probe-' . getmypid();
@mkdir($tmpDir, 0777, true);

foreach (array('shtml', 'shtm', 'sht', 'stm', 'asp', 'aspx', 'php', 'jpg') as $ext) {
	$tmpFile = $tmpDir . '/payload.' . $ext;
	file_put_contents($tmpFile, "<!--#exec cmd=\"id\" -->\n");

	$safe = call_user_func(
		array($cmsFilter, 'isSafeFile'),
		array(
			'name'     => 'payload.' . $ext,
			'tmp_name' => $tmpFile,
			'type'     => 'application/octet-stream',
			'error'    => 0,
			'size'     => filesize($tmpFile),
		)
	);

	@unlink($tmpFile);

	if ($ext === 'jpg') {
		// Control: a benign extension must remain uploadable.
		report('CVE-2026-73373/control-jpg-allowed', $safe !== true, $safe ? 'allowed' : 'blocked');
	} else {
		report('CVE-2026-73373/' . $ext, $safe === true, $safe ? 'allowed' : 'blocked');
	}
}

@rmdir($tmpDir);

// ---------------------------------------------------------------------------
// CVE-2026-90907 - profile.save guest check
//
// Running the controller needs a full CMS application, so this is a structural
// check: is there a guest guard between getUser() and the jform read?
// ---------------------------------------------------------------------------
$profile = file_get_contents($root . '/components/com_users/controllers/profile.php');
$saveBody = '';

if (preg_match('/public function save\(\).*?\n\t\}/s', $profile, $m)) {
	$saveBody = $m[0];
}

$readsForm  = strpos($saveBody, "post->get('jform'") !== false;
$hasGuard   = preg_match('/\$user->get\(\s*[\'"]guest[\'"]\s*\)|\$user->guest/', $saveBody) === 1;
$guardFirst = false;

if ($hasGuard && $readsForm) {
	preg_match('/\$user->get\(\s*[\'"]guest[\'"]\s*\)|\$user->guest/', $saveBody, $gm, PREG_OFFSET_CAPTURE);
	$guardFirst = $gm[0][1] < strpos($saveBody, "post->get('jform'");
}

report(
	'CVE-2026-90907/profile-save-guest-guard',
	!($hasGuard && $guardFirst),
	$hasGuard ? ($guardFirst ? 'guard precedes form read' : 'guard present but after form read') : 'no guard'
);

// ---------------------------------------------------------------------------
// CVE-2026-92222 - SSRF via unrestricted URL schemes on feed fields
//
// Two layers are checked. First, that UrlRule's permissive default scheme list
// really does accept dangerous schemes when a field sets no `schemes`
// attribute. Second, that each feed form field whose value is fetched
// server-side actually constrains the scheme.
// ---------------------------------------------------------------------------
$urlRule = new \Joomla\CMS\Form\Rule\UrlRule();

$dangerousSchemes = array(
	'file'   => 'file:///etc/passwd',
	'gopher' => 'gopher://127.0.0.1:6379/_SET%20k%20v',
	'ldap'   => 'ldap://127.0.0.1/',
);

/*
 * These three are recorded as notes, not findings. They describe UrlRule's
 * permissive default scheme list, which is why constraining the feed fields is
 * necessary — but the patch set deliberately does not change that default,
 * because it is shared by every url-validated field in core and in third-party
 * extensions. They would otherwise report VULNERABLE forever.
 */
foreach ($dangerousSchemes as $id => $url) {
	$unrestricted = new \SimpleXMLElement('<field name="u" required="true" validate="url" />');
	$accepted     = (bool) $urlRule->test($unrestricted, $url);
	note(
		'CVE-2026-92222/urlrule-default-' . $id,
		($accepted ? 'accepted' : 'rejected') . ' for a field declaring no schemes attribute'
	);
}

// Control: the rule must still accept a legitimate feed URL.
$restricted = new \SimpleXMLElement('<field name="u" required="true" validate="url" schemes="http,https" />');
report(
	'CVE-2026-92222/control-https-accepted',
	!$urlRule->test($restricted, 'https://example.com/feed.xml'),
	'legitimate feed URL'
);

// The three 3.10 form fields whose value is fetched server-side by
// FeedFactory::getFeed(). plg_task_requests is Joomla 4.1+ and has no analogue.
$feedForms = array(
	'com_newsfeeds'     => 'administrator/components/com_newsfeeds/models/forms/newsfeed.xml',
	'mod_feed-site'     => 'modules/mod_feed/mod_feed.xml',
	'mod_feed-admin'    => 'administrator/modules/mod_feed/mod_feed.xml',
);

foreach ($feedForms as $id => $rel) {
	$path = $root . '/' . $rel;

	if (!is_file($path)) {
		report('CVE-2026-92222/' . $id, false, 'form not present in this install');
		continue;
	}

	$xml = @simplexml_load_file($path);

	if ($xml === false) {
		report('CVE-2026-92222/' . $id, true, 'could not parse ' . $rel);
		continue;
	}

	$fields = $xml->xpath('//field[@validate="url"]');
	$unconstrained = array();

	foreach ((array) $fields as $field) {
		$schemes = isset($field['schemes']) ? (string) $field['schemes'] : '';
		$list    = array_filter(array_map('trim', explode(',', strtolower($schemes))));
		$bad     = array_diff($list, array('http', 'https'));

		if ($schemes === '' || !empty($bad)) {
			$unconstrained[] = (string) $field['name'] . ($schemes === '' ? ' (no schemes)' : ' (schemes=' . $schemes . ')');
		}
	}

	report(
		'CVE-2026-92222/' . $id,
		!empty($unconstrained),
		empty($unconstrained) ? 'scheme-constrained' : implode(', ', $unconstrained)
	);
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------
$vulnCount = 0;

foreach ($results as $r) {
	printf("%-44s %-11s %s\n", $r[0], $r[1], $r[2]);

	if ($r[1] === 'VULNERABLE') {
		$vulnCount++;
	}
}

printf("\n%d vector(s) VULNERABLE, %d FIXED\n", $vulnCount, count($results) - $vulnCount);

if (!empty($notes)) {
	print("\nNotes (not changed by this patch set, shown as background):\n");

	foreach ($notes as $n) {
		printf("  %-42s %s\n", $n[0], $n[1]);
	}
}

exit($vulnCount > 0 ? 1 : 0);
