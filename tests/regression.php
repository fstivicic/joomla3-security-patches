<?php
/**
 * Regression harness — does ordinary Joomla still work after patching?
 *
 * tests/probe.php answers "is this install vulnerable". It deliberately uses
 * hostile input, which means a patch could pass it perfectly and still break
 * every page on the site. This file is the other half: real usage patterns
 * taken from Joomla 3.10 core call sites, asserted against expected output.
 *
 * Every case below is derived from an actual core call. Sources are cited so a
 * reviewer can check that the input is realistic rather than invented.
 *
 * Usage: php regression.php /path/to/joomla-root
 * Exit 0 = no regressions.
 */

if ($argc < 2) {
	fwrite(STDERR, "usage: php regression.php /path/to/joomla-root\n");
	exit(2);
}

$root = rtrim($argv[1], "/\\");

if (!is_dir($root . '/libraries')) {
	fwrite(STDERR, "not a Joomla root: $root\n");
	exit(2);
}

define('_JEXEC', 1);
define('JPATH_PLATFORM', $root . '/libraries');
define('JPATH_ROOT', $root);
define('JPATH_SITE', $root);

if (!class_exists('JLoader', false)) {
	class JLoader
	{
		public static function import($path, $base = null) { return true; }
		public static function register($class, $path, $force = true) { return true; }
	}
}

require_once $root . '/libraries/vendor/joomla/string/src/phputf8/utf8.php';
require_once $root . '/libraries/vendor/joomla/string/src/phputf8/ord.php';
require_once $root . '/libraries/vendor/joomla/string/src/phputf8/utils/validation.php';
require_once $root . '/libraries/vendor/joomla/string/src/StringHelper.php';
require_once $root . '/libraries/vendor/joomla/filter/src/InputFilter.php';
require_once $root . '/libraries/vendor/joomla/utilities/src/ArrayHelper.php';
require_once $root . '/libraries/src/HTML/HTMLHelper.php';
require_once $root . '/libraries/src/Filter/InputFilter.php';
require_once $root . '/libraries/vendor/joomla/uri/src/UriHelper.php';
require_once $root . '/libraries/src/Form/FormRule.php';
require_once $root . '/libraries/src/Form/Rule/UrlRule.php';

use Joomla\CMS\HTML\HTMLHelper;
use Joomla\Filter\InputFilter;

$pass = 0;
$fail = 0;

function check($name, $condition, $detail = '')
{
	global $pass, $fail;

	if ($condition) {
		printf("  %-54s ok\n", $name);
		$pass++;

		return;
	}

	printf("  %-54s REGRESSION\n", $name);

	if ($detail !== '') {
		printf("      %s\n", $detail);
	}

	$fail++;
}

// ---------------------------------------------------------------------------
// HTMLHelper::link() with real core inputs
// ---------------------------------------------------------------------------
echo "HTMLHelper::link() against real core call sites\n";

/*
 * JRoute::_() HTML-escapes ampersands by default, so URLs arriving here often
 * already contain &amp;. Re-encoding them would produce &amp;amp; and break
 * every paginated link on the site. This is why the patch passes
 * double_encode = false to htmlspecialchars().
 */
$already = HTMLHelper::link('index.php?option=com_content&amp;id=5', 'Read more');
check(
	'pre-escaped &amp; is not double-encoded',
	strpos($already, '&amp;amp;') === false && strpos($already, 'id=5') !== false,
	$already
);

$raw = HTMLHelper::link('index.php?option=com_content&id=5', 'Read more');
check(
	'raw & becomes &amp; (valid HTML)',
	strpos($raw, '&amp;id=5') !== false,
	$raw
);

/*
 * components/com_content/helpers/icon.php:84 and :188 pass an onclick handler
 * containing single quotes. ENT_QUOTES turns those into &#039;. That is correct
 * and still works, because the HTML parser entity-decodes attribute values
 * before the JS engine sees them — but it must not mangle the handler.
 */
$onclick = HTMLHelper::link(
	'index.php?view=article&id=1&tmpl=component&print=1',
	'Print',
	array(
		'title'   => 'Print article',
		'onclick' => "window.open(this.href,'win2','status=no,toolbar=no'); return false;",
		'rel'     => 'nofollow',
	)
);
check(
	'icon.php onclick handler survives escaping',
	strpos($onclick, 'window.open(this.href,') !== false
		&& strpos($onclick, 'return false;') !== false
		&& strpos($onclick, 'onclick="') !== false,
	$onclick
);
check(
	'onclick single quotes become entities, not broken markup',
	substr_count($onclick, '"') % 2 === 0,
	$onclick
);

/*
 * Attribute names used by core: target (com_admin help), itemprop
 * (com_content author block), class, rel, title. All must survive the
 * attribute-name whitelist in escapeAttributesArray().
 */
foreach (array('target', 'itemprop', 'class', 'rel', 'title', 'data-toggle', 'aria-label') as $attr) {
	$out = HTMLHelper::link('index.php', 'x', array($attr => 'v'));
	check("attribute '$attr' is preserved", strpos($out, $attr . '="v"') !== false, $out);
}

/*
 * Link text is intentionally NOT escaped — core passes icon markup through it,
 * e.g. layouts/joomla/content/icons. Escaping it would render tags as text.
 */
$markup = HTMLHelper::link('index.php', '<span class="icon-print"></span> Print');
check(
	'link text keeps HTML (core passes icon markup)',
	strpos($markup, '<span class="icon-print">') !== false,
	$markup
);

/*
 * com_content archive/category templates pass a contact_link that may be an
 * empty string when the author has no linked contact.
 */
$empty = HTMLHelper::link('', 'Author');
check('empty URL does not fatal', is_string($empty) && strpos($empty, '<a href=""') !== false, $empty);

// ---------------------------------------------------------------------------
// checkAttribute() — called by com_contact on every contact save
// ---------------------------------------------------------------------------
echo "\nInputFilter::checkAttribute() against real stored values\n";

/*
 * administrator/components/com_contact/tables/contact.php:139 calls
 * checkAttribute(array('href', $this->webpage)) and REJECTS the save when it
 * returns true. A false positive here makes contacts unsavable.
 */
$legitimateWebpages = array(
	'https://example.com',
	'https://example.com/path?a=1&b=2',
	'https://example.com/path?a=1&amp;b=2',
	'http://sub.example.co.uk/~user/page.html#anchor',
	'https://example.com/caf%C3%A9',
	'https://example.com/a_b-c.d',
	'mailto:someone@example.com',
	'',
);

foreach ($legitimateWebpages as $url) {
	$flagged = InputFilter::checkAttribute(array('href', $url));
	check(
		"contact webpage accepted: " . ($url === '' ? '(empty)' : substr($url, 0, 34)),
		$flagged === false,
		'wrongly flagged as hostile'
	);
}

// Style attributes must still permit ordinary CSS.
foreach (array('color: red', 'margin:0 auto', 'font-family: "Segoe UI", sans-serif') as $css) {
	check(
		'style allowed: ' . substr($css, 0, 30),
		InputFilter::checkAttribute(array('style', $css)) === false,
		'wrongly flagged'
	);
}

// ---------------------------------------------------------------------------
// isSafeFile() — ordinary media manager uploads
// ---------------------------------------------------------------------------
echo "\nInputFilter::isSafeFile() against ordinary uploads\n";

$cmsFilter = 'Joomla\\CMS\\Filter\\InputFilter';
$tmpDir    = sys_get_temp_dir() . '/jsec-regress-' . getmypid();
@mkdir($tmpDir, 0777, true);

$benign = array(
	'photo.jpg'      => "\xFF\xD8\xFF\xE0 jpeg-ish bytes",
	'logo.png'       => "\x89PNG\r\n\x1a\n binary",
	'document.pdf'   => "%PDF-1.4 some text",
	'sheet.xlsx'     => "PK\x03\x04 zip-ish",
	'notes.txt'      => "just text, nothing executable",
	'styles.css'     => "body { color: red; }",
	'script.js'      => "function hello() { return 1; }",
	'archive.zip'    => "PK\x03\x04 archive",
	'font.woff2'     => "wOF2 binary",
	'video.mp4'      => "\x00\x00\x00\x18ftypmp42",
);

foreach ($benign as $filename => $contents) {
	$tmpFile = $tmpDir . '/' . $filename;
	file_put_contents($tmpFile, $contents);

	$safe = call_user_func(
		array($cmsFilter, 'isSafeFile'),
		array(
			'name'     => $filename,
			'tmp_name' => $tmpFile,
			'type'     => 'application/octet-stream',
			'error'    => 0,
			'size'     => filesize($tmpFile),
		)
	);

	@unlink($tmpFile);

	check("upload still allowed: $filename", $safe === true, 'now blocked');
}

@rmdir($tmpDir);

// ---------------------------------------------------------------------------
// UrlRule — ordinary feed URLs must still validate
// ---------------------------------------------------------------------------
echo "\nUrlRule against ordinary feed URLs (JSEC-0005)\n";

$rule       = new \Joomla\CMS\Form\Rule\UrlRule();
$restricted = new \SimpleXMLElement('<field name="u" required="true" validate="url" schemes="http,https" />');

$realFeeds = array(
	'https://example.com/feed.xml',
	'http://example.com/index.php?format=feed&type=rss',
	'https://news.example.co.uk/rss/latest',
	'https://example.com:8443/feed',
	'https://example.com/feed?utm_source=a&utm_medium=b',
);

foreach ($realFeeds as $feed) {
	check(
		'feed URL accepted: ' . substr($feed, 0, 40),
		$rule->test($restricted, $feed) === true,
		'rejected after patch'
	);
}

// And the scheme restriction must still do its job.
check(
	'file:// still rejected on a constrained field',
	$rule->test($restricted, 'file:///etc/passwd') === false
);

// ---------------------------------------------------------------------------
printf("\n%d ok, %d regressions\n", $pass, $fail);

exit($fail > 0 ? 1 : 0);
