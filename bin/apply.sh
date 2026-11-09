#!/bin/sh
#
# Apply the J3-SEC patch set to a Joomla 3.10.12 installation.
#
# Checks every patch applies before applying any of them, so a failure leaves the
# target untouched rather than half-patched.
#
# Usage: bin/apply.sh /path/to/joomla [--check]

set -e

TARGET="$1"
MODE="$2"
HERE=$(cd "$(dirname "$0")/.." && pwd)
PATCHDIR="$HERE/patches"

if [ -z "$TARGET" ]; then
	echo "usage: $0 /path/to/joomla [--check]" >&2
	exit 2
fi

if [ ! -f "$TARGET/libraries/src/Filter/InputFilter.php" ]; then
	echo "error: $TARGET does not look like a Joomla 3 root" >&2
	echo "       (expected libraries/src/Filter/InputFilter.php)" >&2
	exit 2
fi

if [ ! -d "$PATCHDIR" ]; then
	echo "error: no patches directory at $PATCHDIR" >&2
	exit 2
fi

# Pick a patch tool.
if command -v git >/dev/null 2>&1; then
	TOOL=git
elif command -v patch >/dev/null 2>&1; then
	TOOL=patch
else
	echo "error: neither git nor patch found on PATH" >&2
	exit 2
fi

echo "target: $TARGET"
echo "tool:   $TOOL"
echo

# --- version warning -------------------------------------------------------
VERFILE="$TARGET/libraries/src/Version.php"

if [ -f "$VERFILE" ]; then
	REL=$(grep -o "RELEASE *= *'[0-9.]*'" "$VERFILE" | head -1 | grep -o "[0-9.]*" | head -1)
	DEV=$(grep -o "DEV_LEVEL *= *'[0-9]*'" "$VERFILE" | head -1 | grep -o "[0-9]*" | head -1)

	if [ -n "$REL" ]; then
		echo "detected Joomla $REL.$DEV"

		if [ "$REL.$DEV" != "3.10.12" ]; then
			echo "WARNING: patches were built against 3.10.12. Hunks may not apply." >&2
		fi

		echo
	fi
fi

# --- dry run ---------------------------------------------------------------
echo "checking all patches apply..."
FAILED=0

for p in "$PATCHDIR"/*.patch; do
	name=$(basename "$p")
	printf '  %-64s ' "$name"

	if [ "$TOOL" = git ]; then
		if (cd "$TARGET" && git apply --check -p1 "$p" 2>/dev/null); then
			echo "ok"
		else
			echo "FAIL"
			FAILED=1
		fi
	else
		if (cd "$TARGET" && patch -p1 --dry-run -s -f -i "$p" >/dev/null 2>&1); then
			echo "ok"
		else
			echo "FAIL"
			FAILED=1
		fi
	fi
done

if [ "$FAILED" -ne 0 ]; then
	echo
	echo "One or more patches do not apply. Nothing has been changed." >&2
	echo "Either core files are modified, or a patch is already applied." >&2
	echo "Run: php tests/probe.php \"$TARGET\"   to see what is already fixed." >&2
	exit 1
fi

echo
echo "all patches apply cleanly"

if [ "$MODE" = "--check" ]; then
	echo "(--check given: stopping without applying)"
	exit 0
fi

# --- apply -----------------------------------------------------------------
echo
echo "applying..."

for p in "$PATCHDIR"/*.patch; do
	name=$(basename "$p")
	printf '  %-64s ' "$name"

	if [ "$TOOL" = git ]; then
		(cd "$TARGET" && git apply -p1 "$p")
	else
		(cd "$TARGET" && patch -p1 -s -i "$p")
	fi

	echo "applied"
done

echo
echo "done. Verify with:"
echo "  php $HERE/tests/probe.php \"$TARGET\""
