#!/bin/sh
#
# Apply the J3-SEC patch set to a Joomla 3.10.12 installation.
#
# Checks every patch applies before applying any of them, then verifies each one
# actually landed. A failure leaves the target untouched rather than half-patched.
#
# Usage: bin/apply.sh /path/to/joomla [--check]

set -e

TARGET_IN="$1"
MODE="$2"
HERE=$(cd "$(dirname "$0")/.." && pwd)
PATCHDIR="$HERE/patches"

if [ -z "$TARGET_IN" ]; then
	echo "usage: $0 /path/to/joomla [--check]" >&2
	exit 2
fi

if [ ! -d "$TARGET_IN" ]; then
	echo "error: $TARGET_IN is not a directory" >&2
	exit 2
fi

# Absolute path: both patch tools are invoked from inside the target.
TARGET=$(cd "$TARGET_IN" && pwd)

if [ ! -f "$TARGET/libraries/src/Filter/InputFilter.php" ]; then
	echo "error: $TARGET does not look like a Joomla 3 root" >&2
	echo "       (expected libraries/src/Filter/InputFilter.php)" >&2
	exit 2
fi

if [ ! -d "$PATCHDIR" ]; then
	echo "error: no patches directory at $PATCHDIR" >&2
	exit 2
fi

# --- tool selection --------------------------------------------------------
#
# GNU patch is preferred because it resolves paths relative to the working
# directory, full stop.
#
# `git apply` does not: inside a git repository it resolves paths relative to the
# REPOSITORY ROOT and silently ignores paths outside the current directory,
# exiting 0 without changing anything. Any Joomla install that happens to live
# inside a git work tree would therefore appear to patch successfully and not be
# patched at all. Forcing GIT_DIR to a throwaway and GIT_WORK_TREE to the target
# makes the target the work tree root, which restores the expected behaviour.

GIT_SCRATCH=""

cleanup() {
	if [ -n "$GIT_SCRATCH" ] && [ -d "$GIT_SCRATCH" ]; then
		rm -rf "$GIT_SCRATCH"
	fi
}
trap cleanup EXIT HUP INT TERM

if command -v patch >/dev/null 2>&1; then
	TOOL=patch
elif command -v git >/dev/null 2>&1; then
	TOOL=git
	GIT_SCRATCH=$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/j3sec-$$")
	mkdir -p "$GIT_SCRATCH"
else
	echo "error: neither patch nor git found on PATH" >&2
	exit 2
fi

# Zero fuzz (-F0) is deliberate. With GNU patch's default fuzz of 2, an
# already-applied patch can match again at a shifted offset and be applied a
# SECOND time, duplicating the inserted code. For a security patch, context
# must match exactly or not at all. -N makes an already-applied patch a clean
# skip rather than an interactive prompt.

# try_patch <patchfile>  -> 0 if it would apply cleanly
try_patch() {
	if [ "$TOOL" = patch ]; then
		(cd "$TARGET" && patch -p1 -F0 -N --dry-run -s -i "$1" >/dev/null 2>&1 </dev/null)
	else
		(cd "$TARGET" && GIT_DIR="$GIT_SCRATCH" GIT_WORK_TREE="$TARGET" \
			git apply --check -p1 "$1" >/dev/null 2>&1)
	fi
}

# do_patch <patchfile>
do_patch() {
	if [ "$TOOL" = patch ]; then
		(cd "$TARGET" && patch -p1 -F0 -N -s -i "$1" </dev/null)
	else
		(cd "$TARGET" && GIT_DIR="$GIT_SCRATCH" GIT_WORK_TREE="$TARGET" \
			git apply -p1 "$1")
	fi
}

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
	printf '  %-64s ' "$(basename "$p")"

	if try_patch "$p"; then
		echo "ok"
	else
		echo "FAIL"
		FAILED=1
	fi
done

if [ "$FAILED" -ne 0 ]; then
	echo
	echo "One or more patches do not apply. Nothing has been changed." >&2
	echo "Either core files are modified, or a patch is already applied." >&2
	echo "Run: php \"$HERE/tests/probe.php\" \"$TARGET\"   to see what is already fixed." >&2
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
	printf '  %-64s ' "$(basename "$p")"
	do_patch "$p"

	# Verify it landed. An already-applied patch must no longer apply cleanly;
	# if it still does, the tool changed nothing and reported success.
	if try_patch "$p"; then
		echo "NO-OP"
		echo >&2
		echo "error: $(basename "$p") reported success but changed nothing." >&2
		echo "       The tree may be partially patched. Restore your backup and" >&2
		echo "       report this with your tool versions." >&2
		exit 1
	fi

	echo "applied"
done

echo
echo "done. Verify with:"
echo "  php \"$HERE/tests/probe.php\" \"$TARGET\""
