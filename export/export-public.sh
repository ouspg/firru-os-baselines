#!/bin/bash
# Builds the public tree from this repository.
# Usage: export-public.sh DEST
# The
# tracked files the allowlist (export/public.list) selects, and nothing else.
# Refuses (exit 1, DEST removed) if any exported file matches a pattern in
# leak-patterns in $BL_PRIVATE, by default ~/firru-os-baselines-private/ outside
# the checkout (one extended regex per line, # comments): the
# patterns are themselves private, so they never enter a repository.
# DEST must not exist; it gets no .git, so its history starts when you say.
set -eu
R=$(cd "$(dirname "$0")/.." && pwd)
DEST=${1:?DEST}
LIST=$R/export/public.list PAT=${BL_PRIVATE:-$HOME/firru-os-baselines-private}/leak-patterns
[ -e "$DEST" ] && { echo "$DEST exists" >&2; exit 1; }
[ -r "$PAT" ] || { echo "no $PAT: refusing to export unscanned" >&2; exit 1; }

# The allowlist: git pathspecs (globs), one per line, ! to exclude.
mapfile -t specs < <(grep -v '^\s*\(#\|$\)' "$LIST" | sed 's|^!|:(exclude)|')
files=$(mktemp); trap 'rm -f "$files"' EXIT
git -C "$R" ls-files -z -- "${specs[@]}" > "$files"
mkdir -p "$DEST"
rsync -a --from0 --files-from="$files" "$R/" "$DEST/"

hits=$(grep -v '^\s*\(#\|$\)' "$PAT" | LC_ALL=C grep -rIlE -f - "$DEST" || true)
if [ -n "$hits" ]; then
  echo "leak patterns matched; nothing exported:" >&2
  echo "$hits" | sed "s|^$DEST/||" | sort | head -50 >&2
  rm -rf "$DEST"; exit 1
fi
echo "$(tr -cd '\0' < "$files" | wc -c) files, $(du -sh "$DEST" | cut -f1), no leak-pattern matches -> $DEST"
