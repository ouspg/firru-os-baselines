#!/bin/bash
# Finishes egress runs that end while nobody watches: waits for the given
# systemd units (run-list.sh sets) to end, then slices, profiles and commits
# every egress run that has no Zeek slice yet.
# Usage: after-egress.sh UNIT...
cd "$(dirname "$0")/.." || exit 1
for u in "$@"; do
    while systemctl --user is-active -q "$u"; do sleep 300; done
done
for r in runs/*-egress-g*/; do
    r=${r%/}
    [ -f "$r/done" ] && [ ! -f "$r/zeek/SLICE" ] || continue
    python3 pipeline/win/bl-zeek-slice.py "$r" || { echo "$r: slice failed"; continue; }
    python3 analysis/egress-owners.py "$r"
    python3 analysis/egress-profile.py profile "$r"
    git add "$r/zeek" "$r/egress-profile.tsv" "$r/egress-owners.tsv" \
        && git commit -qm "${r#runs/}: zeek slice, egress profile and owners" && echo "$r: committed"
done
