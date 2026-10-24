#!/bin/bash
# One-enable-away sweep: for each installed-but-not-enabled unit, start it,
# record the new non-loopback listeners, stop it and everything it pulled in,
# and record anything still listening afterwards as residue.
#
# Output in $OUT:
#   candidates.tsv  unit <TAB> decision <TAB> reason   (every unit considered)
#   sweep.jsonl     one record per tested unit
set -u
OUT=${1:-/var/tmp/baseline/sweep}
mkdir -p "$OUT"

# Non-loopback listeners, one per line: proto local_addr:port owner-cgroup
listeners() {
    ss -H -tulnpe 2>/dev/null | awk '
        { local=$5; cg=""; for (i=1;i<=NF;i++) if ($i ~ /^cgroup:/) cg=substr($i,8)
          if (local ~ /^127\./ || local ~ /^\[::1\]/ || local ~ /%lo:/) next
          print $1, local, cg }' | sort -u
}
active_units() { systemctl list-units --state=active --no-legend --plain | awk '{print $1}' | sort; }

# Starting any of these would end or wedge the run, or is already accounted for.
DENY='^(systemd-(poweroff|reboot|halt|kexec|soft-reboot|suspend|hibernate|hybrid-sleep|suspend-then-hibernate)|rescue|emergency|debug-shell|getty|serial-getty|console-getty|container-getty|cloud-|ssh\.|ssh@|ua-reboot|unattended-upgrades|apt-daily|snapd)'

: > "$OUT/candidates.tsv"
systemctl list-unit-files --type=service,socket --no-legend --plain \
    | awk '$2=="disabled" || $2=="indirect" {print $1, $2}' | sort \
    | while read -r unit state; do
        reason=""
        base=${unit%.*}
        if [[ $unit == *@.* ]]; then reason="template"
        elif [[ $unit =~ $DENY ]]; then reason="deny-list"
        elif [[ $(systemctl show -P RefuseManualStart "$unit") == yes ]]; then reason="refuses manual start"
        elif [[ $unit == *.service ]] && systemctl list-unit-files "$base.socket" --no-legend 2>/dev/null | grep -qE 'disabled|indirect'; then
            reason="tested via $base.socket"
        elif [[ $unit == *.service && $(systemctl show -P Type "$unit") == oneshot ]]; then reason="oneshot"
        fi
        if [[ -n $reason ]]; then printf '%s\tskip\t%s\n' "$unit" "$reason"
        else printf '%s\ttest\t%s\n' "$unit" "$state"; fi
    done >> "$OUT/candidates.tsv"

listeners > "$OUT/listeners.before"
: > "$OUT/sweep.jsonl"
awk -F'\t' '$2=="test" {print $1}' "$OUT/candidates.tsv" | while read -r unit; do
    pre_units=$(active_units)
    pre=$(listeners)
    timeout 30 systemctl start "$unit" >/dev/null 2>&1; rc=$?
    sleep 3
    state=$(systemctl is-active "$unit")
    # "no" means a Condition*= was not met: the unit needs configuration, which
    # is out of scope for one-enable-away.
    cond=$(systemctl show -P ConditionResult "$unit")
    during=$(comm -13 <(echo "$pre") <(listeners))
    # Stop the unit and anything it pulled in; restart anything it displaced
    # through Conflicts= (sshd.socket stops sshd.service on Alma).
    started=$(comm -13 <(echo "$pre_units") <(active_units))
    displaced=$(comm -23 <(echo "$pre_units") <(active_units))
    timeout 30 systemctl stop "$unit" $started >/dev/null 2>&1
    [ -n "$displaced" ] && timeout 30 systemctl start $displaced >/dev/null 2>&1
    sleep 1
    residue=$(comm -13 <(echo "$pre") <(listeners))
    # Attribute only listeners whose cgroup belongs to a unit this test
    # started; anything else (a DHCP renewal, a timer) is background noise.
    own() { local l u; while read -r l; do [ -z "$l" ] && continue
              for u in $started; do [[ $l == *"/$u"* ]] && { echo "$l"; break; }; done
            done; }
    noise=$(comm -13 <(echo "$pre") <(listeners) | own | comm -13 - <(comm -13 <(echo "$pre") <(listeners)))
    during=$(echo "$during" | own)
    residue=$(echo "$residue" | own)
    python3 - "$unit" "$rc" "$state" "$cond" "$during" "$residue" "$started" "$noise" "$displaced" >> "$OUT/sweep.jsonl" <<'PY'
import json, sys
unit, rc, state, cond, during, residue, started, noise, displaced = sys.argv[1:]
lines = lambda s: [l for l in s.splitlines() if l.strip()]
print(json.dumps({"unit": unit, "start_rc": int(rc), "state": state, "condition_met": cond == "yes",
                  "new_listeners": lines(during), "residue": lines(residue),
                  "pulled_in": started.split(), "unattributed": lines(noise), "displaced": displaced.split()}))
PY
    sync
done
listeners > "$OUT/listeners.after"
