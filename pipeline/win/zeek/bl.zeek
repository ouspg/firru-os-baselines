# Always-on Zeek on the baseline bridges (zeek-bl@<bridge>.service).
# JSON logs rotated hourly in /var/lib/bl-zeek/<bridge>/; conn.log carries
# the MACs (orig_l2_addr/resp_l2_addr), which bl-zeek-slice.py keys runs on.
@load policy/protocols/conn/mac-logging
redef LogAscii::use_json = T;
redef Log::default_rotation_interval = 1 hr;
# Guest packets on a virtual bridge often carry unfilled (offloaded)
# checksums; without this Zeek drops those TCP sessions silently.
redef ignore_checksums = T;
