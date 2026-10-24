# This export

A snapshot of the private working repository, without its history. It differs
from the run-time files in four ways:

- Laptop home paths read `~/`, and links point at `ouspg/`.
- One Windows test mode and some comments are withheld until a vendor
  disclosure is complete: the recipe copies of `collect.ps1`, `bl-win.sh` and
  `tools/loot-host.ps1` are edited, so a `sha256` in `recipe/PROVENANCE` can
  differ from the file next to it. The runs of that mode are not included.
- Two draft posts have sections removed for the same reason.
- One collector section that belongs to unpublished work is removed from the
  recipe copies of `tools/loot-host.sh` (their `sha256` differs for the same
  reason), and its output file is left out of `loot-host/`.
