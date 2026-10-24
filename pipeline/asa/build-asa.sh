#!/bin/bash
# Builds Attack Surface Analyzer as one self-contained executable per
# platform, pinned, so a baseline guest gets a single file and no .NET install
# (which would land in the very file and registry state being compared).
#
#   pipeline/asa/build-asa.sh        # -> work/asa/bin/{win-x64,linux-x64}/, BUILD-INFO (the state directory)
#
# Needs git and a .NET 8 SDK. The release tag's nuget.config points at a
# Microsoft-internal feed; the repo's own NuGet.Config.Public (nuget.org only)
# is used instead. The tag targets net8.0;net9.0; net8.0 is built.
set -euo pipefail
TAG=${TAG:-v2.3.331}
W=$(cd "$(dirname "$0")" && pwd)
B=${BL_STATE:-$(cd "$W/../.." && pwd)/work}/asa/bin
mkdir -p "$B"
SRC=$(mktemp -d)
trap 'rm -rf "$SRC"' EXIT
git clone -q https://github.com/microsoft/AttackSurfaceAnalyzer "$SRC"
git -C "$SRC" checkout -q "$TAG"
export DOTNET_CLI_TELEMETRY_OPTOUT=1
for rid in win-x64 linux-x64; do
  ( cd "$SRC/Cli"
    dotnet restore -p:TargetFrameworks=net8.0 -r "$rid" --configfile ../NuGet.Config.Public >/dev/null
    dotnet publish --no-restore -c Release -p:TargetFrameworks=net8.0 -f net8.0 -r "$rid" \
      --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true \
      -o "$B/$rid" >/dev/null )
done
{ echo "tag=$TAG commit=$(git -C "$SRC" rev-parse HEAD)"
  echo "sdk=$(dotnet --version) framework=net8.0 self-contained single-file"
  sha256sum "$B/win-x64/Asa.exe" "$B/linux-x64/Asa" | sed "s|$B/|bin/|"
} > "$B/BUILD-INFO"
cat "$B/BUILD-INFO"
