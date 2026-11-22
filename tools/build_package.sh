#!/bin/sh
# Build the Splunk packages: dist/SOC-TA-<name>-<version>.tgz for every add-on,
# or only for the ones named on the command line.
#
# A package holds only what Splunk needs: app.manifest, README.md, LICENSE.txt,
# default/, lookups/, metadata/ (no samples/, no local/).
#
# Usage (from anywhere in the repository):
#   sh tools/build_package.sh              # all add-ons
#   sh tools/build_package.sh auditd       # one add-on
set -eu

cd "$(dirname "$0")/.."
NAMES=${*:-"auditbeat auditd"}
mkdir -p dist

for name in $NAMES; do
  app="SOC-TA-$name"
  dir="$name/$app"
  if [ ! -d "$dir" ]; then
    echo "no such add-on: $name (expected $dir)" >&2
    exit 1
  fi
  version=$(sed -n 's/^version = //p' "$dir/default/app.conf" | head -1)
  out="dist/$app-$version.tgz"

  python3 -I tools/check_conf.py "$dir"
  rm -f "$out"
  # Archive from inside <name>/ so the archive root is the app folder.
  # bsdtar (macOS): COPYFILE_DISABLE / --no-mac-metadata keep AppleDouble files out.
  # GNU tar (Linux, CI): the fallback.
  (
    cd "$name"
    COPYFILE_DISABLE=1 tar --no-mac-metadata --no-xattrs --uid 0 --gid 0 --uname root --gname root \
      --exclude .DS_Store --exclude "$app/samples" --exclude "$app/local" --exclude "$app/metadata/local.meta" \
      -czf "../$out" "$app" 2>/dev/null ||
    tar --owner 0 --group 0 --numeric-owner \
      --exclude .DS_Store --exclude "$app/samples" --exclude "$app/local" --exclude "$app/metadata/local.meta" \
      -czf "../$out" "$app"
  )
  echo "built $out"
  tar -tzf "$out" | sed 's/^/  /'
done
