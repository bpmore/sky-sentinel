#!/usr/bin/env bash
# Build the upload bundle: everything a site needs, nothing it does not.
#
#   sky-sentinel/bin/package.sh            -> dist/sky-sentinel-<version>.zip
#
# The zip's mu-plugins/ folder holds exactly what goes into
# wp-content/mu-plugins/ on the target: sky-sentinel-loader.php and the
# sky-sentinel/ directory WITHOUT vendor/ and tests/. Upload that, add the
# site's config file beside the loader, done.
#
# sky-sentinel-config.sample.php sits at the top of the zip, OUTSIDE
# mu-plugins/, because WordPress runs every top-level .php in mu-plugins on
# every request. It is a reference for writing a config by hand, not a file
# to upload. The version is read from sentinel.php so the zip name says what
# is in it.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
version="$(sed -n "s/.*VERSION *= *'\([^']*\)'.*/\1/p" "$root/sky-sentinel/sentinel.php" | head -1)"
[ -n "$version" ] || { echo "could not read VERSION from sentinel.php" >&2; exit 1; }
out="$root/dist/sky-sentinel-$version.zip"
mkdir -p "$root/dist"
rm -f "$out"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/mu-plugins"
cp "$root/sky-sentinel-loader.php" "$stage/mu-plugins/"
cp "$root/sky-sentinel-config.sample.php" "$stage/"
rsync -a --exclude vendor --exclude tests --exclude composer.lock --exclude '.DS_Store' "$root/sky-sentinel/" "$stage/mu-plugins/sky-sentinel/"
# Nothing in the bundle may fail to parse: a fatal in an mu-plugin takes the whole site down.
find "$stage" -name '*.php' -print0 | xargs -0 -n1 php -l >/dev/null
( cd "$stage" && zip -qr "$out" mu-plugins sky-sentinel-config.sample.php )
count="$(unzip -l "$out" | tail -1 | awk '{print $2}')"
echo "Built $out ($count files, version $version)"
echo "Upload the contents of mu-plugins/ only. Contains no vendor/, no tests/, no config file: add the site's sky-sentinel-config.php beside the loader."
echo "sky-sentinel-config.sample.php is at the top of the zip as a reference. Do not upload it."
