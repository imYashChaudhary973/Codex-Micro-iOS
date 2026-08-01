#!/bin/sh
set -eu

ROOT="Spikes/Phase2Transport"
SOURCE_APP="${1:-$ROOT/.build/XcodeSigningProbe/Build/Products/Debug/Phase2TransportProbe.app}"
GENERATIONS="$ROOT/.build/signed-probes"
CURRENT="$ROOT/.build/current-signed-probe"

if [ ! -d "$SOURCE_APP" ]; then
    printf '%s\n' 'Xcode-signed probe app is unavailable' >&2
    exit 66
fi
if [ ! -f "$SOURCE_APP/Contents/embedded.provisionprofile" ]; then
    printf '%s\n' 'Provisioning profile is unavailable' >&2
    exit 66
fi
codesign --verify --strict "$SOURCE_APP"

mkdir -p "$GENERATIONS"
STAGING=$(mktemp -d "$GENERATIONS/.staging.XXXXXX")
CURRENT_NEW="$ROOT/.build/.current-signed-probe.$$"
cleanup_staging() {
    if [ -n "$STAGING" ]; then
        rm -rf "$STAGING"
    fi
    rm -f "$CURRENT_NEW"
}
trap cleanup_staging EXIT INT TERM

APP="$STAGING/Phase2TransportProbe.app"
ditto "$SOURCE_APP" "$APP"
codesign --verify --strict "$APP"
BUNDLE_ID=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$APP/Contents/Info.plist")
if [ "$BUNDLE_ID" != 'com.codexmicro.phase2transport.spike' ]; then
    printf '%s\n' 'Unexpected bundle identifier' >&2
    exit 65
fi

GENERATION="$GENERATIONS/generation-$(date -u +%Y%m%d%H%M%S)-$$"
mv "$STAGING" "$GENERATION"
STAGING=''
FINAL_APP="$(cd "$GENERATION" && pwd)/Phase2TransportProbe.app"
# -h replaces an existing symlink itself instead of following it into the
# previous generation's bundle, which would both break that bundle's seal
# and leave the current pointer stale.
ln -sfh "$FINAL_APP" "$CURRENT"
trap - EXIT INT TERM
printf '%s\n' 'code=entitled_probe_ready count=1'
