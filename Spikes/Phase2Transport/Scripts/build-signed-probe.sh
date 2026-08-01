#!/bin/sh
set -eu

ROOT="Spikes/Phase2Transport"
BINARY="$ROOT/.build/debug/phase2-transport-probe"
GENERATIONS="$ROOT/.build/signed-probes"
CURRENT="$ROOT/.build/current-signed-probe"
IDENTITY="${CODE_SIGN_IDENTITY:-Apple Development}"

if [ ! -x "$BINARY" ]; then
    printf '%s\n' 'Build the nested package before signing' >&2
    exit 66
fi

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
ENTITLEMENTS="$STAGING/Phase2TransportProbe.entitlements"
mkdir -p "$APP/Contents/MacOS"
cp "$ROOT/Configuration/Info.plist" "$APP/Contents/Info.plist"
cp "$BINARY" "$APP/Contents/MacOS/phase2-transport-probe"

if [ -n "${PROVISIONING_PROFILE:-}" ]; then
    if [ -z "${DEVELOPMENT_TEAM:-}" ]; then
        printf '%s\n' 'DEVELOPMENT_TEAM is required with PROVISIONING_PROFILE' >&2
        exit 64
    fi
    cp "$PROVISIONING_PROFILE" "$APP/Contents/embedded.provisionprofile"
    TEAM_ESCAPED=$(printf '%s' "$DEVELOPMENT_TEAM" | sed 's/[&/]/\\&/g')
    sed "s/__DEVELOPMENT_TEAM__/$TEAM_ESCAPED/g" \
        "$ROOT/Configuration/Entitlements.plist.template" > "$ENTITLEMENTS"
    codesign --force --options runtime --timestamp=none \
        --entitlements "$ENTITLEMENTS" \
        --sign "$IDENTITY" "$APP"
else
    codesign --force --options runtime --timestamp=none --sign "$IDENTITY" "$APP"
fi

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
ln -s "$FINAL_APP" "$CURRENT_NEW"
mv -f "$CURRENT_NEW" "$CURRENT"
trap - EXIT INT TERM
printf '%s\n' 'code=signed_probe_ready count=1'
