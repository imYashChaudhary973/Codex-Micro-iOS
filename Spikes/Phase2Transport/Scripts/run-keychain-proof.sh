#!/bin/sh
set -eu

CURRENT="Spikes/Phase2Transport/.build/current-signed-probe"
LEGACY="Spikes/Phase2Transport/.build/Phase2TransportProbe.app"
RUN_ID="${1:-manual-proof}"
PROOF="Spikes/Phase2Transport/.build/keychain-proof.bin"

if [ -L "$CURRENT" ]; then
    APP_ROOT=$(cd -P "$CURRENT" && pwd)
elif [ -d "$LEGACY" ] && codesign --verify --strict "$LEGACY" >/dev/null 2>&1; then
    APP_ROOT=$(cd -P "$LEGACY" && pwd)
else
    printf '%s\n' 'code=keychain_proof_unavailable count=1' >&2
    exit 66
fi
if ! codesign --verify --strict "$APP_ROOT" >/dev/null 2>&1; then
    printf '%s\n' 'code=keychain_proof_unavailable count=1' >&2
    exit 66
fi
EXECUTABLE=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' \
    "$APP_ROOT/Contents/Info.plist" 2>/dev/null || true)
APP="$APP_ROOT/Contents/MacOS/$EXECUTABLE"
if [ -z "$EXECUTABLE" ] || [ ! -x "$APP" ]; then
    printf '%s\n' 'code=keychain_proof_unavailable count=1' >&2
    exit 66
fi

cleanup_best_effort() {
    "$APP" keychain-cleanup "$RUN_ID" "$PROOF" >/dev/null 2>&1 || true
}
trap cleanup_best_effort EXIT INT TERM

"$APP" keychain-create "$RUN_ID" "$PROOF"
"$APP" keychain-retrieve "$RUN_ID" "$PROOF"
"$APP" keychain-mismatch "$RUN_ID" "$PROOF"
"$APP" certificate-probe
"$APP" keychain-cleanup "$RUN_ID" "$PROOF"
trap - EXIT INT TERM
printf '%s\n' 'code=keychain_proof_complete count=1'
