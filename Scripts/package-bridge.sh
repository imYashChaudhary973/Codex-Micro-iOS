#!/bin/bash
#
# Packages the Mac bridge as a signed .app bundle.
#
# SwiftPM builds an executable, not an application bundle, and macOS reads the
# local-network keys from a bundle's Info.plist. An unbundled binary therefore
# binds a listener but cannot publish a Bonjour record on macOS 15+, which the
# LAN control correctly surfaces as advertisementFailed and rolls back. This
# script is the packaging step SwiftPM does not perform.
#
# Signing is required, not cosmetic: the local-network permission is recorded
# against the code signature, so an unsigned bundle is prompted for every
# launch and an ad-hoc one is treated as a new app each time it changes.
#
# Usage:  Scripts/package-bridge.sh [output-directory]
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${1:-$REPO_ROOT/.build/package}"
APP_NAME="CodexMicroBridge"
APP="$OUTPUT_DIR/$APP_NAME.app"
TEAM_ID="8QSM298XJ2"

echo "==> Building release binary"
swift build -c release --product codex-micro-bridge --package-path "$REPO_ROOT"
BINARY="$REPO_ROOT/.build/release/codex-micro-bridge"
test -x "$BINARY" || { echo "missing $BINARY" >&2; exit 1; }

echo "==> Assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp "$BINARY" "$APP/Contents/MacOS/$APP_NAME"

# The plist in Sources is the source of truth for the local-network keys. It
# is copied rather than regenerated so the bundle and the tests that assert
# against that file can never disagree.
cp "$REPO_ROOT/Sources/CodexMicroBridge/Info.plist" "$APP/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Add :CFBundleExecutable string $APP_NAME" \
  "$APP/Contents/Info.plist" >/dev/null
/usr/libexec/PlistBuddy -c "Add :CFBundleVersion string 1" \
  "$APP/Contents/Info.plist" >/dev/null
/usr/libexec/PlistBuddy -c "Add :CFBundleShortVersionString string 0.1" \
  "$APP/Contents/Info.plist" >/dev/null

# NOTE: this script produces an UNENTITLED bundle, which cannot use the Data
# Protection Keychain the identity store requires (ADR §6). It reports
# identity.entitlementMissing and LAN stays unavailable.
#
# The entitlement cannot be added here. macOS refuses to spawn a bundle
# carrying keychain-access-groups or application-identifier without a matching
# provisioning profile — codesign attaches it happily and the kernel then
# rejects the process at exec with "Launchd job spawn failed". A profile needs
# an Xcode target, which is what MacHost/CodexMicroBridge.xcodeproj is for.
#
# Use MacHost for anything that must reach the Keychain:
#   xcodebuild -project MacHost/CodexMicroBridge.xcodeproj \
#     -scheme CodexMicroBridge -destination "platform=macOS" \
#     -allowProvisioningUpdates build
#
# This script remains useful for a quick unsigned-path smoke run.
echo "==> Signing"
# Prefer a real development identity so the local-network grant sticks across
# rebuilds. Fall back to ad-hoc so the script still produces a runnable bundle
# on a machine with no signing identity — and say which one was used, because
# the difference changes how macOS treats the permission.
IDENTITY="$(security find-identity -v -p codesigning \
  | awk -v team="$TEAM_ID" '/Apple Development/ {print $2; exit}')"
if [ -n "$IDENTITY" ]; then
  codesign --force --sign "$IDENTITY" --timestamp=none \
    --options runtime --identifier "com.codexmicro.bridge" "$APP"
  echo "    signed with development identity $IDENTITY"
else
  codesign --force --sign - --identifier "com.codexmicro.bridge" "$APP"
  echo "    signed ad-hoc (no development identity found)"
  echo "    NOTE: macOS will re-prompt for local network access on every rebuild."
fi

echo "==> Verifying"
codesign --verify --strict "$APP"

/usr/libexec/PlistBuddy -c "Print :NSBonjourServices" "$APP/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Print :LSUIElement" "$APP/Contents/Info.plist"

echo
echo "Built $APP"
echo "Launch with:  open \"$APP\""
