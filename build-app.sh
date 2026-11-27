#!/bin/bash
# Builds "XCSSET Guard.app" into ./build using only the Swift compiler
# (no Xcode project, so there's nothing for XCSSET to infect).
set -euo pipefail
cd "$(dirname "$0")"

NAME="XCSSET Guard"
APP="build/$NAME.app"
ARCH="$(uname -m)"

rm -rf "$APP" build/AppIcon.iconset
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

echo "Compiling…"
swiftc -O -swift-version 5 -parse-as-library \
  -target "$ARCH-apple-macos14.0" \
  -o "$APP/Contents/MacOS/XCSSETGuard" app/XCSSETGuard.swift

echo "Making icon…"
swiftc -O -target "$ARCH-apple-macos14.0" -o build/make-icon app/make-icon.swift
build/make-icon build/AppIcon.iconset
iconutil -c icns build/AppIcon.iconset -o "$APP/Contents/Resources/AppIcon.icns"
rm -rf build/AppIcon.iconset build/make-icon

cp xcsset-guard.sh "$APP/Contents/Resources/xcsset-guard.sh"

cat > "$APP/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>XCSSET Guard</string>
  <key>CFBundleDisplayName</key><string>XCSSET Guard</string>
  <key>CFBundleIdentifier</key><string>local.xcsset-guard</string>
  <key>CFBundleExecutable</key><string>XCSSETGuard</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSAppleEventsUsageDescription</key><string>Used to ask for your password when fixing items.</string>
</dict>
</plist>
EOF

codesign --force --sign - "$APP"
echo "Built: $PWD/$APP"
echo "Open it with:  open \"$PWD/$APP\"   (or drag it into /Applications)"
