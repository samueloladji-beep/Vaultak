#!/bin/bash
set -e
echo "Building Vaultak Sentry for Mac..."

APP_NAME="Vaultak Sentry"
VERSION="1.0.0"

/opt/homebrew/bin/python3.11 -m PyInstaller \
  --name "$APP_NAME" \
  --windowed \
  --onedir \
  --noconfirm \
  --icon "assets/icon.icns" \
  --add-data "assets:assets" \
  --hidden-import "tkinter" \
  --hidden-import "requests" \
  --osx-bundle-identifier "com.vaultak.sentry" \
  vaultak_sentry_app.py

echo "App built at: dist/Vaultak Sentry.app"

mkdir -p pkg_root/Applications
cp -r "dist/Vaultak Sentry.app" "pkg_root/Applications/"

pkgbuild \
  --root pkg_root \
  --identifier com.vaultak.sentry \
  --version $VERSION \
  --install-location / \
  "dist/VaultakSentry-$VERSION.pkg"

echo "Installer built at: dist/VaultakSentry-$VERSION.pkg"
rm -rf pkg_root
