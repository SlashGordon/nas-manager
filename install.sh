#!/bin/bash
set -e

# NAS Manager installer script
# Usage: ./install.sh [version]
# Example: ./install.sh v1.0.0
# If no version is specified, the latest release will be installed
REPO="SlashGordon/nas-manager"
BINARY_NAME="nas-manager"
VERSION="${1:-latest}"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case $ARCH in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

case $OS in
    linux|darwin) ;;
    *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

# Get release URL
if [ "$VERSION" = "latest" ]; then
    echo "Fetching latest release..."
    RELEASE_URL="https://api.github.com/repos/$REPO/releases/latest"
else
    echo "Fetching release $VERSION..."
    RELEASE_URL="https://api.github.com/repos/$REPO/releases/tags/$VERSION"
fi

DOWNLOAD_URL=$(curl -s $RELEASE_URL | grep "browser_download_url.*$BINARY_NAME-$OS-$ARCH" | cut -d '"' -f 4)

if [ -z "$DOWNLOAD_URL" ]; then
    echo "Could not find binary for $OS-$ARCH"
    exit 1
fi

# Download and install
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
TMP_FILE="/tmp/$BINARY_NAME"

echo "Downloading $BINARY_NAME for $OS-$ARCH..."
curl -L "$DOWNLOAD_URL" -o "$TMP_FILE"
chmod +x "$TMP_FILE"

echo "Installing to $INSTALL_DIR..."
sudo mv "$TMP_FILE" "$INSTALL_DIR/$BINARY_NAME"

echo "✅ $BINARY_NAME installed successfully!"
echo "Run '$BINARY_NAME --help' to get started."