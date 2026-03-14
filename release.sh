#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-v2.0.0}"
DIST="dist/${VERSION}"

echo "Building ARGUS ${VERSION}"

rm -rf "${DIST}"
mkdir -p "${DIST}"

LDFLAGS="-s -w -X main.version=${VERSION}"

build () {
  local GOOS=$1
  local GOARCH=$2
  local OUT=$3

  echo "-> ${OUT}"

  CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} \
  go build \
    -trimpath \
    -ldflags "${LDFLAGS}" \
    -o "${DIST}/${OUT}" \
    ./cmd/argus
}

build linux amd64   argus-linux-amd64
build linux arm64   argus-linux-arm64
build darwin amd64  argus-darwin-amd64
build darwin arm64  argus-darwin-arm64
build windows amd64 argus-windows-amd64.exe
build windows arm64 argus-windows-arm64.exe

echo "Packaging releases"

cd "${DIST}"

mkdir -p archives

tar -czf archives/argus-linux-amd64.tar.gz argus-linux-amd64
tar -czf archives/argus-linux-arm64.tar.gz argus-linux-arm64
tar -czf archives/argus-darwin-amd64.tar.gz argus-darwin-amd64
tar -czf archives/argus-darwin-arm64.tar.gz argus-darwin-arm64

zip archives/argus-windows-amd64.zip argus-windows-amd64.exe >/dev/null
zip archives/argus-windows-arm64.zip argus-windows-arm64.exe >/dev/null

echo "Generating checksums"

cd archives

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum * > SHA256SUMS.txt
else
  shasum -a 256 * > SHA256SUMS.txt
fi

echo "Release files created in:"
echo "dist/${VERSION}/archives"
echo "Version embedded: ${VERSION}"
