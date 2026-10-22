#!/usr/bin/env bash
# Install TShark for the current user without root.
#
# Downloads the distribution's tshark package, extracts it into ~/.local/bin and
# verifies that it runs against the already-installed Wireshark libraries.
# Re-run the script after a Wireshark library upgrade.
set -euo pipefail

PREFIX="${HOME}/.local"
BIN_DIR="${PREFIX}/bin"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

if command -v tshark >/dev/null 2>&1; then
  echo "tshark already available: $(command -v tshark)"
  tshark --version | head -1
  exit 0
fi

echo "==> apt-get download tshark (no root required)"
cd "${TMP_DIR}"
apt-get download tshark

DEB="$(ls -1 ./*.deb | head -1)"
echo "==> extracting ${DEB}"
dpkg-deb -x "${DEB}" "${TMP_DIR}/root"

mkdir -p "${BIN_DIR}"
install -m 0755 "${TMP_DIR}/root/usr/bin/tshark" "${BIN_DIR}/tshark"

echo "==> verifying"
"${BIN_DIR}/tshark" --version | head -1
echo "Installed ${BIN_DIR}/tshark"
echo "Make sure ${BIN_DIR} is on your PATH (it is on most systems by default)."
