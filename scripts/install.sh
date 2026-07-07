#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "Usage: $0 [--version VERSION]"
    echo ""
    echo "Install pathprofiler from a GitHub release."
    echo ""
    echo "  --version VERSION    Specific version to install (e.g. v1.0.0)."
    echo "                       If omitted, installs the latest release."
    exit 1
}

# Configuration
REPO="ehealth-co-id/pathprofiler"
SERVICE_NAME="pathprofiler"
INSTALL_DIR="/opt/pathprofiler"
BIN_NAME="pathprofiler-daemon"
CONFIG_FILE="/etc/pathprofiler.yaml"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
APPARMOR_FILE="/etc/apparmor.d/opt.pathprofiler.pathprofiler-daemon"
RELEASE_BASE="https://github.com/${REPO}/releases/download"

VERSION=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)
            VERSION="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

if [[ -n "$VERSION" ]]; then
    # Normalise: accept "1.0.0" or "v1.0.0"
    VERSION="${VERSION#v}"
    VERSION="v${VERSION}"
    echo "[*] Installing ${SERVICE_NAME} ${VERSION}..."
else
    echo "[*] Installing ${SERVICE_NAME} from latest release..."
fi

# 1. Pre-flight checks
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root"
    exit 1
fi

for cmd in curl sha256sum systemctl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: Required command not found: $cmd"
        exit 1
    fi
done

case "$(uname -m)" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    *)
        echo "ERROR: Unsupported architecture: $(uname -m)"
        echo "Supported: x86_64, aarch64"
        exit 1
        ;;
esac

# Stop existing service if running
systemctl stop "${SERVICE_NAME}" 2>/dev/null || true

# 2. Fetch release
if [[ -n "$VERSION" ]]; then
    echo "[*] Fetching release information for ${VERSION}..."
    RELEASE_JSON=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/tags/${VERSION}")
else
    echo "[*] Fetching latest release information..."
    RELEASE_JSON=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest")
fi

TAG=$(echo "$RELEASE_JSON" | grep -o '"tag_name": *"[^"]*"' | cut -d'"' -f4)
BASE_URL="${RELEASE_BASE}/${TAG}"

BINARY_URL="${BASE_URL}/pathprofiler-daemon-linux-${ARCH}"
CHECKSUM_URL="${BASE_URL}/SHA256SUMS"
SERVICE_URL="${BASE_URL}/pathprofiler.service"
APPARMOR_URL="${BASE_URL}/pathprofiler.apparmor"
CONFIG_URL="${BASE_URL}/pathprofiler.yaml.example"

RELEASE_BIN="pathprofiler-daemon-linux-${ARCH}"

echo "[*] Downloading release assets..."
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"
curl -fsSL -o "${RELEASE_BIN}" "$BINARY_URL"
curl -fsSL -o SHA256SUMS "$CHECKSUM_URL"
curl -fsSL -o pathprofiler.service "$SERVICE_URL"
curl -fsSL -o pathprofiler.apparmor "$APPARMOR_URL"
curl -fsSL -o pathprofiler.yaml.example "$CONFIG_URL"

# 3. Verify checksum (--ignore-missing skips entries for other arch not downloaded)
echo "[*] Verifying checksum..."
if ! sha256sum -c SHA256SUMS --ignore-missing 2>/dev/null; then
    echo "ERROR: Checksum verification failed"
    exit 1
fi
echo "[+] Checksum OK"

# 4. Install binary (rename from release name to install name)
echo "[*] Installing binary to ${INSTALL_DIR}/..."
mkdir -p "$INSTALL_DIR"
install -m 0755 "${RELEASE_BIN}" "${INSTALL_DIR}/${BIN_NAME}"

# 5. Install example config (don't overwrite existing)
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "[*] Installing example config to ${CONFIG_FILE}..."
    install -m 0644 -o root -g root "${TMP_DIR}/pathprofiler.yaml.example" "$CONFIG_FILE"
else
    echo "[*] Config ${CONFIG_FILE} already exists, leaving it intact"
fi

# 6. Install systemd unit
echo "[*] Installing systemd service unit..."
install -m 0644 "${TMP_DIR}/pathprofiler.service" "$SERVICE_FILE"

# 7. Install and reload AppArmor profile
echo "[*] Installing AppArmor profile..."
install -m 0644 "${TMP_DIR}/pathprofiler.apparmor" "$APPARMOR_FILE"
if command -v apparmor_parser >/dev/null 2>&1; then
    apparmor_parser -r "$APPARMOR_FILE" 2>/dev/null || true
fi

# 8. Enable and start
echo "[*] Reloading systemd and enabling service..."
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"

# Cleanup
cd /
rm -rf "$TMP_DIR"

echo ""
echo "[+] Done. Service is running."
echo ""
echo "    status:  systemctl status ${SERVICE_NAME}"
echo "    logs:    journalctl -u ${SERVICE_NAME} -f"
echo ""
echo "    NOTE: The daemon loads BPF programs at startup and pins maps to"
echo "    /sys/fs/bpf/pathprofiler/. Requires CAP_BPF + CAP_NET_ADMIN"
echo "    (granted by the systemd unit via AmbientCapabilities)."
