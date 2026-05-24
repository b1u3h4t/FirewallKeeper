#!/bin/sh
set -e

INSTALL_DIR="${INSTALL_DIR:-/opt/FirewallKeeper}"
SERVICE_NAME=firewallkeeper

if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 root 运行: sudo $0" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

mkdir -p "$INSTALL_DIR"
cp "$PROJECT_DIR/FirewallKeeper" "$INSTALL_DIR/"
cp "$PROJECT_DIR/config.yaml" "$INSTALL_DIR/config.yaml"

if ! grep -q 'state_file: "/data/state.json"' "$INSTALL_DIR/config.yaml" 2>/dev/null; then
  if grep -q 'state_file:' "$INSTALL_DIR/config.yaml"; then
    sed -i 's|state_file:.*|state_file: "/var/lib/firewallkeeper/state.json"|' "$INSTALL_DIR/config.yaml"
  fi
fi
mkdir -p /var/lib/firewallkeeper

cp "$SCRIPT_DIR/systemd/firewallkeeper.service" "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"
systemctl status "${SERVICE_NAME}" --no-pager

echo "FirewallKeeper 已安装到 $INSTALL_DIR"
