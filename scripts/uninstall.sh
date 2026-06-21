#!/usr/bin/env bash
# =============================================================================
# SentinelPi Uninstaller
# =============================================================================
# Reverses scripts/install.sh: stops and removes the systemd service, the
# install tree, and the system user. Configuration, the database, and logs are
# KEPT by default (so an upgrade/reinstall preserves learned baselines); pass
# --purge to remove them too.
#
# Usage:
#   sudo bash scripts/uninstall.sh           # keep /etc, /var/lib, /var/log
#   sudo bash scripts/uninstall.sh --purge   # also delete config, data, logs

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "This script must be run as root (use sudo)."

PURGE=0
[[ "${1:-}" == "--purge" ]] && PURGE=1

SENTINELPI_USER="sentinelpi"
INSTALL_DIR="/opt/sentinelpi"
CONFIG_DIR="/etc/sentinelpi"
DATA_DIR="/var/lib/sentinelpi"
LOG_DIR="/var/log/sentinelpi"
SERVICE="/etc/systemd/system/sentinelpi.service"

info "Stopping and disabling the service..."
systemctl stop sentinelpi 2>/dev/null || true
systemctl disable sentinelpi 2>/dev/null || true

if [[ -f "$SERVICE" ]]; then
    info "Removing systemd unit..."
    rm -f "$SERVICE"
    systemctl daemon-reload
fi

info "Removing install tree at $INSTALL_DIR..."
rm -rf "$INSTALL_DIR"

if [[ $PURGE -eq 1 ]]; then
    warn "Purging config, data, and logs..."
    rm -rf "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
else
    info "Keeping config, data, and logs:"
    info "  $CONFIG_DIR  $DATA_DIR  $LOG_DIR"
    info "  (re-run with --purge to remove them)"
fi

if id "$SENTINELPI_USER" &>/dev/null; then
    info "Removing system user '$SENTINELPI_USER'..."
    userdel "$SENTINELPI_USER" 2>/dev/null || warn "Could not remove user '$SENTINELPI_USER'."
fi

info "SentinelPi uninstalled."
