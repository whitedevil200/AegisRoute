#!/usr/bin/env bash
set -Eeuo pipefail

PREFIX="${PREFIX:-/usr/local}"
DESTDIR="${DESTDIR:-}"
INSTALL_DIR="${DESTDIR}${PREFIX}/lib/aegisroute"
BIN_DIR="${DESTDIR}${PREFIX}/bin"
MAN_DIR="${DESTDIR}${PREFIX}/share/man/man1"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

say() { printf '%s\n' "$*"; }
die() { printf 'aegisroute installer: %s\n' "$*" >&2; exit 1; }

install_dependency() {
  command -v traceroute >/dev/null 2>&1 && return 0
  say "Linux traceroute is missing; attempting installation..."
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update && sudo apt-get install -y traceroute
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y traceroute
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -S --needed traceroute
  elif command -v zypper >/dev/null 2>&1; then
    sudo zypper --non-interactive install traceroute
  elif command -v apk >/dev/null 2>&1; then
    sudo apk add traceroute
  else
    die "install the 'traceroute' package with your distribution package manager"
  fi
}

[[ "$(uname -s)" == "Linux" ]] || die "this release targets Linux"
command -v python3 >/dev/null 2>&1 || die "python3 (3.10+) is required"
install_dependency

SUDO=()
if [[ ! -w "${DESTDIR}${PREFIX}" ]]; then SUDO=(sudo); fi
"${SUDO[@]}" install -d -m 0755 "$INSTALL_DIR" "$BIN_DIR" "$MAN_DIR"
"${SUDO[@]}" install -m 0755 "$SCRIPT_DIR/aegisroute.py" "$INSTALL_DIR/aegisroute.py"
"${SUDO[@]}" install -m 0644 "$SCRIPT_DIR/aegisroute_advanced.py" "$INSTALL_DIR/aegisroute_advanced.py"
"${SUDO[@]}" install -m 0644 "$SCRIPT_DIR/aegisroute_scamper.py" "$INSTALL_DIR/aegisroute_scamper.py"
"${SUDO[@]}" install -m 0644 "$SCRIPT_DIR/aegisroute_pro.py" "$INSTALL_DIR/aegisroute_pro.py"
"${SUDO[@]}" install -m 0755 "$SCRIPT_DIR/aegisroute_agent.py" "$INSTALL_DIR/aegisroute_agent.py"
"${SUDO[@]}" install -m 0755 "$SCRIPT_DIR/aegisroute" "$INSTALL_DIR/aegisroute"
"${SUDO[@]}" install -m 0755 "$SCRIPT_DIR/aegisroute-agent" "$INSTALL_DIR/aegisroute-agent"
"${SUDO[@]}" install -m 0644 "$SCRIPT_DIR/aegisroute.1" "$MAN_DIR/aegisroute.1"
"${SUDO[@]}" install -m 0644 "$SCRIPT_DIR/aegisroute-agent.1" "$MAN_DIR/aegisroute-agent.1"
"${SUDO[@]}" ln -sfn "$INSTALL_DIR/aegisroute" "$BIN_DIR/aegisroute"
"${SUDO[@]}" ln -sfn "$INSTALL_DIR/aegisroute-agent" "$BIN_DIR/aegisroute-agent"

say "Installed AegisRoute to $INSTALL_DIR"
say "Run: aegisroute example.com"
say "Manual: man aegisroute"
say "Agent manual: man aegisroute-agent"
say "TCP/ICMP probes may require sudo or capabilities on some Linux distributions."
