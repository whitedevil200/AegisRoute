#!/usr/bin/env bash
set -Eeuo pipefail

PREFIX="${PREFIX:-/usr/local}"
DESTDIR="${DESTDIR:-}"
INSTALL_DIR="${DESTDIR}${PREFIX}/lib/aegisroute"
BIN_LINK="${DESTDIR}${PREFIX}/bin/aegisroute"
AGENT_LINK="${DESTDIR}${PREFIX}/bin/aegisroute-agent"
MAN_PAGE="${DESTDIR}${PREFIX}/share/man/man1/aegisroute.1"
AGENT_MAN_PAGE="${DESTDIR}${PREFIX}/share/man/man1/aegisroute-agent.1"
SUDO=()
if [[ ! -w "${DESTDIR}${PREFIX}" ]]; then SUDO=(sudo); fi

[[ -L "$BIN_LINK" ]] && "${SUDO[@]}" rm -- "$BIN_LINK"
[[ -L "$AGENT_LINK" ]] && "${SUDO[@]}" rm -- "$AGENT_LINK"
[[ -f "$MAN_PAGE" ]] && "${SUDO[@]}" rm -- "$MAN_PAGE"
[[ -f "$AGENT_MAN_PAGE" ]] && "${SUDO[@]}" rm -- "$AGENT_MAN_PAGE"
if [[ -d "$INSTALL_DIR" ]]; then
  "${SUDO[@]}" rm -- "$INSTALL_DIR/aegisroute" "$INSTALL_DIR/aegisroute-agent" "$INSTALL_DIR/aegisroute.py" "$INSTALL_DIR/aegisroute_advanced.py" "$INSTALL_DIR/aegisroute_scamper.py" "$INSTALL_DIR/aegisroute_pro.py" "$INSTALL_DIR/aegisroute_agent.py"
  "${SUDO[@]}" rmdir -- "$INSTALL_DIR"
fi
printf 'AegisRoute removed. The system traceroute package was left installed.\n'
