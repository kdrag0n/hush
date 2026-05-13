#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"

IFACE="${IFACE:-}"
IFB_DEV="${IFB_DEV:-ifb0}"
RATE="1gbit"
DELAY="50ms"
LIMIT="20000"

usage() {
  cat <<EOF
Usage:
  sudo ./${SCRIPT_NAME} apply [iface]
  sudo ./${SCRIPT_NAME} reset [iface]
  sudo ./${SCRIPT_NAME} status [iface]

Sets a symmetric ${RATE} + ${DELAY} netem qdisc on egress and ingress via ${IFB_DEV}.

Environment overrides:
  IFACE=${IFACE}
  IFB_DEV=${IFB_DEV}

Examples:
  sudo ./${SCRIPT_NAME} apply eth0
  sudo ./${SCRIPT_NAME} reset eth0
EOF
}

log() {
  printf '[%s] %s\n' "${SCRIPT_NAME}" "$*"
}

die() {
  printf '[%s] %s\n' "${SCRIPT_NAME}" "$*" >&2
  exit 1
}

require_linux() {
  [[ "$(uname -s)" == "Linux" ]] || die "this script only supports Linux"
}

require_root() {
  [[ "${EUID}" -eq 0 ]] || die "run as root (sudo)"
}

require_tools() {
  command -v ip >/dev/null 2>&1 || die "missing required tool: ip"
  command -v tc >/dev/null 2>&1 || die "missing required tool: tc"
  command -v modprobe >/dev/null 2>&1 || die "missing required tool: modprobe"
}

detect_iface() {
  local detected

  if [[ -n "${IFACE}" ]]; then
    printf '%s\n' "${IFACE}"
    return
  fi

  detected="$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}')"
  if [[ -z "${detected}" ]]; then
    detected="$(ip route show default 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}')"
  fi

  [[ -n "${detected}" ]] || die "could not determine default route interface; pass it explicitly"
  printf '%s\n' "${detected}"
}

ensure_iface_exists() {
  local dev="$1"
  ip link show dev "${dev}" >/dev/null 2>&1 || die "interface ${dev} does not exist"
}

ensure_ifb() {
  modprobe ifb || true
  if ! ip link show dev "${IFB_DEV}" >/dev/null 2>&1; then
    ip link add "${IFB_DEV}" type ifb
  fi
  ip link set dev "${IFB_DEV}" up
}

add_netem_root() {
  local dev="$1"
  tc qdisc add dev "${dev}" root netem rate "${RATE}" delay "${DELAY}" limit "${LIMIT}"
}

reset_qdiscs() {
  local dev="$1"

  tc filter del dev "${dev}" parent ffff: >/dev/null 2>&1 || true
  tc qdisc del dev "${dev}" ingress >/dev/null 2>&1 || true
  tc qdisc del dev "${dev}" root >/dev/null 2>&1 || true
  tc qdisc del dev "${IFB_DEV}" root >/dev/null 2>&1 || true
}

apply_1gbps() {
  local dev="$1"

  log "resetting existing qdiscs on ${dev} / ${IFB_DEV}"
  reset_qdiscs "${dev}"

  log "creating and enabling ${IFB_DEV}"
  ensure_ifb

  log "configuring egress on ${dev}: ${RATE} + ${DELAY}"
  add_netem_root "${dev}"

  log "redirecting ingress from ${dev} into ${IFB_DEV}"
  tc qdisc add dev "${dev}" handle ffff: ingress
  tc filter add dev "${dev}" parent ffff: protocol all u32 match u32 0 0 \
    action mirred egress redirect dev "${IFB_DEV}"

  log "configuring ingress on ${IFB_DEV}: ${RATE} + ${DELAY}"
  add_netem_root "${IFB_DEV}"
}

show_status() {
  local dev="$1"

  log "qdiscs on ${dev}"
  tc -s qdisc show dev "${dev}" || true
  log "ingress filters on ${dev}"
  tc filter show dev "${dev}" parent ffff: || true

  if ip link show dev "${IFB_DEV}" >/dev/null 2>&1; then
    log "qdiscs on ${IFB_DEV}"
    tc -s qdisc show dev "${IFB_DEV}" || true
  else
    log "${IFB_DEV} does not exist"
  fi
}

main() {
  local cmd="${1:-}"
  local dev

  case "${cmd}" in
    apply|reset|status) ;;
    -h|--help|"")
      usage
      exit 0
      ;;
    *)
      die "unknown command: ${cmd}"
      ;;
  esac

  require_linux
  require_root
  require_tools

  if [[ -n "${2:-}" ]]; then
    IFACE="${2}"
  fi
  dev="$(detect_iface)"
  ensure_iface_exists "${dev}"

  case "${cmd}" in
    apply)
      apply_1gbps "${dev}"
      show_status "${dev}"
      ;;
    reset)
      reset_qdiscs "${dev}"
      show_status "${dev}"
      ;;
    status)
      show_status "${dev}"
      ;;
  esac
}

main "$@"
