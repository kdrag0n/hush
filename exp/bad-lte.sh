#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"

# Default profile: SSH from Japan to the US over bad LTE.
# This is intentionally asymmetric and much harsher than a local "weak LTE" hop:
# - transpacific base delay
# - cellular scheduling jitter
# - constrained uplink
# - light random loss with occasional reordering
IFACE="${IFACE:-}"
IFB_DEV="${IFB_DEV:-ifb0}"
PROFILE="${PROFILE:-jp-us-bad-lte-ssh}"
QUEUE_LIMIT="${QUEUE_LIMIT:-2000}"

set_defaults() {
  case "${PROFILE}" in
    jp-us-bad-lte-ssh)
      : "${EGRESS_RATE:=1.8mbit}"
      : "${INGRESS_RATE:=7.5mbit}"
      : "${EGRESS_DELAY:=120ms}"
      : "${EGRESS_JITTER:=45ms}"
      : "${INGRESS_DELAY:=95ms}"
      : "${INGRESS_JITTER:=35ms}"
      : "${EGRESS_LOSS:=1.8%}"
      : "${INGRESS_LOSS:=1.2%}"
      : "${EGRESS_DUPLICATE:=0.03%}"
      : "${INGRESS_DUPLICATE:=0.02%}"
      : "${EGRESS_REORDER:=0.15%}"
      : "${INGRESS_REORDER:=0.08%}"
      ;;
    *)
      die "unknown PROFILE: ${PROFILE}"
      ;;
  esac
}

usage() {
  cat <<EOF
Usage:
  sudo ./${SCRIPT_NAME} apply [iface]
  sudo ./${SCRIPT_NAME} reset [iface]
  sudo ./${SCRIPT_NAME} status [iface]

Commands:
  apply   Configure egress netem on the live interface and ingress shaping via ${IFB_DEV}.
  reset   Remove qdiscs/filtering added by this script.
  status  Show qdisc and ingress redirect state.

Arguments:
  iface   Optional network interface. If omitted, the default route interface is used.

Environment overrides:
  PROFILE=${PROFILE}
  IFB_DEV=${IFB_DEV}
  EGRESS_RATE=${EGRESS_RATE}
  INGRESS_RATE=${INGRESS_RATE}
  EGRESS_DELAY=${EGRESS_DELAY}
  EGRESS_JITTER=${EGRESS_JITTER}
  INGRESS_DELAY=${INGRESS_DELAY}
  INGRESS_JITTER=${INGRESS_JITTER}
  EGRESS_LOSS=${EGRESS_LOSS}
  INGRESS_LOSS=${INGRESS_LOSS}
  EGRESS_DUPLICATE=${EGRESS_DUPLICATE}
  INGRESS_DUPLICATE=${INGRESS_DUPLICATE}
  EGRESS_REORDER=${EGRESS_REORDER}
  INGRESS_REORDER=${INGRESS_REORDER}
  QUEUE_LIMIT=${QUEUE_LIMIT}

Examples:
  sudo ./${SCRIPT_NAME} apply
  sudo IFACE=wlan0 ./${SCRIPT_NAME} apply
  sudo PROFILE=jp-us-bad-lte-ssh EGRESS_RATE=1.2mbit ./${SCRIPT_NAME} apply
  sudo ./${SCRIPT_NAME} reset
EOF
}

log() {
  printf '[%s] %s\n' "$SCRIPT_NAME" "$*"
}

die() {
  printf '[%s] %s\n' "$SCRIPT_NAME" "$*" >&2
  exit 1
}

require_linux() {
  [[ "$(uname -s)" == "Linux" ]] || die "this script only supports Linux"
}

require_root() {
  [[ "${EUID}" -eq 0 ]] || die "run as root (sudo)"
}

require_tools() {
  command -v tc >/dev/null 2>&1 || die "missing required tool: tc"
  command -v ip >/dev/null 2>&1 || die "missing required tool: ip"
  command -v modprobe >/dev/null 2>&1 || die "missing required tool: modprobe"
}

detect_iface() {
  local detected

  if [[ -n "${IFACE}" ]]; then
    printf '%s\n' "${IFACE}"
    return 0
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
  modprobe ifb numifbs=1
  if ! ip link show dev "${IFB_DEV}" >/dev/null 2>&1; then
    ip link add "${IFB_DEV}" type ifb
  fi
  ip link set dev "${IFB_DEV}" up
}

clear_qdisc() {
  local dev="$1"
  local kind="$2"

  tc qdisc del dev "${dev}" "${kind}" >/dev/null 2>&1 || true
}

clear_ingress_filter() {
  local dev="$1"
  tc filter del dev "${dev}" parent ffff: >/dev/null 2>&1 || true
}

add_shaped_root() {
  local dev="$1"
  local rate="$2"
  local delay="$3"
  local jitter="$4"
  local loss="$5"
  local duplicate="$6"
  local reorder="$7"

  tc qdisc add dev "${dev}" root handle 1: htb default 10
  tc class add dev "${dev}" parent 1: classid 1:10 htb rate "${rate}" ceil "${rate}"
  tc qdisc add dev "${dev}" parent 1:10 handle 10: netem \
    limit "${QUEUE_LIMIT}" \
    delay "${delay}" "${jitter}" distribution normal \
    loss random "${loss}" \
    duplicate "${duplicate}" \
    reorder "${reorder}" 25%
}

apply_bad_lte() {
  local dev="$1"

  log "resetting any existing shaping on ${dev} / ${IFB_DEV}"
  reset_bad_lte "${dev}" >/dev/null

  log "creating and enabling ${IFB_DEV}"
  ensure_ifb

  log "configuring egress on ${dev}: ${EGRESS_RATE}, ${EGRESS_DELAY} +/- ${EGRESS_JITTER}, loss ${EGRESS_LOSS}"
  add_shaped_root "${dev}" "${EGRESS_RATE}" "${EGRESS_DELAY}" "${EGRESS_JITTER}" "${EGRESS_LOSS}" "${EGRESS_DUPLICATE}" "${EGRESS_REORDER}"

  log "redirecting ingress from ${dev} into ${IFB_DEV}"
  tc qdisc add dev "${dev}" handle ffff: ingress
  tc filter add dev "${dev}" parent ffff: protocol all u32 match u32 0 0 \
    action mirred egress redirect dev "${IFB_DEV}"

  log "configuring ingress on ${IFB_DEV}: ${INGRESS_RATE}, ${INGRESS_DELAY} +/- ${INGRESS_JITTER}, loss ${INGRESS_LOSS}"
  add_shaped_root "${IFB_DEV}" "${INGRESS_RATE}" "${INGRESS_DELAY}" "${INGRESS_JITTER}" "${INGRESS_LOSS}" "${INGRESS_DUPLICATE}" "${INGRESS_REORDER}"
}

reset_bad_lte() {
  local dev="$1"

  clear_ingress_filter "${dev}"
  clear_qdisc "${dev}" ingress
  clear_qdisc "${dev}" root
  clear_qdisc "${IFB_DEV}" root

  if ip link show dev "${IFB_DEV}" >/dev/null 2>&1; then
    ip link set dev "${IFB_DEV}" down >/dev/null 2>&1 || true
  fi
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
  require_tools
  require_root
  set_defaults

  if [[ -n "${2:-}" ]]; then
    IFACE="${2}"
  fi
  dev="$(detect_iface)"
  ensure_iface_exists "${dev}"

  case "${cmd}" in
    apply)
      apply_bad_lte "${dev}"
      show_status "${dev}"
      ;;
    reset)
      reset_bad_lte "${dev}"
      show_status "${dev}"
      ;;
    status)
      show_status "${dev}"
      ;;
  esac
}

main "$@"
