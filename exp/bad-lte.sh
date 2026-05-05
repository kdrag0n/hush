#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"

# Default profile: SSH from Japan to the US over bad LTE.
# This is intentionally asymmetric and much harsher than a local "weak LTE" hop:
# - transpacific base delay
# - cellular scheduling jitter
# - constrained uplink
# - bursty radio loss with occasional reordering
IFACE="${IFACE:-}"
IFB_DEV="${IFB_DEV:-ifb0}"
PROFILE="${PROFILE:-jp-us-bad-lte-ssh}"
QUEUE_LIMIT="${QUEUE_LIMIT:-2000}"
DELAY_DISTRIBUTION="${DELAY_DISTRIBUTION:-paretonormal}"
NETEM_SLOT="${NETEM_SLOT:-auto}"

set_defaults() {
  case "${PROFILE}" in
    jp-us-bad-lte-ssh)
      : "${EGRESS_RATE:=1.8mbit}"
      : "${INGRESS_RATE:=7.5mbit}"
      : "${EGRESS_DELAY:=120ms}"
      : "${EGRESS_JITTER:=45ms}"
      : "${EGRESS_DELAY_CORRELATION:=35%}"
      : "${INGRESS_DELAY:=95ms}"
      : "${INGRESS_JITTER:=35ms}"
      : "${INGRESS_DELAY_CORRELATION:=30%}"
      : "${EGRESS_LOSS:=1.8%}"
      : "${INGRESS_LOSS:=1.2%}"
      : "${EGRESS_LOSS_CORRELATION:=25%}"
      : "${INGRESS_LOSS_CORRELATION:=20%}"
      : "${EGRESS_LOSS_MODEL:=gemodel}"
      : "${INGRESS_LOSS_MODEL:=gemodel}"
      : "${EGRESS_LOSS_GEMODEL:=0.45% 22% 94% 0.03%}"
      : "${INGRESS_LOSS_GEMODEL:=0.30% 18% 95% 0.02%}"
      : "${EGRESS_DUPLICATE:=0.03%}"
      : "${INGRESS_DUPLICATE:=0.02%}"
      : "${EGRESS_REORDER:=0.15%}"
      : "${INGRESS_REORDER:=0.08%}"
      : "${EGRESS_REORDER_CORRELATION:=35%}"
      : "${INGRESS_REORDER_CORRELATION:=30%}"
      : "${EGRESS_SLOT_MIN:=4ms}"
      : "${EGRESS_SLOT_MAX:=18ms}"
      : "${INGRESS_SLOT_MIN:=3ms}"
      : "${INGRESS_SLOT_MAX:=14ms}"
      ;;
    *)
      die "unknown PROFILE: ${PROFILE}"
      ;;
  esac
}

usage() {
  set_defaults
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
  EGRESS_DELAY_CORRELATION=${EGRESS_DELAY_CORRELATION}
  INGRESS_DELAY=${INGRESS_DELAY}
  INGRESS_JITTER=${INGRESS_JITTER}
  INGRESS_DELAY_CORRELATION=${INGRESS_DELAY_CORRELATION}
  DELAY_DISTRIBUTION=${DELAY_DISTRIBUTION}
  EGRESS_LOSS=${EGRESS_LOSS}
  INGRESS_LOSS=${INGRESS_LOSS}
  EGRESS_LOSS_CORRELATION=${EGRESS_LOSS_CORRELATION}
  INGRESS_LOSS_CORRELATION=${INGRESS_LOSS_CORRELATION}
  EGRESS_LOSS_MODEL=${EGRESS_LOSS_MODEL}
  INGRESS_LOSS_MODEL=${INGRESS_LOSS_MODEL}
  EGRESS_LOSS_GEMODEL=${EGRESS_LOSS_GEMODEL}
  INGRESS_LOSS_GEMODEL=${INGRESS_LOSS_GEMODEL}
  EGRESS_DUPLICATE=${EGRESS_DUPLICATE}
  INGRESS_DUPLICATE=${INGRESS_DUPLICATE}
  EGRESS_REORDER=${EGRESS_REORDER}
  INGRESS_REORDER=${INGRESS_REORDER}
  EGRESS_REORDER_CORRELATION=${EGRESS_REORDER_CORRELATION}
  INGRESS_REORDER_CORRELATION=${INGRESS_REORDER_CORRELATION}
  NETEM_SLOT=${NETEM_SLOT}   # auto, on, or off
  EGRESS_SLOT_MIN=${EGRESS_SLOT_MIN}
  EGRESS_SLOT_MAX=${EGRESS_SLOT_MAX}
  INGRESS_SLOT_MIN=${INGRESS_SLOT_MIN}
  INGRESS_SLOT_MAX=${INGRESS_SLOT_MAX}
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
  local delay_correlation="$5"
  local loss="$6"
  local loss_correlation="$7"
  local loss_model="$8"
  local loss_gemodel="$9"
  local duplicate="${10}"
  local reorder="${11}"
  local reorder_correlation="${12}"
  local slot_min="${13}"
  local slot_max="${14}"

  tc qdisc add dev "${dev}" root handle 1: htb default 10
  tc class add dev "${dev}" parent 1: classid 1:10 htb rate "${rate}" ceil "${rate}"
  add_netem_qdisc \
    "${dev}" \
    "${delay}" \
    "${jitter}" \
    "${delay_correlation}" \
    "${loss}" \
    "${loss_correlation}" \
    "${loss_model}" \
    "${loss_gemodel}" \
    "${duplicate}" \
    "${reorder}" \
    "${reorder_correlation}" \
    "${slot_min}" \
    "${slot_max}"
}

add_netem_qdisc() {
  local dev="$1"
  local delay="$2"
  local jitter="$3"
  local delay_correlation="$4"
  local loss="$5"
  local loss_correlation="$6"
  local loss_model="$7"
  local loss_gemodel="$8"
  local duplicate="$9"
  local reorder="${10}"
  local reorder_correlation="${11}"
  local slot_min="${12}"
  local slot_max="${13}"
  local -a args
  local -a gemodel_parts

  args=(
    qdisc add dev "${dev}" parent 1:10 handle 10: netem
    limit "${QUEUE_LIMIT}"
    delay "${delay}" "${jitter}" "${delay_correlation}" distribution "${DELAY_DISTRIBUTION}"
  )

  case "${loss_model}" in
    gemodel)
      read -r -a gemodel_parts <<<"${loss_gemodel}"
      [[ "${#gemodel_parts[@]}" -eq 4 ]] || die "loss gemodel needs four values: ${loss_gemodel}"
      args+=(loss gemodel "${gemodel_parts[@]}")
      ;;
    random)
      args+=(loss random "${loss}" "${loss_correlation}")
      ;;
    none)
      ;;
    *)
      die "unknown netem loss model: ${loss_model}"
      ;;
  esac

  args+=(duplicate "${duplicate}" reorder "${reorder}" "${reorder_correlation}")

  case "${NETEM_SLOT}" in
    auto|on)
      if tc "${args[@]}" slot "${slot_min}" "${slot_max}"; then
        return
      fi
      [[ "${NETEM_SLOT}" == "auto" ]] || die "netem slot rejected by tc"
      log "netem slot unsupported on ${dev}; retrying without slot"
      tc qdisc del dev "${dev}" parent 1:10 handle 10: >/dev/null 2>&1 || true
      ;;
    off)
      ;;
    *)
      die "NETEM_SLOT must be auto, on, or off"
      ;;
  esac

  tc "${args[@]}"
}

apply_bad_lte() {
  local dev="$1"

  log "resetting any existing shaping on ${dev} / ${IFB_DEV}"
  reset_bad_lte "${dev}" >/dev/null

  log "creating and enabling ${IFB_DEV}"
  ensure_ifb

  log "configuring egress on ${dev}: ${EGRESS_RATE}, ${EGRESS_DELAY} +/- ${EGRESS_JITTER}, loss ${EGRESS_LOSS_MODEL}"
  add_shaped_root \
    "${dev}" \
    "${EGRESS_RATE}" \
    "${EGRESS_DELAY}" \
    "${EGRESS_JITTER}" \
    "${EGRESS_DELAY_CORRELATION}" \
    "${EGRESS_LOSS}" \
    "${EGRESS_LOSS_CORRELATION}" \
    "${EGRESS_LOSS_MODEL}" \
    "${EGRESS_LOSS_GEMODEL}" \
    "${EGRESS_DUPLICATE}" \
    "${EGRESS_REORDER}" \
    "${EGRESS_REORDER_CORRELATION}" \
    "${EGRESS_SLOT_MIN}" \
    "${EGRESS_SLOT_MAX}"

  log "redirecting ingress from ${dev} into ${IFB_DEV}"
  tc qdisc add dev "${dev}" handle ffff: ingress
  tc filter add dev "${dev}" parent ffff: protocol all u32 match u32 0 0 \
    action mirred egress redirect dev "${IFB_DEV}"

  log "configuring ingress on ${IFB_DEV}: ${INGRESS_RATE}, ${INGRESS_DELAY} +/- ${INGRESS_JITTER}, loss ${INGRESS_LOSS_MODEL}"
  add_shaped_root \
    "${IFB_DEV}" \
    "${INGRESS_RATE}" \
    "${INGRESS_DELAY}" \
    "${INGRESS_JITTER}" \
    "${INGRESS_DELAY_CORRELATION}" \
    "${INGRESS_LOSS}" \
    "${INGRESS_LOSS_CORRELATION}" \
    "${INGRESS_LOSS_MODEL}" \
    "${INGRESS_LOSS_GEMODEL}" \
    "${INGRESS_DUPLICATE}" \
    "${INGRESS_REORDER}" \
    "${INGRESS_REORDER_CORRELATION}" \
    "${INGRESS_SLOT_MIN}" \
    "${INGRESS_SLOT_MAX}"
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
