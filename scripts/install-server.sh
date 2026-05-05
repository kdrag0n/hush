#!/bin/sh

set -eu

SERVICE_LABEL=dev.kdrag0n.hush
PLIST_PATH=/Library/LaunchDaemons/dev.kdrag0n.hush.plist
SYSTEMD_SERVICE_PATH=/etc/systemd/system/hush.service
OPENWRT_INIT_PATH=/etc/init.d/hush
INSTALL_DIR=${HUSH_INSTALL_DIR:-/usr/local/bin}
INSTALL_PATH=${HUSH_INSTALL_PATH:-"$INSTALL_DIR/hush-server"}
HUSH_REPO=${HUSH_REPO:-kdrag0n/hush}
HUSH_VERSION=${HUSH_VERSION:-latest}

if [ -t 2 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != dumb ]; then
	COLOR_BLUE=$(printf '\033[34m')
	COLOR_GREEN=$(printf '\033[32m')
	COLOR_RED=$(printf '\033[31m')
	COLOR_BOLD=$(printf '\033[1m')
	COLOR_RESET=$(printf '\033[0m')
else
	COLOR_BLUE=
	COLOR_GREEN=
	COLOR_RED=
	COLOR_BOLD=
	COLOR_RESET=
fi

log() {
	printf '%s==>%s %s\n' "$COLOR_BLUE" "$COLOR_RESET" "$*" >&2
}

success() {
	printf '%s==>%s %s%s%s\n' "$COLOR_GREEN" "$COLOR_RESET" "$COLOR_BOLD" "$*" "$COLOR_RESET" >&2
}

die() {
	printf '%serror:%s %s\n' "$COLOR_RED" "$COLOR_RESET" "$*" >&2
	exit 1
}

have() {
	command -v "$1" >/dev/null 2>&1
}

as_root() {
	if [ "$(id -u)" = 0 ]; then
		"$@"
	elif have sudo; then
		sudo "$@"
	else
		die "this step needs root; rerun as root or install sudo"
	fi
}

fetch_to() {
	url=$1
	out=$2

	if have curl; then
		curl -fsSL "$url" -o "$out"
	elif have wget; then
		wget -qO "$out" "$url"
	else
		die "curl or wget is required"
	fi
}

fetch_stdout() {
	url=$1

	if have curl; then
		curl -fsSL "$url"
	elif have wget; then
		wget -qO - "$url"
	else
		die "curl or wget is required"
	fi
}

fetch_stdout_optional() {
	url=$1

	if have curl; then
		curl -fsL "$url"
	elif have wget; then
		wget -qO - "$url"
	else
		die "curl or wget is required"
	fi
}

lower() {
	printf '%s' "$1" | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz'
}

contains_any() {
	text=$1
	words=$2

	while [ -n "$words" ]; do
		word=${words%% *}
		if [ "$word" = "$words" ]; then
			words=
		else
			words=${words#* }
		fi

		case "$text" in
			*"$word"*) return 0 ;;
		esac
	done

	return 1
}

is_ignored_asset() {
	case "$1" in
		*.sha256|*.sha256sum|*.sig|*.asc|*.pem|*.txt) return 0 ;;
	esac

	return 1
}

asset_arch_words() {
	case "$(uname -m)" in
		x86_64|amd64) printf '%s\n' "x86_64 amd64" ;;
		arm64|aarch64) printf '%s\n' "aarch64 arm64" ;;
		armv7l|armv7*) printf '%s\n' "armv7 armv7l armhf" ;;
		armv6l|armv6*) printf '%s\n' "armv6 armv6l armhf" ;;
		i386|i686) printf '%s\n' "i386 i686 x86" ;;
		mips64el) printf '%s\n' "mips64el mips64le" ;;
		mips64) printf '%s\n' "mips64" ;;
		mipsel) printf '%s\n' "mipsel mipsle" ;;
		mips) printf '%s\n' "mips" ;;
		riscv64) printf '%s\n' "riscv64" ;;
		s390x) printf '%s\n' "s390x" ;;
		*) uname -m ;;
	esac
}

asset_os_words() {
	case "$(uname -s)" in
		Darwin) printf '%s\n' "darwin macos apple" ;;
		Linux) printf '%s\n' "linux openwrt" ;;
		*) uname -s | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz' ;;
	esac
}

release_asset_label() {
	case "$(uname -s):$(uname -m)" in
		Darwin:arm64|Darwin:aarch64) printf '%s\n' "macos-aarch64" ;;
		Darwin:x86_64|Darwin:amd64) printf '%s\n' "macos-x86_64" ;;
		Linux:x86_64|Linux:amd64) printf '%s\n' "linux-x86_64-musl" ;;
		Linux:arm64|Linux:aarch64) printf '%s\n' "linux-aarch64-musl" ;;
		*) return 1 ;;
	esac
}

prerelease_asset_url() {
	label=$(release_asset_label) || return 1
	printf 'https://github.com/%s/releases/download/prerelease-main/hush-server-%s\n' "$HUSH_REPO" "$label"
}

select_release_asset_url() {
	tmp_json=$1
	os_words=$(asset_os_words)
	arch_words=$(asset_arch_words)

	for name_words in "hush-server" "hush"; do
		match=$(
			sed -n 's/.*"browser_download_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$tmp_json" |
			while IFS= read -r url; do
				url_lc=$(lower "$url")
				is_ignored_asset "$url_lc" && continue

				if contains_any "$url_lc" "$os_words" &&
					contains_any "$url_lc" "$arch_words" &&
					contains_any "$url_lc" "$name_words"; then
					printf '%s\n' "$url"
					break
				fi
			done
		)

		if [ -n "$match" ]; then
			printf '%s\n' "$match" | head -n 1
			return 0
		fi
	done
}

find_extracted_server() {
	dir=$1

	found=$(find "$dir" -type f -name hush-server -print | head -n 1)
	if [ -n "$found" ]; then
		printf '%s\n' "$found"
		return 0
	fi

	found=$(find "$dir" -type f -name 'hush-server*' -print | head -n 1)
	if [ -n "$found" ]; then
		printf '%s\n' "$found"
		return 0
	fi

	return 1
}

extract_or_select_server() {
	asset=$1
	work=$2
	extract_dir=$work/extract
	mkdir -p "$extract_dir"

	case "$asset" in
		*.tar.gz|*.tgz)
			tar -xzf "$asset" -C "$extract_dir"
			find_extracted_server "$extract_dir"
			return
			;;
		*.tar.xz|*.txz)
			tar -xJf "$asset" -C "$extract_dir"
			find_extracted_server "$extract_dir"
			return
			;;
		*.tar.bz2|*.tbz2)
			tar -xjf "$asset" -C "$extract_dir"
			find_extracted_server "$extract_dir"
			return
			;;
		*.zip)
			have unzip || die "unzip is required for zip release assets"
			unzip -q "$asset" -d "$extract_dir"
			find_extracted_server "$extract_dir"
			return
			;;
	esac

	chmod +x "$asset"
	printf '%s\n' "$asset"
}

download_server() {
	work=$1
	asset=$work/hush-release-asset

	if [ -n "${HUSH_ASSET_URL:-}" ]; then
		asset_url=$HUSH_ASSET_URL
	else
		api_json=$work/release.json
		if [ "$HUSH_VERSION" = latest ]; then
			api_url="https://api.github.com/repos/$HUSH_REPO/releases/latest"
			log "Fetching release metadata from $api_url"
			if ! fetch_stdout_optional "$api_url" >"$api_json"; then
				log "No stable latest release found; using prerelease-main"
				asset_url=$(prerelease_asset_url || true)
			else
				asset_url=$(select_release_asset_url "$api_json")
			fi
		else
			api_url="https://api.github.com/repos/$HUSH_REPO/releases/tags/$HUSH_VERSION"
			log "Fetching release metadata from $api_url"
			fetch_stdout "$api_url" >"$api_json"
			asset_url=$(select_release_asset_url "$api_json")
		fi
	fi

	[ -n "${asset_url:-}" ] || die "could not find a hush release asset for $(uname -s)/$(uname -m); set HUSH_ASSET_URL to override"
	log "Downloading $asset_url"

	case "$asset_url" in
		*.tar.gz) asset=$asset.tar.gz ;;
		*.tgz) asset=$asset.tgz ;;
		*.tar.xz) asset=$asset.tar.xz ;;
		*.txz) asset=$asset.txz ;;
		*.tar.bz2) asset=$asset.tar.bz2 ;;
		*.tbz2) asset=$asset.tbz2 ;;
		*.zip) asset=$asset.zip ;;
	esac

	fetch_to "$asset_url" "$asset"
	extract_or_select_server "$asset" "$work"
}

install_server_binary_from_release() {
	work=$(mktemp -d)
	trap 'rm -rf "$work"' EXIT INT TERM

	server=$(download_server "$work")
	as_root mkdir -p "$INSTALL_DIR"
	staged="$INSTALL_DIR/.hush-server.$$"
	trap 'rm -rf "$work"; as_root rm -f "$staged"' EXIT INT TERM
	as_root cp "$server" "$staged"
	as_root chmod 0755 "$staged"
	as_root mv -f "$staged" "$INSTALL_PATH"
	success "Installed hush-server to $INSTALL_PATH"
}

validate_server_binary() {
	if ! "$INSTALL_PATH" --version >/dev/null 2>&1; then
		die "installed $INSTALL_PATH, but it could not run; check CPU architecture and executable support"
	fi
}

brew_install_server() {
	if brew list --formula hush >/dev/null 2>&1; then
		log "Upgrading hush with Homebrew"
		brew upgrade hush || brew upgrade kdrag0n/tap/hush
	else
		log "Installing hush with Homebrew"
		brew install kdrag0n/tap/hush
	fi

	if brew --prefix hush >/dev/null 2>&1; then
		INSTALL_PATH=$(brew --prefix hush)/bin/hush-server
	elif have hush-server; then
		INSTALL_PATH=$(command -v hush-server)
	elif [ -x /opt/homebrew/opt/hush/bin/hush-server ]; then
		INSTALL_PATH=/opt/homebrew/opt/hush/bin/hush-server
	elif [ -x /usr/local/opt/hush/bin/hush-server ]; then
		INSTALL_PATH=/usr/local/opt/hush/bin/hush-server
	else
		die "brew installed hush, but hush-server was not found"
	fi
}

write_launchd_plist() {
	cat <<EOF | as_root tee "$PLIST_PATH" >/dev/null
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>KeepAlive</key>
	<true/>
	<key>Label</key>
	<string>$SERVICE_LABEL</string>
	<key>LimitLoadToSessionType</key>
	<array>
		<string>Aqua</string>
		<string>Background</string>
		<string>LoginWindow</string>
		<string>StandardIO</string>
		<string>System</string>
	</array>
	<key>ProgramArguments</key>
	<array>
		<string>$INSTALL_PATH</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
</dict>
</plist>
EOF

	as_root chown root:wheel "$PLIST_PATH"
	as_root chmod 0644 "$PLIST_PATH"
}

load_launchd_service() {
	write_launchd_plist

	as_root launchctl bootout system "$PLIST_PATH" >/dev/null 2>&1 || true
	as_root launchctl bootstrap system "$PLIST_PATH"
	as_root launchctl enable "system/$SERVICE_LABEL" >/dev/null 2>&1 || true
	as_root launchctl kickstart -k "system/$SERVICE_LABEL"
	success "Loaded and restarted launch daemon $SERVICE_LABEL"
}

write_systemd_service() {
	cat <<EOF | as_root tee "$SYSTEMD_SERVICE_PATH" >/dev/null
[Unit]
Description=hush server
Documentation=https://github.com/$HUSH_REPO
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$INSTALL_PATH
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
}

install_systemd_service() {
	write_systemd_service
	as_root systemctl daemon-reload
	as_root systemctl enable hush.service
	as_root systemctl restart hush.service
	success "Enabled and restarted hush.service"
}

write_openwrt_init() {
	cat <<EOF | as_root tee "$OPENWRT_INIT_PATH" >/dev/null
#!/bin/sh /etc/rc.common

# shellcheck disable=SC2034
USE_PROCD=1
START=80
STOP=10

PROG=$INSTALL_PATH

start_service() {
	if [ ! -x "\$PROG" ]; then
		echo "\$PROG is not executable" >&2
		return 1
	fi

	procd_open_instance
	procd_set_param command "\$PROG"
	procd_set_param respawn
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_close_instance
}
EOF

	as_root chmod 0755 "$OPENWRT_INIT_PATH"
}

install_openwrt_service() {
	write_openwrt_init
	as_root /etc/init.d/hush enable
	as_root /etc/init.d/hush stop >/dev/null 2>&1 || true
	as_root /etc/init.d/hush start
	success "Enabled and started OpenWrt init service hush"
}

is_openwrt() {
	if [ -f /etc/openwrt_release ]; then
		return 0
	fi

	[ -x /sbin/procd ] && [ -f /etc/rc.common ]
}

install_macos() {
	if have brew; then
		brew_install_server
	else
		log "Homebrew not found; installing hush-server from GitHub releases"
		install_server_binary_from_release
	fi

	load_launchd_service
}

install_linux() {
	install_server_binary_from_release
	validate_server_binary

	if is_openwrt; then
		install_openwrt_service
	elif have systemctl && [ -d /run/systemd/system ]; then
		install_systemd_service
	else
		die "unsupported Linux init system: expected systemd or OpenWrt procd"
	fi
}

main() {
	case "$(uname -s)" in
		Darwin) install_macos ;;
		Linux) install_linux ;;
		*) die "unsupported platform: $(uname -s)" ;;
	esac
}

main "$@"
