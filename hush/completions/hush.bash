# bash completion for hush and hcp (`hush cp`).
#
# Install it where bash-completion finds it, linking hcp to it too:
#   hush --completions bash > ~/.local/share/bash-completion/completions/hush
#   ln -s hush ~/.local/share/bash-completion/completions/hcp
# or load it from ~/.bashrc:
#   source <(hush --completions bash)

# Rejoin what COMP_WORDBREAKS split off, such as `host:path` or
# `--opt=value`: COMP_WORDS that touch in COMP_LINE are one shell word. Sets
# _hush_words, _hush_starts (each word's first index in COMP_WORDS),
# _hush_cword and _hush_cur.
_hush_reassemble() {
    local i w n=-1 pos=0 rest gap
    _hush_words=()
    _hush_starts=()
    for ((i = 0; i < ${#COMP_WORDS[@]}; i++)); do
        w=${COMP_WORDS[i]}
        rest=${COMP_LINE:pos}
        gap=${rest%%[![:space:]]*}
        pos=$((pos + ${#gap} + ${#w}))
        if ((n >= 0 && ${#gap} == 0)); then
            _hush_words[n]+=$w
        else
            n=$((n + 1))
            _hush_words[n]=$w
            _hush_starts[n]=$i
        fi
        ((i == COMP_CWORD)) && _hush_cword=$n
    done
    _hush_cur=${_hush_words[_hush_cword]}
}

# Undo backslash escaping and a leading quote, as typed on the line.
_hush_dequote() {
    local s=$1 out= c i
    case $s in
    \'*)
        s=${s#\'}
        REPLY=${s%\'}
        return
        ;;
    \"*)
        s=${s#\"}
        REPLY=${s%\"}
        return
        ;;
    esac
    for ((i = 0; i < ${#s}; i++)); do
        c=${s:i:1}
        if [[ $c == \\ ]]; then
            i=$((i + 1))
            c=${s:i:1}
        fi
        out+=$c
    done
    REPLY=$out
}

# Quote a path for the line, keeping a leading `~` live.
_hush_quote() {
    local q
    q=$(printf '%q' "$1")
    [[ $q == \\~* ]] && q=${q#\\}
    REPLY=$q
}

# Candidates are whole words, but readline replaces only the text after the
# last unquoted word break character in the word. It keeps `@` and `$` in
# that text, as bash completes after them itself.
_hush_ltrim() {
    local cur=$_hush_cur c i cut=0 quote= prefix
    for ((i = 0; i < ${#cur}; i++)); do
        c=${cur:i:1}
        if [[ -n $quote ]]; then
            [[ $c == "$quote" ]] && quote=
            continue
        fi
        case $c in
        \\) i=$((i + 1)) ;;
        \' | \") quote=$c ;;
        [[:space:]]) ;;
        *)
            if [[ $COMP_WORDBREAKS == *"$c"* ]]; then
                cut=$((i + 1))
                [[ $c == [@\$] ]] && cut=$i
            fi
            ;;
        esac
    done
    ((cut)) || return
    prefix=${cur:0:cut}
    for i in "${!COMPREPLY[@]}"; do
        COMPREPLY[i]=${COMPREPLY[i]#"$prefix"}
    done
}

# Hosts starting with $1: ~/.ssh/config aliases, which hush resolves itself,
# plus known hosts.
_hush_hosts() {
    local cur=$1 key value host
    local -a parts hosts=()
    if [[ -r ~/.ssh/config ]]; then
        while IFS=$'=\t ' read -r key value; do
            [[ $key == [Hh][Oo][Ss][Tt] ]] || continue
            read -r -a parts <<<"$value"
            for host in "${parts[@]}"; do
                [[ $host == *[*?!]* ]] || hosts+=("$host")
            done
        done <~/.ssh/config
    fi
    if declare -F _known_hosts_real >/dev/null; then
        local -a COMPREPLY=()
        _known_hosts_real -- "$cur"
        hosts+=("${COMPREPLY[@]}")
    elif [[ -r ~/.ssh/known_hosts ]]; then
        while read -r key value; do
            [[ $key == \|* || $key == @* ]] && continue
            IFS=, read -r -a parts <<<"$key"
            for host in "${parts[@]}"; do
                [[ $host == \[* ]] || hosts+=("$host")
            done
        done <~/.ssh/known_hosts
    fi
    for host in "${hosts[@]}"; do
        [[ $host == "$cur"* ]] && printf '%s\n' "$host"
    done | sort -u
}

# Where the host part of a `hush cp` operand ends, by the rule hush cp uses:
# the first colon outside brackets, unless it comes first or the word starts
# with /, ./ or ../. Sets REPLY to the colon's index in $1.
_hush_remote_colon() {
    local word=$1 c i depth=0
    case $word in /* | ./* | ../*) return 1 ;; esac
    for ((i = 0; i < ${#word}; i++)); do
        c=${word:i:1}
        if [[ $c == '[' ]]; then
            depth=$((depth + 1))
        elif [[ $c == ']' ]]; then
            ((depth > 0)) && depth=$((depth - 1))
        elif [[ $c == : ]] && ((depth == 0)); then
            ((i > 0)) || return 1
            REPLY=$i
            return 0
        fi
    done
    return 1
}

# Stop readline adding a space, so directories can be completed further.
# Sets REPLY to the space files then need, which bash 3 adds itself as it
# has no compopt.
_hush_nospace() {
    REPLY=
    type compopt &>/dev/null || return
    compopt -o nospace
    REPLY=' '
}

# Local paths starting with the dequoted $1, quoted, with `/` after
# directories and a space after files.
_hush_local_files() {
    local f path space
    _hush_nospace
    space=$REPLY
    while IFS= read -r f; do
        _hush_quote "$f"
        path=$f
        [[ $f == \~/* ]] && path=$HOME/${f#\~/}
        if [[ -d $path ]]; then
            COMPREPLY+=("$REPLY/")
        else
            COMPREPLY+=("$REPLY$space")
        fi
    done < <(compgen -f -- "$1")
}

# Remote paths for the `hush cp` operand $1 (dequoted), whose host part ends
# at index $2. The rest of the arguments are hush options to connect with.
_hush_remote_files() {
    local word=$1 colon=$2 bin name path dir space
    shift 2
    path=${word:colon+1}
    dir=
    [[ $path == */* ]] && dir=${path%/*}/
    bin=${COMP_WORDS[0]}
    type -P "$bin" &>/dev/null || bin=hush
    _hush_nospace
    space=$REPLY
    # Asks hush itself, which connects without prompting and only to hosts it
    # already knows.
    while IFS= read -r name; do
        _hush_quote "$dir$name"
        if [[ $name == */ ]]; then
            COMPREPLY+=("${word:0:colon+1}$REPLY")
        else
            COMPREPLY+=("${word:0:colon+1}$REPLY$space")
        fi
    done < <("$bin" __complete-remote "$@" -- "$word" 2>/dev/null)
}

_hush_cp() {
    local cur=$_hush_cur prev=${_hush_words[_hush_cword - 1]} i w host
    local -a opts=()
    for ((i = $1; i < _hush_cword; i++)); do
        w=${_hush_words[i]}
        case $w in
        -p | -i | --data-dir)
            _hush_dequote "${_hush_words[i + 1]}"
            opts+=("$w" "$REPLY")
            i=$((i + 1))
            ;;
        --data-dir=*)
            _hush_dequote "${w#*=}"
            opts+=(--data-dir "$REPLY")
            ;;
        -k | --insecure) opts+=(-k) ;;
        esac
    done

    case $prev in
    -p) return ;;
    -i)
        _hush_dequote "$cur"
        _hush_local_files "$REPLY"
        return
        ;;
    --data-dir)
        COMPREPLY=($(compgen -d -- "$cur"))
        type compopt &>/dev/null && compopt -o filenames
        return
        ;;
    esac
    if [[ $cur == --data-dir=* ]]; then
        COMPREPLY=($(compgen -d -- "${cur#*=}"))
        type compopt &>/dev/null && compopt -o filenames
        return
    fi
    if [[ $cur == -* ]]; then
        COMPREPLY=($(compgen -W '-v --verbose -k --insecure -p -C --data-dir -i
            -h --help -V --version' -- "$cur"))
        return
    fi

    _hush_dequote "$cur"
    local word=$REPLY
    if _hush_remote_colon "$word"; then
        _hush_remote_files "$word" "$REPLY" "${opts[@]}"
        return
    fi
    _hush_local_files "$word"
    case $word in /* | .* | \~*) return ;; esac
    local user=
    [[ $word == *@* ]] && user=${word%%@*}@
    while IFS= read -r host; do
        COMPREPLY+=("$user$host:")
    done < <(_hush_hosts "${word#"$user"}")
}

_hush() {
    local _hush_cword _hush_cur _hush_delegated=0
    local -a _hush_words _hush_starts
    _hush_reassemble
    COMPREPLY=()
    _hush_main
    ((_hush_delegated)) || _hush_ltrim
}

_hush_main() {
    if [[ ${_hush_words[0]##*/} == hcp ]]; then
        _hush_cp 1
        return
    fi
    if [[ ${_hush_words[1]} == cp ]] && ((_hush_cword > 1)); then
        _hush_cp 2
        return
    fi

    local cur=$_hush_cur prev=${_hush_words[_hush_cword - 1]} i w target=0
    for ((i = 1; i < _hush_cword; i++)); do
        w=${_hush_words[i]}
        case $w in
        -p | -i | -L | -R | --data-dir) i=$((i + 1)) ;;
        --) ;;
        -*) ;;
        *)
            target=$i
            break
            ;;
        esac
    done

    if ((target)); then
        # Like ssh: complete the remote command with local definitions.
        _hush_delegated=1
        local offset=$((target + 1))
        [[ ${_hush_words[offset]} == -- ]] && ((_hush_cword > offset)) && offset=$((offset + 1))
        offset=${_hush_starts[offset]:-$COMP_CWORD}
        if declare -F _comp_command_offset >/dev/null; then
            _comp_command_offset "$offset"
        elif declare -F _command_offset >/dev/null; then
            _command_offset "$offset"
        elif ((COMP_CWORD == offset)); then
            COMPREPLY=($(compgen -c -- "${COMP_WORDS[COMP_CWORD]}"))
        else
            COMPREPLY=($(compgen -f -- "${COMP_WORDS[COMP_CWORD]}"))
            type compopt &>/dev/null && compopt -o filenames
        fi
        return
    fi

    case $prev in
    -p | -L | -R) return ;;
    -i)
        _hush_dequote "$cur"
        _hush_local_files "$REPLY"
        return
        ;;
    --data-dir)
        COMPREPLY=($(compgen -d -- "$cur"))
        type compopt &>/dev/null && compopt -o filenames
        return
        ;;
    esac
    if [[ $cur == --data-dir=* ]]; then
        COMPREPLY=($(compgen -d -- "${cur#*=}"))
        type compopt &>/dev/null && compopt -o filenames
        return
    fi
    if [[ $cur == -* ]]; then
        local flags='-v --verbose -k --insecure -p -t -T --data-dir -i -S
            --no-shell -A -L -R -h --help -V --version'
        ((_hush_cword == 1)) && flags+=' --completions'
        COMPREPLY=($(compgen -W "$flags" -- "$cur"))
        return
    fi
    if [[ $prev == --completions ]]; then
        COMPREPLY=($(compgen -W 'zsh bash' -- "$cur"))
        return
    fi

    local user=
    [[ $cur == *@* ]] && user=${cur%%@*}@
    while IFS= read -r w; do
        COMPREPLY+=("$user$w")
    done < <(_hush_hosts "${cur#"$user"}")
    ((_hush_cword == 1)) && COMPREPLY+=($(compgen -W cp -- "$cur"))
}

complete -F _hush hush hcp
