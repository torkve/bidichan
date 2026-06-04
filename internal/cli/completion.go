package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
)

// runCompletion emits a shell-completion script for the requested shell
// to stdout. The script suggests subcommands, per-subcommand flags,
// the `channel open` kind list, and dynamic profile names by scanning
// the same directories the profile resolver uses.
//
// Install:
//
//	bash:  source <(bidichan completion bash)            # ephemeral
//	       bidichan completion bash | sudo tee /etc/bash_completion.d/bidichan
//	zsh:   source <(bidichan completion zsh)             # ephemeral
//	       bidichan completion zsh > "${fpath[1]}/_bidichan"
//	fish:  bidichan completion fish | source             # ephemeral
//	       bidichan completion fish > ~/.config/fish/completions/bidichan.fish
func runCompletion(args []string) int {
	fs := flag.NewFlagSet("completion", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: bidichan completion <bash|zsh|fish>")
		return 2
	}
	switch fs.Arg(0) {
	case "bash":
		_, _ = io.WriteString(os.Stdout, bashCompletionScript)
	case "zsh":
		_, _ = io.WriteString(os.Stdout, zshCompletionScript)
	case "fish":
		_, _ = io.WriteString(os.Stdout, fishCompletionScript)
	default:
		fmt.Fprintf(os.Stderr, "completion: unknown shell %q (want bash, zsh, or fish)\n", fs.Arg(0))
		return 2
	}
	return 0
}

// The flag sets emitted to scripts MUST stay in sync with the flag
// definitions in commands.go.  The completion tests in
// completion_test.go assert that every flag name the runners register
// shows up in each script.
//
// Profile-name discovery in every script mirrors profileSearchDirs()
// in config.go: first ${XDG_CONFIG_HOME:-$HOME/.config}/bidichan, then
// /etc/bidichan, both with a *.conf glob.

const bashCompletionScript = `# bash completion for bidichan
# Source this file, or drop it into /etc/bash_completion.d/.

_bidichan_profiles() {
    local d f
    d="${XDG_CONFIG_HOME:-$HOME/.config}/bidichan"
    if [ -d "$d" ]; then
        for f in "$d"/*.conf; do [ -e "$f" ] && basename "$f" .conf; done
    fi
    if [ -d /etc/bidichan ]; then
        for f in /etc/bidichan/*.conf; do [ -e "$f" ] && basename "$f" .conf; done
    fi
}

_bidichan() {
    local cur prev words cword
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    cword=$COMP_CWORD

    local top="listen connect status channel shutdown completion help"
    local listen_flags="--config --addr --unix-socket --hostname --psk --psk-file --cert --key --socket"
    local connect_flags="--config --addr --unix-socket --hostname --psk --psk-file --no-tls-binding --socket"
    local status_flags="--socket --json"
    local shutdown_flags="--socket"
    local channel_subs="open close"
    local channel_open_kinds="forward http socks5 tun"
    local channel_open_forward_flags="--socket --peer --listen-side --listen-addr --target --label -L -R"
    local channel_open_http_flags="--socket --peer --listen-side --listen --label"
    local channel_open_socks5_flags="--socket --peer --listen-side --listen --label"
    local channel_open_tun_flags="--socket --peer --tun-side --name --cidr --mtu --label"
    local channel_close_flags="--socket --peer --id"
    local completion_shells="bash zsh fish"

    # Top-level subcommand.
    if [ "$cword" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "$top" -- "$cur") )
        return
    fi

    local sub="${COMP_WORDS[1]}"
    case "$sub" in
        listen|connect)
            # cword==2: positional profile OR a flag.
            if [ "$cword" -eq 2 ] && [[ "$cur" != -* ]]; then
                COMPREPLY=( $(compgen -W "$(_bidichan_profiles)" -- "$cur") )
                return
            fi
            # --config also accepts a profile name.
            if [ "$prev" = "--config" ]; then
                local profs="$(_bidichan_profiles)"
                COMPREPLY=( $(compgen -W "$profs" -- "$cur") $(compgen -f -- "$cur") )
                return
            fi
            if [[ "$cur" == -* ]]; then
                local flags
                if [ "$sub" = "listen" ]; then flags="$listen_flags"; else flags="$connect_flags"; fi
                COMPREPLY=( $(compgen -W "$flags" -- "$cur") )
                return
            fi
            ;;
        status)
            [[ "$cur" == -* ]] && COMPREPLY=( $(compgen -W "$status_flags" -- "$cur") )
            return
            ;;
        shutdown)
            [[ "$cur" == -* ]] && COMPREPLY=( $(compgen -W "$shutdown_flags" -- "$cur") )
            return
            ;;
        completion)
            if [ "$cword" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "$completion_shells" -- "$cur") )
            fi
            return
            ;;
        channel)
            if [ "$cword" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "$channel_subs" -- "$cur") )
                return
            fi
            local chsub="${COMP_WORDS[2]}"
            case "$chsub" in
                open)
                    if [ "$cword" -eq 3 ]; then
                        COMPREPLY=( $(compgen -W "$channel_open_kinds" -- "$cur") )
                        return
                    fi
                    local kind="${COMP_WORDS[3]}"
                    if [[ "$cur" == -* ]]; then
                        local flags=""
                        case "$kind" in
                            forward) flags="$channel_open_forward_flags" ;;
                            http)    flags="$channel_open_http_flags" ;;
                            socks5)  flags="$channel_open_socks5_flags" ;;
                            tun)     flags="$channel_open_tun_flags" ;;
                        esac
                        COMPREPLY=( $(compgen -W "$flags" -- "$cur") )
                    fi
                    return
                    ;;
                close)
                    [[ "$cur" == -* ]] && COMPREPLY=( $(compgen -W "$channel_close_flags" -- "$cur") )
                    return
                    ;;
            esac
            ;;
    esac
}

complete -F _bidichan bidichan
`

const zshCompletionScript = `#compdef bidichan
# zsh completion for bidichan
# Drop into a directory on $fpath named _bidichan, then restart zsh
# (or run "rm -f ~/.zcompdump && compinit").

_bidichan_profiles() {
    local -a profs
    local dir f base
    for dir in "${XDG_CONFIG_HOME:-$HOME/.config}/bidichan" /etc/bidichan; do
        [[ -d $dir ]] || continue
        for f in $dir/*.conf(N); do
            base=${f:t:r}
            profs+=( "$base" )
        done
    done
    _describe 'profile' profs
}

_bidichan() {
    local -a top_cmds
    top_cmds=(
        'listen:run the server end'
        'connect:run the client end'
        'status:list peers and channels'
        'channel:open or close a channel'
        'shutdown:ask the local daemon to exit'
        'completion:emit shell completion (bash|zsh|fish)'
        'help:show usage'
    )

    local context state state_descr line
    typeset -A opt_args

    _arguments -C \
        '1: :->cmd' \
        '*:: :->args'

    case $state in
        cmd)
            _describe -t commands 'bidichan command' top_cmds
            ;;
        args)
            case $words[1] in
                listen)
                    _arguments \
                        '1: :_bidichan_profiles' \
                        '--config[profile name or config path]:profile:_bidichan_profiles' \
                        '--addr[TCP listen address host:port]:host:port' \
                        '--unix-socket[unix socket path; skips TLS]:path:_files' \
                        '--hostname[SNI hostname]' \
                        '--psk[pre-shared key (hex)]' \
                        '--psk-file[file with hex PSK]:path:_files' \
                        '--cert[TLS cert PEM]:path:_files' \
                        '--key[TLS key PEM]:path:_files' \
                        '--socket[local CLI control socket path]:path:_files'
                    ;;
                connect)
                    _arguments \
                        '1: :_bidichan_profiles' \
                        '--config[profile name or config path]:profile:_bidichan_profiles' \
                        '--addr[remote host:port]:host:port' \
                        '--unix-socket[local unix socket to dial]:path:_files' \
                        '--hostname[SNI hostname]' \
                        '--psk[pre-shared key (hex)]' \
                        '--psk-file[file with hex PSK]:path:_files' \
                        '--no-tls-binding[omit TLS-unique channel binding]' \
                        '--socket[local CLI control socket path]:path:_files'
                    ;;
                status)
                    _arguments \
                        '--socket[daemon control socket]:path:_files' \
                        '--json[emit JSON]'
                    ;;
                shutdown)
                    _arguments '--socket[daemon control socket]:path:_files'
                    ;;
                completion)
                    _values 'shell' bash zsh fish
                    ;;
                channel)
                    _arguments -C \
                        '1: :->chsub' \
                        '*:: :->chargs'
                    case $state in
                        chsub)
                            local -a chsubs
                            chsubs=( 'open:open a channel' 'close:close a channel by id' )
                            _describe 'subcommand' chsubs
                            ;;
                        chargs)
                            case $words[1] in
                                open)
                                    _arguments -C \
                                        '1: :->kind' \
                                        '*:: :->kargs'
                                    case $state in
                                        kind)
                                            _values 'kind' forward http socks5 tun
                                            ;;
                                        kargs)
                                            case $words[1] in
                                                forward)
                                                    _arguments \
                                                        '--socket[daemon socket]:path:_files' \
                                                        '--peer[peer id prefix]' \
                                                        '--listen-side[local|remote]:side:(local remote)' \
                                                        '--listen-addr[host:port]' \
                                                        '--target[host:port]' \
                                                        '--label[label]' \
                                                        '-L[SSH-style direct forward LADDR:RHOST:RPORT]' \
                                                        '-R[SSH-style reverse forward LADDR:RHOST:RPORT]'
                                                    ;;
                                                http|socks5)
                                                    _arguments \
                                                        '--socket[daemon socket]:path:_files' \
                                                        '--peer[peer id prefix]' \
                                                        '--listen-side[local|remote]:side:(local remote)' \
                                                        '--listen[host:port]' \
                                                        '--label[label]'
                                                    ;;
                                                tun)
                                                    _arguments \
                                                        '--socket[daemon socket]:path:_files' \
                                                        '--peer[peer id prefix]' \
                                                        '--tun-side[local|remote]:side:(local remote)' \
                                                        '--name[device name]' \
                                                        '--cidr[IP/CIDR]' \
                                                        '--mtu[MTU]' \
                                                        '--label[label]'
                                                    ;;
                                            esac
                                            ;;
                                    esac
                                    ;;
                                close)
                                    _arguments \
                                        '--socket[daemon socket]:path:_files' \
                                        '--peer[peer id prefix]' \
                                        '--id[channel id]'
                                    ;;
                            esac
                            ;;
                    esac
                    ;;
            esac
            ;;
    esac
}

_bidichan "$@"
`

const fishCompletionScript = `# fish completion for bidichan
# Drop into ~/.config/fish/completions/bidichan.fish (per-user) or
# /etc/fish/completions/bidichan.fish (system).

function __bidichan_profiles
    for dir in "$XDG_CONFIG_HOME/bidichan" $HOME/.config/bidichan /etc/bidichan
        test -d $dir; or continue
        for f in $dir/*.conf
            test -e $f; and basename $f .conf
        end
    end
end

function __bidichan_using
    set -l cmd (commandline -opc)
    test (count $cmd) -lt 2; and return 1
    test "$cmd[2]" = "$argv[1]"
end

function __bidichan_at_position
    set -l cmd (commandline -opc)
    test (count $cmd) -eq "$argv[1]"
end

# Top-level subcommands.
complete -c bidichan -f -n '__bidichan_at_position 1' -a 'listen'     -d 'run the server end'
complete -c bidichan -f -n '__bidichan_at_position 1' -a 'connect'    -d 'run the client end'
complete -c bidichan -f -n '__bidichan_at_position 1' -a 'status'     -d 'list peers and channels'
complete -c bidichan -f -n '__bidichan_at_position 1' -a 'channel'    -d 'open or close a channel'
complete -c bidichan -f -n '__bidichan_at_position 1' -a 'shutdown'   -d 'stop the local daemon'
complete -c bidichan -f -n '__bidichan_at_position 1' -a 'completion' -d 'emit shell completion'
complete -c bidichan -f -n '__bidichan_at_position 1' -a 'help'       -d 'show usage'

# Profile names as the positional after listen/connect.
complete -c bidichan -f -n '__bidichan_using listen  ; and __bidichan_at_position 2' -a '(__bidichan_profiles)' -d 'profile'
complete -c bidichan -f -n '__bidichan_using connect ; and __bidichan_at_position 2' -a '(__bidichan_profiles)' -d 'profile'

# Listen flags.
complete -c bidichan -f -n '__bidichan_using listen' -l config        -d 'profile name or config path' -xa '(__bidichan_profiles)'
complete -c bidichan -f -n '__bidichan_using listen' -l addr          -d 'TCP listen address host:port'
complete -c bidichan -f -n '__bidichan_using listen' -l unix-socket   -d 'unix socket path; skips TLS' -r
complete -c bidichan -f -n '__bidichan_using listen' -l hostname      -d 'SNI hostname'
complete -c bidichan -f -n '__bidichan_using listen' -l psk           -d 'pre-shared key (hex)'
complete -c bidichan -f -n '__bidichan_using listen' -l psk-file      -d 'file with hex PSK' -r
complete -c bidichan -f -n '__bidichan_using listen' -l cert          -d 'TLS cert PEM' -r
complete -c bidichan -f -n '__bidichan_using listen' -l key           -d 'TLS key PEM' -r
complete -c bidichan -f -n '__bidichan_using listen' -l socket        -d 'control socket path' -r

# Connect flags.
complete -c bidichan -f -n '__bidichan_using connect' -l config         -d 'profile name or config path' -xa '(__bidichan_profiles)'
complete -c bidichan -f -n '__bidichan_using connect' -l addr           -d 'remote host:port'
complete -c bidichan -f -n '__bidichan_using connect' -l unix-socket    -d 'local unix socket' -r
complete -c bidichan -f -n '__bidichan_using connect' -l hostname       -d 'SNI hostname'
complete -c bidichan -f -n '__bidichan_using connect' -l psk            -d 'pre-shared key (hex)'
complete -c bidichan -f -n '__bidichan_using connect' -l psk-file       -d 'file with hex PSK' -r
complete -c bidichan -f -n '__bidichan_using connect' -l no-tls-binding -d 'omit TLS-unique binding'
complete -c bidichan -f -n '__bidichan_using connect' -l socket         -d 'control socket path' -r

# status / shutdown.
complete -c bidichan -f -n '__bidichan_using status'   -l socket -d 'daemon control socket' -r
complete -c bidichan -f -n '__bidichan_using status'   -l json   -d 'emit JSON'
complete -c bidichan -f -n '__bidichan_using shutdown' -l socket -d 'daemon control socket' -r

# completion <shell>.
complete -c bidichan -f -n '__bidichan_using completion ; and __bidichan_at_position 2' -a 'bash zsh fish'

# channel open|close.
complete -c bidichan -f -n '__bidichan_using channel ; and __bidichan_at_position 2' -a 'open close'

# channel open <kind>.
complete -c bidichan -f -n '__bidichan_using channel ; and test (count (commandline -opc)) -eq 3 ; and test (commandline -opc)[3] = open' -a 'forward http socks5 tun'

# channel open forward flags.
function __bidichan_channel_open_kind
    set -l cmd (commandline -opc)
    test (count $cmd) -ge 4
    and test "$cmd[2]" = channel
    and test "$cmd[3]" = open
    and test "$cmd[4]" = "$argv[1]"
end

complete -c bidichan -f -n '__bidichan_channel_open_kind forward' -l socket      -r
complete -c bidichan -f -n '__bidichan_channel_open_kind forward' -l peer        -d 'peer id prefix'
complete -c bidichan -f -n '__bidichan_channel_open_kind forward' -l listen-side -xa 'local remote'
complete -c bidichan -f -n '__bidichan_channel_open_kind forward' -l listen-addr -d 'host:port'
complete -c bidichan -f -n '__bidichan_channel_open_kind forward' -l target      -d 'host:port'
complete -c bidichan -f -n '__bidichan_channel_open_kind forward' -l label       -d 'label'
complete -c bidichan -f -n '__bidichan_channel_open_kind forward' -s L           -d 'SSH-style direct forward'
complete -c bidichan -f -n '__bidichan_channel_open_kind forward' -s R           -d 'SSH-style reverse forward'

for k in http socks5
    complete -c bidichan -f -n "__bidichan_channel_open_kind $k" -l socket      -r
    complete -c bidichan -f -n "__bidichan_channel_open_kind $k" -l peer        -d 'peer id prefix'
    complete -c bidichan -f -n "__bidichan_channel_open_kind $k" -l listen-side -xa 'local remote'
    complete -c bidichan -f -n "__bidichan_channel_open_kind $k" -l listen      -d 'host:port'
    complete -c bidichan -f -n "__bidichan_channel_open_kind $k" -l label       -d 'label'
end

complete -c bidichan -f -n '__bidichan_channel_open_kind tun' -l socket   -r
complete -c bidichan -f -n '__bidichan_channel_open_kind tun' -l peer     -d 'peer id prefix'
complete -c bidichan -f -n '__bidichan_channel_open_kind tun' -l tun-side -xa 'local remote'
complete -c bidichan -f -n '__bidichan_channel_open_kind tun' -l name     -d 'device name'
complete -c bidichan -f -n '__bidichan_channel_open_kind tun' -l cidr     -d 'IP/CIDR'
complete -c bidichan -f -n '__bidichan_channel_open_kind tun' -l mtu      -d 'MTU'
complete -c bidichan -f -n '__bidichan_channel_open_kind tun' -l label    -d 'label'

# channel close.
complete -c bidichan -f -n '__bidichan_using channel ; and test (count (commandline -opc)) -ge 3 ; and test (commandline -opc)[3] = close' -l socket -r
complete -c bidichan -f -n '__bidichan_using channel ; and test (count (commandline -opc)) -ge 3 ; and test (commandline -opc)[3] = close' -l peer   -d 'peer id prefix'
complete -c bidichan -f -n '__bidichan_using channel ; and test (count (commandline -opc)) -ge 3 ; and test (commandline -opc)[3] = close' -l id     -d 'channel id'
`
