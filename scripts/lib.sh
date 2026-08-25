#!/usr/bin/env sh
#
# Authn Platform — shared shell helpers for the Makefile's targets.
#
# Sourced, never executed. Written for POSIX sh because /bin/sh is dash on most
# Linux distributions and the Makefile invokes these scripts with `sh`.
#
# Everything here exists so that a failed target explains itself. Docker, Go and
# pnpm each report problems in their own vocabulary; the classifiers below turn
# the failures that actually happen during development into a sentence about
# this repository and a command to run next.
#
# Every function declares its variables `local`. POSIX sh gives functions no
# scope of their own, so without it a helper called from inside another function
# writes over the caller's variables of the same name — and since the helpers
# share obvious names like _log, _port and _label, that happens constantly. The
# keyword is outside POSIX but present in dash, ash, busybox sh, ksh and bash,
# which covers every /bin/sh this repository is built on.
#
# License: GNU AGPLv3 — Copyright (C) Authn Platform Authors

if [ -n "${AUTHN_LIB_SH:-}" ]; then
    return 0
fi
AUTHN_LIB_SH=1

# ---------------------------------------------------------------------------
# Presentation
# ---------------------------------------------------------------------------

# Colour is suppressed when stdout is not a terminal, so piping a target into a
# file or a CI log yields plain text. NO_COLOR is honoured as the de facto
# standard for opting out.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != "dumb" ]; then
    C_RESET=$(printf '\033[0m')
    C_BOLD=$(printf '\033[1m')
    C_DIM=$(printf '\033[2m')
    C_RED=$(printf '\033[31m')
    C_GREEN=$(printf '\033[32m')
    C_YELLOW=$(printf '\033[33m')
    C_BLUE=$(printf '\033[34m')
    C_CYAN=$(printf '\033[36m')
else
    C_RESET='' C_BOLD='' C_DIM='' C_RED='' C_GREEN='' C_YELLOW='' C_BLUE='' C_CYAN=''
fi

# Progress and results go to stdout; anything the developer must act on goes to
# stderr, so `make deps-status >/dev/null` still surfaces the problems.
log_step() { printf '%s▸ %s%s\n' "$C_BOLD$C_BLUE" "$*" "$C_RESET"; }
log_info() { printf '%s  %s%s\n' "$C_DIM" "$*" "$C_RESET"; }
log_ok() { printf '%s  ✔ %s%s\n' "$C_GREEN" "$*" "$C_RESET"; }
log_warn() { printf '%s  ! %s%s\n' "$C_YELLOW" "$*" "$C_RESET" >&2; }
log_err() { printf '%s  ✖ %s%s\n' "$C_RED" "$*" "$C_RESET" >&2; }

# hint prints a remediation line. Commands the developer is meant to copy are
# indented under the message that prompted them.
hint() { printf '%s      %s%s\n' "$C_CYAN" "$*" "$C_RESET" >&2; }

# blank writes an empty line to stdout, used to separate phases of a target.
blank() { printf '\n'; }

# die reports a failure and exits. The first argument is the problem; every
# argument after it is printed as a remediation hint.
die() {
    local _msg=$1 _h
    shift
    log_err "$_msg"
    for _h in "$@"; do hint "$_h"; done
    exit 1
}

# ---------------------------------------------------------------------------
# Repository layout
# ---------------------------------------------------------------------------

ENGINE_DIR="apps/auth-engine"

# require_repo_root refuses to continue outside the repository, because every
# path below is relative and a partial run in the wrong directory would create
# stray files rather than fail.
require_repo_root() {
    if [ ! -f docker-compose.yml ] || [ ! -f Makefile ]; then
        die "scripts must run from the repository root (no docker-compose.yml here)." \
            "cd to the directory containing the Makefile and try again."
    fi
}

# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------

have() { command -v "$1" >/dev/null 2>&1; }

# require_cmd checks for an executable and, when it is absent, explains how to
# install it rather than letting the shell report "not found".
require_cmd() {
    local _cmd=$1
    shift
    if have "$_cmd"; then
        return 0
    fi
    die "$_cmd is not installed, and this target cannot run without it." "$@"
}

require_docker_cli() {
    require_cmd docker \
        "Install Docker Engine: https://docs.docker.com/engine/install/" \
        "On a workstation, Docker Desktop includes both the CLI and the daemon."
}

require_go() {
    require_cmd go \
        "Install Go 1.26 or newer: https://go.dev/dl/" \
        "Then re-run this target — no other setup is needed."
    local _want _have
    _want=$(sed -n 's/^go[[:space:]]\{1,\}\([0-9.]*\).*/\1/p' "$ENGINE_DIR/go.mod" | head -n 1)
    _have=$(go env GOVERSION 2>/dev/null | sed 's/^go//')
    if [ -n "$_want" ] && [ -n "$_have" ] && ! version_at_least "$_have" "$_want"; then
        die "Go $_have is installed but $ENGINE_DIR/go.mod requires $_want or newer." \
            "Upgrade Go, or use a toolchain: go env -w GOTOOLCHAIN=go${_want}+auto"
    fi
}

require_pnpm() {
    if have pnpm; then
        return 0
    fi
    local _pm
    _pm=$(sed -n 's/.*"packageManager"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' package.json | head -n 1)
    die "pnpm is not installed, and the JavaScript workspaces are pnpm-only." \
        "This repository pins ${_pm:-pnpm} — let Corepack install it: corepack enable && corepack prepare ${_pm:-pnpm} --activate" \
        "Or install it globally: npm install -g ${_pm:-pnpm}"
}

# version_at_least compares dotted version strings field by field, so 1.26
# counts as newer than 1.9 where a string comparison would not.
version_at_least() {
    local _got=$1 _min=$2 _i=1 _g _m
    while [ "$_i" -le 3 ]; do
        _g=$(printf '%s' "$_got" | cut -d. -f"$_i")
        _m=$(printf '%s' "$_min" | cut -d. -f"$_i")
        [ -n "$_g" ] || _g=0
        [ -n "$_m" ] || _m=0
        # Non-numeric suffixes such as rc1 would break the arithmetic below.
        _g=$(printf '%s' "$_g" | sed 's/[^0-9].*//')
        _m=$(printf '%s' "$_m" | sed 's/[^0-9].*//')
        [ -n "$_g" ] || _g=0
        [ -n "$_m" ] || _m=0
        if [ "$_g" -gt "$_m" ]; then return 0; fi
        if [ "$_g" -lt "$_m" ]; then return 1; fi
        _i=$((_i + 1))
    done
    return 0
}

# ---------------------------------------------------------------------------
# Docker daemon and Compose
# ---------------------------------------------------------------------------

# require_docker_running distinguishes the two ways the daemon is unreachable,
# because the fix for a stopped service and the fix for a missing group
# membership have nothing in common.
require_docker_running() {
    require_docker_cli
    local _out
    _out=$(docker info --format '{{.ServerVersion}}' 2>&1) && return 0

    case "$_out" in
    *"permission denied"*)
        die "the Docker daemon is running but this user may not talk to it." \
            "Add yourself to the docker group: sudo usermod -aG docker \"\$USER\"" \
            "Then start a new login shell, or run: newgrp docker"
        ;;
    *"Cannot connect to the Docker daemon"* | *"docker daemon is not running"* | *"connect: no such file"*)
        die "the Docker daemon is not reachable." \
            "Start it: sudo systemctl start docker" \
            "On Docker Desktop, open the app and wait for it to report Running."
        ;;
    *)
        log_err "docker info failed:"
        printf '%s\n' "$_out" >&2
        exit 1
        ;;
    esac
}

# require_compose insists on Compose v2 or newer. The v1 Python script accepts
# only one --env-file, and this repository needs two.
require_compose() {
    require_docker_running
    local _v
    _v=$(docker compose version --short 2>/dev/null || true)
    if [ -z "$_v" ]; then
        die "the Docker Compose plugin is not installed." \
            "Install it: https://docs.docker.com/compose/install/linux/" \
            "The legacy docker-compose v1 script will not work: this repository passes two --env-file flags."
    fi
    _v=${_v#v}
    if ! version_at_least "$_v" "2.0.0"; then
        die "Docker Compose $_v is too old; v2.0 or newer is required." \
            "Install the Compose v2 plugin: https://docs.docker.com/compose/install/linux/"
    fi
}

# dc runs docker compose with both env files. Compose substitutes ${...} in the
# YAML only from files given with --env-file, so the values derived into
# .env.compose — including COMPOSE_PROFILES, which decides which dependency
# containers start — would otherwise be ignored.
dc() {
    docker compose --env-file .env --env-file .env.compose "$@"
}

COMPOSE_PROJECT_LABEL="com.docker.compose.project"

# docker_inspect reads one Go-template field from a container, printing the empty
# string when there is no such container.
#
# The sanitising matters: `docker inspect --format` on a missing container writes
# its error to stderr but still emits a bare newline on stdout. Command
# substitution strips only trailing newlines, so a naive fallback yields a value
# with a leading blank line rather than the intended default.
docker_inspect() {
    local _v
    _v=$(docker inspect --format "$2" "$1" 2>/dev/null | tr -d '\r\n')
    printf '%s\n' "$_v"
}

# container_state prints the container's status, or "missing" when no container
# by that name exists. Callers branch on the word rather than on exit codes.
container_state() {
    local _s
    _s=$(docker_inspect "$1" '{{.State.Status}}')
    printf '%s\n' "${_s:-missing}"
}

container_exists() { [ "$(container_state "$1")" != "missing" ]; }
container_running() { [ "$(container_state "$1")" = "running" ]; }

# container_project prints the Compose project a container belongs to, and the
# empty string for one started by hand with `docker run`. Compose can adopt only
# its own containers, so this is what separates a reusable dependency from a
# name conflict.
container_project() {
    docker_inspect "$1" "{{index .Config.Labels \"$COMPOSE_PROJECT_LABEL\"}}"
}

# compose_project_name is what Compose derives from the directory name, and the
# value that container labels are compared against.
compose_project_name() {
    if [ -n "${COMPOSE_PROJECT_NAME:-}" ]; then
        printf '%s\n' "$COMPOSE_PROJECT_NAME"
        return
    fi
    basename "$PWD" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_-]//g'
}

container_image() {
    docker_inspect "$1" '{{.Config.Image}}'
}

# container_uptime is the human string Docker shows in `docker ps`, used to make
# "already running" reports concrete about how long that has been true.
container_uptime() {
    docker ps --filter "name=^/$1$" --format '{{.Status}}' 2>/dev/null | head -n 1
}

# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------

port_listening() {
    ss -ltn 2>/dev/null | awk -v p=":$1\$" 'NR > 1 && $4 ~ p { found = 1 } END { exit !found }'
}

# port_pid finds the listening process. It only sees processes this user owns:
# a published container port belongs to root's docker-proxy, so port_container
# is consulted before falling back to a vague answer.
port_pid() {
    ss -ltnp 2>/dev/null | awk -v p=":$1\$" '
        NR > 1 && $4 ~ p {
            if (match($0, /pid=[0-9]+/)) {
                print substr($0, RSTART + 4, RLENGTH - 4)
                exit
            }
        }'
}

port_container() {
    docker ps --format '{{.Names}}|{{.Ports}}' 2>/dev/null |
        awk -F'|' -v p=":$1->" '$2 ~ p { print $1; exit }'
}

# pid_exe reads the real executable behind a pid from /proc. `pgrep` matches on
# the process name, which for a `go run` build cache binary is a random hash and
# for docker-proxy is shared by every published port, so neither identifies the
# process holding a port. The symlink does.
pid_exe() {
    readlink -f "/proc/$1/exe" 2>/dev/null || true
}

pid_cmdline() {
    tr '\0' ' ' <"/proc/$1/cmdline" 2>/dev/null || true
}

# describe_port renders one line naming whatever holds a port, so a bind failure
# names the culprit instead of reporting "address already in use".
describe_port() {
    local _port=$1 _c _p
    if ! port_listening "$_port"; then
        printf 'free\n'
        return
    fi
    _c=$(port_container "$_port")
    if [ -n "$_c" ]; then
        printf 'docker container %s (%s)\n' "$_c" "$(container_image "$_c")"
        return
    fi
    _p=$(port_pid "$_port")
    if [ -n "$_p" ]; then
        printf 'pid %s — %s\n' "$_p" "$(pid_exe "$_p")"
        return
    fi
    printf 'a process owned by another user; run "sudo ss -ltnp | grep :%s" to identify it\n' "$_port"
}

# ---------------------------------------------------------------------------
# Waiting
# ---------------------------------------------------------------------------

tcp_probe() {
    if have nc; then
        nc -z "$1" "$2" >/dev/null 2>&1
    elif have curl; then
        curl -s -o /dev/null --max-time 2 "telnet://$1:$2" >/dev/null 2>&1
    else
        # With no probe available, assume reachable rather than block a target
        # on a missing diagnostic tool.
        return 0
    fi
}

# wait_tcp polls until a port accepts connections. Progress is printed as dots
# so a slow first-boot database does not look like a hang.
wait_tcp() {
    local _host=$1 _port=$2 _timeout=${3:-45} _label=${4:-"$1:$2"} _i=0
    while [ "$_i" -lt "$_timeout" ]; do
        if tcp_probe "$_host" "$_port"; then
            [ "$_i" -eq 0 ] || printf '\n'
            return 0
        fi
        if [ "$_i" -eq 0 ]; then
            printf '%s  … waiting for %s%s' "$C_DIM" "$_label" "$C_RESET"
        else
            printf '.'
        fi
        _i=$((_i + 1))
        sleep 1
    done
    [ "$_i" -eq 0 ] || printf '\n'
    return 1
}

wait_http() {
    local _url=$1 _timeout=${2:-60} _label=${3:-$1} _i=0
    while [ "$_i" -lt "$_timeout" ]; do
        if curl -fsS -o /dev/null --max-time 3 "$_url" 2>/dev/null; then
            [ "$_i" -eq 0 ] || printf '\n'
            return 0
        fi
        if [ "$_i" -eq 0 ]; then
            printf '%s  … waiting for %s%s' "$C_DIM" "$_label" "$C_RESET"
        else
            printf '.'
        fi
        _i=$((_i + 1))
        sleep 1
    done
    [ "$_i" -eq 0 ] || printf '\n'
    return 1
}

# ---------------------------------------------------------------------------
# Retrying
# ---------------------------------------------------------------------------

RETRY_ATTEMPTS=${RETRY_ATTEMPTS:-3}

# retry runs a command until it succeeds, backing off exponentially. Use it for
# anything that reaches the network — registry pulls, module downloads, package
# installs — where the same command usually succeeds a moment later.
#
# Usage: retry <label> -- <command> [args...]
retry() {
    local _label=$1 _n=1 _delay=2 _status
    shift
    [ "${1:-}" = "--" ] && shift
    while :; do
        if "$@"; then
            [ "$_n" -eq 1 ] || log_ok "$_label succeeded on attempt $_n."
            return 0
        fi
        _status=$?
        if [ "$_n" -ge "$RETRY_ATTEMPTS" ]; then
            log_err "$_label failed after $_n attempts (exit $_status)."
            return "$_status"
        fi
        log_warn "$_label failed (exit $_status) — retrying in ${_delay}s (attempt $((_n + 1)) of $RETRY_ATTEMPTS)."
        sleep "$_delay"
        _n=$((_n + 1))
        _delay=$((_delay * 2))
    done
}

# run_logged runs a command, shows its output live and keeps a copy on disk so a
# classifier can read it afterwards. POSIX sh has no PIPESTATUS, so the exit
# status is passed out through a sibling file.
run_logged() {
    local _log=$1 _status
    shift
    {
        "$@" 2>&1
        printf '%s\n' "$?" >"$_log.status"
    } | tee "$_log"
    _status=$(cat "$_log.status" 2>/dev/null || printf '1\n')
    rm -f "$_log.status"
    return "$_status"
}

# retry_logged is retry over run_logged, retrying only when the captured output
# looks like a transient network fault. A compile error or a name conflict is
# reported at once instead of being attempted three times.
#
# Usage: retry_logged <logfile> <label> -- <command> [args...]
retry_logged() {
    local _log=$1 _label=$2 _n=1 _delay=3 _status
    shift 2
    [ "${1:-}" = "--" ] && shift
    while :; do
        if run_logged "$_log" "$@"; then
            [ "$_n" -eq 1 ] || log_ok "$_label succeeded on attempt $_n."
            return 0
        fi
        _status=$?
        if [ "$_n" -ge "$RETRY_ATTEMPTS" ] || ! log_is_transient "$_log"; then
            return "$_status"
        fi
        log_warn "$_label hit a network error — retrying in ${_delay}s (attempt $((_n + 1)) of $RETRY_ATTEMPTS)."
        sleep "$_delay"
        _n=$((_n + 1))
        _delay=$((_delay * 2))
    done
}

# log_is_transient decides whether a failure is worth repeating. Registry
# timeouts, DNS hiccups and reset connections are; everything else is not.
log_is_transient() {
    grep -qiE \
        'i/o timeout|TLS handshake timeout|connection reset by peer|temporary failure in name resolution|no such host|EOF$|net/http: request canceled|failed to fetch oauth token|502 Bad Gateway|503 Service Unavailable|504 Gateway|dial tcp.*(timeout|refused)|ECONNRESET|ETIMEDOUT|EAI_AGAIN|ERR_PNPM_META_FETCH_FAIL|registry.npmjs.org.*(timeout|ETIMEDOUT)|context deadline exceeded' \
        "$1" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Failure classification
# ---------------------------------------------------------------------------

# explain_out_of_space is consulted before any other cause, because a full disk
# surfaces as whatever the failing tool happened to be doing at the time: Go
# reports a link error, Docker a layer it could not register, pnpm an ENOSPC.
# Each of those reads as a defect in the thing being built, and the log usually
# carries a package or image header above it that a narrower check will match
# first.
#
# Both filesystems are reported when they differ, since a toolchain writes its
# temporary output to TMPDIR while its result goes next to the source.
explain_out_of_space() {
    local _log=$1 _tmp _cache

    grep -qiE 'no space left on device|ENOSPC|disk quota exceeded' "$_log" 2>/dev/null || return 1

    log_err "the disk filled up — the code is fine, the tool could not write its output."
    hint "Here: $(disk_free .)"
    _tmp=${TMPDIR:-/tmp}
    if [ "$(disk_device .)" != "$(disk_device "$_tmp")" ]; then
        hint "$_tmp (where toolchains write temporary output): $(disk_free "$_tmp")"
    fi
    blank
    log_info "The caches worth reclaiming first, largest saving usually last:"
    if have go; then
        _cache=$(go env GOCACHE 2>/dev/null)
        if [ -n "$_cache" ] && [ -d "$_cache" ]; then
            hint "Go build cache, $(dir_size "$_cache"):  go clean -cache"
        fi
    fi
    if have pnpm; then
        _cache=$(pnpm store path 2>/dev/null)
        if [ -n "$_cache" ] && [ -d "$_cache" ]; then
            hint "pnpm store, $(dir_size "$_cache"):  pnpm store prune"
        fi
    fi
    if have docker; then
        _cache=$(docker system df 2>/dev/null | awk '$1 == "Build" { print $NF }')
        [ -n "$_cache" ] && hint "Docker build cache, $_cache reclaimable:  docker builder prune"
        hint "Docker images and stopped containers:  docker system prune"
    fi
    hint "This project's build output:  make clean-build"
    blank
    log_info "Retrying alone will not help — free space first, then run the same target again."
    return 0
}

disk_free() {
    df -h "$1" 2>/dev/null | awk 'NR == 2 { printf "%s free of %s, %s used\n", $4, $2, $5 }'
}

disk_device() {
    df -P "$1" 2>/dev/null | awk 'NR == 2 { print $1 }'
}

dir_size() {
    du -sh "$1" 2>/dev/null | cut -f1
}

# explain_docker_failure turns a Compose or build log into advice. Each branch
# handles a failure that occurs routinely on a development machine; anything
# unrecognised falls through with the log left on screen.
explain_docker_failure() {
    local _log=$1 _name _proj _port

    explain_out_of_space "$_log" && return 0

    if grep -qi 'Conflict. The container name' "$_log" 2>/dev/null; then
        _name=$(sed -n 's/.*container name "\/\([^"]*\)".*/\1/p' "$_log" | head -n 1)
        _proj=$(container_project "$_name")
        if [ -z "$_proj" ]; then
            log_err "the container name \"$_name\" is taken by a container Compose does not manage."
            hint "It was started by hand with \`docker run\`, so it carries no Compose labels and cannot be adopted."
            hint "Hand it over to Compose (keeps named volumes, drops anonymous ones): make adopt"
            hint "Or inspect it first: docker inspect $_name"
        elif [ "$_proj" != "$(compose_project_name)" ]; then
            log_err "the container name \"$_name\" is taken by another Compose project."
            hint "It belongs to \"$_proj\", and this stack runs as \"$(compose_project_name)\"."
            hint "Stop that project, or run this one under its name: COMPOSE_PROJECT_NAME=$_proj make dev"
        else
            # Same project and same labels, so Compose should have adopted it. The
            # container is in a state it will not reuse — usually left mid-removal
            # by an interrupted run, occasionally renamed by hand afterwards.
            log_err "the container name \"$_name\" is held by a container this project cannot reuse."
            hint "Its state is: $(container_state "$_name")"
            hint "Clear it and start again: make down && make dev"
        fi
        return 0
    fi

    if grep -qiE 'port is already allocated|bind.*address already in use|failed to bind host port' "$_log" 2>/dev/null; then
        _port=$(grep -oiE '(0\.0\.0\.0:|:::)?[0-9]{2,5}(->| failed| is already)' "$_log" |
            grep -oE '[0-9]{2,5}' | head -n 1)
        log_err "a published port is already in use${_port:+ (port $_port)}."
        [ -n "$_port" ] && hint "Held by: $(describe_port "$_port")"
        hint "Free it, or change the port in .env (PORT, POSTGRES_PORT, REDIS_PORT) and re-run."
        return 0
    fi

    if grep -qiE 'pull access denied|unauthorized: authentication required' "$_log" 2>/dev/null; then
        log_err "Docker Hub refused the image pull."
        hint "Log in and retry: docker login"
        hint "Anonymous pulls are rate-limited; a free account raises the limit."
        return 0
    fi

    if grep -qiE 'toomanyrequests|rate limit' "$_log" 2>/dev/null; then
        log_err "Docker Hub is rate-limiting this IP address."
        hint "Wait a few minutes, or authenticate to raise the limit: docker login"
        return 0
    fi

    if grep -qiE 'manifest unknown|manifest for .* not found' "$_log" 2>/dev/null; then
        log_err "an image tag in docker-compose.yml does not exist in the registry."
        hint "Check the tags named in docker-compose.yml against the registry."
        return 0
    fi

    if log_is_transient "$_log"; then
        log_err "the Docker registry could not be reached, and the retries were exhausted."
        hint "Check connectivity: docker run --rm alpine:3.21 true"
        hint "Behind a proxy, Docker needs its own configuration: https://docs.docker.com/engine/daemon/proxy/"
        return 0
    fi

    if grep -qiE 'failed to solve|ERROR \[' "$_log" 2>/dev/null; then
        log_err "the image build failed. The failing step is in the output above."
        hint "Reproduce it alone: docker compose --env-file .env --env-file .env.compose build auth-engine"
        hint "Rule out a stale layer cache: make rebuild"
        return 0
    fi

    return 1
}

# explain_go_failure reads a go build or test log and names the cause.
explain_go_failure() {
    local _log=$1

    # Ahead of every other branch because a linker that runs out of room prints
    # its error under the `# package` header that the compile branch matches on.
    explain_out_of_space "$_log" && return 0

    if grep -qiE 'missing go.sum entry|updates to go.mod needed' "$_log" 2>/dev/null; then
        log_err "the Go module graph is out of date."
        hint "Reconcile it: make tidy"
        return 0
    fi
    if grep -qiE 'go: downloading|module lookup disabled|dial tcp.*proxy.golang.org' "$_log" 2>/dev/null &&
        log_is_transient "$_log"; then
        log_err "the Go module proxy could not be reached."
        hint "Retry, or vendor from the cache: GOFLAGS=-mod=mod go mod download"
        return 0
    fi
    if grep -qiE 'address already in use|bind: permission denied' "$_log" 2>/dev/null; then
        log_err "the engine could not bind its listening address."
        hint "See what holds it: make ports"
        return 0
    fi
    if grep -qiE '^# |undefined:|cannot use|syntax error|declared and not used' "$_log" 2>/dev/null; then
        log_err "the engine did not compile. The errors are above."
        hint "Compile without running: make build-engine"
        return 0
    fi
    if grep -qiE 'configuration invalid|config: |is required' "$_log" 2>/dev/null; then
        log_err "the engine rejected its configuration."
        hint "Every setting comes from .env — compare it with .env.example."
        return 0
    fi
    return 1
}

# explain_node_failure reads a pnpm or turbo log and names the cause.
explain_node_failure() {
    local _log=$1

    explain_out_of_space "$_log" && return 0

    if grep -qi 'ERR_PNPM_OUTDATED_LOCKFILE' "$_log" 2>/dev/null; then
        log_err "pnpm-lock.yaml no longer matches the package.json files."
        hint "Update the lockfile: pnpm install --no-frozen-lockfile"
        hint "Then commit pnpm-lock.yaml — CI installs with --frozen-lockfile."
        return 0
    fi
    if grep -qi 'ERR_PNPM_NO_MATCHING_VERSION' "$_log" 2>/dev/null; then
        log_err "a dependency version in package.json does not exist on the registry."
        hint "The offending package is named above."
        return 0
    fi
    if grep -qiE 'No projects matched the filters|ERR_PNPM_NO_MATCHING_PROJECT' "$_log" 2>/dev/null; then
        log_err "no workspace package matched the filter."
        hint "List what exists: make list"
        return 0
    fi
    if grep -qiE 'EADDRINUSE|address already in use' "$_log" 2>/dev/null; then
        log_err "the dev server could not bind its port."
        hint "See what holds it: make ports"
        return 0
    fi
    if grep -qiE 'error TS[0-9]+|Type error:|Failed to compile' "$_log" 2>/dev/null; then
        log_err "TypeScript rejected the sources. The errors are above."
        hint "A stale sibling build is a common cause: make build-packages"
        return 0
    fi
    if log_is_transient "$_log"; then
        log_err "the npm registry could not be reached, and the retries were exhausted."
        hint "Check connectivity: pnpm ping"
        return 0
    fi
    return 1
}

# ---------------------------------------------------------------------------
# Environment file
# ---------------------------------------------------------------------------

# ensure_env creates .env on first use. The engine refuses to start without one,
# and every port and URL these scripts report is read from it.
ensure_env() {
    if [ -f .env ]; then
        return 0
    fi
    if [ ! -f .env.example ]; then
        die ".env is missing and there is no .env.example to copy." \
            "Restore .env.example from version control: git checkout -- .env.example"
    fi
    cp .env.example .env
    log_warn "created .env from .env.example."
    hint "It carries development defaults. Review it before deploying anywhere."
}

# env_get reads one key from .env without sourcing the file. Sourcing would
# execute its contents, so a backtick in a password would run as a command.
env_get() {
    local _key=$1 _default=${2:-} _val
    # The name is only known at runtime, so reading it takes an eval. Accepting
    # nothing but an upper-case identifier keeps that safe and, since every local
    # here is lower-case, keeps the eval from overwriting one of them.
    case "$_key" in
    '' | *[!A-Z0-9_]* | [0-9]*)
        _val=""
        ;;
    *)
        eval "_val=\${$_key:-}"
        ;;
    esac
    # An exported value wins over .env, which is the order the engine resolves
    # its own configuration in. Without it a variable given on the command line —
    # `make run PORT=8081` — would reach the engine but not the checks that run
    # first, and the two would disagree about which port is in play.
    if [ -n "$_val" ]; then
        printf '%s\n' "$_val"
        return
    fi
    [ -f .env ] || {
        printf '%s\n' "$_default"
        return
    }
    _val=$(sed -n "s/^[[:space:]]*$_key[[:space:]]*=[[:space:]]*//p" .env | tail -n 1 |
        sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'\$//")
    printf '%s\n' "${_val:-$_default}"
}

# url_port pulls the port out of a URL, falling back to the scheme's default.
url_port() {
    local _p
    _p=$(printf '%s' "$1" | sed -n 's|^[a-zA-Z0-9+]*://[^/]*:\([0-9]\{1,\}\).*|\1|p')
    printf '%s\n' "${_p:-$2}"
}

# db_engine names the database from DATABASE_URL's scheme, matching the profile
# selection in compose-env.sh.
db_engine() {
    case "$(env_get DATABASE_URL)" in
    postgres://* | postgresql://*) printf 'postgres\n' ;;
    mysql://*) printf 'mysql\n' ;;
    sqlite://* | file://*) printf 'sqlite\n' ;;
    *) printf 'unknown\n' ;;
    esac
}

# ensure_compose_env regenerates .env.compose, which docker-compose.yml reads
# for the container-side database and Redis addresses.
ensure_compose_env() {
    ensure_env
    sh scripts/compose-env.sh
}

# ---------------------------------------------------------------------------
# Temporary logs
# ---------------------------------------------------------------------------

LOG_DIR=".turbo/make-logs"

# new_log returns a path for a captured command's output. The logs live under an
# already-ignored directory so a failed run leaves nothing to clean up.
new_log() {
    mkdir -p "$LOG_DIR"
    printf '%s/%s.log\n' "$LOG_DIR" "$1"
}
