#!/usr/bin/env sh
#
# Authn Platform — the engine as a host process.
#
# `make run` compiles the engine and runs it directly, with its dependencies in
# containers. No image is built, so a code change costs a Go compile rather than
# a Docker build, and a debugger or profiler can attach to it.
#
# Because a real binary is executed rather than `go run`, the process holding the
# port has a stable path on disk. `go run` execs a content-addressed binary out
# of the build cache, whose name is a hash — which is why `pgrep auth-engine`
# finds nothing while the server is plainly running.
#
# Usage: scripts/engine.sh run|start|build|stop|migrate|bootstrap|seed
#
# License: GNU AGPLv3 — Copyright (C) Authn Platform Authors

set -eu

. "$(dirname "$0")/lib.sh"

require_repo_root

BIN_DIR="$ENGINE_DIR/bin"
ENGINE_BIN="$BIN_DIR/auth-engine"

# in_engine runs a command in the engine's module directory. A subshell rather
# than `env -C`, which only GNU coreutils provides — BSD env, and so macOS, has
# no such flag.
in_engine() { (cd "$ENGINE_DIR" && "$@"); }

# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------

# go_build compiles one command, retrying only when the module proxy is at
# fault. A compile error is reported on the first attempt.
go_build() {
    local _cmd _out _log
    _cmd=$1
    _out=$2
    _log=$(new_log "go-build-$_cmd")
    if retry_logged "$_log" "compiling $_cmd" -- \
        in_engine go build -o "$_out" "./cmd/$_cmd"; then
        return 0
    fi
    blank
    explain_go_failure "$_log" || log_err "compiling ./cmd/$_cmd failed; its output is above."
    exit 1
}

cmd_build() {
    ensure_env
    require_go
    log_step "Compiling the engine binaries into $BIN_DIR"
    mkdir -p "$BIN_DIR"
    go_build server bin/auth-engine
    go_build bootstrap bin/bootstrap
    go_build migrate bin/migrate
    go_build seed bin/seed
    log_ok "Built: $(cd "$BIN_DIR" && ls | tr '\n' ' ')"
}

# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------

# ensure_port_free refuses to start a second engine on the same port, naming
# whatever holds it. Compose publishes the containerised engine on the same
# port, so this is the usual collision between the two run modes.
ensure_port_free() {
    local _port _owner _pid
    _port=$1
    port_listening "$_port" || return 0

    _owner=$(port_container "$_port")
    if [ -n "$_owner" ]; then
        die "port $_port is published by the container $_owner." \
            "That is the containerised engine. Stop it first: make down" \
            "Or run this one elsewhere: make run PORT=$((_port + 1))"
    fi
    _pid=$(port_pid "$_port")
    if [ -n "$_pid" ]; then
        die "port $_port is already held by pid $_pid ($(pid_exe "$_pid"))." \
            "If that is an earlier engine, stop it: make stop" \
            "Or run this one elsewhere: make run PORT=$((_port + 1))"
    fi
    die "port $_port is in use by $(describe_port "$_port")." \
        "Free it, or set a different PORT in .env."
}

# ensure_deps brings the dependency containers up. Skipped when the developer is
# managing them, or when Docker is not available at all and the configuration
# needs nothing from it.
ensure_deps() {
    if [ "${SKIP_DEPS:-}" = "1" ]; then
        log_info "SKIP_DEPS=1 — not touching the dependency containers."
        return 0
    fi
    if ! have docker; then
        log_warn "Docker is not installed, so dependencies cannot be started here."
        hint "Point DATABASE_URL and REDIS_URL at servers you run yourself, then: make run SKIP_DEPS=1"
        return 0
    fi
    sh scripts/deps.sh up
}

# run_migrations applies the schema before the server starts, so a first run on
# an empty volume works without a second command.
run_migrations() {
    local _log
    if [ "${SKIP_MIGRATE:-}" = "1" ]; then
        log_info "SKIP_MIGRATE=1 — leaving the schema alone."
        return 0
    fi
    blank
    log_step "Applying the schema"
    _log=$(new_log "migrate")
    if retry_logged "$_log" "migrating" -- in_engine go run ./cmd/migrate; then
        log_ok "Schema up to date."
        return 0
    fi
    blank
    if grep -qiE 'connection refused|could not connect|dial tcp' "$_log" 2>/dev/null; then
        die "the database refused the connection." \
            "Check what is listening: make deps-status" \
            "DATABASE_URL in .env is: $(env_get DATABASE_URL)"
    fi
    if grep -qiE 'password authentication failed|access denied for user' "$_log" 2>/dev/null; then
        die "the database rejected the credentials in DATABASE_URL." \
            "A container created with different credentials keeps them in its volume." \
            "Recreate it from the current DATABASE_URL: make deps-reset && make deps"
    fi
    explain_go_failure "$_log" || log_err "the migration failed; its output is above."
    exit 1
}

cmd_run() {
    local _port _status
    ensure_env
    require_go
    _port=$(env_get PORT 8080)
    [ -n "${PORT:-}" ] && _port=$PORT

    ensure_deps
    ensure_port_free "$_port"
    run_migrations

    blank
    log_step "Compiling the engine"
    mkdir -p "$BIN_DIR"
    go_build server bin/auth-engine

    blank
    log_ok "Starting the engine on http://localhost:$_port — press Ctrl-C to stop."
    log_info "Configuration comes from .env. Health: http://localhost:$_port/v1/ready"
    blank

    # Run from the module directory: the engine walks up from its working
    # directory to find .env, and the repository root is within its search depth.
    _status=0
    (cd "$ENGINE_DIR" && PORT="$_port" exec ./bin/auth-engine) || _status=$?

    # 130 is Ctrl-C, which is how a developer is expected to stop it.
    if [ "$_status" -eq 0 ] || [ "$_status" -eq 130 ]; then
        blank
        log_ok "Engine stopped."
        return 0
    fi
    blank
    log_err "the engine exited with status $_status."
    hint "Configuration problems are listed on the first lines of its output above."
    hint "Compare .env against .env.example, then check dependencies: make deps-status"
    exit "$_status"
}

# cmd_start runs the already-compiled binary, skipping dependency and schema
# work. Use it for a fast restart when nothing but the code has changed.
cmd_start() {
    local _port
    ensure_env
    [ -x "$ENGINE_BIN" ] || die "$ENGINE_BIN does not exist." "Compile it first: make build-engine"
    _port=$(env_get PORT 8080)
    [ -n "${PORT:-}" ] && _port=$PORT
    ensure_port_free "$_port"
    log_ok "Starting $ENGINE_BIN on http://localhost:$_port — press Ctrl-C to stop."
    (cd "$ENGINE_DIR" && PORT="$_port" exec ./bin/auth-engine)
}

# ---------------------------------------------------------------------------
# Stopping
# ---------------------------------------------------------------------------

# cmd_stop terminates the host engine by finding the process that holds the
# port, rather than by name. It then confirms the port was actually released:
# a kill that appears to succeed while the port stays bound means a different
# process was holding it.
cmd_stop() {
    local _port _owner _pid _exe _i
    ensure_env
    _port=$(env_get PORT 8080)
    [ -n "${PORT:-}" ] && _port=$PORT

    if ! port_listening "$_port"; then
        log_ok "Nothing is listening on port $_port."
        return 0
    fi

    _owner=$(port_container "$_port")
    if [ -n "$_owner" ]; then
        die "port $_port is published by the container $_owner, not a host process." \
            "Stop the containerised stack instead: make down"
    fi

    _pid=$(port_pid "$_port")
    if [ -z "$_pid" ]; then
        die "port $_port is held by a process this user cannot see." \
            "Identify it: sudo ss -ltnp | grep :$_port"
    fi

    _exe=$(pid_exe "$_pid")
    case "$_exe" in
    *auth-engine* | *go-build* | *"/exe/server"*) ;;
    *)
        die "pid $_pid holds port $_port but does not look like the engine ($_exe)." \
            "Command line: $(pid_cmdline "$_pid")" \
            "Kill it deliberately if that is what you want: kill $_pid"
        ;;
    esac

    log_step "Stopping pid $_pid ($_exe)"
    kill "$_pid" 2>/dev/null || true
    _i=0
    while [ "$_i" -lt 10 ] && port_listening "$_port"; do
        sleep 1
        _i=$((_i + 1))
    done
    if port_listening "$_port"; then
        log_warn "it did not exit within 10s; sending SIGKILL."
        kill -9 "$_pid" 2>/dev/null || true
        sleep 1
    fi
    if port_listening "$_port"; then
        die "port $_port is still bound after the kill: $(describe_port "$_port")" \
            "Another process was holding it as well."
    fi
    log_ok "Engine stopped; port $_port is free."
}

# ---------------------------------------------------------------------------
# Data commands
# ---------------------------------------------------------------------------

cmd_migrate() {
    ensure_env
    require_go
    ensure_deps
    run_migrations
}

cmd_bootstrap() {
    local _log
    ensure_env
    require_go
    if [ -z "${NAME:-}" ]; then
        die "NAME is required." \
            'Usage: make bootstrap NAME="Your Company" [SLUG=acme] [ENV=test]'
    fi
    ensure_deps
    log_step "Creating tenant \"$NAME\""
    _log=$(new_log "bootstrap")
    set -- -name "$NAME"
    [ -n "${SLUG:-}" ] && set -- "$@" -slug "$SLUG"
    [ -n "${ENV:-}" ] && set -- "$@" -env "$ENV"
    if run_logged "$_log" in_engine go run ./cmd/bootstrap "$@"; then
        log_ok "Tenant created. Keep the keys above — the secret is not shown again."
        return 0
    fi
    blank
    if grep -qiE 'already exists|duplicate key|unique constraint' "$_log" 2>/dev/null; then
        die "a tenant with that name or slug already exists." \
            'Choose a different slug: make bootstrap NAME="Your Company" SLUG=another-slug'
    fi
    if grep -qiE 'no such table|relation .* does not exist' "$_log" 2>/dev/null; then
        die "the schema has not been applied to this database." "Apply it: make migrate"
    fi
    explain_go_failure "$_log" || log_err "bootstrap failed; its output is above."
    exit 1
}

cmd_seed() {
    local _appenv _log
    ensure_env
    require_go
    _appenv=$(env_get APP_ENV development)
    case "$_appenv" in
    production | prod)
        die "APP_ENV is \"$_appenv\" and seeding installs fixed development credentials." \
            "This target refuses to run against production."
        ;;
    esac
    ensure_deps
    log_step "Seeding demo users and development credentials"
    _log=$(new_log "seed")
    if run_logged "$_log" in_engine go run ./cmd/seed; then
        log_ok "Seeded."
        return 0
    fi
    blank
    if grep -qiE 'no such table|relation .* does not exist' "$_log" 2>/dev/null; then
        die "the schema has not been applied to this database." "Apply it: make migrate"
    fi
    explain_go_failure "$_log" || log_err "seeding failed; its output is above."
    exit 1
}

# ---------------------------------------------------------------------------
# Quality
# ---------------------------------------------------------------------------

# cmd_test runs both suites. Two invocations because everything under test/ is
# behind //go:build integration, so the first compiles none of it. -race on both
# to match CI, where it is what catches races in the first-admin claim and token
# rotation.
#
# No dependency containers are started: the integration tests boot against a
# private in-memory SQLite database and capture SMTP in process, so they need
# nothing running.
cmd_test() {
    local _log
    require_go
    _log=$(new_log "go-test")

    log_step "Engine unit tests"
    if ! run_logged "$_log" in_engine go test -race ./...; then
        blank
        report_test_failure "$_log"
        exit 1
    fi

    blank
    log_step "Engine integration tests"
    if ! run_logged "$_log" in_engine go test -tags=integration -race ./test/...; then
        blank
        report_test_failure "$_log"
        exit 1
    fi
    log_ok "Engine suites pass."
}

# report_test_failure separates a genuine test failure from the environment
# problems that look like one.
report_test_failure() {
    local _log
    _log=$1
    if grep -qiE 'race detected' "$_log" 2>/dev/null; then
        log_err "the race detector fired. The conflicting goroutines are in the output above."
        hint "Reproduce just that test: cd $ENGINE_DIR && go test -race -run <TestName> ./..."
        return
    fi
    if grep -qiE 'build constraints exclude all Go files|no Go files' "$_log" 2>/dev/null; then
        log_err "a package compiled to nothing, which usually means a missing build tag."
        hint "The integration suite needs: go test -tags=integration ./test/..."
        return
    fi
    if grep -qiE 'no required module provides|missing go.sum entry' "$_log" 2>/dev/null; then
        log_err "the module graph is out of date."
        hint "Reconcile it: make tidy"
        return
    fi
    if explain_go_failure "$_log"; then
        return
    fi
    log_err "tests failed. The failing assertions are in the output above."
    hint "Run one test with progress: cd $ENGINE_DIR && go test -tags=integration -run <TestName> -v ./test/..."
}

cmd_vet() {
    local _log
    require_go
    log_step "go vet"
    _log=$(new_log "go-vet")
    if run_logged "$_log" in_engine go vet -tags=integration ./...; then
        log_ok "vet is clean."
        return 0
    fi
    blank
    explain_go_failure "$_log" || log_err "go vet reported problems; they are above."
    exit 1
}

cmd_fmt() {
    local _changed
    require_go
    log_step "Formatting Go sources"
    _changed=$(in_engine gofmt -l . 2>/dev/null || true)
    if [ -z "$_changed" ]; then
        log_ok "Already formatted."
        return 0
    fi
    in_engine gofmt -w .
    log_ok "Reformatted:"
    printf '%s\n' "$_changed" | sed 's/^/      /'
}

cmd_tidy() {
    local _log
    require_go
    log_step "Tidying module dependencies"
    _log=$(new_log "go-tidy")
    if retry_logged "$_log" "go mod tidy" -- in_engine go mod tidy; then
        log_ok "go.mod and go.sum are tidy."
        return 0
    fi
    blank
    explain_go_failure "$_log" || log_err "go mod tidy failed; its output is above."
    exit 1
}

case "${1:-run}" in
run) cmd_run ;;
start) cmd_start ;;
build) cmd_build ;;
stop) cmd_stop ;;
migrate) cmd_migrate ;;
bootstrap) cmd_bootstrap ;;
seed) cmd_seed ;;
test) cmd_test ;;
vet) cmd_vet ;;
fmt) cmd_fmt ;;
tidy) cmd_tidy ;;
*) die "unknown subcommand \"$1\"." \
    "Usage: scripts/engine.sh run|start|build|stop|migrate|bootstrap|seed|test|vet|fmt|tidy" ;;
esac
