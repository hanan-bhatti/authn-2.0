#!/usr/bin/env sh
#
# Authn Platform — environment report.
#
# `make doctor` checks everything the other targets need and reports all of it at
# once. Unlike those targets it never stops at the first problem: the point is to
# see the whole picture, because a stack that will not start usually has one
# cause with several symptoms.
#
# Exits non-zero when something would block a build or a run, and zero when the
# only findings are advisory.
#
# Usage: scripts/doctor.sh
#
# License: GNU AGPLv3 — Copyright (C) Authn Platform Authors

set -eu

. "$(dirname "$0")/lib.sh"

require_repo_root

BLOCKERS=0
ADVISORIES=0

blocker() {
    local _h
    BLOCKERS=$((BLOCKERS + 1))
    log_err "$1"
    shift
    for _h in "$@"; do hint "$_h"; done
}

advisory() {
    local _h
    ADVISORIES=$((ADVISORIES + 1))
    log_warn "$1"
    shift
    for _h in "$@"; do hint "$_h"; done
}

row() { printf '  %-14s %s\n' "$1" "$2"; }

# ---------------------------------------------------------------------------
# Toolchain
# ---------------------------------------------------------------------------

check_toolchain() {
    local _want _got _pin _cv _err _t
    log_step "Toolchain"

    if have go; then
        _want=$(sed -n 's/^go[[:space:]]\{1,\}\([0-9.]*\).*/\1/p' "$ENGINE_DIR/go.mod" | head -n 1)
        _got=$(go env GOVERSION 2>/dev/null | sed 's/^go//')
        if version_at_least "$_got" "$_want"; then
            log_ok "$(row go "$_got (go.mod requires $_want)")"
        else
            blocker "go $_got is older than the $_want required by $ENGINE_DIR/go.mod." \
                "Upgrade Go, or let the toolchain fetch it: go env -w GOTOOLCHAIN=go${_want}+auto"
        fi
    else
        blocker "go is not installed — the engine cannot be built or run natively." \
            "Install it: https://go.dev/dl/  (Docker mode, \`make dev\`, does not need it)"
    fi

    if have node; then
        log_ok "$(row node "$(node --version)")"
    else
        blocker "node is not installed — the SDKs and web applications need it." \
            "Install Node 22 or newer: https://nodejs.org/en/download"
    fi

    if have pnpm; then
        _pin=$(sed -n 's/.*"packageManager"[[:space:]]*:[[:space:]]*"pnpm@\([^"]*\)".*/\1/p' package.json | head -n 1)
        _got=$(pnpm --version)
        if [ -n "$_pin" ] && [ "$_got" != "$_pin" ]; then
            advisory "pnpm $_got is installed but package.json pins $_pin." \
                "Match it: corepack prepare pnpm@$_pin --activate"
        else
            log_ok "$(row pnpm "$_got")"
        fi
    else
        blocker "pnpm is not installed — the JavaScript workspaces are pnpm-only." \
            "corepack enable && corepack prepare --activate"
    fi

    if have docker; then
        log_ok "$(row docker "$(docker --version | sed 's/^Docker version //')")"
        _cv=$(docker compose version --short 2>/dev/null || true)
        if [ -z "$_cv" ]; then
            blocker "the Docker Compose v2 plugin is missing." \
                "Install it: https://docs.docker.com/compose/install/linux/"
        else
            log_ok "$(row compose "$_cv")"
        fi
        if docker info --format '{{.ServerVersion}}' >/dev/null 2>&1; then
            log_ok "$(row daemon "reachable")"
        else
            _err=$(docker info 2>&1 | head -n 3 | tr '\n' ' ')
            case "$_err" in
            *"permission denied"*)
                blocker "the Docker daemon is running but this user may not talk to it." \
                    "sudo usermod -aG docker \"\$USER\" && newgrp docker"
                ;;
            *)
                blocker "the Docker daemon is not reachable." \
                    "sudo systemctl start docker  (or open Docker Desktop)"
                ;;
            esac
        fi
    else
        blocker "docker is not installed — dependency containers cannot be started." \
            "Install Docker Engine: https://docs.docker.com/engine/install/"
    fi

    for _t in curl ss; do
        have "$_t" || advisory "$_t is not installed; some diagnostics will be less specific."
    done
}

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

check_config() {
    local _db _k
    blank
    log_step "Configuration"

    if [ ! -f .env ]; then
        advisory ".env does not exist; the first target that needs it will copy .env.example." \
            "Create it now: make env"
        return 0
    fi
    log_ok "$(row .env "present")"

    _db=$(db_engine)
    case "$_db" in
    unknown) blocker "DATABASE_URL has an unrecognised scheme." "Supported: postgres://, mysql://, sqlite://" ;;
    *) log_ok "$(row database "$_db")" ;;
    esac

    row appenv "$(env_get APP_ENV development)"
    row engine-port "$(env_get PORT 8080)"
    row email-driver "$(env_get EMAIL_DRIVER noop)"

    # Values that are safe defaults locally and dangerous anywhere else.
    if [ "$(env_get APP_ENV development)" != "development" ]; then
        for _k in JWT_SECRET SESSION_SECRET; do
            case "$(env_get "$_k")" in
            *dev* | *change* | *example* | "")
                advisory "$_k still looks like a development placeholder while APP_ENV is not development."
                ;;
            esac
        done
    fi

    if [ -f .env.compose ]; then
        log_ok "$(row .env.compose "$(sed -n 's/^COMPOSE_PROFILES=/profiles: /p' .env.compose | tail -n 1)")"
    else
        advisory ".env.compose has not been generated yet." "Generate it: make compose-env"
    fi
}

# ---------------------------------------------------------------------------
# Ports and containers
# ---------------------------------------------------------------------------

check_runtime() {
    local _spec _label _port _project _found _foreign
    local _name _state _proj _who
    blank
    log_step "Ports"
    for _spec in \
        "engine:$(env_get PORT 8080)" \
        "database:$(url_port "$(env_get DATABASE_URL)" 5432)" \
        "redis:$(url_port "$(env_get REDIS_URL)" 6379)" \
        "smtp:$(env_get SMTP_PORT 1025)" \
        "mail-ui:$(env_get MAILPIT_UI_PORT 8025)" \
        "web-account:$(env_get WEB_ACCOUNT_PORT)" \
        "web-console:$(env_get WEB_CONSOLE_PORT)"; do
        _label=${_spec%%:*}
        _port=${_spec#*:}
        [ -n "$_port" ] || continue
        printf '  %-14s %-6s %s\n' "$_label" "$_port" "$(describe_port "$_port")"
    done

    have docker || return 0
    docker info >/dev/null 2>&1 || return 0

    blank
    log_step "Authn containers"
    _project=$(compose_project_name)
    _found=0
    _foreign=""
    for _name in authn-postgres authn-mysql authn-redis authn-mailpit authn-engine; do
        _state=$(container_state "$_name")
        [ "$_state" = "missing" ] && continue
        _found=1
        _proj=$(container_project "$_name")
        if [ "$_proj" = "$_project" ]; then
            _who="managed by this project"
        elif [ -z "$_proj" ]; then
            _who="started by hand — no Compose labels"
            _foreign="$_foreign $_name"
        else
            _who="Compose project \"$_proj\""
            _foreign="$_foreign $_name"
        fi
        printf '  %-18s %-10s %-22s %s\n' "$_name" "$_state" "$(container_image "$_name")" "$_who"
    done
    [ "$_found" -eq 0 ] && log_info "none exist yet"

    if [ -n "$_foreign" ]; then
        blank
        advisory "Compose cannot manage these containers, so \`make dev\` will collide with their names:$_foreign" \
            "They are fine for native mode — \`make run\` reuses them over localhost." \
            "For Docker mode, free the names without deleting anything: make adopt"
    fi
}

# ---------------------------------------------------------------------------
# Workspaces
# ---------------------------------------------------------------------------

check_workspaces() {
    local _d
    blank
    log_step "Workspaces"
    if [ -d node_modules ]; then
        log_ok "$(row node_modules "installed")"
    else
        advisory "workspace dependencies are not installed." "Install them: make install"
    fi

    for _d in packages/sdk-js packages/sdk-react packages/ui apps/web-account; do
        if [ ! -f "$_d/package.json" ]; then
            printf '  %-22s %s\n' "$(basename "$_d")" "not scaffolded"
            continue
        fi
        if [ -d "$_d/dist" ] || [ -d "$_d/.next" ]; then
            printf '  %-22s %s\n' "$(basename "$_d")" "built"
        else
            printf '  %-22s %s\n' "$(basename "$_d")" "not built"
        fi
    done
}

# ---------------------------------------------------------------------------

check_toolchain
check_config
check_runtime
check_workspaces

blank
if [ "$BLOCKERS" -gt 0 ]; then
    log_err "$BLOCKERS blocker(s) and $ADVISORIES advisory item(s). The blockers above must be resolved."
    exit 1
fi
if [ "$ADVISORIES" -gt 0 ]; then
    log_ok "No blockers. $ADVISORIES advisory item(s) above are worth reading."
    exit 0
fi
log_ok "Everything checks out. Start the stack with \`make dev\`, or the engine alone with \`make run\`."
