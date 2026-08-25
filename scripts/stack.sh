#!/usr/bin/env sh
#
# Authn Platform — the containerised stack.
#
# `make dev` runs the engine as a container alongside its dependencies. Compose
# owns everything, which means a container holding one of its names but carrying
# another project's labels — or none, from a hand-run `docker run` — is a real
# conflict rather than something to reuse.
#
# Those conflicts are found here before Compose is invoked, so the failure names
# the container and the command that resolves it instead of reporting that a
# name is in use.
#
# Usage: scripts/stack.sh up|down|clean|restart|rebuild|logs|ps
#
# License: GNU AGPLv3 — Copyright (C) Authn Platform Authors

set -eu

. "$(dirname "$0")/lib.sh"

require_repo_root

ENGINE_CONTAINER="authn-engine"

# stack_services lists the containers Compose will manage for this .env. The
# database is profile-gated on DATABASE_URL's scheme and the mail catcher on
# EMAIL_DRIVER, so neither appears when the configuration does not call for it.
stack_services() {
    local _profiles
    _profiles=$(sed -n 's/^COMPOSE_PROFILES=//p' .env.compose 2>/dev/null | tail -n 1)
    case ",$_profiles," in
    *,postgres,*) printf 'authn-postgres\n' ;;
    *,mysql,*) printf 'authn-mysql\n' ;;
    esac
    printf 'authn-redis\n'
    case ",$_profiles," in
    *,mail,*) printf 'authn-mailpit\n' ;;
    esac
    printf '%s\n' "$ENGINE_CONTAINER"
}

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

# check_name_conflicts stops before Compose does, because Compose reports only
# the first name it collides with and says nothing about why it cannot adopt it.
check_name_conflicts() {
    local _project _conflicts _name _state _proj _owner
    _project=$(compose_project_name)
    _conflicts=""

    for _name in $(stack_services); do
        _state=$(container_state "$_name")
        [ "$_state" = "missing" ] && continue
        _proj=$(container_project "$_name")
        [ "$_proj" = "$_project" ] && continue
        _conflicts="$_conflicts $_name"
    done

    [ -z "$_conflicts" ] && return 0

    log_err "containers are holding names this stack needs, and Compose cannot adopt them:"
    for _name in $_conflicts; do
        _proj=$(container_project "$_name")
        if [ -n "$_proj" ]; then
            _owner="project \"$_proj\""
        else
            _owner="started by hand, no Compose labels"
        fi
        printf '%s      %-18s %-10s %-22s %s%s\n' "$C_CYAN" \
            "$_name" "$(container_state "$_name")" "$(container_image "$_name")" \
            "$_owner" "$C_RESET" >&2
    done
    hint ""
    hint "Compose matches containers by label, not by name, so it tries to create its own and the name collides."
    hint ""
    hint "Free the names without deleting anything (stops and renames them):  make adopt"
    hint "Or keep using them and run the engine on the host instead:          make run"
    exit 1
}

# check_port_conflicts warns about a published port held by something outside
# Docker. A warning rather than an error: the bind failure that follows is
# precise, and a stale listener is sometimes gone by the time Compose gets there.
check_port_conflicts() {
    local _port
    for _port in "$(env_get PORT 8080)" "$(url_port "$(env_get REDIS_URL)" 6379)"; do
        port_listening "$_port" || continue
        # A container holding the port is either this stack's or a conflict
        # check_name_conflicts has already reported.
        [ -n "$(port_container "$_port")" ] && continue
        log_warn "port $_port is held by a host process: $(describe_port "$_port")"
        hint "A container in this stack publishes that port and will fail to bind."
        hint "If that is the host engine, stop it first: make stop"
    done
}

# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

cmd_up() {
    local _log _args
    ensure_compose_env
    require_compose
    check_name_conflicts
    check_port_conflicts

    blank
    log_step "Building and starting the stack"
    _log=$(new_log "stack-up")
    _args="up -d --build --remove-orphans"
    [ "${NO_CACHE:-}" = "1" ] && _args="up -d --build --force-recreate --remove-orphans"

    # shellcheck disable=SC2086
    if ! retry_logged "$_log" "docker compose up" -- dc $_args; then
        blank
        explain_docker_failure "$_log" ||
            log_err "docker compose up failed; its output is above."
        exit 1
    fi

    blank
    wait_for_engine
}

# wait_for_engine polls /v1/ready, which the engine answers only once it has
# reached the database and Redis. A container that is up but not ready has a
# configuration or connectivity problem, and its logs say which.
wait_for_engine() {
    local _port _state _code
    _port=$(env_get PORT 8080)
    log_step "Waiting for the engine to report ready"

    if wait_http "http://127.0.0.1:$_port/v1/ready" 90 "http://127.0.0.1:$_port/v1/ready"; then
        log_ok "Engine ready on http://localhost:$_port"
        blank
        log_info "Follow it:            make logs"
        log_info "Create a tenant:      make bootstrap NAME=\"Your Company\""
        if [ "$(container_state authn-mailpit)" = "running" ]; then
            log_info "Mail inbox:           http://localhost:$(env_get MAILPIT_UI_PORT 8025)"
        fi
        return 0
    fi

    _state=$(container_state "$ENGINE_CONTAINER")
    log_err "the engine did not become ready within 90s (container is $_state)."
    if [ "$_state" != "running" ]; then
        _code=$(docker_inspect "$ENGINE_CONTAINER" '{{.State.ExitCode}}')
        log_err "it exited with code ${_code:-?}. Its last output:"
        docker logs --tail 30 "$ENGINE_CONTAINER" 2>&1 | sed 's/^/      /' >&2
        hint "Configuration problems are reported on the first lines of that output."
    else
        log_err "it is running but not ready, which means it cannot reach a dependency:"
        docker logs --tail 30 "$ENGINE_CONTAINER" 2>&1 | sed 's/^/      /' >&2
        hint "Dependency addresses inside the network are derived into .env.compose."
        hint "Check them: make deps-status"
    fi
    exit 1
}

cmd_down() {
    local _log
    ensure_compose_env
    require_compose
    log_step "Stopping the stack"
    _log=$(new_log "stack-down")
    if ! run_logged "$_log" dc down --remove-orphans; then
        explain_docker_failure "$_log" || log_err "docker compose down failed; its output is above."
        exit 1
    fi
    log_ok "Stopped. Database volumes are intact — use \`make clean\` to delete them."
}

cmd_clean() {
    local _reply
    ensure_compose_env
    require_compose
    log_warn "This deletes every volume in Compose project \"$(compose_project_name)\": all local users, tenants and sessions."
    if [ "${YES:-}" != "1" ]; then
        printf '%s  Type "yes" to continue: %s' "$C_YELLOW" "$C_RESET"
        read -r _reply || _reply=""
        [ "$_reply" = "yes" ] || die "aborted; nothing was deleted." \
            "To skip this prompt in a script: make clean YES=1"
    fi
    dc down -v --remove-orphans
    log_ok "Stack and volumes deleted."
}

cmd_restart() {
    local _log
    ensure_compose_env
    require_compose
    log_step "Restarting the engine container"
    _log=$(new_log "stack-restart")
    if ! run_logged "$_log" dc restart auth-engine; then
        explain_docker_failure "$_log" || log_err "restart failed; its output is above."
        exit 1
    fi
    wait_for_engine
}

cmd_rebuild() {
    local _log
    ensure_compose_env
    require_compose
    check_name_conflicts
    log_step "Rebuilding the engine image without the layer cache"
    _log=$(new_log "stack-rebuild")
    if ! retry_logged "$_log" "docker compose build" -- dc build --no-cache auth-engine; then
        explain_docker_failure "$_log" || log_err "the build failed; its output is above."
        exit 1
    fi
    log_ok "Image rebuilt. Start it with: make dev"
}

cmd_logs() {
    ensure_compose_env
    require_compose
    if [ -n "${SERVICE:-}" ]; then
        dc logs -f --tail "${TAIL:-100}" "$SERVICE"
    else
        dc logs -f --tail "${TAIL:-100}" auth-engine
    fi
}

cmd_ps() {
    ensure_compose_env
    require_docker_running
    log_step "Compose project \"$(compose_project_name)\""
    dc ps --all
    blank
    log_step "Every Authn container on this machine"
    docker ps --all --filter 'name=authn' \
        --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}\t{{.Ports}}'
}

case "${1:-up}" in
up | dev) cmd_up ;;
down | stop) cmd_down ;;
clean) cmd_clean ;;
restart) cmd_restart ;;
rebuild) cmd_rebuild ;;
logs) cmd_logs ;;
ps | status) cmd_ps ;;
*) die "unknown subcommand \"$1\"." "Usage: scripts/stack.sh up|down|clean|restart|rebuild|logs|ps" ;;
esac
