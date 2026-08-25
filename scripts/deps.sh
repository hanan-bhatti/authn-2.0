#!/usr/bin/env sh
#
# Authn Platform — dependency containers for local development.
#
# The engine needs a database, Redis and, when EMAIL_DRIVER=smtp against a local
# host, somewhere for mail to land. This script starts exactly the ones .env
# calls for and — the point of it — reuses whatever is already serving those
# ports instead of failing on the name.
#
# A dependency already up is normal on a development machine: containers survive
# reboots, and the mail catcher is documented as a hand-run `docker run`. Such a
# container carries no Compose labels, so Compose cannot adopt it and would stop
# at a name conflict. Here it is reported and reused.
#
# Usage: scripts/deps.sh up|down|status|reset|logs|adopt
#
# License: GNU AGPLv3 — Copyright (C) Authn Platform Authors

set -eu

. "$(dirname "$0")/lib.sh"

require_repo_root

# ---------------------------------------------------------------------------
# What this .env requires
# ---------------------------------------------------------------------------

# mail_is_local is true when the engine is configured to hand mail to an SMTP
# server on this machine, which in development means the bundled catcher. A
# managed relay or the noop driver needs no container.
mail_is_local() {
    [ "$(env_get EMAIL_DRIVER noop)" = "smtp" ] || return 1
    case "$(env_get SMTP_HOST localhost)" in
    localhost | 127.0.0.1 | ::1 | mailpit) return 0 ;;
    *) return 1 ;;
    esac
}

# dep_keys prints the dependencies this configuration actually needs, so a
# deployment on sqlite and a managed mail relay is told to start only Redis.
dep_keys() {
    case "$(db_engine)" in
    postgres) printf 'postgres\n' ;;
    mysql) printf 'mysql\n' ;;
    esac
    printf 'redis\n'
    if mail_is_local; then printf 'mail\n'; fi
}

dep_container() {
    case $1 in
    postgres) printf 'authn-postgres\n' ;;
    mysql) printf 'authn-mysql\n' ;;
    redis) printf 'authn-redis\n' ;;
    mail) printf 'authn-mailpit\n' ;;
    esac
}

dep_service() {
    case $1 in
    postgres) printf 'postgres\n' ;;
    mysql) printf 'mysql\n' ;;
    redis) printf 'redis\n' ;;
    mail) printf 'mailpit\n' ;;
    esac
}

dep_port() {
    case $1 in
    postgres) url_port "$(env_get DATABASE_URL)" 5432 ;;
    mysql) url_port "$(env_get DATABASE_URL)" 3306 ;;
    redis) url_port "$(env_get REDIS_URL)" 6379 ;;
    mail) env_get SMTP_PORT 1025 ;;
    esac
}

dep_label() {
    case $1 in
    postgres) printf 'PostgreSQL\n' ;;
    mysql) printf 'MySQL\n' ;;
    redis) printf 'Redis\n' ;;
    mail) printf 'Mailpit (SMTP catcher)\n' ;;
    esac
}

# ---------------------------------------------------------------------------
# Bringing one dependency up
# ---------------------------------------------------------------------------

# dep_up settles one dependency, reporting what it found rather than assuming.
# It returns 0 whenever the port ends up served, whoever is serving it.
dep_up() {
    local _key _name _svc _port _label _project
    local _owner _label_proj _state _log
    _key=$1
    _name=$(dep_container "$_key")
    _svc=$(dep_service "$_key")
    _port=$(dep_port "$_key")
    _label=$(dep_label "$_key")
    _project=$(compose_project_name)

    # Something answering on the port is enough: the engine connects over TCP
    # and does not care which container, or whether a container at all, is
    # behind it. Recreating it would only destroy working state.
    if port_listening "$_port"; then
        _owner=$(port_container "$_port")
        if [ -n "$_owner" ]; then
            _label_proj=$(container_project "$_owner")
            if [ "$_label_proj" = "$_project" ]; then
                log_ok "$_label already up — $_owner, $(container_uptime "$_owner")."
            elif [ -z "$_label_proj" ]; then
                log_warn "$_label already up on port $_port as $_owner, started outside Compose."
                hint "Reusing it. Compose cannot manage it, so \`make down\` will leave it running."
                hint "To put it under Compose's control: make adopt"
            else
                log_warn "$_label already up on port $_port as $_owner, from Compose project \"$_label_proj\"."
                hint "Reusing it. This project will not manage its lifecycle."
            fi
        else
            log_warn "$_label port $_port is already served by $(describe_port "$_port")."
            hint "Reusing it. If that is not a $_label, the engine will fail to connect."
        fi
        return 0
    fi

    # The port is free. A stopped container of the right name can be restarted,
    # which preserves its data whether or not Compose created it.
    _state=$(container_state "$_name")
    if [ "$_state" != "missing" ] && [ "$_state" != "running" ]; then
        _label_proj=$(container_project "$_name")
        if [ -z "$_label_proj" ]; then
            log_info "$_label container $_name exists but is $_state, and was started outside Compose."
            log_step "Starting the existing $_name"
            if docker start "$_name" >/dev/null 2>&1; then
                wait_tcp 127.0.0.1 "$_port" 45 "$_label on port $_port" ||
                    die "$_name started but nothing is listening on port $_port." \
                        "Read its output: docker logs --tail 50 $_name"
                log_ok "$_label up — reused the existing container."
                return 0
            fi
            log_warn "could not start $_name; letting Compose create its own."
        fi
    fi

    # Nothing to reuse: let Compose create it. Retried because this is where an
    # image pull happens and a registry timeout is the usual first failure.
    log_step "Starting $_label"
    _log=$(new_log "deps-$_key")
    if ! retry_logged "$_log" "starting $_label" -- dc up -d "$_svc"; then
        explain_docker_failure "$_log" || log_err "starting $_label failed; its output is above."
        exit 1
    fi
    wait_tcp 127.0.0.1 "$_port" 60 "$_label on port $_port" ||
        die "$_label started but is not accepting connections on port $_port." \
            "Read its output: docker compose logs --tail 50 $_svc" \
            "Confirm the port in .env matches the one it publishes: make ports"
    log_ok "$_label up on port $_port."
}

# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

cmd_up() {
    local _keys _k
    ensure_compose_env
    require_compose

    _keys=$(dep_keys)
    if [ "$(db_engine)" = "sqlite" ]; then
        log_info "DATABASE_URL is sqlite — no database container is needed."
    elif [ "$(db_engine)" = "unknown" ]; then
        die "DATABASE_URL in .env has an unrecognised scheme." \
            "Supported: postgres://, mysql://, sqlite://"
    fi
    if ! mail_is_local; then
        log_info "EMAIL_DRIVER=$(env_get EMAIL_DRIVER noop) — no mail catcher is needed."
    fi

    for _k in $_keys; do dep_up "$_k"; done

    blank
    log_ok "Dependencies ready."
    if mail_is_local; then
        log_info "Mail lands in Mailpit's inbox: http://localhost:$(env_get MAILPIT_UI_PORT 8025)"
    fi
}

cmd_down() {
    local _project _foreign _k _name _state
    ensure_compose_env
    require_compose
    _project=$(compose_project_name)
    _foreign=""

    for _k in $(dep_keys); do
        _name=$(dep_container "$_k")
        _state=$(container_state "$_name")
        [ "$_state" = "missing" ] && continue
        if [ "$(container_project "$_name")" = "$_project" ]; then
            continue
        fi
        _foreign="$_foreign $_name"
    done

    log_step "Stopping this project's dependency containers"
    dc stop postgres mysql redis mailpit 2>/dev/null || true
    log_ok "Stopped. Data volumes are untouched — use \`make deps-reset\` to delete them."

    if [ -n "$_foreign" ]; then
        blank
        log_warn "left running, because Compose does not manage them:$_foreign"
        hint "Stop them by hand: docker stop$_foreign"
    fi
}

cmd_reset() {
    local _reply
    ensure_compose_env
    require_compose
    log_warn "This deletes every local database and Redis volume in project \"$(compose_project_name)\"."
    if [ "${YES:-}" != "1" ]; then
        printf '%s  Type "yes" to continue: %s' "$C_YELLOW" "$C_RESET"
        read -r _reply || _reply=""
        [ "$_reply" = "yes" ] || die "aborted; nothing was deleted." \
            "To skip this prompt in a script: make deps-reset YES=1"
    fi
    dc down -v --remove-orphans
    log_ok "Volumes deleted. Re-create the schema with: make migrate"
}

cmd_status() {
    local _project _k _name _port _label _state
    local _proj _who _eport
    ensure_env
    require_docker_running
    _project=$(compose_project_name)

    log_step "Dependencies required by .env"
    for _k in $(dep_keys); do
        _name=$(dep_container "$_k")
        _port=$(dep_port "$_k")
        _label=$(dep_label "$_k")
        _state=$(container_state "$_name")
        _proj=$(container_project "$_name")

        if port_listening "$_port"; then
            case "$_state:$_proj" in
            running:"$_project") _who="container $_name, managed here" ;;
            running:) _who="container $_name, started outside Compose" ;;
            running:*) _who="container $_name, Compose project \"$_proj\"" ;;
            *) _who=$(describe_port "$_port") ;;
            esac
            log_ok "$(printf '%-22s port %-6s %s' "$_label" "$_port" "$_who")"
        else
            log_warn "$(printf '%-22s port %-6s not listening (container: %s)' "$_label" "$_port" "$_state")"
        fi
    done

    blank
    log_step "Engine"
    _eport=$(env_get PORT 8080)
    if port_listening "$_eport"; then
        log_ok "$(printf '%-22s port %-6s %s' "auth-engine" "$_eport" "$(describe_port "$_eport")")"
    else
        log_info "$(printf '%-22s port %-6s not listening' "auth-engine" "$_eport")"
    fi
}

cmd_logs() {
    local _svcs _k
    ensure_compose_env
    require_compose
    _svcs=""
    for _k in $(dep_keys); do _svcs="$_svcs $(dep_service "$_k")"; done
    # shellcheck disable=SC2086
    dc logs -f --tail 100 $_svcs
}

# cmd_adopt frees the names Compose needs without destroying anything: each
# foreign container is stopped and renamed, so its volumes stay attached to it
# and it can be restored by renaming it back.
cmd_adopt() {
    local _project _targets _name _state _proj _line
    local _reply _new _n
    ensure_compose_env
    require_compose
    _project=$(compose_project_name)
    _targets=""

    for _name in authn-postgres authn-mysql authn-redis authn-mailpit authn-engine; do
        _state=$(container_state "$_name")
        [ "$_state" = "missing" ] && continue
        _proj=$(container_project "$_name")
        [ "$_proj" = "$_project" ] && continue
        _targets="$_targets $_name"
    done

    if [ -z "$_targets" ]; then
        log_ok "Nothing to adopt — every Authn container belongs to project \"$_project\"."
        return 0
    fi

    log_step "Containers holding names this project needs"
    for _name in $_targets; do
        _proj=$(container_project "$_name")
        log_info "$(printf '%-18s %-12s %-24s %s' \
            "$_name" "$(container_state "$_name")" "$(container_image "$_name")" \
            "project: ${_proj:-none (started by hand)}")"
        # Anonymous volumes are the data at risk. Naming them here is the whole
        # reason this target does not simply remove the containers.
        docker inspect --format '{{range .Mounts}}{{if eq .Type "volume"}}    volume {{.Name}} -> {{.Destination}}
{{end}}{{end}}' "$_name" 2>/dev/null | sed '/^$/d' | while IFS= read -r _line; do
            log_info "$_line"
        done
    done

    blank
    if [ "${PRUNE:-}" = "1" ]; then
        log_warn "PRUNE=1: these containers will be REMOVED. Anonymous volumes become unreachable."
    else
        log_info "Each will be stopped and renamed to <name>.pre-compose, freeing the name."
        log_info "Nothing is deleted: rename one back to restore it, or pass PRUNE=1 to remove instead."
    fi

    if [ "${YES:-}" != "1" ]; then
        printf '%s  Type "yes" to continue: %s' "$C_YELLOW" "$C_RESET"
        read -r _reply || _reply=""
        [ "$_reply" = "yes" ] || die "aborted; nothing was changed." \
            "To skip this prompt in a script: make adopt YES=1"
    fi

    for _name in $_targets; do
        docker stop "$_name" >/dev/null 2>&1 || true
        if [ "${PRUNE:-}" = "1" ]; then
            docker rm "$_name" >/dev/null 2>&1 ||
                die "could not remove $_name." "Inspect it: docker inspect $_name"
            log_ok "removed $_name."
            continue
        fi
        _new="$_name.pre-compose"
        _n=2
        while container_exists "$_new"; do
            _new="$_name.pre-compose.$_n"
            _n=$((_n + 1))
        done
        docker rename "$_name" "$_new" ||
            die "could not rename $_name to $_new." "Inspect it: docker inspect $_name"
        log_ok "stopped and renamed $_name -> $_new."
    done

    blank
    log_ok "Names are free. Bring the stack up with: make dev"
    if [ "${PRUNE:-}" != "1" ]; then
        log_info "The old containers are stopped and still on disk: docker ps -a --filter name=pre-compose"
    fi
}

case "${1:-up}" in
up | start) cmd_up ;;
down | stop) cmd_down ;;
status | ps) cmd_status ;;
reset) cmd_reset ;;
logs) cmd_logs ;;
adopt) cmd_adopt ;;
*) die "unknown subcommand \"$1\"." "Usage: scripts/deps.sh up|down|status|reset|logs|adopt" ;;
esac
