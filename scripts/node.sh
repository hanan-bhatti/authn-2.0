#!/usr/bin/env sh
#
# Authn Platform — the JavaScript workspaces.
#
# Builds and runs the SDKs, the shared UI package and the Next.js applications.
# Targets are named by their short alias (sdk, react, ui, account) and resolved
# to a workspace directory, so an application that has not been scaffolded yet
# reports that rather than failing inside pnpm.
#
# Builds go through turbo because the workspace graph matters: an application
# resolves a sibling package from the declarations its build emits, not from its
# source, so a consumer built before its dependency sees missing modules.
#
# Usage: scripts/node.sh install|build|dev|start|test|lint|clean|list [target...]
#
# License: GNU AGPLv3 — Copyright (C) Authn Platform Authors

set -eu

. "$(dirname "$0")/lib.sh"

require_repo_root

# Every workspace directory, in dependency order: packages before the
# applications that consume them.
ALL_PACKAGES="packages/sdk-js packages/sdk-react packages/ui"
ALL_APPS="apps/web-account apps/web-console apps/web-demo apps/web-docs apps/web-landing"

# ---------------------------------------------------------------------------
# Resolving targets
# ---------------------------------------------------------------------------

# target_dir maps a short alias to a workspace directory. Anything unrecognised
# is tried as a directory name under apps/ or packages/, so a package added
# later needs no entry here.
target_dir() {
    case "$1" in
    sdk | js | sdk-js | @authn/js) printf 'packages/sdk-js\n' ;;
    react | sdk-react | @authn/react) printf 'packages/sdk-react\n' ;;
    ui | @authn/ui) printf 'packages/ui\n' ;;
    account | web-account | @authn/web-account) printf 'apps/web-account\n' ;;
    console | web-console) printf 'apps/web-console\n' ;;
    demo | web-demo) printf 'apps/web-demo\n' ;;
    docs | web-docs) printf 'apps/web-docs\n' ;;
    landing | web-landing) printf 'apps/web-landing\n' ;;
    packages) printf '%s\n' $ALL_PACKAGES ;;
    apps | web) printf '%s\n' $ALL_APPS ;;
    *)
        if [ -f "apps/$1/package.json" ]; then
            printf 'apps/%s\n' "$1"
        elif [ -f "packages/$1/package.json" ]; then
            printf 'packages/%s\n' "$1"
        fi
        ;;
    esac
}

# dir_alias is target_dir read backwards: the alias a workspace is named by in
# the make targets and in `make list`. Deriving it from the directory name
# instead would print "js" for packages/sdk-js, an alias that works but is not
# the one `make build-sdk` and the documentation use.
dir_alias() {
    case "$1" in
    packages/sdk-js) printf 'sdk\n' ;;
    packages/sdk-react) printf 'react\n' ;;
    *) basename "$1" | sed -e 's/^sdk-//' -e 's/^web-//' ;;
    esac
}

# pkg_json_get reads one field out of a package.json. Node is used rather than
# sed because a script name must be looked up inside the scripts object, and a
# dependency happening to be called "build" would fool a plain grep.
pkg_json_get() {
    node -e '
      const fs = require("fs");
      let pkg;
      try { pkg = JSON.parse(fs.readFileSync(process.argv[1] + "/package.json", "utf8")); }
      catch { process.exit(0); }
      const value = process.argv[2].split(".").reduce((a, k) => (a == null ? a : a[k]), pkg);
      process.stdout.write(value == null ? "" : String(value));
    ' "$1" "$2" 2>/dev/null || true
}

pkg_name() { pkg_json_get "$1" name; }
pkg_has_script() { [ -n "$(pkg_json_get "$1" "scripts.$2")" ]; }

# resolve_target turns one alias into a directory, refusing an alias that names
# a planned but unscaffolded application. Those directories exist and are empty.
#
# It returns non-zero rather than exiting, because callers read it through
# command substitution — where an `exit` would end only the subshell and let the
# caller carry on with an empty result.
resolve_target() {
    local _dirs _d
    _dirs=$(target_dir "$1")
    if [ -z "$_dirs" ]; then
        log_err "\"$1\" is not a workspace in this repository."
        hint "See what exists: make list"
        return 1
    fi
    for _d in $_dirs; do
        if [ ! -f "$_d/package.json" ]; then
            if [ -d "$_d" ]; then
                log_err "$_d has not been scaffolded yet — the directory is empty."
                hint "See what is available: make list"
                return 1
            fi
            log_err "$_d does not exist."
            hint "See what is available: make list"
            return 1
        fi
        printf '%s\n' "$_d"
    done
}

# resolve_targets resolves every alias given, or fails without running anything.
# Resolving all of them up front means a typo in the second of three arguments
# does not leave the first already built.
resolve_targets() {
    local _t _out _all=""
    for _t in "$@"; do
        _out=$(resolve_target "$_t") || return 1
        _all="$_all $_out"
    done
    printf '%s\n' "$_all"
}

# scaffolded prints every workspace directory that actually has a package.json,
# so bulk targets skip the placeholders rather than failing on them.
scaffolded() {
    local _d
    for _d in $ALL_PACKAGES $ALL_APPS; do
        [ -f "$_d/package.json" ] && printf '%s\n' "$_d"
    done
}

# ---------------------------------------------------------------------------
# Installing
# ---------------------------------------------------------------------------

# ensure_install installs dependencies when node_modules is absent, and is a
# no-op afterwards. FORCE=1 reinstalls, FROZEN=1 matches what CI does.
ensure_install() {
    require_pnpm
    if [ -d node_modules ] && [ "${FORCE:-}" != "1" ]; then
        return 0
    fi
    cmd_install
}

cmd_install() {
    local _log _args
    require_pnpm
    log_step "Installing workspace dependencies"
    _log=$(new_log "pnpm-install")
    _args="install"
    [ "${FROZEN:-}" = "1" ] && _args="install --frozen-lockfile"

    # shellcheck disable=SC2086
    if retry_logged "$_log" "pnpm install" -- pnpm $_args; then
        log_ok "Dependencies installed."
        return 0
    fi
    blank
    explain_node_failure "$_log" || log_err "pnpm install failed; its output is above."
    exit 1
}

# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------

# turbo_run drives one turbo task over a set of workspace filters. turbo resolves
# the dependency order from turbo.json, so a filtered build still builds the
# packages the target imports.
turbo_run() {
    local _task _filters _d _name _log
    _task=$1
    shift
    _filters=""
    for _d in "$@"; do
        _name=$(pkg_name "$_d")
        [ -n "$_name" ] && _filters="$_filters --filter=$_name"
    done
    if [ -z "$_filters" ]; then
        die "no workspace package matched." "See what exists: make list"
    fi

    log_step "turbo run $_task$_filters"
    _log=$(new_log "turbo-$_task")
    # shellcheck disable=SC2086
    if retry_logged "$_log" "turbo run $_task" -- pnpm exec turbo run "$_task" $_filters; then
        log_ok "$_task complete."
        return 0
    fi
    blank
    explain_node_failure "$_log" || log_err "turbo run $_task failed; its output is above."
    exit 1
}

cmd_build() {
    local _dirs
    ensure_install
    if [ "$#" -eq 0 ]; then
        # shellcheck disable=SC2046
        turbo_run build $(scaffolded)
        return 0
    fi
    _dirs=$(resolve_targets "$@") || exit 1
    # shellcheck disable=SC2086
    turbo_run build $_dirs
}

cmd_test() {
    local _dirs
    ensure_install
    if [ "$#" -eq 0 ]; then
        # shellcheck disable=SC2046
        turbo_run test $(scaffolded)
        return 0
    fi
    _dirs=$(resolve_targets "$@") || exit 1
    # shellcheck disable=SC2086
    turbo_run test $_dirs
}

cmd_lint() {
    local _dirs
    ensure_install
    if [ "$#" -eq 0 ]; then
        # shellcheck disable=SC2046
        turbo_run lint $(scaffolded)
        return 0
    fi
    _dirs=$(resolve_targets "$@") || exit 1
    # shellcheck disable=SC2086
    turbo_run lint $_dirs
}

cmd_clean() {
    local _d
    log_step "Removing build output from the workspaces"
    for _d in $(scaffolded); do
        rm -rf "$_d/dist" "$_d/.next" "$_d/.turbo" "$_d/tsconfig.tsbuildinfo"
    done
    rm -rf .turbo/cache
    log_ok "Cleaned. The next build starts from scratch."
}

# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------

# app_port_var is the .env key holding an application's dev port, derived from
# its directory name: apps/web-account reads WEB_ACCOUNT_PORT.
app_port_var() {
    basename "$1" | tr '[:lower:]-' '[:upper:]_' | sed 's/$/_PORT/'
}

# ensure_workspace_deps builds the sibling packages an application imports. Next
# resolves a workspace dependency from the declarations in its dist directory,
# and turbo's dev task deliberately has no build prerequisite, so a first `dev`
# in a fresh checkout would otherwise report every @authn import as missing.
ensure_workspace_deps() {
    local _dir _missing _dep _dd
    _dir=$1
    _missing=""
    for _dep in $(node -e '
      const fs = require("fs");
      const pkg = JSON.parse(fs.readFileSync(process.argv[1] + "/package.json", "utf8"));
      const deps = Object.assign({}, pkg.dependencies, pkg.devDependencies);
      for (const [name, range] of Object.entries(deps)) {
        if (String(range).startsWith("workspace:")) process.stdout.write(name + "\n");
      }
    ' "$_dir" 2>/dev/null || true); do
        _dd=$(target_dir "$_dep")
        [ -z "$_dd" ] && continue
        # A package with a build script must have produced dist/ to be importable.
        if pkg_has_script "$_dd" build && [ ! -d "$_dd/dist" ]; then
            _missing="$_missing $_dd"
        fi
    done
    [ -z "$_missing" ] && return 0

    log_info "workspace dependencies are not built yet:$_missing"
    # shellcheck disable=SC2086
    turbo_run build $_missing
    blank
}

cmd_dev() {
    local _dir _name _var _port _api
    [ "$#" -ge 1 ] || die "a target is required." \
        "Usage: make dev-web APP=account   (aliases: sdk, react, ui, account)"
    _dir=$(resolve_target "$1") || exit 1
    _name=$(pkg_name "$_dir")
    ensure_install

    pkg_has_script "$_dir" dev ||
        die "$_name has no \"dev\" script." "Build it instead: make build-js TARGET=$1"

    ensure_workspace_deps "$_dir"

    # Applications read their port from .env through dotenv-cli, so a busy port
    # can be reported here by name rather than as a Next.js stack trace.
    _var=$(app_port_var "$_dir")
    _port=$(env_get "$_var")
    if [ -n "$_port" ] && port_listening "$_port"; then
        die "$_name's port $_port ($_var in .env) is already in use by $(describe_port "$_port")." \
            "Stop it, or change $_var in .env."
    fi

    _api=$(env_get NEXT_PUBLIC_AUTHN_API_URL "http://localhost:$(env_get PORT 8080)")
    if ! curl -fsS -o /dev/null --max-time 2 "$_api/v1/ready" 2>/dev/null; then
        log_warn "the engine at $_api is not answering /v1/ready."
        hint "Sign-in and sign-up will fail until it is running. Start it: make run"
    fi

    log_ok "Starting $_name in development mode${_port:+ on http://localhost:$_port} — press Ctrl-C to stop."
    blank
    exec pnpm --filter "$_name" run dev
}

cmd_start() {
    local _dir _name _var _port
    [ "$#" -ge 1 ] || die "a target is required." "Usage: make start-web APP=account"
    _dir=$(resolve_target "$1") || exit 1
    _name=$(pkg_name "$_dir")
    ensure_install

    pkg_has_script "$_dir" start ||
        die "$_name has no \"start\" script — it is not a long-running application."

    if [ ! -d "$_dir/.next" ] && [ ! -d "$_dir/dist" ]; then
        die "$_name has not been built, and \"start\" serves a production build." \
            "Build it first: make build-web APP=$1"
    fi

    _var=$(app_port_var "$_dir")
    _port=$(env_get "$_var")
    if [ -n "$_port" ] && port_listening "$_port"; then
        die "$_name's port $_port ($_var in .env) is already in use by $(describe_port "$_port")." \
            "Stop it, or change $_var in .env."
    fi

    log_ok "Serving $_name's production build${_port:+ on http://localhost:$_port} — press Ctrl-C to stop."
    blank
    exec pnpm --filter "$_name" run start
}

# ---------------------------------------------------------------------------
# Listing
# ---------------------------------------------------------------------------

cmd_list() {
    local _d _alias _scripts _s _port
    log_step "JavaScript workspaces"
    printf '%s  %-22s %-24s %-9s %s%s\n' "$C_DIM" ALIAS PACKAGE PORT SCRIPTS "$C_RESET"
    for _d in $ALL_PACKAGES $ALL_APPS; do
        _alias=$(dir_alias "$_d")
        if [ ! -f "$_d/package.json" ]; then
            printf '%s  %-22s %-24s %-9s %s%s\n' "$C_YELLOW" \
                "$_alias" "($_d)" "-" "not scaffolded yet" "$C_RESET"
            continue
        fi
        _scripts=""
        for _s in build dev start test lint; do
            pkg_has_script "$_d" "$_s" && _scripts="$_scripts $_s"
        done
        _port=$(env_get "$(app_port_var "$_d")")
        printf '  %-22s %-24s %-9s%s\n' "$_alias" "$(pkg_name "$_d")" "${_port:--}" "$_scripts"
    done
    blank
    log_info "Use an alias with any of: make build-js TARGET=sdk   make dev-web APP=account"
}

_sub=${1:-list}
[ "$#" -ge 1 ] && shift
case "$_sub" in
install) cmd_install ;;
build) cmd_build "$@" ;;
dev) cmd_dev "$@" ;;
start) cmd_start "$@" ;;
test) cmd_test "$@" ;;
lint) cmd_lint "$@" ;;
clean) cmd_clean ;;
list) cmd_list ;;
*) die "unknown subcommand \"$_sub\"." \
    "Usage: scripts/node.sh install|build|dev|start|test|lint|clean|list [target...]" ;;
esac
