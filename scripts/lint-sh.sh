#!/usr/bin/env sh
#
# Authn Platform — checks on the build scripts themselves.
#
# Two problems here that no other target would report:
#
#   Syntax the scripts must not use. /bin/sh is bash on macOS and on some
#   distributions, and bash in POSIX mode still accepts array literals and the
#   `function` keyword — so a script can work for whoever wrote it and fail to
#   parse at all on a machine where /bin/sh really is dash. The parse therefore
#   uses dash whenever it is installed. It is a parse, not an interpretation:
#   `[[ ]]` reads as an ordinary command word and survives until it runs.
#
#   A variable assigned inside a function with no `local` declaration. POSIX sh
#   gives functions no scope of their own, so that variable is a global: a
#   nested call assigning the same name overwrites the caller's copy with no
#   error at all, leaving a wrong value in a message or a decision.
#
# Both checks report everything they find rather than stopping at the first
# problem, so one run shows the whole picture.
#
# Usage: scripts/lint-sh.sh
#
# License: GNU AGPLv3 — Copyright (C) Authn Platform Authors

set -eu

. "$(dirname "$0")/lib.sh"

require_repo_root

# parser prefers dash over whatever /bin/sh happens to be, for the reason given
# above. `sh` is the fallback so the check still runs where dash is absent.
parser() {
    if have dash; then printf 'dash\n'; else printf 'sh\n'; fi
}

check_syntax() {
    local _parser _bad _count _f _out
    _parser=$(parser)
    _bad=0
    _count=0
    log_step "Parsing every script with $_parser"
    for _f in scripts/*.sh; do
        _count=$((_count + 1))
        if ! _out=$("$_parser" -n "$_f" 2>&1); then
            log_err "$_f does not parse:"
            printf '%s\n' "$_out" | sed 's/^/      /' >&2
            _bad=$((_bad + 1))
        fi
    done
    [ "$_bad" -eq 0 ] || return 1
    log_ok "$_count scripts parse cleanly."
}

# check_scope delegates to check-locals.sh, which reads the scripts as data and
# prints one file:function:variable line per undeclared name.
check_scope() {
    local _found
    log_step "Auditing variable scope inside functions"
    _found=$(sh scripts/check-locals.sh scripts/*.sh)
    if [ -z "$_found" ]; then
        log_ok "Every function declares its own variables."
        return 0
    fi
    log_err "these are assigned inside a function without a \`local\` declaration:"
    printf '%s\n' "$_found" | sed 's/^/      /' >&2
    hint ""
    hint "Each line names the file, the function, and the variable to add to its \`local\` line."
    return 1
}

_status=0
check_syntax || _status=1
blank
check_scope || _status=1

if [ "$_status" -ne 0 ]; then
    blank
    die "the build scripts have problems, listed above."
fi
