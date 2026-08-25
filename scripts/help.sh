#!/usr/bin/env sh
#
# Authn Platform — the Makefile's own documentation.
#
# Both jobs here read the Makefile as data: the target list is whatever the
# Makefile currently documents, so a target added without touching this script
# still appears in the help and still turns up as a suggestion.
#
# Usage: scripts/help.sh list
#        scripts/help.sh unknown <name>
#
# License: GNU AGPLv3 — Copyright (C) Authn Platform Authors

set -eu

. "$(dirname "$0")/lib.sh"

MAKEFILE="${MAKEFILE:-Makefile}"

# A documented target is one with a `##` comment on its rule line. `##@` opens a
# group heading. Anything else in the Makefile is machinery, not interface.
TARGET_RE='^[a-zA-Z0-9_-]+:[^=]*##[^@]'

cmd_list() {
    # lib.sh has already decided whether colour is appropriate for this output,
    # so its verdict is reused rather than tested a second time here.
    awk -v color="$([ -n "$C_RESET" ] && printf 1 || printf 0)" '
        function paint(c, s) { return color ? "\033[" c "m" s "\033[0m" : s }
        /^##@/ { printf "\n%s\n", paint("1", substr($0, 5)); next }
        /'"$TARGET_RE"'/ {
            split($0, parts, "## ")
            target = substr($0, 1, index($0, ":") - 1)
            printf "  %s %s\n", paint("36", sprintf("%-16s", target)), parts[2]
        }
    ' "$MAKEFILE"
    blank
    printf '  Variables: %s\n\n' \
        "APP= TARGET= NAME= PORT= SERVICE= YES=1 SKIP_DEPS=1 NO_CACHE=1"
}

# target_names prints every documented target, one per line. awk rather than sed
# because the pattern is an extended regular expression, where sed would read
# the `+` as a literal plus and match nothing.
target_names() {
    awk '/'"$TARGET_RE"'/ { print substr($0, 1, index($0, ":") - 1) }' "$MAKEFILE" | sort -u
}

# rank_matches scores each target against a name that does not exist and prints
# the plausible ones, closest first.
#
# Edit distance alone is not enough: "buld-sdk" is four edits from "build-sdk"
# by no reasonable threshold on a short string, yet the shared "sdk" makes the
# intent obvious. So a target sharing a hyphen-separated word is always offered,
# ranked by how close the rest of the name is.
rank_matches() {
    target_names | awk -v want="$1" '
        function lev(a, b,   la, lb, i, j, d, cost, prev, cur) {
            la = length(a); lb = length(b)
            for (j = 0; j <= lb; j++) prev[j] = j
            for (i = 1; i <= la; i++) {
                cur[0] = i
                for (j = 1; j <= lb; j++) {
                    cost = (substr(a, i, 1) == substr(b, j, 1)) ? 0 : 1
                    d = prev[j] + 1
                    if (cur[j - 1] + 1 < d) d = cur[j - 1] + 1
                    if (prev[j - 1] + cost < d) d = prev[j - 1] + cost
                    cur[j] = d
                }
                for (j = 0; j <= lb; j++) prev[j] = cur[j]
            }
            return prev[lb]
        }
        # shares_word is true when a word of three or more characters appears in
        # both names. Two-character words are too common to mean anything.
        function shares_word(a, b,   n, m, i, j, aw, bw) {
            n = split(a, aw, "-"); m = split(b, bw, "-")
            for (i = 1; i <= n; i++)
                for (j = 1; j <= m; j++)
                    if (length(aw[i]) >= 3 && aw[i] == bw[j]) return 1
            return 0
        }
        BEGIN { limit = length(want) / 3; if (limit < 2) limit = 2 }
        {
            d = lev(want, $0)
            shared = shares_word(want, $0)
            substring = (index($0, want) || index(want, $0))
            if (!shared && !substring && d > limit) next
            # Shared words and substrings outrank a merely small edit distance,
            # so an obvious intent is not buried under coincidental neighbours.
            printf "%d\t%s\n", (shared || substring) ? d : d + 100, $0
        }
    ' | sort -n | head -6 | cut -f2-
}

cmd_unknown() {
    local _want _matches
    _want=${1:-}
    # Everything here goes to stderr: this is make's failure output, and a
    # developer piping stdout to a file still needs to see why nothing ran.
    printf '\n' >&2
    log_err "there is no target named \"$_want\"."
    _matches=$(rank_matches "$_want")
    if [ -n "$_matches" ]; then
        printf '\n  Did you mean:\n' >&2
        printf '%s\n' "$_matches" | sed 's/^/      make /' >&2
    fi
    printf '\n' >&2
    hint "Every target: make help"
    hint "Check the environment: make doctor"
    printf '\n' >&2
    exit 2
}

case "${1:-list}" in
list) cmd_list ;;
unknown) shift && cmd_unknown "${1:-}" ;;
*) die "unknown subcommand \"$1\"." "Usage: scripts/help.sh list|unknown <name>" ;;
esac
