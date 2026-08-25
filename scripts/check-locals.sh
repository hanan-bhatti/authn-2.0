#!/usr/bin/env sh
#
# Reports underscore-prefixed variables assigned inside a shell function without
# a matching `local` declaration. POSIX sh gives functions no scope of their own,
# so such a variable is a global that a nested call can silently overwrite.
#
# Usage: scripts/check-locals.sh [file...]   (defaults to scripts/*.sh)
#
# License: GNU AGPLv3 — Copyright (C) Authn Platform Authors

set -eu

cd "$(dirname "$0")/.."

awk '
    # A function opens at column zero and closes with a brace at column zero,
    # which is the layout every script here follows.
    /^[a-zA-Z_][a-zA-Z0-9_]*\(\)[[:space:]]*\{/ {
        fn = $0
        sub(/\(\).*/, "", fn)
        depth = 1
        delete declared
        delete assigned
        delete order
        n = 0
        next
    }
    depth == 0 { next }
    /^\}/ {
        for (i = 1; i <= n; i++) {
            v = order[i]
            if (!(v in declared)) printf "%s:%s: %s\n", FILENAME, fn, v
        }
        depth = 0
        next
    }
    {
        line = $0
        # Declarations first: every name in a `local` list is scoped, whether or
        # not it is given a value on the same line.
        if (match(line, /^[[:space:]]*local[[:space:]]/)) {
            rest = substr(line, RSTART + RLENGTH)
            cnt = split(rest, words, /[[:space:]]+/)
            for (i = 1; i <= cnt; i++) {
                name = words[i]
                sub(/=.*/, "", name)
                if (name ~ /^_?[a-zA-Z][a-zA-Z0-9_]*$/) declared[name] = 1
            }
            next
        }
        # Assignments, loop variables and `read` targets are all bindings.
        while (match(line, /(^|[[:space:];({&|]|\|\|)_[a-zA-Z0-9_]+=/)) {
            name = substr(line, RSTART, RLENGTH)
            gsub(/[^_a-zA-Z0-9]/, "", name)
            sub(/=$/, "", name)
            if (!(name in assigned)) { assigned[name] = 1; order[++n] = name }
            line = substr(line, RSTART + RLENGTH)
        }
        line = $0
        while (match(line, /(for|read([[:space:]]+-r)?)[[:space:]]+_[a-zA-Z0-9_]+/)) {
            name = substr(line, RSTART, RLENGTH)
            sub(/^.*[[:space:]]/, "", name)
            if (!(name in assigned)) { assigned[name] = 1; order[++n] = name }
            line = substr(line, RSTART + RLENGTH)
        }
    }
' "$@"
