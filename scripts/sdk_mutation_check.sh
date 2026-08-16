#!/usr/bin/env bash
# Mutation check for the SDK cancellation / provider-lifecycle work.
#
# For each fix, remove or invert the line that implements it and require the
# matching test to fail. A test that still passes against mutated code is pinning
# nothing, whatever colour it prints normally.
set -uo pipefail

ROOT=$(git rev-parse --show-toplevel)
JS=$ROOT/packages/sdk-js
RE=$ROOT/packages/sdk-react

pass=0
fail=0

run_mutation() {
  local name="$1" file="$2" pattern="$3" replacement="$4" pkg="$5" testfile="$6" testname="$7"

  cp "$file" "$file.bak"

  local matched
  matched=$(PATTERN="$pattern" REPL="$replacement" python3 - "$file" <<'PY'
import os, re, sys
path = sys.argv[1]
src = open(path).read()
pat = os.environ["PATTERN"]
n = len(re.findall(pat, src, flags=re.S))
if n == 1:
    open(path, "w").write(re.sub(pat, os.environ["REPL"], src, flags=re.S))
print(n)
PY
)

  if [ "$matched" != "1" ]; then
    echo "SKIP  $name — pattern matched $matched times (expected exactly 1)"
    mv "$file.bak" "$file"
    fail=$((fail + 1))
    return
  fi

  # sdk-react consumes @authn/js from dist, so a mutation there needs a rebuild.
  if [ "$pkg" = "$RE" ] || [ "$file" = "$JS/src/client.ts" ] || [ "$file" = "$JS/src/core/http.ts" ]; then
    (cd "$JS" && npm run build >/dev/null 2>&1)
  fi

  local out
  out=$(cd "$pkg" && npx vitest run "$testfile" -t "$testname" 2>&1)
  local verdict
  if echo "$out" | command grep -qE "^ *Tests +.*failed"; then
    verdict="DETECTED"
    pass=$((pass + 1))
  else
    verdict="SURVIVED"
    fail=$((fail + 1))
    echo "$out" | tail -6
  fi

  mv "$file.bak" "$file"
  printf '%-9s %s\n' "$verdict" "$name"
}

echo "=== sdk-js: HTTP cancellation ==="

run_mutation "entry check on a cancelled lifetime" \
  "$JS/src/core/http.ts" \
  'if \(this\.lifetimeSignal\?\.aborted\) \{\n      throw AuthnError\.cancelled\(path\);\n    \}' \
  '' \
  "$JS" "src/__tests__/cancellation.test.ts" "already-cancelled lifetime"

run_mutation "AbortError disambiguation" \
  "$JS/src/core/http.ts" \
  'throw this\.lifetimeSignal\?\.aborted\n          \? AuthnError\.cancelled\(path\)\n          : AuthnError\.timeout\(path, this\.timeout\);' \
  'throw AuthnError.timeout(path, this.timeout);' \
  "$JS" "src/__tests__/cancellation.test.ts" "not as a timeout"

run_mutation "lifetime linked to the request controller" \
  "$JS/src/core/http.ts" \
  'onLifetimeAbort = \(\) => controller!\.abort\(\);' \
  'onLifetimeAbort = () => undefined;' \
  "$JS" "src/__tests__/cancellation.test.ts" "not as a timeout"

run_mutation "backoff wakes on cancellation" \
  "$JS/src/core/http.ts" \
  'await sleep\(delay, this\.lifetimeSignal\);\n        return this\.request<T>\(' \
  'await sleep(delay);\n        return this.request<T>(' \
  "$JS" "src/__tests__/cancellation.test.ts" "mid-backoff"

run_mutation "per-request headers survive a retry" \
  "$JS/src/core/http.ts" \
  'attempt \+ 1,\n        isRetryAfterRefresh,\n        extraHeaders,\n      \);\n    \}\n\n    if \(response\.status === 204\)' \
  'attempt + 1,\n        isRetryAfterRefresh,\n      );\n    }\n\n    if (response.status === 204)' \
  "$JS" "src/__tests__/cancellation.test.ts" "retried attempt"

run_mutation "destroy aborts the lifetime" \
  "$JS/src/client.ts" \
  'this\.lifetime\?\.abort\(\);' \
  '' \
  "$JS" "src/__tests__/cancellation.test.ts" "already in flight"

echo
echo "=== sdk-react: provider lifecycle ==="

run_mutation "spent client replaced on re-setup" \
  "$RE/src/provider.tsx" \
  'if \(client\.isDestroyed\(\)\) \{.*?\n      return;\n    \}\n' \
  '' \
  "$RE" "src/__tests__/provider_lifecycle.test.tsx" "double mount"

run_mutation "only an owned client is destroyed" \
  "$RE/src/provider.tsx" \
  'if \(ownsClient\) \{\n        client\.destroy\(\);' \
  'if (true) {\n        client.destroy();' \
  "$RE" "src/__tests__/provider_lifecycle.test.tsx" "did not create"

run_mutation "a swapped-in client is adopted" \
  "$RE/src/provider.tsx" \
  'if \(externalClient && externalClient !== client\) \{\n    setClient\(externalClient\);\n    setUser\(externalClient\.getUser\(\)\);\n    setSession\(externalClient\.getSession\(\)\);\n  \}' \
  '' \
  "$RE" "src/__tests__/provider_lifecycle.test.tsx" "supplied later"

echo
echo "=== restoring and rebuilding ==="
(cd "$JS" && npm run build >/dev/null 2>&1)
echo "detected: $pass   survived/skipped: $fail"
[ "$fail" -eq 0 ]
