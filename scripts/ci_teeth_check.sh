#!/usr/bin/env bash
# CI teeth check.
#
# The pipeline claims to gate the integration suite and the SDK suites. That is
# testable: break a test, then run the command CI runs. A pipeline nobody has
# tried to fool is not known to gate anything.
#
# Each Go case also runs the untagged command over the same break, because
# everything under apps/auth-engine/test/ is behind //go:build integration and an
# untagged run compiles none of it — the failure mode this check exists to catch.
#
# Every mutation is reverted, including on early exit.
set -uo pipefail

ROOT=$(git rev-parse --show-toplevel)
ENGINE=$ROOT/apps/auth-engine
TARGET=$ENGINE/test/logout_test.go
SDKTEST=$ROOT/packages/sdk-js/src/__tests__/cancellation.test.ts

fails=0

restore() {
  [ -f "$TARGET.bak" ] && mv "$TARGET.bak" "$TARGET"
  [ -f "$SDKTEST.bak" ] && mv "$SDKTEST.bak" "$SDKTEST"
  return 0
}
trap restore EXIT

expect() {
  local want="$1" got="$2" label="$3"
  if [ "$want" = "$got" ]; then
    printf '  ok    %s (%s)\n' "$label" "$got"
  else
    printf '  BAD   %s — wanted %s, got %s\n' "$label" "$want" "$got"
    fails=$((fails + 1))
  fi
}

# -count=1 on every Go run: a cached pass would report the mutation as undetected.
status() { if [ "$1" -eq 0 ]; then echo pass; else echo fail; fi; }

echo "=== Go: a broken integration assertion ==="

cp "$TARGET" "$TARGET.bak"
# Invert a status assertion so a successful logout reads as a failure.
python3 - "$TARGET" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = "\tif resp.status != http.StatusOK {"
assert s.count(old) >= 1, "anchor not found"
open(p, "w").write(s.replace(old, "\tif resp.status == http.StatusOK {", 1))
PY

(cd "$ENGINE" && go test -race -count=1 ./... >/dev/null 2>&1)
expect pass "$(status $?)" "untagged run is blind to it"

(cd "$ENGINE" && go test -tags=integration -race -count=1 ./test/... >/dev/null 2>&1)
expect fail "$(status $?)" "tagged run catches it"

mv "$TARGET.bak" "$TARGET"
(cd "$ENGINE" && go test -tags=integration -race -count=1 ./test/... >/dev/null 2>&1)
expect pass "$(status $?)" "restored cleanly"

echo
echo "=== Go: vet over the integration harness ==="

cp "$TARGET" "$TARGET.bak"
# An unkeyed Printf argument — vet's bread and butter, and invisible to the
# compiler, so only a tagged vet can report it.
python3 - "$TARGET" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
i = s.index("func TestLogout")
j = s.index("{", i) + 1
open(p, "w").write(s[:j] + '\n\tt.Logf("%d", "not a number")\n' + s[j:])
PY

(cd "$ENGINE" && go vet ./... >/dev/null 2>&1)
expect pass "$(status $?)" "untagged vet never sees the harness"

(cd "$ENGINE" && go vet -tags=integration ./... >/dev/null 2>&1)
expect fail "$(status $?)" "tagged vet reports it"

mv "$TARGET.bak" "$TARGET"

echo
echo "=== SDK: a broken cancellation assertion ==="

cp "$SDKTEST" "$SDKTEST.bak"
# Expect a cancelled request to report TIMEOUT — the exact confusion the
# cancellation work exists to prevent.
python3 - "$SDKTEST" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = "AuthnErrorCode.CANCELLED"
assert old in s, "anchor not found"
open(p, "w").write(s.replace(old, "AuthnErrorCode.TIMEOUT", 1))
PY

(cd "$ROOT" && pnpm test >/dev/null 2>&1)
expect fail "$(status $?)" "pnpm test catches it"

mv "$SDKTEST.bak" "$SDKTEST"
(cd "$ROOT" && pnpm test >/dev/null 2>&1)
expect pass "$(status $?)" "restored cleanly"

echo
if [ "$fails" -eq 0 ]; then
  echo "all checks behaved as expected"
else
  echo "$fails check(s) did not behave as expected"
fi
[ "$fails" -eq 0 ]
