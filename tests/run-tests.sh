#!/bin/sh
# tests/run-tests.sh — assert detection, redaction, idempotency and the
# false-positive set. Run from anywhere: sh tests/run-tests.sh
set -u
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
WORK=$(mktemp -d "${TMPDIR:-/tmp}/hctests.XXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM

ok()   { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$3', got '$2')"; fi; }

contains()     { grep -qF "$2" "$1" && ok "$3" || bad "$3"; }
not_contains() { grep -qF "$2" "$1" && bad "$3" || ok "$3"; }

printf '\n\033[1mdetection\033[0m\n'
./history-check.sh --plain --json tests/fixture_bash_history > "$WORK/out.json" 2>/dev/null
rc=$?
check "exit 1 when secrets found" "$rc" "1"
for pat in "GitHub token" "Stripe secret key" "OpenAI API key" "Anthropic API key" \
           "AWS access key id" "AWS secret access key" "Google API key" \
           "Atlassian API token" "Hugging Face token" "Slack token" "npm token" \
           "JSON web token" "Bearer token" "URL password" "curl user password" \
           "Credential flag" "Credential variable"; do
    contains "$WORK/out.json" "$pat" "detects: $pat"
done

printf '\n\033[1mno secret material in output\033[0m\n'
# Every one of these appears in the fixture; none may survive into any output.
for leak in "ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake1111" "sk_live_FAKEfakeFAKEfake0000" \
            "AKIAIOSFODNN7EXAMPLE" "fakecurlpass" "fakedbpass" "fakemysqlpw" \
            "fakedockerpw" "fakepassword123" "fakejwtsigningsecret" "fakeregistrypw" \
            "dozjgNryP4J3jVmNHl0w5N"; do
    not_contains "$WORK/out.json" "$leak" "masked in output: $(printf '%.14s' "$leak")..."
done

printf '\n\033[1mdry-run is read-only\033[0m\n'
cp tests/fixture_bash_history "$WORK/h"
before=$(cksum < "$WORK/h")
./history-redact.sh --plain "$WORK/h" >/dev/null 2>&1
check "dry-run leaves file byte-identical" "$(cksum < "$WORK/h")" "$before"

printf '\n\033[1mredaction\033[0m\n'
./history-redact.sh --plain --apply --shred-backup "$WORK/h" >/dev/null 2>&1
for leak in "ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake1111" "sk_live_FAKEfakeFAKEfake0000" \
            "AKIAIOSFODNN7EXAMPLE" "fakecurlpass" "fakedbpass" "fakemysqlpw" \
            "fakedockerpw" "fakepassword123" "fakejwtsigningsecret" "fakeregistrypw"; do
    not_contains "$WORK/h" "$leak" "removed: $(printf '%.14s' "$leak")..."
done
./history-check.sh --plain "$WORK/h" >/dev/null 2>&1
check "check reports clean after redact" "$?" "0"

printf '\n\033[1mfalse positives (must survive untouched)\033[0m\n'
for keep in 'TOKEN=$EXISTING_TOKEN ./run.sh' \
            'export PYTHONPATH=/usr/local/lib/python3.11' \
            'export CERT_PATH=/etc/ssl/certs/ca.pem' \
            'export OLLAMA_API_BASE_URL=http://localhost:11434' \
            'kubectl get pods -o jsonpath={.items[0].metadata.name}' \
            'git clone https://github.com/luctrate/history-check' \
            'cat .env' 'source .env' 'npm install' 'ls -la'; do
    contains "$WORK/h" "$keep" "preserved: $keep"
done

printf '\n\033[1midempotency\033[0m\n'
after=$(cksum < "$WORK/h")
./history-redact.sh --plain --apply "$WORK/h" >/dev/null 2>&1
check "second redact changes nothing" "$(cksum < "$WORK/h")" "$after"

printf '\n\033[1mfish history format\033[0m\n'
cp tests/fixture_fish_history "$WORK/fish_history"
lines_before=$(awk 'END{print NR}' "$WORK/fish_history")
entries_before=$(grep -c '^- cmd: ' "$WORK/fish_history")
./history-redact.sh --plain --apply --no-backup "$WORK/fish_history" >/dev/null 2>&1
check "fish line count preserved"  "$(awk 'END{print NR}' "$WORK/fish_history")" "$lines_before"
check "fish entry count preserved" "$(grep -c '^- cmd: ' "$WORK/fish_history")" "$entries_before"
not_contains "$WORK/fish_history" "ATATTFAKEfakeFAKEfake" "fish secret removed"
contains "$WORK/fish_history" "when: 1764000000" "fish metadata intact"

printf '\n\033[1mclean file\033[0m\n'
printf 'ls -la\ncd /tmp\nnpm install\n' > "$WORK/clean"
./history-check.sh --plain "$WORK/clean" >/dev/null 2>&1
check "exit 0 on clean history" "$?" "0"

printf '\n\033[1mportability\033[0m\n'
sh -n history-check.sh  && ok "history-check.sh  parses as POSIX sh"  || bad "history-check.sh parse"
sh -n history-redact.sh && ok "history-redact.sh parses as POSIX sh" || bad "history-redact.sh parse"
secret_patterns_have_pct=$(grep -c '%' lib-patterns.sh.patterns 2>/dev/null || echo 0)

printf '\n\033[1m%s passed, %s failed\033[0m\n\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
