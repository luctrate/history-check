#!/bin/sh
# build.sh — inline lib-patterns.sh into both scripts so each is standalone.
# Run after editing lib-patterns.sh.
set -eu
cd "$(dirname "$0")"

for target in history-check.sh history-redact.sh; do
    awk '
        /^# >>> PATTERNS/ { print; while ((getline l < "lib-patterns.sh") > 0) {
            if (l ~ /^#!/) continue
            print l
        }; skip = 1; next }
        /^# <<< PATTERNS/ { skip = 0 }
        !skip { print }
    ' "$target" > "$target.new"
    mv "$target.new" "$target"
    chmod +x "$target"
    printf 'built %s (%s lines)\n' "$target" "$(wc -l < "$target" | tr -d ' ')"
done

for target in history-check.sh history-redact.sh; do
    sh -n "$target" && printf 'syntax OK: %s\n' "$target"
done
