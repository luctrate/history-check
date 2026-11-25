#!/bin/sh
# history-check.sh — read-only scan for credentials in shell history.
#
#   Secrets end up in shell history because the shell records the command LINE.
#   `export TOKEN=s3cr3t` is stored verbatim, forever, in a plain-text file.
#   (Command OUTPUT is never recorded, so `cat .env` leaks nothing by itself.)
#
# THIS SCRIPT ONLY READS. It opens history files read-only, never writes to
# them, never phones home, and prints every finding with the secret masked.
# To clean up afterwards, use history-redact.sh.
#
#   ./history-check.sh              scan default history files
#   ./history-check.sh --json       machine-readable output
#   ./history-check.sh FILE...      scan specific files
#
# Exit: 0 = clean, 1 = findings, 2 = usage/error.
#
# Supports macOS and Linux; bash, zsh, fish, ksh + REPL histories.
# https://github.com/luctrate/history-check

set -u

VERSION='1.0.0'
WIDTH=120
JSON=0
SHOW_ADVISORY=1
FILES=''

# >>> PATTERNS (generated from lib-patterns.sh — do not edit by hand) >>>
# lib-patterns.sh — shared secret-detection table.
#
# This file is the SOURCE OF TRUTH. It is inlined verbatim into history-check.sh
# and history-redact.sh by ./build.sh so each script stays standalone and
# auditable in a single read. Do not edit the generated blocks by hand.
#
# Table format, one pattern per line:
#     NAME@@@EXTENDED_REGEX@@@SED_REPLACEMENT
#
# Conventions that keep check/redact behaviour identical:
#   * POSIX ERE only. No \b, no \d, no lazy quantifiers, no lookaround --
#     BSD (macOS) and GNU grep/sed must agree.
#   * Capture group \1 holds the non-secret prefix worth keeping (the variable
#     name, the flag, the key prefix) so output stays readable and greppable.
#   * Every replacement contains the literal string REDACTED, which is what
#     makes redaction idempotent -- see already_clean() in the scripts.

REDACT_MARK='REDACTED'

secret_patterns() {
    cat <<'PATEOF'
Private key@@@(-----BEGIN[A-Z0-9 _-]*PRIVATE KEY-----).*@@@\1REDACTED
JSON web token@@@eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}@@@eyJ.REDACTED.jwt
Bearer token@@@([Bb]earer[ 	]+)[A-Za-z0-9._~+/-]{16,}=*@@@\1REDACTED
Authorization header@@@([Aa]uthorization["']?[ 	]*[:=][ 	]*["']?([Bb]asic|[Tt]oken)[ 	]+)[A-Za-z0-9._~+/-]{8,}=*@@@\1REDACTED
curl user password@@@(curl.*[ 	](-u|--user)(=|[ 	]+)["']?[^:[:space:]"']*:)[^[:space:]"']+@@@\1REDACTED
URL password@@@([a-zA-Z][a-zA-Z0-9+.-]{1,31}://[^[:space:]/?#@"'<>:]*:)[^[:space:]/?#@"'<>]+@@@@\1REDACTED@
Connection string password@@@([?&;]([Pp]assword|[Pp]wd|PASSWORD)=)[^&;[:space:]"']+@@@\1REDACTED
AWS secret access key@@@([Aa][Ww][Ss]_[Ss][Ee][Cc][Rr][Ee][Tt]_[Aa][Cc][Cc][Ee][Ss][Ss]_[Kk][Ee][Yy]["']?[ 	]*[:=][ 	]*["']?)[A-Za-z0-9/+]{40,}@@@\1REDACTED
Credential variable@@@([A-Z0-9_]*(SECRET|TOKEN|PASSWORD|PASSWD|PASSPHRASE|_PWD|API_?KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY|SECRET_KEY|CREDENTIALS?|AUTH)S?[ 	]*=[ 	]*["']?)[^[:space:]"'$,;)]{6,}@@@\1REDACTED
Credential setting@@@([A-Za-z0-9_.-]*([Pp]assw(or)?d|[Pp]assphrase|[Ss]ecret|[Aa]pi[_-]?[Kk]ey|[Aa]ccess[_-]?[Kk]ey|[Aa]uth[_-]?[Tt]oken|[Cc]lient[_-]?[Ss]ecret|[Tt]oken)["']?[ 	]*(:=|=>|\?=|[=:])[ 	]*["']?)[^[:space:]"'$,;)]{6,}@@@\1REDACTED
Credential flag@@@(--(password|passwd|token|api-key|apikey|secret|client-secret|auth-token|access-token)(=|[ 	]+)["']?)[^[:space:]"']{4,}@@@\1REDACTED
Anthropic API key@@@sk-ant-(api|admin|oat|ort)[0-9]{2}-[A-Za-z0-9_-]{20,}@@@sk-ant-REDACTED
OpenAI API key@@@sk-(proj|svcacct|admin)-[A-Za-z0-9_-]{20,}@@@sk-REDACTED
OpenAI API key (legacy)@@@sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}@@@sk-REDACTED
OpenRouter API key@@@sk-or-v1-[a-f0-9]{64}@@@sk-or-v1-REDACTED
Groq API key@@@gsk_[A-Za-z0-9]{52}@@@gsk_REDACTED
xAI API key@@@xai-[A-Za-z0-9]{60,}@@@xai-REDACTED
Perplexity API key@@@pplx-[A-Za-z0-9]{48}@@@pplx-REDACTED
GitHub token@@@(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}@@@\1_REDACTED
GitHub fine-grained PAT@@@github_pat_[A-Za-z0-9_]{60,}@@@github_pat_REDACTED
GitLab token@@@glpat-[A-Za-z0-9_-]{20,}@@@glpat-REDACTED
Stripe secret key@@@(sk|rk)_(live|test)_[A-Za-z0-9]{10,}@@@\1_\2_REDACTED
AWS access key id@@@(AKIA|ASIA)[0-9A-Z]{16}@@@\1REDACTED
Google API key@@@AIza[A-Za-z0-9_-]{35}@@@AIzaREDACTED
Slack token@@@xox[baprs]-[A-Za-z0-9-]{10,}@@@xox-REDACTED
Slack webhook@@@(hooks\.slack\.com/services/)[A-Za-z0-9/+]{20,}@@@\1REDACTED
Atlassian API token@@@(ATATT|ATCTT)[A-Za-z0-9_=-]{20,}@@@\1REDACTED
Hugging Face token@@@hf_[A-Za-z0-9]{30,}@@@hf_REDACTED
npm token@@@npm_[A-Za-z0-9]{36}@@@npm_REDACTED
PyPI token@@@pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}@@@pypi-REDACTED
SendGrid API key@@@SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}@@@SG.REDACTED
DigitalOcean token@@@dop_v1_[a-f0-9]{64}@@@dop_v1_REDACTED
Doppler token@@@dp\.pt\.[A-Za-z0-9]{40,}@@@dp.pt.REDACTED
Notion integration token@@@(ntn_|secret_)[A-Za-z0-9]{40,}@@@\1REDACTED
Telegram bot token@@@[0-9]{8,10}:AA[A-Za-z0-9_-]{33}@@@REDACTED-telegram
Twilio API key@@@SK[0-9a-f]{32}@@@SKREDACTED
PATEOF
}

# Habits worth flagging but NOT redacting: the command text itself holds no
# secret (a shell never records command OUTPUT), it just shows a risky pattern.
advisory_patterns() {
    cat <<'ADVEOF'
Reading a .env file@@@(cat|bat|less|more|head|tail|source|\.)[ 	]+[^ 	]*\.env
Echoing a secret variable@@@echo[ 	]+[$]{1,2}[{]?[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|KEY)
Exporting from .env inline@@@(export|set -x|set -gx)[ 	].*\.env
ADVEOF
}

# Emit a sed script: one s%%%g command per line, fed via `sed -f`.
#
# Why a script file and not shell arguments: several patterns contain spaces
# (e.g. "PRIVATE KEY"), and `sed -E $(...)` would word-split them into garbage.
# Why `%` as the delimiter and not `/`: patterns contain slashes (`://`,
# character classes like [A-Za-z0-9/+]). No pattern contains `%`; build.sh
# asserts that.
build_sed_script() {
    secret_patterns | while IFS= read -r line; do
        [ -z "$line" ] && continue
        pat=${line#*@@@}; pat=${pat%@@@*}
        rep=${line##*@@@}
        printf 's%%%s%%%s%%g\n' "$pat" "$rep"
    done
}
# <<< PATTERNS <<<

usage() {
    cat <<'USAGEEOF'
history-check — read-only scan for secrets in shell history

USAGE
    ./history-check.sh [options] [FILE...]

OPTIONS
    --json           machine-readable output (for agents/CI)
    --no-advisory    skip risky-habit notes, report only secrets
    --width N        truncate displayed lines to N chars (default 120)
    --plain          disable colour
    -h, --help       this text

This script never modifies anything. Secrets are masked in all output.
USAGEEOF
}

while [ $# -gt 0 ]; do
    case $1 in
        --json)        JSON=1 ;;
        --no-advisory) SHOW_ADVISORY=0 ;;
        --width)       shift; WIDTH=${1:-120} ;;
        --plain)       NO_COLOR=1 ;;
        -h|--help)     usage; exit 0 ;;
        -*)            printf 'unknown option: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
        *)             FILES="$FILES $1" ;;
    esac
    shift
done

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    B=$(printf '\033[1m'); DIM=$(printf '\033[2m'); RED=$(printf '\033[31m')
    YEL=$(printf '\033[33m'); GRN=$(printf '\033[32m'); CYA=$(printf '\033[36m')
    Z=$(printf '\033[0m')
else
    B=''; DIM=''; RED=''; YEL=''; GRN=''; CYA=''; Z=''
fi

TMP=$(mktemp "${TMPDIR:-/tmp}/histcheck.XXXXXX") || exit 2
TMPA=$(mktemp "${TMPDIR:-/tmp}/histcheckA.XXXXXX") || exit 2
TMPD=$(mktemp "${TMPDIR:-/tmp}/histcheckD.XXXXXX") || exit 2
cleanup() { rm -f "$TMP" "$TMPA" "$TMPD" "$SEDF"; }
trap cleanup EXIT INT TERM

# Mask every known secret shape in whatever flows through, so that NOTHING we
# print can contain live credential material -- even for a pattern that only
# partially matched the line we are showing.
SEDF=$(mktemp "${TMPDIR:-/tmp}/histsed.XXXXXX") || exit 2
build_sed_script > "$SEDF"
redact_stream() {
    sed -E -f "$SEDF"
}

# Default search set. Covers the three mainstream shells plus the REPL
# histories people forget about -- psql and mysql in particular love to store
# connection strings with inline passwords.
default_files() {
    cat <<FEOF
$HOME/.bash_history
$HOME/.zsh_history
$HOME/.zhistory
$HOME/.histfile
$HOME/.sh_history
$HOME/.ksh_history
$HOME/.local/share/fish/fish_history
$HOME/.config/fish/fish_history
${XDG_DATA_HOME:-$HOME/.local/share}/fish/fish_history
${XDG_STATE_HOME:-$HOME/.local/state}/bash/history
$HOME/.python_history
$HOME/.node_repl_history
$HOME/.psql_history
$HOME/.mysql_history
$HOME/.irb_history
$HOME/.sqlite_history
$HOME/.rediscli_history
$HOME/.mongodb/mongosh/mongosh_repl_history
$HOME/.Rhistory
$HOME/.php_history
${HISTFILE:-}
FEOF
}

# Resolve the file list: explicit args win, otherwise the default set.
resolve_files() {
    if [ -n "$(printf '%s' "$FILES" | tr -d ' ')" ]; then
        printf '%s\n' $FILES
    else
        default_files
    fi | awk 'NF' | sort -u | while IFS= read -r f; do
        [ -f "$f" ] && [ -r "$f" ] && printf '%s\n' "$f"
    done
}

entry_count() {
    case $1 in
        *fish_history) grep -a '^- cmd: ' "$1" 2>/dev/null | awk 'END{print NR+0}' ;;
        *)             awk 'NF{n++} END{print n+0}' "$1" 2>/dev/null ;;
    esac
}

# Collect findings into $TMP as: file \t lineno \t pattern \t masked-text
scan_file() {
    f=$1
    secret_patterns | while IFS= read -r row; do
        [ -z "$row" ] && continue
        name=${row%%@@@*}
        rest=${row#*@@@}
        pat=${rest%@@@*}
        grep -anE "$pat" "$f" 2>/dev/null | while IFS= read -r hit; do
            ln=${hit%%:*}
            txt=${hit#*:}
            # Strip fish/zsh metadata so the displayed command is readable.
            txt=$(printf '%s' "$txt" | sed -E 's/^- cmd: //; s/^: [0-9]+:[0-9]+;//')
            full=$(printf '%s' "$txt" | redact_stream)
            # Already-redacted lines still match the patterns (the literal
            # "REDACTED" is 8 chars, long enough to look like a value). If
            # redaction would not change the line, there is no live secret on
            # it. This is the same gate history-redact.sh uses, so check and
            # redact can never disagree.
            [ "$full" = "$txt" ] && continue
            masked=$(printf '%s' "$full" | cut -c1-"$WIDTH")
            printf '%s\t%s\t%s\t%s\n' "$f" "$ln" "$name" "$masked"
        done
    done
}

scan_advisory() {
    f=$1
    advisory_patterns | while IFS= read -r row; do
        [ -z "$row" ] && continue
        name=${row%%@@@*}
        pat=${row##*@@@}
        n=$(grep -aE "$pat" "$f" 2>/dev/null | awk 'END{print NR+0}')
        [ "$n" -gt 0 ] && printf '%s\t%s\t%s\n' "$f" "$name" "$n"
    done
}

FILELIST=$(resolve_files)
if [ -z "$FILELIST" ]; then
    if [ "$JSON" = 1 ]; then
        printf '{"version":"%s","files_scanned":0,"findings":[],"error":"no readable history files found"}\n' "$VERSION"
    else
        printf '%sNo readable history files found.%s\n' "$YEL" "$Z"
        printf 'Pass a path explicitly:  ./history-check.sh ~/.bash_history\n'
    fi
    exit 2
fi

: > "$TMP"; : > "$TMPA"
printf '%s\n' "$FILELIST" | while IFS= read -r f; do
    scan_file "$f" >> "$TMP"
    [ "$SHOW_ADVISORY" = 1 ] && scan_advisory "$f" >> "$TMPA"
done

# Dedupe, then order by file and by line NUMERICALLY (plain sort puts 10 < 3).
sort -u "$TMP" | sort -t"$(printf '\t')" -k1,1 -k2,2n -o "$TMP"
TOTAL=$(awk 'END{print NR+0}' "$TMP")
AFFECTED=$(cut -f1 "$TMP" | sort -u | awk 'END{print NR+0}')
NFILES=$(printf '%s\n' "$FILELIST" | awk 'NF{n++} END{print n+0}')
UNIQ_LINES=$(cut -f1,2 "$TMP" | sort -u | awk 'END{print NR+0}')

if [ "$JSON" = 1 ]; then
    printf '{"version":"%s","files_scanned":%s,"files_affected":%s,' "$VERSION" "$NFILES" "$AFFECTED"
    printf '"commands_affected":%s,"findings_total":%s,"findings":[' "$UNIQ_LINES" "$TOTAL"
    first=1
    while IFS="$(printf '\t')" read -r f ln name masked; do
        [ -z "${f:-}" ] && continue
        [ "$first" = 0 ] && printf ','
        first=0
        esc=$(printf '%s' "$masked" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
        printf '{"file":"%s","line":%s,"pattern":"%s","masked":"%s"}' "$f" "$ln" "$name" "$esc"
    done < "$TMP"
    printf ']}\n'
    [ "$TOTAL" -gt 0 ] && exit 1 || exit 0
fi

printf '\n%shistory-check%s %sv%s%s  %s(read-only — nothing is modified)%s\n\n' \
    "$B" "$Z" "$DIM" "$VERSION" "$Z" "$DIM" "$Z"

printf '%sScanned%s\n' "$B" "$Z"
printf '%s\n' "$FILELIST" | while IFS= read -r f; do
    printf '  %-58s %s%s entries%s\n' "$(printf '%s' "$f" | sed "s|^$HOME|~|")" "$DIM" "$(entry_count "$f")" "$Z"
done
printf '\n'

if [ "$TOTAL" -eq 0 ]; then
    printf '%s✓ No credentials found in your shell history.%s\n\n' "$GRN" "$Z"
else
    printf '%s%s⚠  %s command%s in your history contain%s a credential%s %s(%s total matches)%s\n\n' \
        "$B" "$RED" "$UNIQ_LINES" "$([ "$UNIQ_LINES" -eq 1 ] || echo s)" \
        "$([ "$UNIQ_LINES" -eq 1 ] && echo s)" "$Z" "$DIM" "$TOTAL" "$Z"
    # One row per command: several patterns often match the same line (a
    # GitHub token is also a "Credential variable"), so join their names.
    awk 'BEGIN{FS=OFS="\t"} {
        k = $1 FS $2
        if (!(k in seen)) { seen[k] = 1; order[++n] = k; masked[k] = $4 }
        if (!((k SUBSEP $3) in pn)) {
            pn[k SUBSEP $3] = 1
            names[k] = (k in names) ? names[k] ", " $3 : $3
        }
    } END { for (i = 1; i <= n; i++) { k = order[i]; split(k, a, FS); print a[1], a[2], names[k], masked[k] } }' "$TMP" > "$TMPD"
    lastf=''
    while IFS="$(printf '\t')" read -r f ln name masked; do
        [ -z "${f:-}" ] && continue
        if [ "$f" != "$lastf" ]; then
            printf '%s%s%s\n' "$CYA" "$(printf '%s' "$f" | sed "s|^$HOME|~|")" "$Z"
            lastf=$f
        fi
        printf '  %s%6s%s  %s%-34s%s %s\n' "$DIM" "$ln" "$Z" "$YEL" "$name" "$Z" "$masked"
    done < "$TMPD"
    printf '\n%sBy type%s\n' "$B" "$Z"
    cut -f3 "$TMP" | sort | uniq -c | sort -rn | while read -r n name; do
        printf '  %s%4s%s  %s\n' "$B" "$n" "$Z" "$name"
    done
    printf '\n'
fi

if [ "$SHOW_ADVISORY" = 1 ] && [ -s "$TMPA" ]; then
    printf '%sRisky habits%s %s(no secret in the command itself — shells never record output)%s\n' \
        "$B" "$Z" "$DIM" "$Z"
    cut -f2,3 "$TMPA" | awk -F'\t' '{a[$1]+=$2} END {for (k in a) printf "  %4d  %s\n", a[k], k}' | sort -rn
    printf '\n'
fi

if [ "$TOTAL" -gt 0 ]; then
    printf '%sNext%s\n' "$B" "$Z"
    printf '  1. %sRotate these credentials.%s Redacting history does not un-leak them —\n' "$B" "$Z"
    printf '     backups, Time Machine and search indexes may still hold the old file.\n'
    printf '  2. Clean the history files:  %s./history-redact.sh%s   (dry-run by default)\n' "$B" "$Z"
    printf '  3. Prevent a repeat:         see the Prevention section in README.md\n\n'
    exit 1
fi
exit 0
