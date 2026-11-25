#!/bin/sh
# history-redact.sh — replace credential VALUES in shell history with REDACTED.
#
# Commands are preserved, only the secret value is replaced, so your history
# stays searchable:
#     export STRIPE_KEY=sk_live_51H...   ->   export STRIPE_KEY=REDACTED
#
# DRY-RUN BY DEFAULT. Nothing is written until you pass --apply.
#
#   ./history-redact.sh                 show what would change
#   ./history-redact.sh --apply         write the changes (keeps a backup)
#   ./history-redact.sh --apply --shred-backup
#
# Exit: 0 = nothing to do / success, 1 = changes pending (dry-run), 2 = error.
#
# Run history-check.sh first to see what is there.
# https://github.com/luctrate/history-check

set -u

VERSION='1.0.0'
APPLY=0
SHRED=0
KEEP_BACKUP=1
FILES=''
STAMP=$(date +%Y%m%d-%H%M%S)

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
history-redact — replace secret values in shell history with REDACTED

USAGE
    ./history-redact.sh [options] [FILE...]

OPTIONS
    --apply           actually write changes (default: dry-run only)
    --no-backup       do not keep a .pre-redact backup
    --shred-backup    overwrite + delete the backup once written
    --plain           disable colour
    -h, --help        this text

SAFETY
    Dry-run unless --apply. Keeps a mode-0600 backup beside each file.
    THE BACKUP STILL CONTAINS YOUR SECRETS IN CLEARTEXT -- delete it once
    you have checked the result, or pass --shred-backup.

    Idempotent: re-running finds nothing, it will not re-mangle REDACTED.
USAGEEOF
}

while [ $# -gt 0 ]; do
    case $1 in
        --apply)        APPLY=1 ;;
        --no-backup)    KEEP_BACKUP=0 ;;
        --shred-backup) SHRED=1 ;;
        --plain)        NO_COLOR=1 ;;
        -h|--help)      usage; exit 0 ;;
        -*)             printf 'unknown option: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
        *)              FILES="$FILES $1" ;;
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

SEDF=$(mktemp "${TMPDIR:-/tmp}/histsed.XXXXXX") || exit 2
build_sed_script > "$SEDF"
trap 'rm -f "$SEDF"' EXIT INT TERM
redact_stream() {
    sed -E -f "$SEDF"
}

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

resolve_files() {
    if [ -n "$(printf '%s' "$FILES" | tr -d ' ')" ]; then
        printf '%s\n' $FILES
    else
        default_files
    fi | awk 'NF' | sort -u | while IFS= read -r f; do
        [ -f "$f" ] && [ -r "$f" ] && [ -w "$f" ] && printf '%s\n' "$f"
    done
}

# A live shell holds its history in memory and rewrites the file when it exits,
# which can resurrect what we just removed. Warn loudly -- this is the single
# most common way a history cleanup silently fails.
warn_live_shells() {
    n=0
    for s in bash zsh fish ksh; do
        c=$(pgrep -x "$s" 2>/dev/null | grep -c . || true)
        [ "${c:-0}" -gt 0 ] && n=$((n + c))
    done
    # Our own shell is one of them; anything beyond that is another session.
    if [ "$n" -gt 1 ]; then
        printf '%s%s⚠  %s interactive shell(s) are running.%s\n' "$B" "$YEL" "$n" "$Z"
        printf '   Each keeps history in memory and may rewrite it on exit, undoing this\n'
        printf '   cleanup. Close other terminals, then re-run. (Re-running is safe.)\n\n'
    fi
}

shred_file() {
    # rm -P on BSD / shred on GNU; both best-effort on copy-on-write filesystems
    # such as APFS, btrfs and ZFS, where old blocks can survive. Said plainly in
    # the README rather than pretended away.
    if command -v shred >/dev/null 2>&1; then
        shred -u "$1" 2>/dev/null && return 0
    fi
    rm -P "$1" 2>/dev/null || rm -f "$1"
}

FILELIST=$(resolve_files)
if [ -z "$FILELIST" ]; then
    printf '%sNo writable history files found.%s\n' "$YEL" "$Z"
    exit 2
fi

printf '\n%shistory-redact%s %sv%s%s' "$B" "$Z" "$DIM" "$VERSION" "$Z"
if [ "$APPLY" = 1 ]; then
    printf '  %s%sAPPLY — files will be modified%s\n\n' "$B" "$RED" "$Z"
else
    printf '  %sdry-run — nothing will be modified%s\n\n' "$DIM" "$Z"
fi

[ "$APPLY" = 1 ] && warn_live_shells

TOTAL_CHANGED=0
TOTAL_FILES=0

printf '%s\n' "$FILELIST" | {
while IFS= read -r f; do
    tmp=$(mktemp "${TMPDIR:-/tmp}/histredact.XXXXXX") || exit 2
    redact_stream < "$f" > "$tmp" 2>/dev/null

    if cmp -s "$f" "$tmp"; then
        rm -f "$tmp"
        continue
    fi

    # Count changed lines without ever printing their original content.
    changed=$(diff "$f" "$tmp" 2>/dev/null | grep -c '^>' || echo 0)
    short=$(printf '%s' "$f" | sed "s|^$HOME|~|")
    printf '%s%s%s\n' "$CYA" "$short" "$Z"
    printf '  %s lines with secrets %s\n' "$changed" \
        "$([ "$APPLY" = 1 ] && printf 'redacted' || printf 'would be redacted')"

    if [ "$APPLY" = 1 ]; then
        if [ "$KEEP_BACKUP" = 1 ] && [ "$SHRED" = 0 ]; then
            bak="$f.pre-redact-$STAMP"
            cp "$f" "$bak" && chmod 600 "$bak"
            printf '  %sbackup: %s  (CONTAINS SECRETS — delete it)%s\n' "$YEL" \
                "$(printf '%s' "$bak" | sed "s|^$HOME|~|")" "$Z"
        fi
        cat "$tmp" > "$f"
        chmod 600 "$f"
        printf '  %s✓ written, mode 600%s\n' "$GRN" "$Z"
        if [ "$SHRED" = 1 ] && [ "$KEEP_BACKUP" = 1 ]; then
            printf '  %sbackup shredded%s\n' "$DIM" "$Z"
        fi
    fi
    printf '\n'
    rm -f "$tmp"
    TOTAL_CHANGED=$((TOTAL_CHANGED + changed))
    TOTAL_FILES=$((TOTAL_FILES + 1))
done

if [ "$TOTAL_FILES" -eq 0 ]; then
    printf '%s✓ Nothing to redact — history is already clean.%s\n\n' "$GRN" "$Z"
    exit 0
fi

if [ "$APPLY" = 1 ]; then
    printf '%s✓ %s lines redacted across %s file(s).%s\n\n' "$GRN" "$TOTAL_CHANGED" "$TOTAL_FILES" "$Z"
    printf '%sNow do the part a script cannot do for you:%s\n' "$B" "$Z"
    printf '  • %sRotate every credential that showed up.%s Redaction is not revocation —\n' "$B" "$Z"
    printf '    backups and search indexes may still hold the old file.\n'
    printf '  • Delete the backups once you have checked the result.\n'
    printf '  • Turn on prevention so this cannot recur (see README.md).\n\n'
    exit 0
else
    printf '%s%s lines in %s file(s) would change.%s\n' "$B" "$TOTAL_CHANGED" "$TOTAL_FILES" "$Z"
    printf 'Re-run with %s--apply%s to write them.\n\n' "$B" "$Z"
    exit 1
fi
}
