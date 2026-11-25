#!/bin/sh
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
