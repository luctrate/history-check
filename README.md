# history-check

**Your shell saved that token. It's still there.**

Every command you type is appended verbatim to a plain-text file. So this:

```sh
export STRIPE_SECRET_KEY=sk_live_51FAKEfakeFAKEfake0000…
```

is now sitting in `~/.bash_history` (or `~/.zsh_history`, or `~/.local/share/fish/fish_history`) in cleartext, unencrypted, readable by anything that can read your home directory — and copied into every backup you've made since.

Two scripts, no dependencies, macOS + Linux:

| | |
|---|---|
| **`history-check.sh`** | Read-only scan. Shows every finding with the secret masked. Touches nothing. |
| **`history-redact.sh`** | Replaces secret *values* with `REDACTED`, keeping commands searchable. Dry-run by default. |

> **Good news first:** a shell records the command, never its **output**. So `cat .env` leaks nothing by itself. The damage comes from secrets typed *on the command line* — `export TOKEN=…`, `curl -H "Authorization: Bearer …"`, `mysql --password=…`.

---

## Quickest safe way: ask your coding agent

Don't pipe a stranger's script into your shell. If you use Claude Code, Codex, Cursor, Aider or similar, paste this instead — it puts a reviewer between you and the code:

```text
Clone https://github.com/luctrate/history-check into a temp directory.
Before running anything, read history-check.sh and tell me in plain language:
does it write to any file, make any network request, or send data anywhere?
If it is read-only and offline, run it and summarise which of my shell
history files contain credentials, grouped by credential type.
Do not print any secret values — the script masks them, keep them masked.
Then tell me what I should rotate, most urgent first.
```

A correct answer: `history-check.sh` opens files read-only, has no network calls at all, and every finding passes through a masking filter before display. The only thing it writes is temp files in `$TMPDIR` for its own bookkeeping.

To clean up afterwards:

```text
Now run history-redact.sh in dry-run mode and show me what it would change.
If that looks right, run it with --apply. Then remind me which credentials
to rotate, because redacting history does not revoke anything.
```

## Or run it yourself

```sh
git clone https://github.com/luctrate/history-check
cd history-check

sh history-check.sh                    # read-only scan, nothing is modified
sh history-redact.sh                   # dry-run: show what would change
sh history-redact.sh --apply           # write changes (keeps a 0600 backup)
```

Useful flags:

```sh
sh history-check.sh --json             # machine-readable, for agents and CI
sh history-check.sh ~/.bash_history    # scan specific files
sh history-redact.sh --apply --shred-backup
sh tests/run-tests.sh                  # 59 assertions
```

Exit codes: `0` clean · `1` findings (or dry-run with pending changes) · `2` error.

**There is deliberately no `curl … | sh` one-liner in this README.** Handing your shell to an unread script, in a repo about credential hygiene, would be a bit much. Clone it, read it, then run it.

---

## What it looks like

```
history-check v1.0.0  (read-only — nothing is modified)

Scanned
  ~/.bash_history                                            1204 entries
  ~/.local/share/fish/fish_history                           9778 entries

⚠  21 commands in your history contain a credential (34 total matches)

~/.bash_history
       3  Credential variable, GitHub token  export GITHUB_TOKEN=REDACTED
      17  Bearer token, JSON web token       curl -H 'Authorization: Bearer REDACTED' …
      18  URL password                       psql postgres://dbuser:REDACTED@db…
      19  Credential flag                    mysql --user=root --password=REDACTED

Risky habits (no secret in the command itself — shells never record output)
     12  Reading a .env file
```

## What it finds

**By vendor shape** — Anthropic, OpenAI, OpenRouter, Groq, xAI, Perplexity, GitHub (classic + fine-grained), GitLab, Stripe, AWS, Google, Slack (tokens + webhooks), Atlassian, Hugging Face, npm, PyPI, SendGrid, DigitalOcean, Doppler, Notion, Telegram, Twilio.

**By structure** — private key blocks, JWTs, `Authorization: Bearer/Basic/Token`, `curl -u user:pass`, passwords in URLs and connection strings, `--password` / `--token` / `--client-secret` flags, and the generic `*_TOKEN=` / `*_SECRET=` / `*_PASSWORD=` / `*_API_KEY=` family.

**Files searched** — bash, zsh, fish, ksh, plus the REPL histories people forget: `.python_history`, `.node_repl_history`, `.psql_history`, `.mysql_history`, `.irb_history`, `.sqlite_history`, `.rediscli_history`, `.Rhistory`, mongosh. `psql` and `mysql` are worth a look; they happily store connection strings with inline passwords.

## Limitations — read this

- **Values under 6 characters are not matched.** `export TOKEN=aad` is invisible to this tool, and to every tool like it, because a 3-character threshold would flag half your history. Real credentials are long; this only matters for toy values.
- **A high-entropy string with no context is not detectable.** `./deploy xK9mQ2p` could be a password or a build ID. No regex settles that.
- **Redaction is not revocation.** This is the big one. Cleaning your history does nothing about the credential itself — Time Machine snapshots, Spotlight indexes, `rsync` backups and your agent's conversation logs may still hold the old file. **Rotate anything that shows up.**
- **Shredding is best-effort.** On APFS, btrfs and ZFS (copy-on-write), overwriting a file does not reliably overwrite the old blocks. `--shred-backup` does what it can and no more.
- **Live shells fight you.** An open terminal holds its history in memory and rewrites the file on exit, which can resurrect what you just removed. The script warns when it detects other sessions. Close them and re-run — re-running is always safe.

---

## Prevention: the part that actually matters

Cleaning up is a one-time chore. Not leaking again is a setting.

### 1. Stop putting secrets on the command line

The root cause, and the only real fix. Pick whichever fits:

```sh
set -a; . ./.env; set +a      # load a 0600 .env into the environment
chmod 600 .env                 # and keep it that way

direnv allow                   # per-directory env, automatic
op run -- ./deploy.sh          # 1Password; also: aws-vault, doppler run, infisical run
read -rs TOKEN                 # prompt instead of typing it inline
```

### 2. Turn on Atuin's secret filter

[Atuin](https://atuin.sh) replaces your shell history with a searchable SQLite database, and **`secrets_filter` is on by default**. A command matching a known secret pattern is **dropped entirely** — it never reaches the database. Coverage is vendor token shapes plus structural rules (private keys, JWTs, `Bearer`, `curl -u`, URL passwords, `--password` flags, the generic `*_TOKEN=` family), each covered by unit tests in [`secrets/structural.rs`](https://github.com/atuinsh/atuin/blob/main/crates/atuin-common/src/secrets/structural.rs) and [`secrets/vendors.rs`](https://github.com/atuinsh/atuin/blob/main/crates/atuin-common/src/secrets/vendors.rs).

Prevention beats cleanup, so **Atuin is the better permanent answer** and this repo is explicitly not competing with it. Verify it's on in `~/.config/atuin/config.toml`:

```toml
secrets_filter = true                       # default: true — leave it on
history_filter = ["^\\s*vault ", "^op "]    # optional: your own regexes
```

Two details worth knowing, both verified against atuin 18.25.1 rather than taken from the docs:

- **Command history is drop-only, not redact.** `secrets_filter` discards the
  whole command. The `REDACTED` / `****` machinery in Atuin's source belongs to
  its separate *output capture* feature (`session_capture/policy.rs`), not to
  command history (`history.rs::should_save` → `contains_secret` → bool).
- **`atuin import` does not apply `secrets_filter` at all.** `import.rs` calls
  `db.save_bulk()` directly and never consults `should_save`. Confirmed by
  experiment: with `secrets_filter = true`, importing a history file containing
  three synthetic secrets stored all three verbatim.

**Order matters.** Atuin does not clean what you already have, and `atuin import` will pull your existing history — secrets included — straight into a fresh database:

```
1. sh history-check.sh            ← what's in there?
2. sh history-redact.sh --apply   ← clean the backlog
3. rotate the credentials         ← the only step that un-leaks
4. install atuin, then import     ← prevention, in that order
```

### 3. A space is a surprisingly good habit

```sh
# bash
HISTCONTROL=ignoreboth                 # ~/.bashrc — leading space = not recorded
# zsh
setopt HIST_IGNORE_SPACE               # ~/.zshrc
# fish — on by default
```

Then prefix the risky command with one space and it's never written:

```sh
 export TOKEN=sk-whatever
```

### 4. Why there is no background daemon here

A timer that re-redacts your history forever sounds appealing. It isn't:

- **There's always a window.** The secret sits in cleartext from keystroke until the timer fires. If a backup runs in that window, it's gone.
- **It races your shells.** Every live terminal rewrites history on exit. A daemon fighting that is a bug factory.
- **It's redundant.** Once the backlog is clean and prevention is on, there's nothing left to do.

If you still want a safety net, `optional-timer/` has a launchd agent (macOS) and a systemd timer (Linux). They're a backstop, never the primary fix.

---

## How it works

`lib-patterns.sh` is the single source of truth: a table of `NAME@@@REGEX@@@REPLACEMENT`. `build.sh` inlines it into both scripts so each stays standalone and auditable in one read.

Both scripts share one gate: **a line contains a live secret if, and only if, redacting it would change it.** Check and redact therefore cannot disagree, and already-redacted lines are correctly ignored (the literal `REDACTED` is 8 characters, long enough to look like a value — an earlier version flagged its own output).

POSIX `sh`, ERE only, no `\b` / `\d` / lookaround, so BSD and GNU `grep`/`sed` behave identically. The sed delimiter is `%` because patterns contain `/`; `build.sh` asserts no pattern contains `%`.

Editing patterns:

```sh
vim lib-patterns.sh && ./build.sh && sh tests/run-tests.sh
```

## Contributing

A missing credential shape is the most useful PR: add a line to `lib-patterns.sh`, a synthetic example to `tests/fixture_bash_history`, and an assertion to `tests/run-tests.sh`. **Only synthetic secrets in fixtures, obviously.**

## License

MIT
