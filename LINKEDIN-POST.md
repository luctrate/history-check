# LinkedIn post

## Poll (LinkedIn's native poll — max 4 options, 30 chars each)

**Question** (max 140 chars):
> Be honest: check your shell history for API keys right now. What did you find?

**Options** (max 30 chars each):
1. `Nothing — I'm clean` *(19)*
2. `A few. Oops.` *(12)*
3. `Dozens. Sending help.` *(21)*
4. `Too scared to look` *(18)*

Duration: **1 week.**

> Why a poll and not a link post: LinkedIn suppresses posts with external links.
> A poll keeps reach, and the repo goes in the first comment. Pin that comment.

---

## Post body

*(3,012 characters — LinkedIn's limit is 3,000. Only the first ~210 show before "see more", so the first two lines carry the whole post.)*

Your shell saved that token. It's still there.

I cleaned my own shell history last week and found 392 credentials in cleartext. Stripe keys. A GitHub PAT. AWS keys. An Atlassian token, 84 times over. GitLab passwords I'd typed into curl two years ago.

Not in a repo. Not in a leaked .env. In ~/.bash_history — plain text, unencrypted, readable by anything that can read my home directory, and copied into every backup since.

Here's the part most people miss.

Your shell records the command, not its output. So `cat .env` leaks nothing — the secret was never on that line. What gets saved is what you typed:

  export GITHUB_TOKEN=ghp_xxxxxxxx
  curl -H "Authorization: Bearer eyJhb..."
  mysql --password=hunter2
  psql postgres://user:password@host/db

`export TOKEN=...` is the most common way engineers leak credentials to their own disk, and nobody counts it as a leak, because it never left the machine. Except it did — into Time Machine, Spotlight's index, rsync, whatever syncs your home.

So I wrote two scripts and made them public.

→ history-check.sh — read-only. Scans bash, zsh, fish, ksh, plus the REPL histories everyone forgets (psql and mysql cheerfully store connection strings with inline passwords). Secrets masked in output. Writes nothing, sends nothing.

→ history-redact.sh — replaces the secret VALUE with REDACTED, keeps the command, so history stays searchable. Dry-run by default.

36 rules, 59 tests, POSIX sh, no dependencies, macOS + Linux.

Two things before you run it.

ONE: there's no curl-pipe-to-shell one-liner in that repo, deliberately. Telling you to pipe an unread script from a stranger into your shell, in a post about credential hygiene, would be absurd. If you use a coding agent, paste this instead — it puts a reviewer between you and my code:

  "Clone github.com/luctrate/history-check into a temp dir. Read
   history-check.sh first and tell me: does it write anything, or make
   any network request? If it's read-only and offline, run it and
   summarise which history files have credentials. Keep values masked."

That's the workflow I'd want for any script off the internet, mine included.

TWO: redacting history is not revoking anything. Your backups still hold the old file. If something shows up, rotate it.

The real fix is neither script. It's never typing secrets at a prompt:

  set -a; . ./.env; set +a
  direnv allow
  op run -- ./deploy.sh

And if you want a seatbelt: Atuin (atuin.sh) replaces your shell history with a searchable database, and its secrets filter is ON BY DEFAULT — it redacts credentials before they're ever written. Better than any cleanup, mine included.

Order matters though: clean your existing history FIRST. Atuin won't touch what's already there, and importing old history pulls the secrets straight into the new database.

Repo's in the comments. MIT, ~400 lines of shell you can read in one sitting. I'd rather you read it than trust me.

Vote honestly — I want to know if 392 makes me an outlier or just typical.

---

## First comment (pin this)

Repo: https://github.com/luctrate/history-check

Read-only check, dry-run redaction, 59 tests, MIT. macOS + Linux, bash/zsh/fish/ksh.

Prior art worth knowing: Atuin (atuin.sh) prevents this going forward and its
secrets filter is on by default — the right permanent fix. gitleaks and
trufflehog cover repos and CI, but neither looks at your shell history. This
fills that one gap, then gets out of the way.

Missing a credential shape? PRs welcome — one line in lib-patterns.sh, one
fixture entry, one assertion.

---

## Notes on the numbers

Use YOUR real numbers, not these. From this session they were:
  - 392 credentials redacted across 2 files (first pass, ad-hoc script)
  -  43 more found later by the finished tool, which caught `curl --user`
     where the quick version had only matched `-u` — worth a follow-up post
     on its own: the first pass missed real GitLab registry passwords.
  - Breakdown: 84 Atlassian + 76 FORGE_API_TOKEN, 44 JWT/Bearer,
    17 Google API keys, 12 Stripe, 49 --password/--token/curl -u, ~110 others.

If the follow-up angle appeals: "I wrote a secret scanner, then it found
secrets my first scanner missed" is a strong second post, and the honest
lesson is that `-u` vs `--user` is exactly the kind of gap a hand-rolled
regex pass leaves behind.
