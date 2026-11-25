# Optional: periodic re-scrub

**Read this first: you probably don't want this.** A periodic redactor is a
backstop, not a fix. See "Why there is no background daemon here" in the main
README. Prevention (Atuin's `secrets_filter`, `direnv`, not typing secrets)
stops the leak; this only shortens how long it sits around.

Two honest caveats:

- **There is always an exposure window** — from keystroke until the next run.
- **It races your shells.** A live terminal rewrites history on exit, so the
  timer may run against a file that is about to be overwritten from memory.

Both configs below run the redactor against your own history, log to
`~/.local/state/history-redact.log`, and keep **no** backups (a backup full of
cleartext secrets, written automatically forever, is its own problem).

## macOS (launchd)

```sh
mkdir -p ~/Library/LaunchAgents ~/.local/state
sed "s|__HOME__|$HOME|g; s|__REPO__|$PWD/..|g" \
    com.luctrate.history-redact.plist > ~/Library/LaunchAgents/com.luctrate.history-redact.plist
launchctl load ~/Library/LaunchAgents/com.luctrate.history-redact.plist
```

Remove it:

```sh
launchctl unload ~/Library/LaunchAgents/com.luctrate.history-redact.plist
rm ~/Library/LaunchAgents/com.luctrate.history-redact.plist
```

## Linux (systemd --user)

```sh
mkdir -p ~/.config/systemd/user ~/.local/state
sed "s|__REPO__|$PWD/..|g" history-redact.service > ~/.config/systemd/user/history-redact.service
cp history-redact.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now history-redact.timer
systemctl --user list-timers history-redact.timer
```

Remove it:

```sh
systemctl --user disable --now history-redact.timer
rm ~/.config/systemd/user/history-redact.{service,timer}
systemctl --user daemon-reload
```
