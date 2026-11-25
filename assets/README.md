# Post images

| File | Size | Use |
|---|---|---|
| `history-check-square.png` | 1200×1200 | **Default for LinkedIn.** Square takes the most vertical space in the mobile feed. |
| `history-check-wide.png` | 1200×627 | 1.91:1 — link previews, Twitter/X, blog header, GitHub social preview. |

Both are rendered from the HTML next to them at 2× then downsampled, so the
type stays crisp. To edit, change the HTML and re-run:

```sh
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --headless --disable-gpu --hide-scrollbars --force-device-scale-factor=2 \
  --window-size=1200,1200 --screenshot=/tmp/sq.png "file://$PWD/post-image.html"
magick /tmp/sq.png -resize 1200x1200 -strip -quality 95 history-check-square.png
```

## ⚠ LinkedIn polls cannot have an attached image

This forces a choice, so decide before posting:

- **Poll post + image in the first comment** — recommended. Keeps the poll
  (good reach, and the poll *is* the hook), and LinkedIn comments do accept
  images. Pin that comment with the repo link.
- **Image post now, poll as a follow-up** — use the image as the main visual
  and run the poll a few days later as a second post. Two posts from one idea.

Verify the current behaviour in LinkedIn's composer before you commit to a
plan; they change these rules more often than they announce.

## The numbers in the image are real

392 credentials, 84 Atlassian, 44 JWT, 17 Google, 12 Stripe — these came from
an actual scan. Swap them for whatever you're comfortable publishing; the
file paths and entry counts are illustrative.

Every secret shown is masked, and the fixture values elsewhere in this repo
are synthetic.
