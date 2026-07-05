# Changelog

Dev-iteration log, not a public-release changelog — that already exists
separately: `release.yml` + `docker-build.yml`'s `generate_release_notes`
auto-generate categorized GitHub release notes from PR labels for every
`v*` tag. This file is just an informal running log for what's on `dev`
*before* something's tagged — one entry per meaningful round of changes,
newest on top.

**Identifying a running build:** `docker-build.yml` already versions every
build precisely — a `v*` tag gets that tag's version, every `dev`-branch
push gets `dev-<short-sha>`. So a running instance's `/status`, `/healthz`,
or Telegram `/apps` output tells you the exact commit; check that SHA
against git log to see which section below covers it. No separate counter
to maintain here — just add an entry when you make a meaningful round of
changes, and the git history + version string already do the matching for
you.

---

## Unreleased (dev)

**Backend**
- `docker.go`: replaced per-app container matching (`FindContainers`), which
  spawned up to ~6 `docker ps`/`docker inspect` subprocesses *per app, per
  30s health poll*, with a single `docker ps -a` snapshot shared across a
  whole batch (`FindContainersFor`). Health/exit code now parsed from that
  same snapshot's status string instead of a separate `docker inspect` call.
  Per-match logging is now opt-in (`verbose`) so real operations (backup/
  update/restore) still get an audit trail, but the health poll stays quiet.
- `imagemeta.go`: added `ImageMeta.Skipped` — distinguishes a benign,
  non-actionable check outcome (image pinned by digest, or locally built —
  nothing to compare against by design) from a genuine check failure
  (registry unreachable, bad tag, etc.).
- `updatecheck.go`: `buildUpdateReportMessage` uses `Skipped` to render those
  cases as informational (`ℹ️`) instead of a warning, and to keep them out of
  the "Update check had issues" headline. Fixed a double-counting bug in the
  same pass (an app with 2+ updatable images was briefly miscounted as
  multiple apps).
- `server.go`: merged the Telegram `/status` and `/apps` commands — they
  overlapped almost completely, each missing a field the other had (path vs.
  human schedule + next-run + volume count). `/apps` now shows everything in
  one pass; `/status` still works as a silent alias for muscle memory but is
  dropped from the `/help` text and Telegram's autocomplete list.
- `server.go` / `updatecheck.go` / `imagemeta.go`: added `GET/POST
  /api/updates/check` — the dashboard's on-demand equivalent of Telegram's
  `/check`, with the full per-image report (version delta, size, skip/error
  reason) now JSON-tagged and exposed, not just built for Telegram's message
  text.
- `server.go`: fixed the "👀 Remind me later" button on an update alert —
  it used to just reply with a message and do nothing else, despite saying
  "I'll remind you again if it's still pending at the next check." It now
  actually clears the alert debounce for the apps in that batch.

**Frontend (`index.html`)**
- Added a "🔍 Check now" button on the updates banner, wired to the new
  `/api/updates/check` endpoint. Per-app update badges now show real
  version-delta detail on hover once a check has run, and a distinct
  "⚠ check issue" badge for a genuine failure (pinned-by-digest/locally-built
  skips get no badge at all — nothing actionable to flag).
- Fixed a stale cron-preview bug in the Add/Edit App modals: the "next 5
  runs" preview only ever recomputed on the cron field's `oninput` event,
  which never fires when the modal populates the field programmatically.
  Opening one app's edit modal right after another's would silently keep
  showing the *previous* app's schedule. Both modals now recompute the
  preview immediately on open.
