# Device-pairing (QR-link) patch

Adds a Plex/GitHub-CLI-style pairing flow: an already-logged-in device shows a QR,
a second device scans it, logs in for real, and gets its own named,
independently-revocable API key. The shared master key (`handleRegenKey`) is
untouched and still works exactly as before.

## Files (drop-in replacements / new files)

- `internal/config/config.go` — modified: added `PairedKey` type, `paired_keys`
  in the on-disk JSON, and wiring in `Load()`/`save()`. Everything else in this
  file is unchanged from your original.
- `internal/config/pairing.go` — **new file**. All pairing-session and
  paired-key logic (`StartPairing`, `PairingStatus`, `ClaimPairing`,
  `ValidatePairedKey`, `TouchPairedKey`, `ListPairedKeys`, `DeletePairedKey`).
- `internal/api/auth.go` — modified: `authJWT` now also accepts a paired key
  (checked by hash) alongside the legacy master key. No new imports needed.
- `internal/api/server.go` — modified: 4 new routes + handlers
  (`/api/pairing/start`, `/api/pairing/status`, `/api/pairing/claim`,
  `/api/pairing/keys`), inserted right after `handleRegenKey`.
- `web/static/index.html` — modified: a "Paired Devices" card in
  Settings → Security, two new modals (QR display + "Authorize this device"),
  and the JS to drive both sides of the flow.
- `web/static/qrcode.min.js` — **new file**. Kazuhiko Arase's
  `qrcode-generator` (MIT), vendored so no CDN dependency is introduced. I
  round-tripped it (encode → render → decode with jsQR) before including it —
  see verification notes below.

## How it works

1. Settings → Security → **Link a New Device** → `POST /api/pairing/start`
   returns a short-lived code (10 hex chars, 5 min TTL).
2. The browser renders a QR of `<origin>/?pair=<code>` and polls
   `GET /api/pairing/status`.
3. The second device scans it, logs in normally (this is the real auth
   boundary, not the code), and the app shows "Authorize This Device" —
   confirming calls `POST /api/pairing/claim`, which mints a fresh key,
   stores only its SHA-256 hash, and returns the raw key once.
4. The first device's next poll shows "Paired as '<name>'" and the key list
   refreshes. Either device can revoke that key independently later via
   `DELETE /api/pairing/keys?id=...` — the master key is never touched.

## What I actually verified vs. what needs your own build

- `internal/config` (config.go + pairing.go) — compiled clean with
  `go build`, `go vet`, and `gofmt` as an isolated package.
- `internal/api/auth.go` — parses and is gofmt-clean; only calls the two new
  `Config` methods (verified above) and reuses existing symbols
  (`roleAdmin`, header patterns) unchanged elsewhere in the file.
- `internal/api/server.go` — parses and is gofmt-clean.
- `web/static/index.html` — inline JS extracted and passed `node --check`;
  the newly inserted modal markup has balanced `<div>`/`</div>` tags.
- `qrcode.min.js` — encode → bitmap-render → decode round-tripped correctly
  in Node with jsQR before I vendored it.
- **Not done:** a full `go build ./...` of the whole repo together. The
  sandbox's network egress allowlist blocks `gopkg.in` and `golang.org`,
  which a transitive *test* dependency of the vendored `github.com/pkg/sftp`
  needs during full module-graph resolution — unrelated to anything in this
  patch. Please run `go build ./...` once you've merged these files in; if
  anything doesn't line up with parts of `server.go`/`config.go` I didn't
  have in front of me, it'll show up there immediately.

## Notes / things you may want to adjust

- Paired keys are all admin-equivalent right now, matching what the legacy
  key already grants. If you want a viewer-scoped paired key later, add a
  `Role` field to `PairedKey` and thread it through `ClaimPairing`/`authJWT`
  the same way `User.Role` already works.
- Pairing sessions live in memory only (not persisted), same reasoning
  already used for `revokedTokens`/`loginAttempts` in your codebase — a
  restart mid-pairing just means "generate a new QR," nothing worse.
