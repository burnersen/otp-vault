# Instructions for AI in this project

Applies to every AI working here (`AGENTS.md` points here). This file is public: only write what anyone may read. Private notes go to `_notes/` (not committed).

## Basis

- This project follows the **dev-starterkit** (`burnersen/dev-starterkit`, private). Kit version when created: **3.2**, template `go-wails`. Before larger work, fetch the kit, read `00-INDEX.md` and only the guides the task needs (`03` to `09`). If the kit is newer than the version above, say in one sentence what changed according to the newest entries at the top of `CHANGELOG.md`.
- **Language**: everything written into this repo is English (code, comments, commits, README, docs, release notes). The chat with the user is German, casual, without dashes. The language of the program's user interface is in the profile below; for new user-facing text ask the user if it is not decided yet (`09-docs.md`, D1).
- First say how you understood the task, wait for an okay on anything larger.
- Commands the user runs: one complete block to copy, with a backup first and the command to undo (`01-workflow.md`).

## Profile

| | |
|---|---|
| Purpose | Two-factor codes (TOTP, HOTP, Steam) in an encrypted vault on Windows: window and tray, import from most authenticator apps, export, printed A4 recovery sheets |
| Visibility | private |
| Language of code, comments, commits, docs | English |
| Language of the user interface | German and English (switchable) |
| Platforms | Windows x64 and ARM64 (window with Wails v2 and WebView2) |
| License | GPL-3.0-only |

## Commands

```
gofmt -l .                      # must stay empty
GOOS=windows go vet ./...
go test -race -count=1 ./...
node frontend/app_check.js      # check the page without a browser
wails build -platform windows/amd64 -skipbindings -trimpath   # Windows only
```

Release: write `.github/release-notes/1.2.3.md`, then push the tag `v1.2.3` or start "Release > Run workflow" (`07-build-and-release.md`).

## Structure

Security model: secrets never leave Go except in the details dialog (QR, secret) and on the clipboard. The vault is one file (`vault.go`): Argon2id key, XChaCha20-Poly1305, header bound as additional data. Every change is saved at once with a `.bak` of the previous file. Icons are fetched only on request and only from the service's own website.

Without the Go proxy (cloud session): replace `golang.org/x/crypto` and `golang.org/x/sys` with clones of the same tags from GitHub and Wails with a stand-in module (kit `01`, section 3), then vet and test with the installed Go version.

See the head comment in `main.go`. Every method in `app.go` returns errors to the page only through `uiError` (first line message, second line hint), the technical cause goes to the log. A failure at start shows a message box (`showFatal`), never `log.Fatal`. The page is in `frontend/dist` (HTML, CSS, JS separate, no npm) and is checked with `frontend/*_check.js`. `logging.go`, `paths.go` and `files.go` are the same as in the other Go templates.

## Before every commit

Go through the checklists of `03` to `09` in the kit, at least: gofmt empty, vet and tests green, no new `_ =` without a comment, no secrets and private paths, README and release notes updated when something changes for users. Then `bash <kit>/tools/check-project.sh .`

## The kit learns along

If something comes up that helps other projects too (a bug that can come back, a good solution, a library with a good or bad result, a build trick, a better rule), add it to the kit right away, without asking, and tell the user afterwards in one sentence what went in. Append only, never reload whole files: `21-kit-learns.md` of the kit.
