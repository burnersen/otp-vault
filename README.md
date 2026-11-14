<div align="center">

<img src="frontend/dist/icon.png" alt="" width="96">

# otp-vault

### Your two-factor codes on Windows, encrypted

A window and a tray icon for all your TOTP codes: click a code and it is copied. Import from nearly every authenticator app, export in every direction, and print A4 recovery sheets with QR codes. One EXE, nothing to install.

</div>

---

## ⚡ 30 seconds, no manual

1. Download `otp-vault.exe` from the latest release and start it.
2. Choose a master password. It encrypts everything.
3. **Add** an account (paste the secret or the `otpauth://` link) or **Import** the export of your old app. Click a code to copy it.

## ✨ What it does

- **All codes at a glance**: big, readable codes with a countdown ring and the next code below. TOTP, HOTP and Steam; SHA1, SHA256, SHA512; 6, 7 or 8 digits; any period.
- **Click to copy**: the clipboard is cleared again after 30 seconds, and Windows keeps the code out of the clipboard history (Win+V) and the cloud clipboard. The same goes for a secret or link copied from the details, and the clipboard is cleared when you quit.
- **Import from almost anything**: a bare secret, `otpauth://` links (with or without issuer; missing names are asked for), Google Authenticator export QR codes, Aegis (plain and encrypted), 2FAS (plain and encrypted), andOTP, Bitwarden JSON and CSV, KeePassXC CSV, any CSV with a secret column, otp-vault backups. QR codes from image files or a pasted screenshot (Win+Shift+S, then Ctrl+V). Duplicates are recognised.
- **Export in every direction**: encrypted backup (with the master password or its own), A4 recovery sheet (PDF) with QR code, service, user name and secret, QR codes for Google Authenticator, Aegis JSON, `otpauth://` links, CSV. Plain exports warn first.
- **Icons**: on request, fetched from the service's own website and stored inside the vault. Or choose your own image.
- **Tray**: the close button sends it to the tray; left click shows or hides the window, right click to lock or quit. Optional start with Windows.
- **German and English**, light and dark like Windows.

## 🔒 Security

- The vault is one file, encrypted with **XChaCha20-Poly1305**; the key comes from your master password with **Argon2id** (64 MiB, 3 passes). Without the password nothing is readable, not even the names of the accounts.
- **Auto lock** after 5 minutes without use (adjustable), when Windows is locked (Win+L), and optionally when the window goes to the tray.
- Every change is saved at once; the previous file is kept as `vault.otpv.bak`. After a password change the backup is replaced too, so no file opens with the old password any more.
- **No network**, except when you click "Fetch icons": then only the host name of the service is contacted, never a secret or a user name. No icon service in between.

## 📁 Where its files live

| What | Where |
|---|---|
| Vault | `%LOCALAPPDATA%\otp-vault\vault.otpv` (and `vault.otpv.bak`) |
| Settings | `%LOCALAPPDATA%\otp-vault\settings.json` |
| Log | `%LOCALAPPDATA%\otp-vault\logs\otp-vault.log` |

**Portable:** put an empty file `portable.txt` next to the exe, and everything stays in that folder (vault in `data\`). The log never grows past 2 MB and contains no secrets.

**Keyboard:** Ctrl+F search, Enter copies the first match, Ctrl+N add, Ctrl+L lock, Esc closes.

## 💻 Requirements

Windows 10 or 11 (x64 or ARM64). The window uses the Microsoft Edge WebView2 runtime, which is part of current Windows.

**Windows SmartScreen** may warn because the files are not digitally signed yet. Choose "More info", then "Run anyway". Every release is built by GitHub Actions from this repository, and `SHA256SUMS.txt` lists the checksum of every file.

## 🔧 Building it yourself

Go in the version from `go.mod` and the Wails CLI (`go install github.com/wailsapp/wails/v2/cmd/wails@v2.17.1`):

```
go test ./...
node frontend/app_check.js
wails build -platform windows/amd64 -skipbindings -trimpath
```

## 📜 License

GPL-3.0-only, see [LICENSE](LICENSE). Included: the QR encoder of [rsc.io/qr](https://github.com/rsc/qr) (BSD-3-Clause, `internal/qr/LICENSE`) and [jsQR](https://github.com/cozmo/jsQR) 1.4.0 for reading QR codes (Apache-2.0, `frontend/dist/vendor/jsQR.LICENSE.txt`).
