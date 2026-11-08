// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/scrypt"
)

// Formats an import can be. The page shows the name.
const (
	fmtOTPVault  = "otp-vault backup"
	fmtText      = "otpauth links"
	fmtSecret    = "secret"
	fmtMigration = "Google Authenticator"
	fmtAegis     = "Aegis"
	fmt2FAS      = "2FAS"
	fmtAndOTP    = "andOTP"
	fmtBitwarden = "Bitwarden"
	fmtCSV       = "CSV"
)

// errNeedPassword: the file is encrypted and no password was given yet.
var errNeedPassword = errors.New("password needed")

// maxImportSize keeps a wrongly chosen file (a video, a disk image) from
// filling the memory.
const maxImportSize = 20 << 20

// parseImport finds out what data is and returns the accounts in it, not
// normalized yet. Encrypted files need the password; without one the result
// is errNeedPassword, so the page can ask.
func parseImport(data []byte, password string) (string, []Entry, error) {
	if len(data) > maxImportSize {
		return "", nil, userError(nil, "The file is too large for an export of accounts", "Choose the export file of your authenticator app.")
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")) // BOM of Windows editors
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return "", nil, userError(nil, "There is nothing to import", "Paste a secret or an otpauth:// link, or choose a file.")
	}
	if !utf8.Valid(trimmed) {
		return "", nil, userError(nil, "This file is not a text or JSON export", "Images are read as QR codes; for other apps choose their JSON, CSV or TXT export.")
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		return parseJSONImport(trimmed, password)
	}
	return parseTextImport(string(trimmed))
}

func parseJSONImport(data []byte, password string) (string, []Entry, error) {
	var probe map[string]json.RawMessage
	if data[0] == '[' {
		var arr []json.RawMessage
		if err := json.Unmarshal(data, &arr); err != nil {
			return "", nil, userError(err, "The JSON file is damaged", "Export it again from the app it came from.")
		}
		return parseJSONArray(arr)
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return "", nil, userError(err, "The JSON file is damaged", "Export it again from the app it came from.")
	}
	switch {
	case probe["format"] != nil && bytes.Contains(probe["format"], []byte(vaultFormat)):
		if password == "" {
			return fmtOTPVault, nil, errNeedPassword
		}
		v, k, err := open(data, password)
		if err != nil {
			return fmtOTPVault, nil, err
		}
		k.wipe()
		return fmtOTPVault, v.Entries, nil
	case probe["db"] != nil && probe["header"] != nil:
		list, err := parseAegis(probe, password)
		return fmtAegis, list, err
	case probe["services"] != nil || probe["servicesEncrypted"] != nil:
		list, err := parse2FAS(probe, password)
		return fmt2FAS, list, err
	case probe["items"] != nil:
		if bytes.Equal(bytes.TrimSpace(probe["encrypted"]), []byte("true")) {
			return fmtBitwarden, nil, userError(nil, "This Bitwarden export is encrypted", "Export again in Bitwarden as \"JSON\" (not \"JSON (Encrypted)\"), import it, then delete the file.")
		}
		list, err := parseBitwarden(probe["items"])
		return fmtBitwarden, list, err
	}
	return "", nil, userError(nil, "This JSON file has a format otp-vault does not know", "Supported: otp-vault, Aegis, 2FAS, andOTP, Bitwarden. Otherwise export as otpauth links or CSV.")
}

// parseJSONArray reads andOTP (objects) or a plain list of otpauth links.
func parseJSONArray(arr []json.RawMessage) (string, []Entry, error) {
	var out []Entry
	format := fmtAndOTP
	for _, raw := range arr {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			e, err := parseOTPAuth(s)
			if err != nil {
				return fmtText, nil, err
			}
			format = fmtText
			out = append(out, e)
			continue
		}
		var a struct {
			Secret    string   `json:"secret"`
			Issuer    string   `json:"issuer"`
			Label     string   `json:"label"`
			Digits    int      `json:"digits"`
			Type      string   `json:"type"`
			Algorithm string   `json:"algorithm"`
			Period    int      `json:"period"`
			Counter   uint64   `json:"counter"`
			Tags      []string `json:"tags"`
		}
		if err := json.Unmarshal(raw, &a); err != nil || a.Secret == "" {
			return fmtAndOTP, nil, userError(err, "The andOTP export could not be read", "Export it again as \"Plain-text\" backup.")
		}
		e := Entry{Kind: strings.ToLower(a.Type), Secret: a.Secret, Issuer: a.Issuer, Account: a.Label,
			Digits: a.Digits, Algorithm: a.Algorithm, Period: a.Period, Counter: a.Counter}
		if i := strings.Index(e.Account, ":"); i > 0 && (e.Issuer == "" || strings.EqualFold(e.Account[:i], e.Issuer)) {
			e.Issuer, e.Account = strings.TrimSpace(e.Account[:i]), strings.TrimSpace(e.Account[i+1:])
		}
		out = append(out, e)
	}
	return format, out, nil
}

type aegisSlot struct {
	Type      int    `json:"type"`
	Key       string `json:"key"`
	KeyParams struct {
		Nonce string `json:"nonce"`
		Tag   string `json:"tag"`
	} `json:"key_params"`
	N    int    `json:"n"`
	R    int    `json:"r"`
	P    int    `json:"p"`
	Salt string `json:"salt"`
}

type aegisHeader struct {
	Slots  []aegisSlot `json:"slots"`
	Params *struct {
		Nonce string `json:"nonce"`
		Tag   string `json:"tag"`
	} `json:"params"`
}

type aegisDB struct {
	Entries []struct {
		Type     string `json:"type"`
		Name     string `json:"name"`
		Issuer   string `json:"issuer"`
		Note     string `json:"note"`
		Favorite bool   `json:"favorite"`
		Icon     string `json:"icon"`
		IconMime string `json:"icon_mime"`
		Info     struct {
			Secret  string `json:"secret"`
			Algo    string `json:"algo"`
			Digits  int    `json:"digits"`
			Period  int    `json:"period"`
			Counter uint64 `json:"counter"`
		} `json:"info"`
	} `json:"entries"`
}

func gcmOpen(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCMWithNonceSize(block, len(nonce))
	if err != nil {
		return nil, err
	}
	return g.Open(nil, nonce, ciphertext, nil)
}

// parseAegis reads plain and password encrypted Aegis exports (scrypt slots,
// AES-256-GCM). Biometric slots are skipped; the password slot opens it.
func parseAegis(probe map[string]json.RawMessage, password string) ([]Entry, error) {
	var h aegisHeader
	if err := json.Unmarshal(probe["header"], &h); err != nil {
		return nil, userError(err, "The Aegis export is damaged", "Export it again in Aegis.")
	}
	dbRaw := probe["db"]
	if len(h.Slots) > 0 && h.Params != nil {
		if password == "" {
			return nil, errNeedPassword
		}
		var enc string
		if err := json.Unmarshal(dbRaw, &enc); err != nil {
			return nil, userError(err, "The Aegis export is damaged", "Export it again in Aegis.")
		}
		master, err := aegisMasterKey(h.Slots, password)
		if err != nil {
			return nil, err
		}
		ct, err1 := base64.StdEncoding.DecodeString(enc)
		nonce, err2 := hex.DecodeString(h.Params.Nonce)
		tag, err3 := hex.DecodeString(h.Params.Tag)
		if err := errors.Join(err1, err2, err3); err != nil {
			return nil, userError(err, "The Aegis export is damaged", "Export it again in Aegis.")
		}
		plain, err := gcmOpen(master, nonce, append(ct, tag...))
		if err != nil {
			return nil, userError(err, "The Aegis export could not be decrypted", "Export it again in Aegis.")
		}
		dbRaw = plain
	}
	var db aegisDB
	if err := json.Unmarshal(dbRaw, &db); err != nil {
		return nil, userError(err, "The Aegis export is damaged", "Export it again in Aegis.")
	}
	var out []Entry
	for _, a := range db.Entries {
		e := Entry{Kind: strings.ToLower(a.Type), Issuer: a.Issuer, Account: a.Name, Note: a.Note, Favorite: a.Favorite,
			Secret: a.Info.Secret, Algorithm: a.Info.Algo, Digits: a.Info.Digits, Period: a.Info.Period, Counter: a.Info.Counter}
		if a.Icon != "" && iconMimeOK(a.IconMime) {
			e.Icon = "data:" + a.IconMime + ";base64," + a.Icon
		}
		out = append(out, e)
	}
	return out, nil
}

func aegisMasterKey(slots []aegisSlot, password string) ([]byte, error) {
	for _, s := range slots {
		if s.Type != 1 {
			continue
		}
		salt, err1 := hex.DecodeString(s.Salt)
		key, err2 := hex.DecodeString(s.Key)
		nonce, err3 := hex.DecodeString(s.KeyParams.Nonce)
		tag, err4 := hex.DecodeString(s.KeyParams.Tag)
		if errors.Join(err1, err2, err3, err4) != nil || s.N <= 1 || s.N > 1<<22 || s.R <= 0 || s.P <= 0 {
			continue
		}
		derived, err := scrypt.Key([]byte(password), salt, s.N, s.R, s.P, 32)
		if err != nil {
			continue
		}
		if master, err := gcmOpen(derived, nonce, append(key, tag...)); err == nil {
			return master, nil
		}
	}
	return nil, userError(errWrongPassword, "Wrong password for the Aegis export", "Enter the password of the Aegis vault the export came from.")
}

type twoFASService struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
	OTP    struct {
		Label     string `json:"label"`
		Account   string `json:"account"`
		Issuer    string `json:"issuer"`
		Digits    int    `json:"digits"`
		Period    int    `json:"period"`
		Algorithm string `json:"algorithm"`
		Counter   uint64 `json:"counter"`
		TokenType string `json:"tokenType"`
	} `json:"otp"`
}

// parse2FAS reads 2FAS backups, plain or encrypted (PBKDF2 SHA-256,
// 10000 rounds, AES-256-GCM; "servicesEncrypted" is data:salt:iv in base64).
func parse2FAS(probe map[string]json.RawMessage, password string) ([]Entry, error) {
	servicesRaw := probe["services"]
	if enc := probe["servicesEncrypted"]; enc != nil {
		var s string
		if err := json.Unmarshal(enc, &s); err != nil {
			return nil, userError(err, "The 2FAS backup is damaged", "Export it again in 2FAS.")
		}
		if s != "" {
			if password == "" {
				return nil, errNeedPassword
			}
			parts := strings.Split(s, ":")
			if len(parts) != 3 {
				return nil, userError(nil, "The 2FAS backup is damaged", "Export it again in 2FAS.")
			}
			ct, err1 := base64.StdEncoding.DecodeString(parts[0])
			salt, err2 := base64.StdEncoding.DecodeString(parts[1])
			iv, err3 := base64.StdEncoding.DecodeString(parts[2])
			if err := errors.Join(err1, err2, err3); err != nil {
				return nil, userError(err, "The 2FAS backup is damaged", "Export it again in 2FAS.")
			}
			key, err := pbkdf2.Key(sha256.New, password, salt, 10000, 32)
			if err != nil {
				return nil, err
			}
			plain, err := gcmOpen(key, iv, ct)
			if err != nil {
				return nil, userError(errWrongPassword, "Wrong password for the 2FAS backup", "Enter the password you set for the 2FAS backup.")
			}
			servicesRaw = plain
		}
	}
	var services []twoFASService
	if err := json.Unmarshal(servicesRaw, &services); err != nil {
		return nil, userError(err, "The 2FAS backup is damaged", "Export it again in 2FAS.")
	}
	var out []Entry
	for _, s := range services {
		e := Entry{Kind: strings.ToLower(s.OTP.TokenType), Secret: s.Secret, Issuer: s.OTP.Issuer, Account: s.OTP.Account,
			Digits: s.OTP.Digits, Period: s.OTP.Period, Algorithm: s.OTP.Algorithm, Counter: s.OTP.Counter}
		if e.Issuer == "" {
			e.Issuer = s.Name
		}
		if e.Account == "" {
			e.Account = s.OTP.Label
		}
		out = append(out, e)
	}
	return out, nil
}

func parseBitwarden(raw json.RawMessage) ([]Entry, error) {
	var items []struct {
		Name     string `json:"name"`
		Notes    string `json:"notes"`
		Favorite bool   `json:"favorite"`
		Login    *struct {
			Username string `json:"username"`
			TOTP     string `json:"totp"`
			URIs     []struct {
				URI string `json:"uri"`
			} `json:"uris"`
		} `json:"login"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, userError(err, "The Bitwarden export is damaged", "Export it again in Bitwarden as JSON.")
	}
	var out []Entry
	for _, it := range items {
		if it.Login == nil || strings.TrimSpace(it.Login.TOTP) == "" {
			continue
		}
		site := ""
		if len(it.Login.URIs) > 0 {
			site = it.Login.URIs[0].URI
		}
		e, err := entryFromTOTPField(it.Login.TOTP, it.Name, it.Login.Username, site)
		if err != nil {
			return nil, err
		}
		e.Favorite = it.Favorite
		out = append(out, e)
	}
	if len(out) == 0 {
		return nil, userError(nil, "The Bitwarden export has no entries with a TOTP code", "Only logins with an authenticator key are imported.")
	}
	return out, nil
}

// entryFromTOTPField reads what password managers keep in their TOTP field:
// an otpauth link, "steam://SECRET" or the bare secret.
func entryFromTOTPField(field, issuer, account, site string) (Entry, error) {
	field = strings.TrimSpace(field)
	var e Entry
	switch {
	case strings.HasPrefix(strings.ToLower(field), "otpauth://"):
		var err error
		if e, err = parseOTPAuth(field); err != nil {
			return Entry{}, err
		}
	case strings.HasPrefix(strings.ToLower(field), "steam://"):
		e = Entry{Kind: kindSteam, Secret: field[len("steam://"):]}
	default:
		e = Entry{Secret: field}
	}
	if e.Issuer == "" {
		e.Issuer = strings.TrimSpace(issuer)
	}
	if e.Account == "" {
		e.Account = strings.TrimSpace(account)
	}
	e.Website = normalizeHost(site)
	return e, nil
}

// parseTextImport reads text: otpauth links, Google migration links, CSV,
// or one bare secret.
func parseTextImport(text string) (string, []Entry, error) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	first := strings.ToLower(strings.TrimSpace(lines[0]))
	if strings.Contains(text, ",") && !strings.HasPrefix(first, "otpauth") && csvHeader(first) {
		list, err := parseCSV(text)
		return fmtCSV, list, err
	}
	var out []Entry
	format := fmtText
	for _, line := range lines {
		line = strings.TrimSpace(line)
		low := strings.ToLower(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(low, "otpauth-migration://"):
			list, err := parseMigration(line)
			if err != nil {
				return fmtMigration, nil, err
			}
			format = fmtMigration
			out = append(out, list...)
		case strings.HasPrefix(low, "steam://") && len(lines) == 1:
			return fmtSecret, []Entry{{Kind: kindSteam, Issuer: "Steam", Secret: line[len("steam://"):]}}, nil
		case strings.HasPrefix(low, "otpauth://"):
			e, err := parseOTPAuth(line)
			if err != nil {
				return fmtText, nil, err
			}
			out = append(out, e)
		default:
			if len(out) == 0 && len(lines) == 1 {
				sec, err := normalizeSecret(line)
				if err != nil {
					return fmtSecret, nil, userError(err, "This is neither a secret nor an otpauth:// link", "Paste the secret (letters A to Z, digits 2 to 7) or the whole link.")
				}
				return fmtSecret, []Entry{{Secret: sec}}, nil
			}
			return fmtText, nil, userError(nil, "A line is not an otpauth:// link: "+shorten(line, 40), "Put one link per line.")
		}
	}
	if len(out) == 0 {
		return fmtText, nil, userError(nil, "No account found", "Paste a secret or an otpauth:// link.")
	}
	return format, out, nil
}

func shorten(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}

var csvColumns = map[string][]string{
	"issuer":    {"issuer", "service", "title", "name"},
	"account":   {"account", "username", "user", "login_username", "email", "label"},
	"secret":    {"secret", "totp", "login_totp", "otp", "key", "seed", "otpauth", "uri"},
	"website":   {"website", "url", "login_uri"},
	"algorithm": {"algorithm", "algo"},
	"digits":    {"digits"},
	"period":    {"period"},
	"type":      {"type", "kind"},
	"counter":   {"counter"},
	"note":      {"note", "notes"},
}

func csvHeader(first string) bool {
	for _, name := range csvColumns["secret"] {
		for _, cell := range strings.Split(first, ",") {
			if strings.Trim(strings.TrimSpace(cell), `"`) == name {
				return true
			}
		}
	}
	return false
}

// parseCSV reads CSV with a header row: the export of otp-vault, Bitwarden,
// KeePassXC and most spreadsheets. Rows without a secret are skipped.
func parseCSV(text string) ([]Entry, error) {
	r := csv.NewReader(strings.NewReader(text))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	rows, err := r.ReadAll()
	if err != nil || len(rows) < 2 {
		return nil, userError(err, "The CSV file could not be read", "It needs a header row and a column with the secret or the otpauth link.")
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		h = strings.ToLower(strings.TrimSpace(h))
		for field, names := range csvColumns {
			for rank, n := range names {
				if h == n {
					if old, ok := col[field+"#rank"]; !ok || rank < old {
						col[field], col[field+"#rank"] = i, rank
					}
				}
			}
		}
	}
	if _, ok := col["secret"]; !ok {
		return nil, userError(nil, "The CSV file has no column with the secret", "Name the column \"secret\" or \"otpauth\".")
	}
	get := func(row []string, field string) string {
		i, ok := col[field]
		if !ok || i >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[i])
	}
	var out []Entry
	for _, row := range rows[1:] {
		field := get(row, "secret")
		if field == "" {
			continue
		}
		e, err := entryFromTOTPField(field, get(row, "issuer"), get(row, "account"), get(row, "website"))
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(strings.ToLower(field), "otpauth://") {
			switch v := strings.ToLower(get(row, "type")); v {
			case kindTOTP, kindHOTP, kindSteam:
				e.Kind = v
			}
			e.Algorithm = get(row, "algorithm")
			e.Digits, _ = strconv.Atoi(get(row, "digits"))                // ignore: empty means default
			e.Period, _ = strconv.Atoi(get(row, "period"))                // ignore: as above
			e.Counter, _ = strconv.ParseUint(get(row, "counter"), 10, 64) // ignore: as above
		}
		e.Note = get(row, "note")
		out = append(out, e)
	}
	if len(out) == 0 {
		return nil, userError(nil, "The CSV file has no rows with a secret", "Check that the secret column is filled.")
	}
	return out, nil
}
