// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Export kinds the page offers.
const (
	exportBackup    = "backup"    // encrypted, opens in otp-vault
	exportURIs      = "uris"      // plain text, one otpauth link per line
	exportCSV       = "csv"       // plain CSV
	exportAegisJSON = "aegis"     // plain Aegis JSON, also read by 2FAS and others
	exportPDF       = "pdf"       // A4 sheets with QR codes to print
	exportGoogle    = "google"    // Google Authenticator migration link (text)
	exportBackupNew = "backup-pw" // encrypted with its own password
)

func exportURIList(list []Entry) []byte {
	var b strings.Builder
	for _, e := range list {
		b.WriteString(buildOTPAuth(e))
		b.WriteString("\r\n")
	}
	return []byte(b.String())
}

func exportCSVFile(list []Entry) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.UseCRLF = true
	rows := [][]string{{"issuer", "account", "secret", "type", "algorithm", "digits", "period", "counter", "website", "note", "otpauth"}}
	for _, e := range list {
		rows = append(rows, []string{e.Issuer, e.Account, e.Secret, e.Kind, e.Algorithm, strconv.Itoa(e.Digits),
			strconv.Itoa(e.Period), strconv.FormatUint(e.Counter, 10), e.Website, e.Note, buildOTPAuth(e)})
	}
	if err := w.WriteAll(rows); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func uuid4() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported systems
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// exportAegis writes a plain Aegis export (database version 2), which
// Aegis, 2FAS, Ente Auth and others can import.
func exportAegis(list []Entry) ([]byte, error) {
	type info struct {
		Secret  string `json:"secret"`
		Algo    string `json:"algo"`
		Digits  int    `json:"digits"`
		Period  int    `json:"period"`
		Counter uint64 `json:"counter,omitempty"`
	}
	type entry struct {
		Type     string  `json:"type"`
		UUID     string  `json:"uuid"`
		Name     string  `json:"name"`
		Issuer   string  `json:"issuer"`
		Note     string  `json:"note"`
		Favorite bool    `json:"favorite"`
		Icon     *string `json:"icon"`
		IconMime *string `json:"icon_mime"`
		Info     info    `json:"info"`
	}
	entries := []entry{}
	for _, e := range list {
		x := entry{Type: e.Kind, UUID: uuid4(), Name: e.Account, Issuer: e.Issuer, Note: e.Note, Favorite: e.Favorite,
			Info: info{Secret: e.Secret, Algo: e.Algorithm, Digits: e.Digits, Period: e.Period, Counter: e.Counter}}
		if mime, data, ok := splitDataURL(e.Icon); ok {
			x.Icon, x.IconMime = &data, &mime
		}
		entries = append(entries, x)
	}
	doc := map[string]any{
		"version": 1,
		"header":  map[string]any{"slots": nil, "params": nil},
		"db":      map[string]any{"version": 2, "entries": entries, "groups": []any{}},
	}
	return json.MarshalIndent(doc, "", "    ")
}

// exportSealed writes an encrypted otp-vault backup.
func exportSealed(list []Entry, k sealKey) ([]byte, error) {
	return seal(k, vaultData{Entries: list, Saved: time.Now().Unix()})
}

var iconMimes = map[string]bool{
	"image/png": true, "image/jpeg": true, "image/gif": true, "image/webp": true,
	"image/svg+xml": true, "image/x-icon": true, "image/vnd.microsoft.icon": true,
}

func iconMimeOK(m string) bool { return iconMimes[strings.ToLower(strings.TrimSpace(m))] }

// splitDataURL splits "data:image/png;base64,AAAA" into mime and base64 data.
func splitDataURL(s string) (mime, data string, ok bool) {
	rest, found := strings.CutPrefix(s, "data:")
	if !found {
		return "", "", false
	}
	head, data, found := strings.Cut(rest, ",")
	mime, enc, _ := strings.Cut(head, ";")
	if !found || enc != "base64" || !iconMimeOK(mime) || data == "" {
		return "", "", false
	}
	return mime, data, true
}
