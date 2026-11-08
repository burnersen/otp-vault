// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"errors"
	"fmt"
	"strings"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// ---- import ---------------------------------------------------------------

// ImportItem is one account of an import, shown in the list before it is
// taken over. The secret stays on the Go side.
type ImportItem struct {
	Index     int    `json:"index"`
	Kind      string `json:"kind"`
	Issuer    string `json:"issuer"`
	Account   string `json:"account"`
	Details   string `json:"details"`
	Icon      string `json:"icon"`
	Duplicate bool   `json:"duplicate"` // the vault has it already
	Missing   bool   `json:"missing"`   // no service and no user name: the page asks
	Problem   string `json:"problem"`   // cannot be imported, with the reason
}

type ImportPreview struct {
	Format        string       `json:"format"`
	NeedsPassword bool         `json:"needsPassword"`
	Items         []ImportItem `json:"items"`
}

// ImportText reads pasted text, the content of a file or a decoded QR code.
// Encrypted files come back with NeedsPassword; the page asks and calls
// again with the password.
func (a *App) ImportText(text, password string) (ImportPreview, error) {
	a.Touch()
	if !a.store.unlocked() {
		return ImportPreview{}, a.uiError(errLocked)
	}
	format, list, err := parseImport([]byte(text), password)
	if errors.Is(err, errNeedPassword) {
		return ImportPreview{Format: format, NeedsPassword: true}, nil
	}
	if err != nil {
		return ImportPreview{}, a.uiError(err)
	}
	have, err := a.store.entries()
	if err != nil {
		return ImportPreview{}, a.uiError(err)
	}
	prev := ImportPreview{Format: format}
	for i := range list {
		e := &list[i]
		it := ImportItem{Index: i}
		if err := normalizeEntry(e); err != nil {
			var ue *UserError
			if errors.As(err, &ue) && e.Secret != "" && e.Issuer == "" && e.Account == "" {
				it.Missing = true // the only problem is the missing name
			} else if errors.As(err, &ue) {
				it.Problem = ue.Msg
			} else {
				it.Problem = err.Error()
			}
		}
		_, dup := duplicateOf(have, *e)
		if !dup {
			for _, x := range list[:i] {
				if x.Secret == e.Secret && x.Kind == e.Kind {
					dup = true
				}
			}
		}
		it.Kind, it.Issuer, it.Account, it.Icon, it.Duplicate = e.Kind, e.Issuer, e.Account, e.Icon, dup
		if it.Problem == "" {
			it.Details = entryDetails(*e)
		}
		prev.Items = append(prev.Items, it)
	}
	a.mu.Lock()
	a.pending, a.pendingFmt = list, format
	a.mu.Unlock()
	a.logger.Info("import read", "format", format, "count", len(list))
	return prev, nil
}

// ImportChoice is the user's decision for one item of the preview.
type ImportChoice struct {
	Index   int    `json:"index"`
	Include bool   `json:"include"`
	Issuer  string `json:"issuer"`
	Account string `json:"account"`
}

type ImportResult struct {
	Added   int `json:"added"`
	Skipped int `json:"skipped"`
}

func (a *App) CommitImport(choices []ImportChoice) (ImportResult, error) {
	a.Touch()
	a.mu.Lock()
	pending := a.pending
	a.pending = nil
	a.mu.Unlock()
	if pending == nil {
		return ImportResult{}, a.uiError(userError(nil, "There is no import waiting", "Start the import again."))
	}
	var take []Entry
	for _, c := range choices {
		if !c.Include || c.Index < 0 || c.Index >= len(pending) {
			continue
		}
		e := pending[c.Index]
		if s := strings.TrimSpace(c.Issuer); s != "" {
			e.Issuer = s
		}
		if s := strings.TrimSpace(c.Account); s != "" {
			e.Account = s
		}
		take = append(take, e)
	}
	added, skipped, err := a.store.addMany(take)
	if err != nil {
		return ImportResult{}, a.uiError(err)
	}
	a.logger.Info("import done", "added", added, "skipped", skipped)
	return ImportResult{Added: added, Skipped: skipped + len(pending) - len(take)}, nil
}

func (a *App) CancelImport() {
	a.mu.Lock()
	a.pending = nil
	a.mu.Unlock()
}

// ---- export ---------------------------------------------------------------

// ExportRequest says what to export. IDs empty means all entries.
type ExportRequest struct {
	Kind     string    `json:"kind"`
	IDs      []string  `json:"ids"`
	Password string    `json:"password"` // only for "backup-pw"
	Sheet    sheetText `json:"sheet"`    // words on the PDF, in the page's language
	Title    string    `json:"title"`    // title of the save dialog
}

var exportFiles = map[string]struct{ ext, filter string }{
	exportBackup:    {"otpv", "otp-vault backup (*.otpv)"},
	exportBackupNew: {"otpv", "otp-vault backup (*.otpv)"},
	exportURIs:      {"txt", "otpauth links (*.txt)"},
	exportCSV:       {"csv", "CSV (*.csv)"},
	exportAegisJSON: {"json", "Aegis JSON (*.json)"},
	exportPDF:       {"pdf", "PDF (*.pdf)"},
}

// exportData builds the content of an export; it needs no window.
func (a *App) exportData(req ExportRequest) ([]byte, error) {
	list, err := a.store.selected(req.IDs)
	if err != nil {
		return nil, err
	}
	switch req.Kind {
	case exportBackup:
		k, err := a.store.backupKey()
		if err != nil {
			return nil, err
		}
		defer k.wipe()
		return exportSealed(list, k)
	case exportBackupNew:
		k, err := newSealKey(req.Password)
		if err != nil {
			return nil, err
		}
		defer k.wipe()
		return exportSealed(list, k)
	case exportURIs:
		return exportURIList(list), nil
	case exportCSV:
		return exportCSVFile(list)
	case exportAegisJSON:
		return exportAegis(list)
	case exportPDF:
		return buildPDF(list, req.Sheet, a.now())
	}
	return nil, fmt.Errorf("unknown export %q", req.Kind)
}

// Export asks where to save and writes the file. An empty path means the
// user cancelled.
func (a *App) Export(req ExportRequest) (string, error) {
	a.Touch()
	f, ok := exportFiles[req.Kind]
	if !ok {
		return "", a.uiError(fmt.Errorf("unknown export %q", req.Kind))
	}
	data, err := a.exportData(req)
	if err != nil {
		return "", a.uiError(err)
	}
	defer wipeBytes(data)
	name := fmt.Sprintf("otp-vault-%s.%s", a.now().Format("2006-01-02"), f.ext)
	if req.Kind == exportPDF {
		name = fmt.Sprintf("otp-vault-sheet-%s.pdf", a.now().Format("2006-01-02"))
	}
	path, err := wailsruntime.SaveFileDialog(a.ctx, wailsruntime.SaveDialogOptions{
		Title: req.Title, DefaultFilename: name,
		Filters: []wailsruntime.FileFilter{{DisplayName: f.filter, Pattern: "*." + f.ext}},
	})
	if err != nil {
		return "", a.uiError(userError(err, "The save dialog did not open", "Try again."))
	}
	if path == "" {
		return "", nil
	}
	if !strings.HasSuffix(strings.ToLower(path), "."+f.ext) {
		path += "." + f.ext
	}
	if err := writeFileAtomic(path, data, 0o600); err != nil {
		return "", a.uiError(fileError(err, "write", path))
	}
	a.logger.Info("exported", "kind", req.Kind, "path", path)
	return path, nil
}

// GoogleExport returns Google Authenticator transfer QR codes (SVG data
// URLs), ten accounts per code like the app itself does.
func (a *App) GoogleExport(ids []string) ([]string, error) {
	a.Touch()
	list, err := a.store.selected(ids)
	if err != nil {
		return nil, a.uiError(err)
	}
	var out []string
	var batch []Entry
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		q, err := qrSVG(buildMigration(batch))
		if err != nil {
			return err
		}
		out = append(out, q)
		batch = nil
		return nil
	}
	for _, e := range list {
		if e.Kind == kindSteam || (e.Digits != 6 && e.Digits != 8) || e.Kind == kindTOTP && e.Period != 30 {
			continue // Google Authenticator cannot hold these
		}
		batch = append(batch, e)
		if len(batch) == 10 {
			if err := flush(); err != nil {
				return nil, a.uiError(err)
			}
		}
	}
	if err := flush(); err != nil {
		return nil, a.uiError(err)
	}
	if len(out) == 0 {
		return nil, a.uiError(userError(nil, "None of these accounts fit Google Authenticator", "Google Authenticator takes 6 or 8 digits and 30 seconds only."))
	}
	return out, nil
}
