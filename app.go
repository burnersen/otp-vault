// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/options"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// version is set by the release build with -ldflags "-X main.version=1.2.3".
// Local builds say "dev". Never edit it by hand: the tag is the only source.
var version = "dev"

const (
	appName       = "otp-vault" // shown to users, file names on Windows
	appID         = "otp-vault" // lower case: log file name
	vaultFileName = "vault.otpv"
	settingsName  = "settings.json"
	flagMinimized = "-minimized"
	flagSelfTest  = "-selftest"
)

// App is everything the page may call. Wails turns every exported method
// into a JavaScript function on window.go.main.App. Secrets stay on this
// side: the page gets names, icons and the codes, the secret only when the
// user opens the details of one entry.
type App struct {
	ctx    context.Context
	paths  appPaths
	logger *slog.Logger
	store  *store
	icons  *iconFetcher

	mu           sync.Mutex
	settings     Settings
	warning      string // shown once on the page (damaged settings file)
	lastActivity time.Time
	pending      []Entry // import waiting for the user's choice
	pendingFmt   string
	clipTimer    *time.Timer
	clipClear    func() // empties the clipboard if it still holds what was copied
	hidden       bool
	quitting     bool
	selfTest     bool
	now          func() time.Time

	// The private clipboard of Windows; tests replace both.
	clipSet   func(text string) (uint32, error)
	clipClean func(seq uint32)

	// emit sends an event to the page; tests replace it.
	emit func(name string, data ...any)
}

func NewApp(paths appPaths, logger *slog.Logger) *App {
	a := &App{
		paths:  paths,
		logger: logger,
		store:  newStore(filepath.Join(paths.DataDir, vaultFileName)),
		icons:  newIconFetcher(),
		now:    time.Now,

		clipSet:   setClipboardSecret,
		clipClean: clearClipboardIf,
	}
	a.settings, a.warning = loadSettings(filepath.Join(paths.DataDir, settingsName))
	if a.warning != "" {
		logger.Warn(a.warning)
	}
	a.lastActivity = a.now()
	a.emit = func(name string, data ...any) {
		if a.ctx != nil {
			wailsruntime.EventsEmit(a.ctx, name, data...)
		}
	}
	return a
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	go a.autoLockLoop(ctx)
}

// onSecondInstance brings this window to the front when the program is
// started a second time.
func (a *App) onSecondInstance(options.SecondInstanceData) { a.ShowWindow() }

// beforeClose: the X button sends the window to the tray, unless the user
// switched that off or chose Quit.
func (a *App) beforeClose(ctx context.Context) bool {
	a.mu.Lock()
	toTray := a.settings.CloseToTray && !a.quitting
	a.mu.Unlock()
	if toTray {
		a.HideWindow()
		return true
	}
	return false
}

func (a *App) shutdown(context.Context) {
	a.clearClipboardNow()
	a.store.lock()
	stopTray()
}

// ---- state and settings ---------------------------------------------------

// AppState is what the page needs at start and after every lock.
type AppState struct {
	HasVault  bool     `json:"hasVault"`
	Unlocked  bool     `json:"unlocked"`
	Version   string   `json:"version"`
	Settings  Settings `json:"settings"`
	Autostart bool     `json:"autostart"`
	VaultPath string   `json:"vaultPath"`
	Warning   string   `json:"warning"`
	SelfTest  bool     `json:"selfTest"`
}

func (a *App) State() (AppState, error) {
	exists, err := vaultExists(a.store.path)
	if err != nil {
		return AppState{}, a.uiError(err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	st := AppState{HasVault: exists, Unlocked: a.store.unlocked(), Version: version, Settings: a.settings,
		Autostart: autostartEnabled(), VaultPath: a.store.path, Warning: a.warning, SelfTest: a.selfTest}
	a.warning = ""
	return st, nil
}

// Ready is called by the page once it has loaded. In the self test of the
// CI the window then closes with exit code 0: start, page and Go all work.
func (a *App) Ready() {
	a.mu.Lock()
	st := a.selfTest
	a.mu.Unlock()
	if st {
		a.logger.Info("self test passed")
		go func() {
			time.Sleep(300 * time.Millisecond)
			a.Quit()
		}()
	}
}

func (a *App) SaveSettings(s Settings) (Settings, error) {
	s.clean()
	if err := saveSettings(filepath.Join(a.paths.DataDir, settingsName), s); err != nil {
		return Settings{}, a.uiError(err)
	}
	a.mu.Lock()
	a.settings = s
	a.mu.Unlock()
	return s, nil
}

func (a *App) SetAutostart(on bool) error {
	if err := setAutostart(on); err != nil {
		return a.uiError(userError(err, "Autostart could not be changed", "Try again; details are in the log."))
	}
	return nil
}

// ---- lock and unlock ------------------------------------------------------

func (a *App) Create(password string) error {
	if err := a.store.create(password); err != nil {
		return a.uiError(err)
	}
	a.logger.Info("vault created", "path", a.store.path)
	a.Touch()
	return nil
}

func (a *App) Unlock(password string) error {
	if err := a.store.unlock(password); err != nil {
		var ue *UserError
		if errors.As(err, &ue) && errors.Is(ue.Err, errWrongPassword) {
			a.logger.Warn("unlock failed: wrong password")
			return errors.New(ue.Msg + "\n" + ue.Hint)
		}
		return a.uiError(err)
	}
	a.logger.Info("unlocked")
	a.Touch()
	return nil
}

func (a *App) Lock() {
	if !a.store.unlocked() {
		return
	}
	a.store.lock()
	a.mu.Lock()
	a.pending = nil
	a.mu.Unlock()
	a.logger.Info("locked")
	a.emit("locked")
}

// Touch tells the auto lock that the user is still there.
func (a *App) Touch() {
	a.mu.Lock()
	a.lastActivity = a.now()
	a.mu.Unlock()
}

func (a *App) autoLockLoop(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.checkAutoLock()
		}
	}
}

func (a *App) checkAutoLock() {
	a.mu.Lock()
	limit := time.Duration(a.settings.AutoLockMinutes) * time.Minute
	idle := a.now().Sub(a.lastActivity)
	a.mu.Unlock()
	if limit > 0 && idle >= limit && a.store.unlocked() {
		a.logger.Info("auto lock", "idle", idle.Round(time.Second).String())
		a.Lock()
	}
}

func (a *App) ChangePassword(oldPw, newPw string) error {
	if err := a.store.changePassword(oldPw, newPw); err != nil {
		return a.uiError(err)
	}
	a.logger.Info("password changed")
	return nil
}

// ---- window ---------------------------------------------------------------

func (a *App) ShowWindow() {
	if a.ctx == nil {
		return
	}
	a.mu.Lock()
	a.hidden = false
	a.mu.Unlock()
	wailsruntime.WindowShow(a.ctx)
	wailsruntime.WindowUnminimise(a.ctx)
	a.emit("shown")
}

func (a *App) HideWindow() {
	if a.ctx == nil {
		return
	}
	a.mu.Lock()
	a.hidden = true
	lock := a.settings.LockOnHide
	a.mu.Unlock()
	wailsruntime.WindowHide(a.ctx)
	if lock {
		a.Lock()
	}
}

func (a *App) toggleWindow() {
	a.mu.Lock()
	hidden := a.hidden
	a.mu.Unlock()
	if hidden || (a.ctx != nil && wailsruntime.WindowIsMinimised(a.ctx)) {
		a.ShowWindow()
	} else {
		a.HideWindow()
	}
}

func (a *App) Quit() {
	a.mu.Lock()
	a.quitting = true
	a.mu.Unlock()
	if a.ctx != nil {
		wailsruntime.Quit(a.ctx)
	}
}

func (a *App) trayHooks() trayHooks {
	return trayHooks{
		toggle: a.toggleWindow,
		show:   a.ShowWindow,
		lock:   a.Lock,
		quit:   a.Quit,
		labels: func() trayLabels {
			a.mu.Lock()
			de := a.settings.Language == "de"
			a.mu.Unlock()
			if de {
				return trayLabels{Show: "otp-vault öffnen", Lock: "Sperren", Quit: "Beenden", Tooltip: "otp-vault"}
			}
			return trayLabels{Show: "Open otp-vault", Lock: "Lock", Quit: "Quit", Tooltip: "otp-vault"}
		},
		sessionLocked: func() bool {
			a.mu.Lock()
			defer a.mu.Unlock()
			return a.settings.LockOnWindowsLock
		},
		logger: a.logger,
	}
}

// ---- entries --------------------------------------------------------------

// EntryView is an entry without its secret.
type EntryView struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Issuer    string `json:"issuer"`
	Account   string `json:"account"`
	Algorithm string `json:"algorithm"`
	Digits    int    `json:"digits"`
	Period    int    `json:"period"`
	Counter   uint64 `json:"counter"`
	Website   string `json:"website"`
	Icon      string `json:"icon"`
	Note      string `json:"note"`
	Favorite  bool   `json:"favorite"`
}

func viewOf(e Entry) EntryView {
	return EntryView{ID: e.ID, Kind: e.Kind, Issuer: e.Issuer, Account: e.Account, Algorithm: e.Algorithm,
		Digits: e.Digits, Period: e.Period, Counter: e.Counter, Website: e.Website, Icon: e.Icon, Note: e.Note, Favorite: e.Favorite}
}

func (a *App) List() ([]EntryView, error) {
	list, err := a.store.entries()
	if err != nil {
		return nil, a.uiError(err)
	}
	out := make([]EntryView, len(list))
	for i, e := range list {
		out[i] = viewOf(e)
	}
	return out, nil
}

// Codes is called by the page every second; it does not count as activity.
func (a *App) Codes() ([]CodeView, error) {
	list, err := a.store.entries()
	if err != nil {
		return nil, a.uiError(err)
	}
	now := a.now()
	out := make([]CodeView, len(list))
	for i, e := range list {
		out[i] = codeView(e, now)
	}
	return out, nil
}

// EntryInput is what the add and edit dialogs send. Secret may be a bare
// secret or an otpauth link; empty when editing means: keep it.
type EntryInput struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Issuer    string `json:"issuer"`
	Account   string `json:"account"`
	Secret    string `json:"secret"`
	Algorithm string `json:"algorithm"`
	Digits    int    `json:"digits"`
	Period    int    `json:"period"`
	Counter   uint64 `json:"counter"`
	Website   string `json:"website"`
	Icon      string `json:"icon"`
	Note      string `json:"note"`
	Favorite  bool   `json:"favorite"`
}

func (in EntryInput) entry() (Entry, error) {
	e := Entry{ID: in.ID, Kind: in.Kind, Issuer: in.Issuer, Account: in.Account, Secret: in.Secret,
		Algorithm: in.Algorithm, Digits: in.Digits, Period: in.Period, Counter: in.Counter,
		Website: in.Website, Icon: in.Icon, Note: in.Note, Favorite: in.Favorite}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(in.Secret)), "otpauth://") {
		p, err := parseOTPAuth(in.Secret)
		if err != nil {
			return Entry{}, err
		}
		e.Secret, e.Kind, e.Algorithm, e.Digits, e.Period, e.Counter = p.Secret, p.Kind, p.Algorithm, p.Digits, p.Period, p.Counter
		if e.Issuer == "" {
			e.Issuer = p.Issuer
		}
		if e.Account == "" {
			e.Account = p.Account
		}
	}
	if e.Icon != "" {
		if _, _, ok := splitDataURL(e.Icon); !ok {
			e.Icon = ""
		}
	}
	return e, nil
}

// ParsedInput fills the add dialog from what the user pasted.
type ParsedInput struct {
	Format  string     `json:"format"`
	Count   int        `json:"count"` // more than 1: the page switches to the import list
	Entry   EntryInput `json:"entry"`
	Website string     `json:"website"`
}

func (a *App) ParseInput(text string) (ParsedInput, error) {
	a.Touch()
	format, list, err := parseImport([]byte(text), "")
	if err != nil {
		if errors.Is(err, errNeedPassword) {
			return ParsedInput{Format: format, Count: 2}, nil
		}
		return ParsedInput{}, a.uiError(err)
	}
	p := ParsedInput{Format: format, Count: len(list)}
	if len(list) == 1 {
		e := list[0]
		normalizeEntry(&e) // ignore: an unnamed entry is completed in the dialog
		p.Entry = EntryInput{Kind: e.Kind, Issuer: e.Issuer, Account: e.Account, Algorithm: e.Algorithm,
			Digits: e.Digits, Period: e.Period, Counter: e.Counter, Note: e.Note}
		p.Website = e.Website
		if p.Website == "" {
			p.Website = guessWebsite(e.Issuer)
		}
	}
	return p, nil
}

func (a *App) AddEntry(in EntryInput) (EntryView, error) {
	a.Touch()
	e, err := in.entry()
	if err != nil {
		return EntryView{}, a.uiError(err)
	}
	e, err = a.store.add(e)
	if err != nil {
		return EntryView{}, a.uiError(err)
	}
	a.logger.Info("entry added", "id", e.ID)
	return viewOf(e), nil
}

func (a *App) UpdateEntry(in EntryInput) (EntryView, error) {
	a.Touch()
	e, err := in.entry()
	if err != nil {
		return EntryView{}, a.uiError(err)
	}
	e, err = a.store.update(e)
	if err != nil {
		return EntryView{}, a.uiError(err)
	}
	return viewOf(e), nil
}

func (a *App) DeleteEntry(id string) error {
	a.Touch()
	if err := a.store.remove(id); err != nil {
		return a.uiError(err)
	}
	a.logger.Info("entry deleted", "id", id)
	return nil
}

func (a *App) ToggleFavorite(id string) (EntryView, error) {
	a.Touch()
	e, err := a.store.modify(id, func(e *Entry) { e.Favorite = !e.Favorite })
	if err != nil {
		return EntryView{}, a.uiError(err)
	}
	return viewOf(e), nil
}

// NextHOTP moves an HOTP entry to its next counter (a new code).
func (a *App) NextHOTP(id string) error {
	a.Touch()
	if _, err := a.store.modify(id, func(e *Entry) {
		if e.Kind == kindHOTP {
			e.Counter++
		}
	}); err != nil {
		return a.uiError(err)
	}
	return nil
}

// SecretView is shown in the details dialog: secret, link and QR code.
type SecretView struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
	QR     string `json:"qr"` // SVG data URL
}

func (a *App) Details(id string) (SecretView, error) {
	a.Touch()
	e, err := a.store.get(id)
	if err != nil {
		return SecretView{}, a.uiError(err)
	}
	uri := buildOTPAuth(e)
	q, err := qrSVG(uri)
	if err != nil {
		return SecretView{}, a.uiError(userError(err, "The QR code could not be made", "The link is too long for a QR code."))
	}
	return SecretView{Secret: e.Secret, URI: uri, QR: q}, nil
}

// ---- clipboard ------------------------------------------------------------

// Copy puts the current (or next) code on the clipboard and clears it after
// the time from the settings, if it is still there.
func (a *App) Copy(id string, next bool) (string, error) {
	a.Touch()
	e, err := a.store.get(id)
	if err != nil {
		return "", a.uiError(err)
	}
	v := codeView(e, a.now())
	code := v.Current
	if next {
		code = v.Next
	}
	if err := a.toClipboard(code); err != nil {
		return "", a.uiError(err)
	}
	a.mu.Lock()
	hide := a.settings.HideAfterCopy
	a.mu.Unlock()
	if hide {
		go func() {
			time.Sleep(400 * time.Millisecond) // let the page show "copied"
			a.HideWindow()
		}()
	}
	return code, nil
}

// CopySecret puts the secret of an entry (or its otpauth link) on the
// clipboard, the same private way as a code: kept out of the Windows
// clipboard history and cleared after the time from the settings. The page
// never copies a secret itself.
func (a *App) CopySecret(id string, link bool) error {
	a.Touch()
	e, err := a.store.get(id)
	if err != nil {
		return a.uiError(err)
	}
	text := e.Secret
	if link {
		text = buildOTPAuth(e)
	}
	if err := a.toClipboard(text); err != nil {
		return a.uiError(err)
	}
	return nil
}

// toClipboard copies text as private content and plans the clearing.
func (a *App) toClipboard(text string) error {
	seq, nerr := a.clipSet(text)
	native := nerr == nil
	if !native {
		if a.ctx == nil {
			return userError(nerr, "The clipboard is not available", "Try again.")
		}
		if err := wailsruntime.ClipboardSetText(a.ctx, text); err != nil {
			return userError(err, "The code could not be copied", "Try again.")
		}
	}
	clear := func() {
		if native {
			a.clipClean(seq)
		} else if a.ctx != nil {
			if cur, err := wailsruntime.ClipboardGetText(a.ctx); err == nil && cur == text {
				wailsruntime.ClipboardSetText(a.ctx, "") // best effort
			}
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.clipTimer != nil {
		a.clipTimer.Stop()
	}
	a.clipTimer, a.clipClear = nil, nil
	if secs := a.settings.ClipboardSeconds; secs > 0 {
		a.clipClear = clear
		a.clipTimer = time.AfterFunc(time.Duration(secs)*time.Second, a.clearClipboardNow)
	}
	return nil
}

// clearClipboardNow runs a planned clearing at once: at the end of the
// program the timer would never fire and the code would stay behind.
func (a *App) clearClipboardNow() {
	a.mu.Lock()
	clear := a.clipClear
	if a.clipTimer != nil {
		a.clipTimer.Stop()
	}
	a.clipTimer, a.clipClear = nil, nil
	a.mu.Unlock()
	if clear != nil {
		clear()
	}
}

// ---- icons ----------------------------------------------------------------

func (a *App) FetchIcon(id string) (EntryView, error) {
	a.Touch()
	e, err := a.store.get(id)
	if err != nil {
		return EntryView{}, a.uiError(err)
	}
	host := e.Website
	if host == "" {
		host = guessWebsite(e.Issuer)
	}
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	icon, err := a.icons.fetch(ctx, host)
	if err != nil {
		return EntryView{}, a.uiError(err)
	}
	e, err = a.store.modify(id, func(x *Entry) { x.Icon, x.Website = icon, host })
	if err != nil {
		return EntryView{}, a.uiError(err)
	}
	return viewOf(e), nil
}

// FetchMissingIcons looks up icons for all entries without one, in the
// background; every result arrives as an "icon" event, the end as
// "icons-done" with the number found and missed.
func (a *App) FetchMissingIcons() error {
	list, err := a.store.entries()
	if err != nil {
		return a.uiError(err)
	}
	a.Touch()
	go func() {
		found, missed := 0, 0
		for _, e := range list {
			if e.Icon != "" {
				continue
			}
			v, err := a.FetchIcon(e.ID)
			if err != nil {
				missed++
				continue
			}
			found++
			a.emit("icon", v)
		}
		a.emit("icons-done", found, missed)
	}()
	return nil
}

// SetIcon stores an icon the user chose (a data URL), or removes it.
func (a *App) SetIcon(id, dataURL string) (EntryView, error) {
	a.Touch()
	if dataURL != "" {
		_, data, ok := splitDataURL(dataURL)
		if !ok || len(data) > maxIconBytes*4/3 {
			return EntryView{}, a.uiError(userError(nil, "This image cannot be used as an icon", "Use a PNG, JPG, SVG or ICO file up to 512 KB."))
		}
	}
	e, err := a.store.modify(id, func(x *Entry) { x.Icon = dataURL })
	if err != nil {
		return EntryView{}, a.uiError(err)
	}
	return viewOf(e), nil
}
