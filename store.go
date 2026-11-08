// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// store holds the open vault. Every change is saved at once; nothing is
// kept only in memory. When locked, key and entries are dropped.
type store struct {
	mu   sync.Mutex
	path string
	key  sealKey
	data vaultData
	now  func() time.Time
}

func newStore(path string) *store {
	return &store{path: path, now: time.Now}
}

var errLocked = userError(nil, "The vault is locked", "Unlock it with your password.")

func (s *store) unlocked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.key.valid()
}

// create starts a new, empty vault. It refuses to replace an existing one.
func (s *store) create(password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	exists, err := vaultExists(s.path)
	if err != nil {
		return err
	}
	if exists {
		return userError(nil, "A vault exists already", "Unlock it, or move the file away first: "+s.path)
	}
	k, err := newSealKey(password)
	if err != nil {
		return err
	}
	data := vaultData{Entries: []Entry{}, Saved: s.now().Unix()}
	if err := saveVault(s.path, k, data); err != nil {
		k.wipe()
		return err
	}
	s.key, s.data = k, data
	return nil
}

func (s *store) unlock(password string) error {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return fileError(err, "read the vault", s.path)
	}
	data, k, err := open(raw, password)
	if err != nil {
		return err
	}
	if data.Entries == nil {
		data.Entries = []Entry{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.key.wipe()
	s.key, s.data = k, data
	return nil
}

// lock forgets the key and every secret. Strings in Go cannot be wiped, but
// dropping them makes them garbage and the key bytes are overwritten.
func (s *store) lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.key.wipe()
	s.data = vaultData{}
}

// changePassword checks the old password against the open vault, then seals
// the vault with a new salt and key.
func (s *store) changePassword(oldPw, newPw string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.key.valid() {
		return errLocked
	}
	check, err := deriveKey(oldPw, s.key.kdf)
	if err != nil {
		return err
	}
	same := subtle.ConstantTimeCompare(check.key, s.key.key) == 1
	check.wipe()
	if !same {
		return userError(errWrongPassword, "The current password is wrong", "Enter the password you unlock the vault with.")
	}
	k, err := newSealKey(newPw)
	if err != nil {
		return err
	}
	if err := s.saveWith(k); err != nil {
		k.wipe()
		return err
	}
	s.key.wipe()
	s.key = k
	return nil
}

func (s *store) saveWith(k sealKey) error {
	s.data.Saved = s.now().Unix()
	return saveVault(s.path, k, s.data)
}

// save must be called with s.mu held.
func (s *store) save() error { return s.saveWith(s.key) }

// entries returns a copy, sorted favorites first, then by service and name.
func (s *store) entries() ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.key.valid() {
		return nil, errLocked
	}
	out := append([]Entry(nil), s.data.Entries...)
	sortEntries(out)
	return out, nil
}

func sortEntries(list []Entry) {
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if a.Favorite != b.Favorite {
			return a.Favorite
		}
		ai, bi := strings.ToLower(a.Issuer), strings.ToLower(b.Issuer)
		if ai != bi {
			return ai < bi
		}
		return strings.ToLower(a.Account) < strings.ToLower(b.Account)
	})
}

func (s *store) find(id string) (int, error) {
	if !s.key.valid() {
		return -1, errLocked
	}
	for i := range s.data.Entries {
		if s.data.Entries[i].ID == id {
			return i, nil
		}
	}
	return -1, userError(nil, "The entry does not exist any more", "The list was refreshed.")
}

func (s *store) get(id string) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, err := s.find(id)
	if err != nil {
		return Entry{}, err
	}
	return s.data.Entries[i], nil
}

func newID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported systems
	}
	return hex.EncodeToString(b)
}

// duplicateOf returns the entry with the same secret and kind, if any.
func duplicateOf(list []Entry, e Entry) (Entry, bool) {
	for _, x := range list {
		if x.Secret == e.Secret && x.Kind == e.Kind {
			return x, true
		}
	}
	return Entry{}, false
}

// add stores a new entry. It fails for a duplicate secret.
func (s *store) add(e Entry) (Entry, error) {
	if err := normalizeEntry(&e); err != nil {
		return Entry{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.key.valid() {
		return Entry{}, errLocked
	}
	if d, ok := duplicateOf(s.data.Entries, e); ok {
		return Entry{}, userError(nil, "This account is in the vault already: "+label(d), "Edit the existing entry instead.")
	}
	now := s.now().Unix()
	e.ID, e.Created, e.Updated = newID(), now, now
	if e.Website == "" {
		e.Website = guessWebsite(e.Issuer)
	}
	s.data.Entries = append(s.data.Entries, e)
	if err := s.save(); err != nil {
		s.data.Entries = s.data.Entries[:len(s.data.Entries)-1]
		return Entry{}, err
	}
	return e, nil
}

// addMany stores what an import found. Duplicates (in the vault or twice in
// the import) are skipped and counted.
func (s *store) addMany(list []Entry) (added, skipped int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.key.valid() {
		return 0, 0, errLocked
	}
	before := len(s.data.Entries)
	now := s.now().Unix()
	for _, e := range list {
		if err := normalizeEntry(&e); err != nil {
			skipped++
			continue
		}
		if _, ok := duplicateOf(s.data.Entries, e); ok {
			skipped++
			continue
		}
		e.ID, e.Created, e.Updated = newID(), now, now
		if e.Website == "" {
			e.Website = guessWebsite(e.Issuer)
		}
		s.data.Entries = append(s.data.Entries, e)
		added++
	}
	if added == 0 {
		return 0, skipped, nil
	}
	if err := s.save(); err != nil {
		s.data.Entries = s.data.Entries[:before]
		return 0, 0, err
	}
	return added, skipped, nil
}

// update replaces the editable fields of an entry. An empty secret keeps the
// old one (the page never holds secrets it does not need).
func (s *store) update(e Entry) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, err := s.find(e.ID)
	if err != nil {
		return Entry{}, err
	}
	old := s.data.Entries[i]
	if strings.TrimSpace(e.Secret) == "" {
		e.Secret = old.Secret
	}
	if err := normalizeEntry(&e); err != nil {
		return Entry{}, err
	}
	for _, x := range s.data.Entries {
		if x.ID != e.ID && x.Secret == e.Secret && x.Kind == e.Kind {
			return Entry{}, userError(nil, "Another entry has the same secret: "+label(x), "Delete one of them.")
		}
	}
	e.Created, e.Updated = old.Created, s.now().Unix()
	if e.Website != old.Website && e.Icon == old.Icon {
		e.Icon = "" // the icon belonged to the old website
	}
	s.data.Entries[i] = e
	if err := s.save(); err != nil {
		s.data.Entries[i] = old
		return Entry{}, err
	}
	return e, nil
}

// modify runs fn on one entry and saves; on a failed save the change is
// undone.
func (s *store) modify(id string, fn func(*Entry)) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, err := s.find(id)
	if err != nil {
		return Entry{}, err
	}
	old := s.data.Entries[i]
	fn(&s.data.Entries[i])
	s.data.Entries[i].Updated = s.now().Unix()
	if err := s.save(); err != nil {
		s.data.Entries[i] = old
		return Entry{}, err
	}
	return s.data.Entries[i], nil
}

func (s *store) remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, err := s.find(id)
	if err != nil {
		return err
	}
	old := append([]Entry(nil), s.data.Entries...)
	s.data.Entries = append(s.data.Entries[:i], s.data.Entries[i+1:]...)
	if err := s.save(); err != nil {
		s.data.Entries = old
		return err
	}
	return nil
}

// selected returns the entries with the given IDs, all when ids is empty.
func (s *store) selected(ids []string) ([]Entry, error) {
	all, err := s.entries()
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return all, nil
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var out []Entry
	for _, e := range all {
		if want[e.ID] {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("none of the chosen entries exist")
	}
	return out, nil
}

// backupKey returns the key of the open vault, for a backup with the same
// password.
func (s *store) backupKey() (sealKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.key.valid() {
		return sealKey{}, errLocked
	}
	return sealKey{kdf: s.key.kdf, key: append([]byte(nil), s.key.key...)}, nil
}

func label(e Entry) string {
	switch {
	case e.Issuer != "" && e.Account != "":
		return e.Issuer + " (" + e.Account + ")"
	case e.Issuer != "":
		return e.Issuer
	default:
		return e.Account
	}
}
