// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// The vault file is JSON with a small clear header and one sealed block:
//
//	{"format":"otp-vault","version":1,
//	 "kdf":{"name":"argon2id","time":3,"memory":65536,"threads":4,"salt":"..."},
//	 "cipher":"xchacha20poly1305","nonce":"...","data":"..."}
//
// The key comes from the password with Argon2id. The header is bound to the
// sealed block as additional data, so changing a parameter breaks the seal
// instead of weakening it. Nothing about the accounts is readable without
// the password, not even their names or icons.
const (
	vaultFormat  = "otp-vault"
	vaultVersion = 1
	cipherName   = "xchacha20poly1305"
	kdfName      = "argon2id"
	minPassword  = 8
)

// kdfParams are stored in the file, so stronger defaults later still open
// older files.
type kdfParams struct {
	Name    string `json:"name"`
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"` // KiB
	Threads uint8  `json:"threads"`
	Salt    string `json:"salt"`
}

// defaultKDF: 64 MiB and three passes take about half a second on a normal
// PC, which is nothing at unlock and a lot for someone guessing. Tests use
// cheaper values.
var defaultKDF = kdfParams{Name: kdfName, Time: 3, Memory: 64 * 1024, Threads: 4}

type sealedFile struct {
	Format  string    `json:"format"`
	Version int       `json:"version"`
	KDF     kdfParams `json:"kdf"`
	Cipher  string    `json:"cipher"`
	Nonce   string    `json:"nonce"`
	Data    string    `json:"data"`
}

// vaultData is the sealed content.
type vaultData struct {
	Entries []Entry `json:"entries"`
	Saved   int64   `json:"saved"`
}

// sealKey is a derived key with the parameters it came from.
type sealKey struct {
	kdf kdfParams
	key []byte
}

var errWrongPassword = errors.New("wrong password or damaged file")

func newSealKey(password string) (sealKey, error) {
	if len([]rune(password)) < minPassword {
		return sealKey{}, userError(nil, fmt.Sprintf("The password is too short (at least %d characters)", minPassword),
			"A sentence of several words is easy to remember and hard to guess.")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return sealKey{}, err
	}
	p := defaultKDF
	p.Salt = base64.StdEncoding.EncodeToString(salt)
	return deriveKey(password, p)
}

func deriveKey(password string, p kdfParams) (sealKey, error) {
	if p.Name != kdfName || p.Time == 0 || p.Threads == 0 || p.Memory < 8*1024 || p.Memory > 4*1024*1024 || p.Time > 64 {
		return sealKey{}, userError(nil, "The file uses key settings this version does not know", "Update otp-vault, or check that this is an otp-vault file.")
	}
	salt, err := base64.StdEncoding.DecodeString(p.Salt)
	if err != nil || len(salt) < 8 {
		return sealKey{}, userError(err, "The file is damaged (salt)", "Use a backup.")
	}
	key := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, chacha20poly1305.KeySize)
	return sealKey{kdf: p, key: key}, nil
}

func (k *sealKey) wipe() {
	for i := range k.key {
		k.key[i] = 0
	}
	k.key = nil
}

func (k sealKey) valid() bool { return len(k.key) == chacha20poly1305.KeySize }

func additionalData(p kdfParams) []byte {
	return []byte(fmt.Sprintf("%s/%d/%s/%s/%d/%d/%d/%s", vaultFormat, vaultVersion, cipherName, p.Name, p.Time, p.Memory, p.Threads, p.Salt))
}

// seal encrypts v with k and returns the file content.
func seal(k sealKey, v vaultData) ([]byte, error) {
	if !k.valid() {
		return nil, errors.New("vault is locked")
	}
	plain, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	defer wipeBytes(plain)
	aead, err := chacha20poly1305.NewX(k.key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := aead.Seal(nil, nonce, plain, additionalData(k.kdf))
	return json.MarshalIndent(sealedFile{
		Format: vaultFormat, Version: vaultVersion, KDF: k.kdf, Cipher: cipherName,
		Nonce: base64.StdEncoding.EncodeToString(nonce),
		Data:  base64.StdEncoding.EncodeToString(out),
	}, "", "  ")
}

// readSealed checks the clear header of a vault or backup.
func readSealed(raw []byte) (sealedFile, error) {
	var f sealedFile
	if err := json.Unmarshal(raw, &f); err != nil || f.Format != vaultFormat {
		return f, userError(err, "This is not an otp-vault file", "Choose a vault or a backup made by otp-vault.")
	}
	if f.Version != vaultVersion || f.Cipher != cipherName {
		return f, userError(nil, fmt.Sprintf("The file has version %d, which this otp-vault cannot read", f.Version), "Update otp-vault.")
	}
	return f, nil
}

// open decrypts a vault or backup with the password. It returns the key, so
// the caller can save again without asking for the password.
func open(raw []byte, password string) (vaultData, sealKey, error) {
	f, err := readSealed(raw)
	if err != nil {
		return vaultData{}, sealKey{}, err
	}
	k, err := deriveKey(password, f.KDF)
	if err != nil {
		return vaultData{}, sealKey{}, err
	}
	v, err := openWithKey(f, k)
	if err != nil {
		k.wipe()
		return vaultData{}, sealKey{}, err
	}
	return v, k, nil
}

func openWithKey(f sealedFile, k sealKey) (vaultData, error) {
	nonce, err1 := base64.StdEncoding.DecodeString(f.Nonce)
	data, err2 := base64.StdEncoding.DecodeString(f.Data)
	if err1 != nil || err2 != nil {
		return vaultData{}, userError(errors.Join(err1, err2), "The file is damaged", "Use a backup.")
	}
	aead, err := chacha20poly1305.NewX(k.key)
	if err != nil {
		return vaultData{}, err
	}
	if len(nonce) != aead.NonceSize() {
		return vaultData{}, userError(nil, "The file is damaged (nonce)", "Use a backup.")
	}
	plain, err := aead.Open(nil, nonce, data, additionalData(f.KDF))
	if err != nil {
		return vaultData{}, userError(errWrongPassword, "Wrong password", "Check the password and the keyboard layout (Caps Lock, Y and Z).")
	}
	defer wipeBytes(plain)
	var v vaultData
	if err := json.Unmarshal(plain, &v); err != nil {
		return vaultData{}, userError(err, "The content of the file is damaged", "Use a backup.")
	}
	return v, nil
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func vaultExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, fileError(err, "check", path)
}

// saveVault writes the vault atomically and keeps the previous file as
// <name>.bak, so a broken disk write never costs more than the last change.
func saveVault(path string, k sealKey, v vaultData) error {
	raw, err := seal(k, v)
	if err != nil {
		return userError(err, "The vault could not be encrypted", "Try again. Details are in the log.")
	}
	if old, err := os.ReadFile(path); err == nil {
		if err := writeFileAtomic(path+".bak", old, 0o600); err != nil {
			return fileError(err, "write the backup", path+".bak")
		}
	}
	if err := writeFileAtomic(path, raw, 0o600); err != nil {
		return fileError(err, "write", path)
	}
	return nil
}
