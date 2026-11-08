// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"errors"
	"fmt"
	"io/fs"
)

// UserError is an error the user can act on (same as template go-cli).
//
//	Msg  what happened, in plain words
//	Hint what the user can do about it
//	Err  the technical cause: for the log and for errors.Is/As only
type UserError struct {
	Msg  string
	Hint string
	Err  error
}

func (e *UserError) Error() string {
	if e.Err == nil {
		return e.Msg
	}
	return e.Msg + ": " + e.Err.Error()
}

func (e *UserError) Unwrap() error { return e.Err }

func userError(err error, msg, hint string) error {
	return &UserError{Msg: msg, Hint: hint, Err: err}
}

// fileError explains the usual file problems in words a user can act on.
func fileError(err error, action, path string) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return userError(err, fmt.Sprintf("Cannot %s %s: it does not exist", action, path),
			"Check the name and the folder.")
	case errors.Is(err, fs.ErrPermission):
		return userError(err, fmt.Sprintf("Cannot %s %s: no permission", action, path),
			"Check that you may access it, or that no other program has it open.")
	default:
		return userError(err, fmt.Sprintf("Cannot %s %s", action, path),
			"Try again. If it keeps failing, the log file has the details.")
	}
}

// uiError is how every error reaches the page. The page shows the text as it
// is: first line the message, second line the hint. The technical cause goes
// to the log only.
func (a *App) uiError(err error) error {
	var ue *UserError
	if errors.As(err, &ue) {
		if ue.Err != nil {
			a.logger.Error(ue.Msg, "cause", ue.Err.Error())
		} else {
			a.logger.Error(ue.Msg)
		}
		if ue.Hint == "" {
			return errors.New(ue.Msg)
		}
		return errors.New(ue.Msg + "\n" + ue.Hint)
	}
	a.logger.Error("unexpected error", "err", err)
	return fmt.Errorf("Something went wrong: %v\nDetails are in the log file: %s", err, a.paths.LogFile)
}
