// otp-vault (https://github.com/burnersen/otp-vault)
// Copyright (C) 2026 burnersen
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// appPaths says where the program keeps its files. Every path the program
// writes to comes from here, nowhere else.
type appPaths struct {
	ConfigFile string // settings the user may edit (INI)
	LogFile    string
	DataDir    string // anything else the program keeps for itself
}

// homeEnv moves everything below one folder. Tests set it; users may set it
// too, to keep the program's files on another drive.
const homeEnv = "OTP_VAULT_HOME"

// portableMarker: an empty file of this name next to the exe keeps all
// files next to the exe (USB stick, no traces on the PC).
const portableMarker = "portable.txt"

func defaultPaths() (appPaths, error) {
	if dir := os.Getenv(homeEnv); dir != "" {
		return pathsBelow(dir), nil
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		if _, err := os.Stat(filepath.Join(dir, portableMarker)); err == nil {
			return pathsBelow(dir), nil
		}
	}

	config, err := os.UserConfigDir() // Windows: %APPDATA%, Linux: ~/.config
	if err != nil {
		return appPaths{}, userError(err, "Cannot find the folder for settings",
			"Set "+homeEnv+" to a folder the program may write to.")
	}
	if runtime.GOOS == "windows" {
		local := os.Getenv("LOCALAPPDATA")
		if local == "" {
			local = config
		}
		return appPaths{
			ConfigFile: filepath.Join(config, appName, appName+".ini"),
			LogFile:    filepath.Join(local, appName, "logs", appID+".log"),
			DataDir:    filepath.Join(local, appName),
		}, nil
	}
	state, err := xdgStateHome()
	if err != nil {
		return appPaths{}, err
	}
	return appPaths{
		ConfigFile: filepath.Join(config, appID, appID+".ini"),
		LogFile:    filepath.Join(state, appID, appID+".log"),
		DataDir:    filepath.Join(state, appID),
	}, nil
}

func pathsBelow(dir string) appPaths {
	return appPaths{
		ConfigFile: filepath.Join(dir, appName+".ini"),
		LogFile:    filepath.Join(dir, "logs", appID+".log"),
		DataDir:    filepath.Join(dir, "data"),
	}
}

// xdgStateHome is where Linux programs keep logs and state
// ($XDG_STATE_HOME, by default ~/.local/state).
func xdgStateHome() (string, error) {
	if dir := os.Getenv("XDG_STATE_HOME"); strings.HasPrefix(dir, "/") {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", userError(err, "Cannot find your home folder",
			"Set "+homeEnv+" to a folder the program may write to.")
	}
	if home == "" {
		return "", errors.New("empty home folder")
	}
	return filepath.Join(home, ".local", "state"), nil
}
