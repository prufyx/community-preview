//go:build !darwin && !linux

package main

import "os"

func ownedByCurrentUser(os.FileInfo) bool { return false }
