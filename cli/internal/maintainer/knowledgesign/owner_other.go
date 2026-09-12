//go:build !darwin && !linux

package knowledgesign

import "os"

func ownedByCurrentUser(os.FileInfo) bool { return false }
