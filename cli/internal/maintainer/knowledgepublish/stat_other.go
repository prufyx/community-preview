//go:build !darwin && !linux

package knowledgepublish

import "os"

func fileUID(os.FileInfo) (int, bool) { return 0, false }
