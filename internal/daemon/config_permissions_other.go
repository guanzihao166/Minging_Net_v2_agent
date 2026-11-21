//go:build !linux

package daemon

import "os"

func managedConfigMode(os.FileInfo) bool { return false }
