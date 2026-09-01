//go:build windows

package hostruntime

import "os"

func managedSnapshotOwnedByCurrentUser(os.FileInfo) bool { return true }

func snapshotModeEnforced() bool { return false }
