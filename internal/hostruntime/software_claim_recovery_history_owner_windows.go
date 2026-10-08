//go:build windows

package hostruntime

import "os"

func softwareClaimRecoveryDirectoryOwnerSafe(info os.FileInfo, owner func(os.FileInfo) bool) bool {
	return info != nil && owner != nil && owner(info)
}

func softwareClaimRecoveryRecordOwnerSafe(info os.FileInfo, owner func(os.FileInfo) bool) bool {
	return softwareClaimRecoveryDirectoryOwnerSafe(info, owner)
}
