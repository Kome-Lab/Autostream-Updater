//go:build linux

package hostruntime

import (
	"context"
	"fmt"
	"os"
)

// The textual /proc exe name does not establish a mount namespace binding.
// Both the live executable and its slot path in that process's root must be
// the measured protected inode, and the live bytes must retain its digest.
func verifySoftwareClaimWatchdogProcessBinary(ctx context.Context, pid int, expected secureManualHostUpgradeFile, observed os.FileInfo, testPaths bool) error {
	if pid < 1 || !sameSoftwareClaimWatchdogBinaryInfo(expected.info, observed) {
		return softwareClaimWatchdogRefusal("process_binary_namespace")
	}
	for index, path := range []string{fmt.Sprintf("/proc/%d/exe", pid), fmt.Sprintf("/proc/%d/root%s", pid, expected.path)} {
		if ctx.Err() != nil {
			return softwareClaimWatchdogRefusal("process_deadline")
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		info, err := file.Stat()
		if err != nil || !sameSoftwareClaimWatchdogBinaryInfo(expected.info, info) ||
			(!testPaths && !manualHostRecoveryUnitRootOwned(info)) || (testPaths && !managedSnapshotOwnedByCurrentUser(info)) {
			file.Close()
			return softwareClaimWatchdogRefusal("process_binary_namespace")
		}
		if index == 0 {
			digest, readErr := hashSoftwareClaimWatchdogReader(ctx, file, info.Size())
			if readErr != nil || digest != expected.digest {
				file.Close()
				return softwareClaimWatchdogRefusal("process_binary_namespace")
			}
		}
		final, fdErr := file.Stat()
		named, pathErr := os.Stat(path)
		file.Close()
		if pathErr != nil {
			return pathErr
		}
		if fdErr != nil || ctx.Err() != nil || !sameSoftwareClaimWatchdogBinaryInfo(expected.info, final) || !sameSoftwareClaimWatchdogBinaryInfo(expected.info, named) {
			return softwareClaimWatchdogRefusal("process_binary_namespace")
		}
	}
	return nil
}

func sameSoftwareClaimWatchdogBinaryInfo(left, right os.FileInfo) bool {
	return left != nil && right != nil && left.Mode().IsRegular() && right.Mode().IsRegular() &&
		os.SameFile(left, right) && softwareClaimWatchdogSnapshotInfoMatches(left, right) &&
		manualHostRecoveryUnitLinkCount(left) == 1 && manualHostRecoveryUnitLinkCount(right) == 1
}
