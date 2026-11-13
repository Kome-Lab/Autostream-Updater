//go:build linux

package registry

import (
	"context"
	"io"
	"os"
	"strconv"
	"strings"
)

func (FixedLocalExecutorIdentitySource) ReadLocalIdentity(ctx context.Context) (LocalExecutorIdentity, error) {
	return observeLocalExecutorIdentity(ctx, uint64(os.Getpid()), readLocalIdentityFile)
}

func readLocalIdentityFile(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fault(CodeUnavailable, "guard.local_identity")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) == 0 || int64(len(data)) > maximum {
		return nil, fault(CodeUnavailable, "guard.local_identity")
	}
	return data, nil
}

// The reader is an internal test seam, never a product path/FD interface.
func observeLocalExecutorIdentity(ctx context.Context, pid uint64, read func(string, int64) ([]byte, error)) (LocalExecutorIdentity, error) {
	unknown := LocalExecutorIdentity{Knowledge: Unknown}
	if ctx == nil || pid == 0 || read == nil {
		return unknown, invalid("guard.local_identity")
	}
	var first LocalExecutorIdentity
	for pass := 0; pass < 2; pass++ {
		if err := ctx.Err(); err != nil {
			return unknown, err
		}
		boot, err := read("/proc/sys/kernel/random/boot_id", 128)
		if err != nil {
			return unknown, fault(CodeUnavailable, "guard.local_identity")
		}
		if err := ctx.Err(); err != nil {
			return unknown, err
		}
		stat, err := read("/proc/self/stat", 64<<10)
		if err != nil {
			return unknown, fault(CodeUnavailable, "guard.local_identity")
		}
		identity, err := parseLocalExecutorIdentity(boot, stat, pid)
		if err != nil {
			return unknown, err
		}
		if pass == 0 {
			first = identity
		} else if first != identity {
			return unknown, fault(CodeEvidenceUnknown, "guard.local_identity_changed")
		}
	}
	if err := ctx.Err(); err != nil {
		return unknown, err
	}
	return first, nil
}

func parseLocalExecutorIdentity(bootData, statData []byte, expectedPID uint64) (LocalExecutorIdentity, error) {
	unknown := LocalExecutorIdentity{Knowledge: Unknown}
	if len(bootData) == 0 || len(bootData) > 128 || len(statData) == 0 || len(statData) > 64<<10 || expectedPID == 0 {
		return unknown, fault(CodeEvidenceUnknown, "guard.local_identity")
	}
	boot := strings.TrimSuffix(string(bootData), "\n")
	if len(boot) != 36 {
		return unknown, fault(CodeEvidenceUnknown, "guard.local_identity")
	}
	for index, character := range boot {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return unknown, fault(CodeEvidenceUnknown, "guard.local_identity")
			}
		} else if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return unknown, fault(CodeEvidenceUnknown, "guard.local_identity")
		}
	}
	line := string(statData)
	open, close := strings.IndexByte(line, '('), strings.LastIndexByte(line, ')')
	if open < 2 || close <= open || close+2 >= len(line) || line[open-1] != ' ' || line[close+1] != ' ' {
		return unknown, fault(CodeEvidenceUnknown, "guard.local_identity")
	}
	pid, err := strconv.ParseUint(strings.TrimSuffix(line[:open], " "), 10, 64)
	if err != nil || pid != expectedPID {
		return unknown, fault(CodeEvidenceUnknown, "guard.local_identity")
	}
	fields := strings.Fields(line[close+2:])
	if len(fields) < 20 {
		return unknown, fault(CodeEvidenceUnknown, "guard.local_identity")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || ticks == 0 {
		return unknown, fault(CodeEvidenceUnknown, "guard.local_identity")
	}
	return LocalExecutorIdentity{Knowledge: Known, BootID: ID(boot), ProcessID: pid, StartTicks: ticks}, nil
}
