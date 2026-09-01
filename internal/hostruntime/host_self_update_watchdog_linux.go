//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

// RecoverHostSelfUpdate is the fixed, policy-independent entry point used by
// the two root systemd recovery timers. It accepts only the A/B slot identity;
// paths, URLs, credentials and mutation input are not configurable.
func RecoverHostSelfUpdate(ctx context.Context, recoverySlot string) error {
	if os.Geteuid() != 0 {
		return errors.New("host self-update recovery requires root")
	}
	if !validHostSelfUpdateSlot(recoverySlot) {
		return errors.New("host self-update recovery slot is invalid")
	}
	executable, err := os.Executable()
	if err != nil {
		return errors.New("resolve host self-update recovery executable")
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return errors.New("resolve host self-update recovery executable")
	}
	expected := filepath.Join(
		HostSelfUpdateSlotsRoot,
		recoverySlot,
		"bin",
		"autostream-local-executor",
	)
	if filepath.Clean(executable) != expected {
		return errors.New("host self-update recovery executable is outside the selected fixed slot")
	}
	unlock, err := acquireHostLifecycleLock()
	if err != nil {
		return errors.New("acquire host lifecycle recovery lock")
	}
	defer unlock()
	rt := defaultHostSelfUpdateExecutorRuntime()
	_, err = rt.recoverExpiredHostSelfUpdate(ctx, recoverySlot)
	return err
}
