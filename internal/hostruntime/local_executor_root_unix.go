//go:build !windows

package hostruntime

import (
	"errors"
	"os"
)

func RequireLocalExecutorRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("local executor requires root")
	}
	return nil
}
