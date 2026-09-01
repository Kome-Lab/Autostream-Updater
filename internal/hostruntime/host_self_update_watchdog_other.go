//go:build !linux

package hostruntime

import (
	"context"
	"errors"
)

func RecoverHostSelfUpdate(context.Context, string) error {
	return errors.New("host self-update recovery is supported only on Linux")
}
