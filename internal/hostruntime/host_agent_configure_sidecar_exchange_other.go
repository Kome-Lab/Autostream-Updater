//go:build !linux

package hostruntime

import (
	"errors"
	"os"
)

func exchangeHostAgentSystemdSidecar(string, string) error {
	return errors.New("systemd sidecar adoption requires Linux rename exchange")
}

func prepareHostAgentSystemdSidecarExchange(
	string,
) (*os.File, string, os.FileInfo, error) {
	return nil, "", nil, errors.New("systemd sidecar adoption requires Linux rename exchange")
}
