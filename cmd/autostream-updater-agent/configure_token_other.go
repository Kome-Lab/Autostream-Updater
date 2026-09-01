//go:build !linux

package main

import (
	"context"
	"os"
)

func defaultReadHostAgentConfigureToken(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return readBoundedHostAgentConfigureToken(os.Stdin)
}
