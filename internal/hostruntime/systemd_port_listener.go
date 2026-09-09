package hostruntime

import (
	"context"
	"net"
	"time"
)

func waitForSystemdPortListener(ctx context.Context, endpoint LocalExecutorEndpoint, dial func(context.Context, string, string) (net.Conn, error)) error {
	readyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		if err := readyCtx.Err(); err != nil {
			return err
		}
		connection, err := dial(readyCtx, "tcp", endpoint.address())
		if err == nil {
			_ = connection.Close()
			return readyCtx.Err()
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-readyCtx.Done():
			timer.Stop()
			return readyCtx.Err()
		case <-timer.C:
		}
	}
}
