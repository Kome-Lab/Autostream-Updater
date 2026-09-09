package hostruntime

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestSystemdPortListenerWaitsForDelayedBind(t *testing.T) {
	reserved, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := LocalExecutorEndpoint{Host: "127.0.0.1", Port: reserved.Addr().(*net.TCPAddr).Port}
	_ = reserved.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	firstDial := make(chan struct{}, 1)
	result := make(chan error, 1)
	dialer := net.Dialer{Timeout: 100 * time.Millisecond}
	go func() {
		result <- waitForSystemdPortListener(ctx, endpoint, func(ctx context.Context, network, address string) (net.Conn, error) {
			connection, err := dialer.DialContext(ctx, network, address)
			select {
			case firstDial <- struct{}{}:
			default:
			}
			return connection, err
		})
	}()
	select {
	case <-firstDial:
	case <-result:
		t.Fatal("restart completed before observing listener readiness")
	case <-ctx.Done():
		t.Fatal("readiness did not inspect the target endpoint")
	}
	select {
	case <-result:
		t.Fatal("closed target endpoint was treated as ready")
	default:
	}
	listener, err := net.Listen("tcp4", endpoint.address())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal("delayed listener did not become ready within the existing context")
		}
	case <-ctx.Done():
		t.Fatal("readiness did not observe the delayed listener")
	}
}

func TestSystemdPortListenerHonorsExistingDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := waitForSystemdPortListener(ctx, LocalExecutorEndpoint{Host: "127.0.0.1", Port: 18084}, func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("listener has not bound")
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("missing listener was accepted or the caller deadline was lost")
	}
}

func TestSystemdPortListenerCanceledBeforeDialDoesNoWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	err := waitForSystemdPortListener(ctx, LocalExecutorEndpoint{Host: "127.0.0.1", Port: 18084}, func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, errors.New("unexpected dial")
	})
	if !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatal("canceled listener wait performed new work or reported readiness")
	}
}
