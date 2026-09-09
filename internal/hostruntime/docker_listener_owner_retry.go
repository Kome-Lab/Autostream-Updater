package hostruntime

import (
	"context"
	"errors"
	"time"
)

var errLocalDockerOwnerProcessDisappeared = errors.New("Docker owner process disappeared during enumeration")
var errLocalDockerOwnerDescriptorDisappeared = errors.New("Docker owner descriptor disappeared during enumeration")

func retryLocalDockerOwnerProof(ctx context.Context, observe func() (int, [32]byte, error)) (int, [32]byte, error) {
	// A vanished PID or descriptor invalidates the entire scan. Retry a fresh
	// process inventory and all owner/namespace checks, never a partial owner
	// set. Unreadable, foreign or changed stable identities remain failures.
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return 0, [32]byte{}, err
		}
		pid, proof, err := observe()
		if contextErr := ctx.Err(); contextErr != nil {
			return 0, [32]byte{}, contextErr
		}
		if err == nil {
			return pid, proof, nil
		}
		if attempt == 2 || !errors.Is(err, errLocalDockerOwnerProcessDisappeared) && !errors.Is(err, errLocalDockerOwnerDescriptorDisappeared) {
			return 0, [32]byte{}, err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0, [32]byte{}, ctx.Err()
		case <-timer.C:
		}
	}
}
