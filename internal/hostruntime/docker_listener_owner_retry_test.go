package hostruntime

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestDockerListenerOwnerProofRecapturesAfterProcessOrDescriptorExit(t *testing.T) {
	for _, transient := range []error{errLocalDockerOwnerProcessDisappeared, errLocalDockerOwnerDescriptorDisappeared} {
		calls := 0
		pid, proof, err := retryLocalDockerOwnerProof(context.Background(), func() (int, [32]byte, error) {
			calls++
			if calls == 1 {
				return 101, [32]byte{1}, transient
			}
			return 202, [32]byte{2}, nil
		})
		if err != nil || calls != 2 || pid != 202 || proof != [32]byte{2} {
			t.Fatal("transient enumeration did not discard partial proof and recapture every owner")
		}
	}
}

func TestDockerListenerOwnerProofNeverHidesIncompleteOrForeignOwners(t *testing.T) {
	for _, failure := range []error{os.ErrPermission, errors.New("foreign namespace"), errors.New("changed owner start time")} {
		calls := 0
		pid, proof, err := retryLocalDockerOwnerProof(context.Background(), func() (int, [32]byte, error) {
			calls++
			return 101, [32]byte{1}, failure
		})
		if !errors.Is(err, failure) || calls != 1 || pid != 0 || proof != [32]byte{} {
			t.Fatal("unreadable or foreign possible co-owner was retried or produced accepted proof")
		}
	}
}

func TestDockerListenerOwnerProofBoundsPersistentChurn(t *testing.T) {
	calls := 0
	pid, proof, err := retryLocalDockerOwnerProof(context.Background(), func() (int, [32]byte, error) {
		calls++
		return 101, [32]byte{1}, errLocalDockerOwnerDescriptorDisappeared
	})
	if !errors.Is(err, errLocalDockerOwnerDescriptorDisappeared) || calls != 3 || pid != 0 || proof != [32]byte{} {
		t.Fatal("persistent churn exceeded its bound or returned partial owner proof")
	}
}

func TestDockerListenerOwnerProofRejectsCompletionAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pid, proof, err := retryLocalDockerOwnerProof(ctx, func() (int, [32]byte, error) {
		cancel()
		return 202, [32]byte{2}, nil
	})
	if !errors.Is(err, context.Canceled) || pid != 0 || proof != [32]byte{} {
		t.Fatal("expired observation was accepted as complete owner proof")
	}
}

func TestDockerListenerOwnerProofHonorsCancellationBeforeAndBetweenAttempts(t *testing.T) {
	for _, canceledBefore := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if canceledBefore {
			cancel()
		}
		calls := 0
		pid, proof, err := retryLocalDockerOwnerProof(ctx, func() (int, [32]byte, error) {
			calls++
			cancel()
			return 101, [32]byte{1}, errLocalDockerOwnerProcessDisappeared
		})
		expectedCalls := 1
		if canceledBefore {
			expectedCalls = 0
		}
		if !errors.Is(err, context.Canceled) || calls != expectedCalls || pid != 0 || proof != [32]byte{} {
			t.Fatal("canceled observation repeated work or accepted partial owner proof")
		}
	}
}
