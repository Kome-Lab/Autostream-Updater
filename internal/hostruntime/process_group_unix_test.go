//go:build !windows

package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestTopLevelRunnerCleansHelperChildrenAfterCrash(t *testing.T) {
	root := t.TempDir()
	childFile := filepath.Join(root, "child.pid")
	grandFile := filepath.Join(root, "grand.pid")
	script := fmt.Sprintf(`sleep 300 & echo $! > %q; /bin/sh -c 'sleep 300 & echo $! > %q; wait' & for i in $(seq 1 100); do test -s %q && break; sleep .01; done; exit 7`, childFile, grandFile, grandFile)
	runner := OSCommandRunner{NewProcessGroup: true}
	if _, err := runner.Run(context.Background(), "", nil, "/bin/sh", "-c", script); err == nil {
		t.Fatal("expected crashing helper command")
	}
	for _, path := range []string{childFile, grandFile} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			err = syscall.Kill(pid, 0)
			if errors.Is(err, syscall.ESRCH) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("orphan process %d survived top-level runner cleanup", pid)
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
}
