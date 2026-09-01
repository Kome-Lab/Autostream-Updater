package boundary_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestProductionSourceBoundary(t *testing.T) {
	repositoryRoot := filepath.Clean(filepath.Join("..", ".."))
	commandRoot := filepath.Join(repositoryRoot, "cmd")
	entries, err := os.ReadDir(commandRoot)
	if err != nil {
		t.Fatal(err)
	}
	var commands []string
	for _, entry := range entries {
		if entry.IsDir() {
			commands = append(commands, entry.Name())
		}
	}
	sort.Strings(commands)
	wantCommands := []string{"autostream-local-executor", "autostream-updater-agent"}
	if fmt.Sprint(commands) != fmt.Sprint(wantCommands) {
		t.Fatalf("production commands = %v, want %v", commands, wantCommands)
	}

	forbidden := []string{
		`"database` + `/sql"`,
		`github.com/go-sql-driver` + `/mysql`,
		`autostream-control-panel` + `/internal`,
		`golang.org/x/crypto` + `/ssh`,
		`SSH_` + `ORIGINAL_COMMAND`,
		`RunRemote` + `HelperRPC`,
		`Central` + `Coordinator`,
		`Managed` + `Supervisor`,
		`/bin/` + `sh`,
		`/bin/` + `bash`,
		`"sh", "` + `-c"`,
	}
	callerCounts := map[string]int{
		"hostruntime.NewHostPullAgent(":                                     2,
		"hostruntime.ServeLocalExecutor":                                    1,
		"(applicationprobe.Client{HTTP: client}).FetchApplicationIdentity(": 1,
	}
	observed := make(map[string]int, len(callerCounts))
	for _, tree := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(repositoryRoot, tree), func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				if entry.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, marker := range forbidden {
				if bytes.Contains(data, []byte(marker)) {
					t.Errorf("forbidden production marker %q in %s", marker, path)
				}
			}
			for marker := range callerCounts {
				observed[marker] += bytes.Count(data, []byte(marker))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for marker, want := range callerCounts {
		if observed[marker] != want {
			t.Errorf("production caller count for %q = %d, want %d", marker, observed[marker], want)
		}
	}
}

func TestExecutorWireHasNoArbitraryExecutionFields(t *testing.T) {
	repositoryRoot := filepath.Clean(filepath.Join("..", ".."))
	files := []string{
		"internal/hostruntime/local_executor_protocol.go",
		"internal/hostruntime/mutation_protocol.go",
		"internal/hostruntime/runtime_token_rotation_protocol.go",
		"internal/controlplane/v2_boundary.go",
	}
	forbiddenTags := []string{
		`json:"argv`,
		`json:"args`,
		`json:"env`,
		`json:"path`,
		`json:"command`,
	}
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(repositoryRoot, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		for _, tag := range forbiddenTags {
			if bytes.Contains(data, []byte(tag)) {
				t.Errorf("wire file %s contains forbidden field tag %q", name, tag)
			}
		}
	}
}
