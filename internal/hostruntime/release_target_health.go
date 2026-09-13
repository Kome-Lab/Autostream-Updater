package hostruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	applicationprobe "github.com/Kome-Lab/Autostream-Updater/internal/probe"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func checkpointEnv(checkpoint *updateCheckpoint) []byte {
	if checkpoint == nil {
		return nil
	}
	return checkpoint.PreviousVersionEnv
}

func checkpointMode(checkpoint *updateCheckpoint) os.FileMode {
	if checkpoint == nil || checkpoint.VersionEnvMode == 0 {
		return 0o600
	}
	return checkpoint.VersionEnvMode
}

func runFixedCommand(ctx context.Context, runner CommandRunner, argv []string) error {
	if len(argv) == 0 {
		return nil
	}
	commandCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	_, err := runner.Run(commandCtx, "", nil, argv[0], argv[1:]...)
	return err
}

func verifyTarget(ctx context.Context, target Target, expectedVersion string) error {
	deadlineCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var lastErr error
	for {
		if err := checkHealth(deadlineCtx, client, target.HealthURL); err == nil {
			if actual, err := fetchApplicationIdentityVersion(deadlineCtx, client, target); err == nil && versionsEqual(actual, expectedVersion) {
				return nil
			} else if err != nil {
				lastErr = err
			} else {
				lastErr = fmt.Errorf("reported version %q does not match %q", actual, expectedVersion)
			}
		} else {
			lastErr = err
		}
		select {
		case <-deadlineCtx.Done():
			return fmt.Errorf("post-update verification failed: %w", lastErr)
		case <-ticker.C:
		}
	}
}

func checkHealth(ctx context.Context, client *http.Client, raw string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("health endpoint returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func fetchApplicationIdentityVersion(ctx context.Context, client *http.Client, target Target) (string, error) {
	identity, err := (applicationprobe.Client{HTTP: client}).FetchApplicationIdentity(
		ctx,
		target.VersionURL,
		applicationprobe.ExpectedIdentity{
			ServiceID:      target.TargetID,
			ServiceType:    target.ServiceType,
			ConfigRevision: target.ConfigRevision,
		},
	)
	if err != nil {
		return "", err
	}
	return identity.Version, nil
}

func versionMatches(output, expected string) bool {
	for _, field := range strings.Fields(output) {
		if versionsEqual(strings.Trim(field, ",;()"), expected) {
			return true
		}
	}
	return false
}

func versionsEqual(a, b string) bool {
	return strings.TrimPrefix(strings.TrimSpace(a), "v") == strings.TrimPrefix(strings.TrimSpace(b), "v")
}

func shortID(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:6])
}

func firstError(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
