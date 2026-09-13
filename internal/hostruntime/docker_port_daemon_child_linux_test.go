//go:build linux

package hostruntime

import (
	"context"
	"errors"
	contracts "github.com/example/autostream-contracts/pkg/contracts"
	"net/http"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestDockerPortDaemonSmokeChild(t *testing.T) {
	if os.Getenv(dockerPortDaemonSmokeChildEnv) != "1" {
		t.Skip("Docker port daemon smoke child only")
	}
	var payload dockerPortSmokeChildPayload
	readDockerPortSmokeJSON(
		t, os.Getenv(dockerPortDaemonSmokePayloadEnv), &payload,
	)
	policy, err := LoadLocalExecutorPolicy(dockerPortSmokePolicyPath, true)
	if err != nil {
		t.Fatalf("load child root policy: %v", err)
	}
	adapter, err := dockerPortAdapterFor(
		"worker", policy.Targets[0].Docker,
	)
	if err != nil {
		t.Fatal(err)
	}
	runner := newDockerPortSmokeRunner(
		t, payload.ImageID, payload.RepositoryDigest,
		payload.CaptureDir, adapter,
	)
	grantCalls := 0
	request := dockerPortSmokeRequest(payload.Plan, payload.Operation)
	ctx := context.Background()
	failurePhase, failureClass := -1, -1
	ctx = context.WithValue(ctx, localExecutionFailureContextKey{}, func(phase localExecutionFailurePhase, class localExecutionFailureClass) {
		if failurePhase == -1 {
			failurePhase, failureClass = int(phase), int(class)
		}
	})
	if payload.Plan.PortContractVersion == 2 {
		runner.beginSTPortDiagnostic("combined_recovery", true)
		request = newSTPortV2Request(t, payload.Plan, time.Now(), payload.Operation)
		manager, err := newFilePortPolicyStore(dockerPortSmokePolicyPath, true)
		if err != nil {
			t.Fatal(err)
		}
		ctx = context.WithValue(ctx, portPolicyContextKey{}, portPolicyStore(manager))
	}
	remoteRuntime := executorMutationRuntime{
		platformOS:    "linux",
		localStateDir: payload.StateDir,
		runner:        runner,
		consumeGrant: func(
			_ context.Context,
			panelURL, jobID, grant string,
			binding MutationGrantBinding,
			_ *http.Client,
		) error {
			grantCalls++
			if err := validateDockerPortSmokeGrantBinding(
				payload.Plan, payload.Operation,
				panelURL, jobID, grant, binding,
			); err != nil {
				return err
			}
			writeDockerPortSmokeJSON(
				t, payload.GrantRecordPath, binding,
			)
			return nil
		},
		consumeV2Grant: func(_ context.Context, panelURL, jobID, grant string, consumed contracts.UpdaterMutationGrantConsumeRequest, _ *http.Client, now time.Time) error {
			grantCalls++
			if request.MutationGrantV2Binding == nil || panelURL != "https://panel.example.com" || jobID != payload.Plan.JobID || grant != dockerPortDaemonSmokeGrant ||
				!reflect.DeepEqual(consumed.Binding, *request.MutationGrantV2Binding) || contracts.ValidateUpdaterMutationGrantBinding(now, consumed.Binding) != nil {
				return errors.New("versioned child mutation grant binding changed")
			}
			writeDockerPortSmokeJSON(t, payload.GrantRecordPath, consumed.Binding)
			return nil
		},
	}
	crashPhase := payload.CrashPhase
	if crashPhase == "" && payload.CrashAfterRecreate {
		crashPhase = "after_docker_recreate"
		if payload.Plan.PortContractVersion == 2 {
			crashPhase = "after_restart"
		}
	}
	switch crashPhase {
	case "", "after_docker_recreate", "after_restart", "after_target_verify":
	default:
		t.Fatal("unknown Docker smoke crash phase")
	}
	remoteRuntime.dockerPortCrashPointForTest = func(point string) error {
		_ = runner.observeSTPortPhase(point)
		if crashPhase != "" && point == crashPhase {
			os.Exit(dockerPortDaemonSmokeCrashExit)
		}
		return nil
	}
	request.MutationGrant = NewBoundedSecret(
		os.Getenv(dockerPortDaemonSmokeGrantEnv),
	)
	response := handleLocalExecutorMutation(
		ctx,
		policy,
		request,
		remoteRuntime,
	)
	runner.logSTPortChildReturn(t, payload, crashPhase, response, grantCalls)
	if failurePhase >= 0 {
		t.Logf("ST-PORT child first failure: phase=%d class=%d", failurePhase, failureClass)
	}
	if payload.ExpectGrant != (grantCalls == 1) {
		t.Fatalf(
			"child grant calls=%d expect_grant=%t",
			grantCalls, payload.ExpectGrant,
		)
	}
	if payload.ResponsePath == "" {
		t.Fatal("child returned without a response path")
	}
	writeDockerPortSmokeJSON(t, payload.ResponsePath, response)
}
