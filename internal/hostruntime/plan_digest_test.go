package hostruntime

import (
	"strings"
	"testing"
)

func TestMutationPlanSHA256BindsHostAndImmutableDigestsButNotSecretsOrPaths(t *testing.T) {
	base := ApplyPlan{JobID: "job-one", HostID: "host-a", TargetID: "worker", ServiceType: "worker", DeploymentMode: ModeDocker, TargetVersion: "v1.2.3", CurrentVersion: "v1.2.2", ConfigSHA256: "sha256:" + strings.Repeat("d", 64), LeaseGeneration: 2, ExpectedVersion: "v1.0.0", ExpectedImageDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ExpectedPlatformDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	digest, err := MutationPlanSHA256(base)
	if err != nil || len(digest) != 64 {
		t.Fatalf("digest=%q err=%v", digest, err)
	}
	secretChanged := base
	secretChanged.LeaseToken = "not-part-of-the-remote-plan"
	secretChanged.StageDir = "/different/local/path"
	if got, err := MutationPlanSHA256(secretChanged); err != nil || got != digest {
		t.Fatalf("secret/path changed digest: got=%q err=%v want=%q", got, err, digest)
	}
	hostChanged := base
	hostChanged.HostID = "host-b"
	if got, _ := MutationPlanSHA256(hostChanged); got == digest {
		t.Fatal("host change did not alter mutation plan digest")
	}
	imageChanged := base
	imageChanged.ExpectedPlatformDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if got, _ := MutationPlanSHA256(imageChanged); got == digest {
		t.Fatal("platform digest change did not alter mutation plan digest")
	}
	configChanged := base
	configChanged.ConfigSHA256 = "sha256:" + strings.Repeat("e", 64)
	if got, _ := MutationPlanSHA256(configChanged); got == digest {
		t.Fatal("helper config digest change did not alter mutation plan digest")
	}
}

func TestMutationPlanSHA256RejectsIncompleteIdentity(t *testing.T) {
	if _, err := MutationPlanSHA256(ApplyPlan{JobID: "job-one", TargetID: "worker", DeploymentMode: ModeDocker, TargetVersion: "v1.2.3", LeaseGeneration: 1}); err == nil {
		t.Fatal("missing host was accepted")
	}
	base := ApplyPlan{JobID: "job-one", HostID: "host-a", TargetID: "worker", ServiceType: "worker", DeploymentMode: ModeSystemd, TargetVersion: "v1.2.3", CurrentVersion: "v1.2.2", ConfigSHA256: "sha256:" + strings.Repeat("d", 64), LeaseGeneration: 1}
	missingCurrent := base
	missingCurrent.CurrentVersion = ""
	if _, err := MutationPlanSHA256(missingCurrent); err == nil {
		t.Fatal("unknown current version was accepted")
	}
	missingConfig := base
	missingConfig.ConfigSHA256 = ""
	if _, err := MutationPlanSHA256(missingConfig); err == nil {
		t.Fatal("missing helper config digest was accepted")
	}
}
