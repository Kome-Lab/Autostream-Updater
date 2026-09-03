package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type dockerPortPreflightRunner struct {
	containers []string
	bindings   map[string]string
	err        error
	calls      []commandCall
}

type dockerPortApplyRunner struct {
	baseline *executorDockerBaselineRunner
	owners   string
	bindings map[string]string
}

type dockerPortRollbackRunner struct {
	calls             []commandCall
	oldContainer      string
	newContainer      string
	rollbackContainer string
	oldImage          string
	newImage          string
	oldRepository     string
	targetPlatform    string
	imageRepo         string
	upCount           int
	configCount       int
	cancelApply       context.CancelFunc
}

func canonicalWorkerDockerPortTarget() *DockerTarget {
	return &DockerTarget{
		Service:   "worker",
		ImageRepo: "ghcr.io/kome-lab/autostream-docker/worker",
	}
}

func (r *dockerPortApplyRunner) Run(ctx context.Context, dir string, env []string, name string, args ...string) (string, error) {
	if len(args) >= 2 && args[0] == "container" && args[1] == "ls" {
		r.baseline.calls = append(r.baseline.calls, commandCall{
			dir:  dir,
			env:  append([]string(nil), env...),
			name: name,
			args: append([]string(nil), args...),
		})
		return r.owners, nil
	}
	if len(args) >= 2 && args[0] == "container" && args[1] == "inspect" {
		r.baseline.calls = append(r.baseline.calls, commandCall{
			dir:  dir,
			env:  append([]string(nil), env...),
			name: name,
			args: append([]string(nil), args...),
		})
		var results []string
		for _, owner := range args[3:] {
			results = append(results, r.bindings[owner])
		}
		return strings.Join(results, "\n") + "\n", nil
	}
	return r.baseline.Run(ctx, dir, env, name, args...)
}

func (r *dockerPortPreflightRunner) Run(_ context.Context, dir string, env []string, name string, args ...string) (string, error) {
	r.calls = append(r.calls, commandCall{
		dir:  dir,
		env:  append([]string(nil), env...),
		name: name,
		args: append([]string(nil), args...),
	})
	if r.err != nil {
		return "", r.err
	}
	if len(args) >= 2 && args[0] == "container" && args[1] == "ls" {
		return strings.Join(r.containers, "\n") + "\n", nil
	}
	if len(args) >= 2 && args[0] == "container" && args[1] == "inspect" {
		var results []string
		for _, owner := range args[3:] {
			results = append(results, r.bindings[owner])
		}
		return strings.Join(results, "\n") + "\n", nil
	}
	return "", nil
}

func (r *dockerPortRollbackRunner) Run(_ context.Context, dir string, env []string, name string, args ...string) (string, error) {
	r.calls = append(r.calls, commandCall{
		dir:  dir,
		env:  append([]string(nil), env...),
		name: name,
		args: append([]string(nil), args...),
	})
	joined := strings.Join(args, " ")
	switch {
	case len(args) >= 2 && args[0] == "container" && args[1] == "ls":
		return r.oldContainer + "\n", nil
	case len(args) >= 2 && args[0] == "container" && args[1] == "inspect":
		return `{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"18084"}]}` + "\n", nil
	case len(args) > 0 && args[0] == "ps":
		switch r.upCount {
		case 0:
			return r.oldContainer + "\n", nil
		case 1:
			return r.newContainer + "\n", nil
		default:
			return r.rollbackContainer + "\n", nil
		}
	case len(args) > 0 && args[0] == "inspect":
		if args[len(args)-1] == r.newContainer {
			return r.newImage + "\n", nil
		}
		return r.oldImage + "\n", nil
	case len(args) > 2 && args[0] == "image" && args[1] == "inspect" && strings.Contains(joined, "RepoDigests"):
		if strings.Contains(args[len(args)-1], "@"+r.targetPlatform) {
			return `["` + r.imageRepo + `@` + r.targetPlatform + `"]`, nil
		}
		return `["` + r.imageRepo + `@` + r.oldRepository + `"]`, nil
	case len(args) > 1 && args[0] == "image" && args[1] == "inspect":
		return r.newImage + "\n", nil
	case strings.Contains(joined, "config --format json"):
		r.configCount++
		return dockerRollbackComposeModel(r.oldImage), nil
	case strings.Contains(joined, " up -d "):
		r.upCount++
		if r.upCount == 1 && r.cancelApply != nil {
			r.cancelApply()
		}
		return "", nil
	default:
		return "", nil
	}
}

func dockerRollbackComposeModel(image string) string {
	raw := []byte(`{"services":{"worker":{` +
		`"image":"` + image + `",` +
		`"ports":[{"host_ip":"127.0.0.1","target":8080,"published":"18084","protocol":"tcp","mode":"ingress"}]` +
		`}}}`)
	model, err := dockerNodeListenerTestModel(raw, "worker", "0.0.0.0:8080", 1)
	if err != nil {
		panic(err)
	}
	return string(model)
}

func TestValidateDockerComposePortMappingsSeparatesPublishedAndContainerPorts(t *testing.T) {
	target := canonicalWorkerDockerPortTarget()
	raw := mustDockerNodeListenerModel(t, []byte(`{
		"services": {
			"worker": {
				"ports": [{
					"host_ip": "127.0.0.1",
					"target": 18080,
					"published": "18084",
					"protocol": "tcp",
					"mode": "ingress"
				}]
			}
		}
	}`), "worker", "0.0.0.0:18080", 1)
	mappings, err := validateDockerComposePortMappings(raw, target)
	if err != nil {
		t.Fatal(err)
	}
	if len(mappings) != 1 ||
		mappings[0].HostIP != "127.0.0.1" ||
		mappings[0].PublishedPort != 18084 ||
		mappings[0].ContainerPort != 18080 ||
		mappings[0].Protocol != "tcp" {
		t.Fatalf("mappings = %+v", mappings)
	}
}

func TestValidateDockerComposePortMappingsKeepsReverseProxyOriginSeparate(t *testing.T) {
	raw := mustDockerNodeListenerModel(t, []byte(`{
		"services": {
			"worker": {
				"ports": [{
					"host_ip": "127.0.0.1",
					"target": 8080,
					"published": "18084",
					"protocol": "tcp",
					"mode": "ingress"
				}]
			},
			"reverse-proxy": {
				"ports": [{
					"target": 443,
					"published": "443",
					"protocol": "tcp",
					"mode": "ingress"
				}]
			}
		}
	}`), "worker", "0.0.0.0:8080", 1)
	mappings, err := validateDockerComposePortMappings(raw, canonicalWorkerDockerPortTarget())
	if err != nil {
		t.Fatal(err)
	}
	if len(mappings) != 1 ||
		mappings[0].PublishedPort != 18084 ||
		mappings[0].ContainerPort != 8080 {
		t.Fatalf("managed mapping = %+v", mappings)
	}
}

func TestValidateDockerComposePortMappingsLeavesControlPanelOutsideNodePortContract(t *testing.T) {
	raw := []byte(`{
		"services": {
			"control-panel": {
				"image": "ghcr.io/kome-lab/autostream-docker/control-panel:v1.0.0",
				"ports": [{
					"host_ip": "127.0.0.1",
					"target": 8080,
					"published": "8080",
					"protocol": "tcp",
					"mode": "ingress"
				}]
			}
		}
	}`)
	target := &DockerTarget{
		Service:   "control-panel",
		ImageRepo: "ghcr.io/kome-lab/autostream-docker/control-panel",
	}
	mappings, err := validateDockerComposePortMappings(raw, target)
	if err != nil {
		t.Fatal(err)
	}
	if len(mappings) != 0 {
		t.Fatalf("control-panel mapping = %+v", mappings)
	}
	if err := validateComposeModelSecurity(raw, target); err != nil {
		t.Fatalf("legacy Control Panel software-update model regressed: %v", err)
	}
}

func TestValidateDockerComposePortMappingsLeavesCustomBridgeTargetUnchanged(t *testing.T) {
	raw := []byte(`{
		"services": {
			"worker": {
				"image": "ghcr.io/example/custom-worker:v1.0.0",
				"ports": [{"target":9000,"published":"9001","protocol":"tcp"}]
			}
		}
	}`)
	target := &DockerTarget{
		Service:   "worker",
		ImageRepo: "ghcr.io/example/custom-worker",
	}
	mappings, err := validateDockerComposePortMappings(raw, target)
	if err != nil {
		t.Fatal(err)
	}
	if len(mappings) != 0 {
		t.Fatalf("custom bridge mapping = %+v", mappings)
	}
	if err := validateComposeModelSecurity(raw, target); err != nil {
		t.Fatalf("custom bridge software-update model regressed: %v", err)
	}
}

func TestValidateDockerComposePortMappingsRejectsUnsafeOrAmbiguousModels(t *testing.T) {
	tests := map[string]struct {
		raw         string
		bindAddress string
	}{
		"privileged published port": {raw: `{
			"services":{"worker":{
				"ports":[{"target":8080,"published":"443","protocol":"tcp"}]
			}}
		}`, bindAddress: "0.0.0.0:8080"},
		"bind target mismatch": {raw: `{
			"services":{"worker":{
				"ports":[{"target":18080,"published":"18084","protocol":"tcp"}]
			}}
		}`, bindAddress: "0.0.0.0:8080"},
		"container loopback bind": {raw: `{
			"services":{"worker":{
				"ports":[{"target":8080,"published":"18084","protocol":"tcp"}]
			}}
		}`, bindAddress: "127.0.0.1:8080"},
		"duplicate project host port": {raw: `{
			"services":{
				"worker":{
					"ports":[{"host_ip":"0.0.0.0","target":8080,"published":"18084","protocol":"tcp"}]
				},
				"other":{
					"ports":[{"host_ip":"127.0.0.1","target":8080,"published":"18084","protocol":"tcp"}]
				}
			}
		}`, bindAddress: "0.0.0.0:8080"},
		"udp mapping": {raw: `{
			"services":{"worker":{
				"ports":[{"target":8080,"published":"18084","protocol":"udp"}]
			}}
		}`, bindAddress: "0.0.0.0:8080"},
		"multiple managed mappings": {raw: `{
			"services":{"worker":{
				"ports":[
					{"target":8080,"published":"18084","protocol":"tcp"},
					{"target":8080,"published":"18085","protocol":"tcp"}
				]
			}}
		}`, bindAddress: "0.0.0.0:8080"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			raw := mustDockerNodeListenerModel(
				t,
				[]byte(test.raw),
				"worker",
				test.bindAddress,
				1,
			)
			if _, err := validateDockerComposePortMappings(raw, canonicalWorkerDockerPortTarget()); err == nil {
				t.Fatal("unsafe Docker port mapping was accepted")
			}
		})
	}
}

func TestValidateDockerComposePortMappingsRejectsTrailingGarbage(t *testing.T) {
	raw := []byte(`{
		"services":{"worker":{
			"ports":[{"target":8080,"published":"18084","protocol":"tcp"}]
		}}
	} trailing`)
	if _, err := validateDockerComposePortMappings(raw, canonicalWorkerDockerPortTarget()); err == nil {
		t.Fatal("Compose mapping with trailing garbage was accepted")
	}
}

func TestComposeModelHashBindsPublishedAndContainerPorts(t *testing.T) {
	base := mustDockerNodeListenerModel(t, []byte(`{
		"services":{"worker":{
			"image":"ghcr.io/kome-lab/autostream-docker/worker:v1.0.0",
			"ports":[{"target":8080,"published":"8084","protocol":"tcp"}]
		}}
	}`), "worker", "0.0.0.0:8080", 1)
	changedPublished := []byte(strings.Replace(string(base), `"published":"8084"`, `"published":"18084"`, 1))
	changedContainer := []byte(strings.Replace(
		strings.Replace(string(base), `"target":8080`, `"target":18080`, 1),
		`0.0.0.0:8080`,
		`0.0.0.0:18080`,
		1,
	))
	baseDigest, err := composeModelHash(base, "worker")
	if err != nil {
		t.Fatal(err)
	}
	publishedDigest, err := composeModelHash(changedPublished, "worker")
	if err != nil {
		t.Fatal(err)
	}
	containerDigest, err := composeModelHash(changedContainer, "worker")
	if err != nil {
		t.Fatal(err)
	}
	if baseDigest == publishedDigest || baseDigest == containerDigest || publishedDigest == containerDigest {
		t.Fatalf("port mapping is not bound by the trusted Compose digest: base=%s published=%s container=%s", baseDigest, publishedDigest, containerDigest)
	}
}

func TestPreflightDockerPublishedPortOwnershipRejectsForeignContainer(t *testing.T) {
	const current = "aaaaaaaaaaaa"
	const foreign = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	runner := &dockerPortPreflightRunner{
		containers: []string{foreign},
		bindings: map[string]string{
			foreign: `{"9999/tcp":[{"HostIp":"127.0.0.1","HostPort":"18084"}]}`,
		},
	}
	err := preflightDockerPublishedPortOwnership(
		context.Background(),
		runner,
		&DockerTarget{DockerPath: "/usr/bin/docker", ProjectDir: "/opt/autostream"},
		[]dockerPortMapping{{HostIP: "127.0.0.1", PublishedPort: 18084, ContainerPort: 8080, Protocol: "tcp"}},
		current,
	)
	if err == nil || !strings.Contains(err.Error(), "already owned") {
		t.Fatalf("foreign host-port owner result = %v", err)
	}
}

func TestPreflightDockerPublishedPortOwnershipAllowsOnlyCurrentContainer(t *testing.T) {
	const current = "aaaaaaaaaaaa"
	const currentFull = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	runner := &dockerPortPreflightRunner{
		containers: []string{currentFull},
		bindings: map[string]string{
			currentFull: `{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"18084"}]}`,
		},
	}
	err := preflightDockerPublishedPortOwnership(
		context.Background(),
		runner,
		&DockerTarget{DockerPath: "/usr/bin/docker", ProjectDir: "/opt/autostream"},
		[]dockerPortMapping{{HostIP: "127.0.0.1", PublishedPort: 18084, ContainerPort: 8080, Protocol: "tcp"}},
		current,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("calls = %+v", runner.calls)
	}
	listCall, inspectCall := runner.calls[0], runner.calls[1]
	if listCall.name != "/usr/bin/docker" ||
		!strings.Contains(strings.Join(listCall.args, " "), "container ls --quiet --no-trunc") ||
		strings.Contains(strings.Join(listCall.args, " "), "publish=") ||
		!strings.Contains(strings.Join(inspectCall.args, " "), "container inspect --format={{json .NetworkSettings.Ports}}") {
		t.Fatalf("unexpected Docker collision probe: %+v", runner.calls)
	}
}

func TestPreflightDockerPublishedPortOwnershipAllowsSamePortOnDifferentSpecificIP(t *testing.T) {
	const current = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const foreign = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	runner := &dockerPortPreflightRunner{
		containers: []string{current, foreign},
		bindings: map[string]string{
			current: `{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"18084"}]}`,
			foreign: `{"8080/tcp":[{"HostIp":"192.0.2.10","HostPort":"18084"}]}`,
		},
	}
	err := preflightDockerPublishedPortOwnership(
		context.Background(),
		runner,
		&DockerTarget{DockerPath: "/usr/bin/docker", ProjectDir: "/opt/autostream"},
		[]dockerPortMapping{{HostIP: "127.0.0.1", PublishedPort: 18084, ContainerPort: 8080, Protocol: "tcp"}},
		current,
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPreflightDockerPublishedPortOwnershipRejectsWrongCurrentContainerTarget(t *testing.T) {
	const current = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	runner := &dockerPortPreflightRunner{
		containers: []string{current},
		bindings: map[string]string{
			current: `{"9999/tcp":[{"HostIp":"127.0.0.1","HostPort":"18084"}]}`,
		},
	}
	err := preflightDockerPublishedPortOwnership(
		context.Background(),
		runner,
		&DockerTarget{DockerPath: "/usr/bin/docker", ProjectDir: "/opt/autostream"},
		[]dockerPortMapping{{HostIP: "127.0.0.1", PublishedPort: 18084, ContainerPort: 8080, Protocol: "tcp"}},
		current,
	)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("wrong current container target result = %v", err)
	}
}

func TestPreflightDockerPublishedPortOwnershipRejectsCurrentHostIPDrift(t *testing.T) {
	const current = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tests := []struct {
		name     string
		expected string
		actual   string
	}{
		{name: "broader actual", expected: "127.0.0.1", actual: "0.0.0.0"},
		{name: "narrower actual", expected: "0.0.0.0", actual: "127.0.0.1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &dockerPortPreflightRunner{
				containers: []string{current},
				bindings: map[string]string{
					current: `{"8080/tcp":[{"HostIp":"` + test.actual + `","HostPort":"18084"}]}`,
				},
			}
			err := preflightDockerPublishedPortOwnership(
				context.Background(),
				runner,
				&DockerTarget{DockerPath: "/usr/bin/docker", ProjectDir: "/opt/autostream"},
				[]dockerPortMapping{{HostIP: test.expected, PublishedPort: 18084, ContainerPort: 8080, Protocol: "tcp"}},
				current,
			)
			if err == nil || !strings.Contains(err.Error(), "does not match") {
				t.Fatalf("HostIP drift result = %v", err)
			}
		})
	}
}

func TestPreflightDockerPublishedPortOwnershipNormalizesUnspecifiedCurrentHostIP(t *testing.T) {
	const current = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	runner := &dockerPortPreflightRunner{
		containers: []string{current},
		bindings: map[string]string{
			current: `{"8080/tcp":[
				{"HostIp":"0.0.0.0","HostPort":"18084"},
				{"HostIp":"::","HostPort":"18084"}
			]}`,
		},
	}
	err := preflightDockerPublishedPortOwnership(
		context.Background(),
		runner,
		&DockerTarget{DockerPath: "/usr/bin/docker", ProjectDir: "/opt/autostream"},
		[]dockerPortMapping{{HostIP: "", PublishedPort: 18084, ContainerPort: 8080, Protocol: "tcp"}},
		current,
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPreflightDockerPublishedPortOwnershipFailsClosedOnProbeError(t *testing.T) {
	runner := &dockerPortPreflightRunner{err: errors.New("daemon unavailable")}
	err := preflightDockerPublishedPortOwnership(
		context.Background(),
		runner,
		&DockerTarget{DockerPath: "/usr/bin/docker", ProjectDir: "/opt/autostream"},
		[]dockerPortMapping{{PublishedPort: 18084, ContainerPort: 8080, Protocol: "tcp"}},
		"aaaaaaaaaaaa",
	)
	if err == nil || !strings.Contains(err.Error(), "could not verify") {
		t.Fatalf("Docker collision probe error result = %v", err)
	}
}

func TestPreflightDockerPublishedPortOwnershipRequiresManagedOwner(t *testing.T) {
	runner := &dockerPortPreflightRunner{}
	err := preflightDockerPublishedPortOwnership(
		context.Background(),
		runner,
		&DockerTarget{DockerPath: "/usr/bin/docker", ProjectDir: "/opt/autostream"},
		[]dockerPortMapping{{PublishedPort: 18084, ContainerPort: 8080, Protocol: "tcp"}},
		"aaaaaaaaaaaa",
	)
	if err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Fatalf("unowned Docker published port result = %v", err)
	}
}

func TestPreflightDockerProposedPortAvailabilityIgnoresOnlyManagedContainer(t *testing.T) {
	const current = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const foreign = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	runner := &dockerPortPreflightRunner{
		containers: []string{current, foreign},
		bindings: map[string]string{
			current: `{"8080/tcp":[{"HostIp":"0.0.0.0","HostPort":"18084"}]}`,
			foreign: `{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"19000"}]}`,
		},
	}
	err := preflightDockerProposedPortAvailability(
		context.Background(),
		runner,
		&DockerTarget{DockerPath: "/usr/bin/docker", ProjectDir: "/opt/autostream"},
		dockerPortMapping{
			HostIP:        "127.0.0.1",
			PublishedPort: 18084,
			ContainerPort: 18080,
			Protocol:      "tcp",
		},
		current,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("calls = %+v", runner.calls)
	}
	inspectArgs := runner.calls[1].args
	if strings.Contains(strings.Join(inspectArgs, " "), current) ||
		!strings.Contains(strings.Join(inspectArgs, " "), foreign) {
		t.Fatalf("proposed-port probe did not exclude exactly the managed container: %+v", runner.calls)
	}
}

func TestPreflightDockerProposedPortAvailabilityRejectsForeignConflictingBindings(t *testing.T) {
	const current = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const foreign = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	for _, hostIP := range []string{"127.0.0.1", "0.0.0.0", "::"} {
		t.Run(hostIP, func(t *testing.T) {
			runner := &dockerPortPreflightRunner{
				containers: []string{current, foreign},
				bindings: map[string]string{
					foreign: `{"8080/tcp":[{"HostIp":"` + hostIP + `","HostPort":"18084"}]}`,
				},
			}
			err := preflightDockerProposedPortAvailability(
				context.Background(),
				runner,
				&DockerTarget{DockerPath: "/usr/bin/docker", ProjectDir: "/opt/autostream"},
				dockerPortMapping{
					HostIP:        "127.0.0.1",
					PublishedPort: 18084,
					ContainerPort: 18080,
					Protocol:      "tcp",
				},
				current,
			)
			if err == nil || !strings.Contains(err.Error(), "already owned") {
				t.Fatalf("foreign conflicting binding result = %v", err)
			}
		})
	}
}

func TestPreflightDockerProposedPortAvailabilityRequiresManagedContainer(t *testing.T) {
	const current = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const foreign = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	runner := &dockerPortPreflightRunner{
		containers: []string{foreign},
		bindings: map[string]string{
			foreign: `{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"19000"}]}`,
		},
	}
	err := preflightDockerProposedPortAvailability(
		context.Background(),
		runner,
		&DockerTarget{DockerPath: "/usr/bin/docker", ProjectDir: "/opt/autostream"},
		dockerPortMapping{
			HostIP:        "127.0.0.1",
			PublishedPort: 18084,
			ContainerPort: 18080,
			Protocol:      "tcp",
		},
		current,
	)
	if err == nil || !strings.Contains(err.Error(), "managed Docker container") {
		t.Fatalf("missing managed container result = %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("foreign containers were inspected after the managed identity was lost: %+v", runner.calls)
	}
}

func TestPreflightDockerProposedPortAvailabilityRejectsAbbreviatedManagedID(t *testing.T) {
	const current = "aaaaaaaaaaaa"
	runner := &dockerPortPreflightRunner{
		containers: []string{current + strings.Repeat("1", 52)},
	}
	err := preflightDockerProposedPortAvailability(
		context.Background(),
		runner,
		&DockerTarget{DockerPath: "/usr/bin/docker", ProjectDir: "/opt/autostream"},
		dockerPortMapping{
			HostIP:        "127.0.0.1",
			PublishedPort: 18084,
			ContainerPort: 18080,
			Protocol:      "tcp",
		},
		current,
	)
	if err == nil || !strings.Contains(err.Error(), "baseline is invalid") {
		t.Fatalf("abbreviated managed container result = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("abbreviated managed identity reached Docker: %+v", runner.calls)
	}
}

func TestPreflightDockerProposedPortAvailabilityRejectsNonCanonicalRunningIDs(t *testing.T) {
	const current = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tests := map[string][]string{
		"abbreviated": {current, "bbbbbbbbbbbb"},
		"uppercase":   {current, strings.Repeat("B", 64)},
		"duplicate":   {current, current},
	}
	for name, containers := range tests {
		t.Run(name, func(t *testing.T) {
			runner := &dockerPortPreflightRunner{containers: containers}
			err := preflightDockerProposedPortAvailability(
				context.Background(),
				runner,
				&DockerTarget{DockerPath: "/usr/bin/docker", ProjectDir: "/opt/autostream"},
				dockerPortMapping{
					HostIP:        "127.0.0.1",
					PublishedPort: 18084,
					ContainerPort: 18080,
					Protocol:      "tcp",
				},
				current,
			)
			if err == nil || !strings.Contains(err.Error(), "identities") {
				t.Fatalf("non-canonical running container result = %v", err)
			}
			if len(runner.calls) != 1 {
				t.Fatalf("non-canonical container identities reached inspect: %+v", runner.calls)
			}
		})
	}
}

func TestPreflightDockerProposedPortAvailabilityBoundsContainerEnumeration(t *testing.T) {
	containers := make([]string, 257)
	for index := range containers {
		containers[index] = fmt.Sprintf("%064x", index+1)
	}
	runner := &dockerPortPreflightRunner{containers: containers}
	err := preflightDockerProposedPortAvailability(
		context.Background(),
		runner,
		&DockerTarget{DockerPath: "/usr/bin/docker", ProjectDir: "/opt/autostream"},
		dockerPortMapping{
			HostIP:        "127.0.0.1",
			PublishedPort: 18084,
			ContainerPort: 18080,
			Protocol:      "tcp",
		},
		containers[0],
	)
	if err == nil || !strings.Contains(err.Error(), "unbounded") {
		t.Fatalf("unbounded container enumeration result = %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("unbounded container set reached inspect: %+v", runner.calls)
	}
}

func TestTrustedDockerApplyRejectsForeignPublishedPortOwnerBeforeCheckpoint(t *testing.T) {
	target, plan, baselineRunner, _ := executorDockerMutationFixture(t)
	baselineRunner.containerID = strings.Repeat("a", 64)
	frozen := mustDockerNodeListenerModel(t, []byte(`{
		"services":{"worker":{
			"image":"`+target.Docker.ImageRepo+`@`+plan.ExpectedPlatformDigest+`",
			"ports":[{"host_ip":"127.0.0.1","target":8080,"published":"18084","protocol":"tcp","mode":"ingress"}]
		}}
	}`), "worker", "0.0.0.0:8080", 1)
	digest, err := composeModelHash(frozen, target.Docker.Service)
	if err != nil {
		t.Fatal(err)
	}
	target.Docker.ComposeConfigSHA256 = digest
	frozenPath := filepath.Join(plan.StageDir, "compose-frozen.json")
	if err := os.WriteFile(frozenPath, frozen, 0o600); err != nil {
		t.Fatal(err)
	}
	staged, err := observeDockerMutationBaseline(context.Background(), target, baselineRunner)
	if err != nil {
		t.Fatal(err)
	}
	baselineRunner.calls = nil
	runner := &dockerPortApplyRunner{
		baseline: baselineRunner,
		owners:   strings.Repeat("b", 64) + "\n",
		bindings: map[string]string{
			strings.Repeat("b", 64): `{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"18084"}]}`,
		},
	}
	gateCalled := false
	_, err = applyDockerWithGateAndBaselineWithOwnerCheck(
		context.Background(),
		target,
		plan,
		runner,
		func(context.Context) error {
			gateCalled = true
			return nil
		},
		true,
		&staged.Baseline,
		baselineRunner.targetImage,
		acceptTestFixtureOwner,
	)
	if err == nil || !strings.Contains(err.Error(), "already owned") || !gateCalled {
		t.Fatalf("foreign published-port owner result=%v gate_called=%v", err, gateCalled)
	}
	if _, statErr := os.Stat(checkpointPath(target)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("checkpoint was created before the collision rejection: %v", statErr)
	}
	for _, call := range baselineRunner.calls {
		if strings.Contains(strings.Join(call.args, " "), " up ") {
			t.Fatalf("Compose service mutated before the collision rejection: %+v", call)
		}
	}
}

func TestTrustedDockerSoftwareUpdatePreservesPortMappingDuringForcedRollback(t *testing.T) {
	const oldSource = "v1.5.0"
	const newSource = "v1.6.0"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/version") {
			w.Header().Set("Cache-Control", "no-store")
			_, _ = fmt.Fprintf(w, `{"version":%q,"service_id":"worker-01","service_type":"worker","config_revision":1}`, oldSource)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	root := t.TempDir()
	stageDir := filepath.Join(root, "stage")
	if err := os.MkdirAll(stageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	imageRepo := "ghcr.io/kome-lab/autostream-docker/worker"
	oldManifest := "sha256:" + strings.Repeat("b", 64)
	targetPlatform := "sha256:" + strings.Repeat("e", 64)
	oldImage := "sha256:" + strings.Repeat("a", 64)
	newImage := "sha256:" + strings.Repeat("d", 64)
	frozen := []byte(dockerRollbackComposeModel(imageRepo + "@" + targetPlatform))
	modelDigest, err := composeModelHash(frozen, "worker")
	if err != nil {
		t.Fatal(err)
	}
	versionEnv := filepath.Join(root, "worker.env")
	oldVersionEnv := "AUTOSTREAM_DOCKER_VERSION=v1.0.0@" + oldManifest + "\n"
	if err := os.WriteFile(versionEnv, []byte(oldVersionEnv), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stageDir, "compose-frozen.json"), frozen, 0o600); err != nil {
		t.Fatal(err)
	}
	target := Target{
		TargetID: "worker-01", HostID: "edge-01", ServiceType: "worker", DeploymentMode: ModeDocker, ConfigRevision: 1,
		HealthURL: server.URL + "/health", VersionURL: server.URL + "/updater/version",
		Docker: &DockerTarget{
			DockerPath: filepath.Join(root, "docker"), ComposeProject: "autostream", ProjectDir: root,
			ComposeFiles: []string{filepath.Join(root, "compose.yml")}, Service: "worker", ImageRepo: imageRepo,
			ImageVariable: "AUTOSTREAM_DOCKER_VERSION", VersionEnvFile: versionEnv,
			CurrentVersion: "v1.0.0", ComposeConfigSHA256: modelDigest,
		},
	}
	runner := &dockerPortRollbackRunner{
		oldContainer:      strings.Repeat("1", 64),
		newContainer:      strings.Repeat("2", 64),
		rollbackContainer: strings.Repeat("3", 64),
		oldImage:          oldImage,
		newImage:          newImage,
		oldRepository:     "sha256:" + strings.Repeat("c", 64),
		targetPlatform:    targetPlatform,
		imageRepo:         imageRepo,
	}
	staged, err := observeDockerMutationBaseline(context.Background(), target, runner)
	if err != nil {
		t.Fatal(err)
	}
	runner.calls = nil
	plan := ApplyPlan{
		JobID: "job-01", TargetID: target.TargetID, ServiceType: target.ServiceType, DeploymentMode: ModeDocker,
		CurrentVersion: "v1.0.0", TargetVersion: "v2.0.0", StageDir: stageDir,
		ExpectedVersion: newSource, ExpectedImageDigest: "sha256:" + strings.Repeat("8", 64),
		ExpectedPlatformDigest: targetPlatform,
	}
	gateCalled := false
	applyContext, cancelApply := context.WithCancel(context.Background())
	defer cancelApply()
	runner.cancelApply = cancelApply
	result, err := applyDockerWithGateAndBaselineWithOwnerCheck(
		applyContext,
		target,
		plan,
		runner,
		func(context.Context) error {
			gateCalled = true
			return nil
		},
		true,
		&staged.Baseline,
		newImage,
		acceptTestFixtureOwner,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !gateCalled || result.Status != "rolled_back" || !result.RolledBack ||
		runner.upCount != 2 || runner.configCount != 1 {
		t.Fatalf("rollback result=%+v gate=%v up=%d config=%d", result, gateCalled, runner.upCount, runner.configCount)
	}
	restored, err := os.ReadFile(versionEnv)
	if err != nil || string(restored) != oldVersionEnv {
		t.Fatalf("restored version env=%q err=%v", restored, err)
	}
	checkpoint, err := os.ReadFile(checkpointPath(target))
	if err != nil || !strings.Contains(string(checkpoint), `"phase":"rolled_back"`) {
		t.Fatalf("terminal rollback checkpoint=%q err=%v", checkpoint, err)
	}
}
