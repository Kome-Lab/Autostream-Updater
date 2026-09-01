package hostruntime

import (
	"strings"
	"testing"
)

func TestDockerPortComposePolicyHashAllowsOnlyManagedMappingValues(t *testing.T) {
	target := &DockerTarget{
		Service:   "worker",
		ImageRepo: "ghcr.io/kome-lab/autostream-docker/worker",
	}
	first := []byte(`{
	  "services": {
	    "worker": {
	      "image": "ghcr.io/kome-lab/autostream-docker/worker:v1.0.0",
	      "environment": {
	        "AUTOSTREAM_BIND_ADDR": "0.0.0.0:8080",
	        "AUTOSTREAM_CONFIG_REVISION": "7",
	        "UNCHANGED": "yes"
	      },
	      "ports": [{
	        "host_ip": "127.0.0.1",
	        "published": "8084",
	        "target": 8080,
	        "protocol": "tcp"
	      }]
	    }
	  }
	}`)
	second := []byte(`{
	  "services": {
	    "worker": {
	      "image": "ghcr.io/kome-lab/autostream-docker/worker:v2.0.0",
	      "environment": {
	        "AUTOSTREAM_BIND_ADDR": "0.0.0.0:18080",
	        "AUTOSTREAM_CONFIG_REVISION": "8",
	        "UNCHANGED": "yes"
	      },
	      "ports": [{
	        "host_ip": "127.0.0.1",
	        "published": "18084",
	        "target": 18080,
	        "protocol": "tcp"
	      }]
	    }
	  }
	}`)
	firstHash, err := dockerPortComposePolicyHash(first, target)
	if err != nil {
		t.Fatal(err)
	}
	secondHash, err := dockerPortComposePolicyHash(second, target)
	if err != nil {
		t.Fatal(err)
	}
	if firstHash != secondHash {
		t.Fatalf("approved mapping-only change altered policy hash: %q != %q", firstHash, secondHash)
	}

	unsafe := []byte(strings.Replace(
		string(second),
		`"host_ip": "127.0.0.1"`,
		`"host_ip": "0.0.0.0"`,
		1,
	))
	unsafeHash, err := dockerPortComposePolicyHash(unsafe, target)
	if err != nil {
		t.Fatal(err)
	}
	if unsafeHash == firstHash {
		t.Fatal("published host address change escaped the Docker port policy hash")
	}
}

func TestDockerPortComposePolicyHashRequiresRuntimeConfigRevision(t *testing.T) {
	target := &DockerTarget{
		Service:   "worker",
		ImageRepo: "ghcr.io/kome-lab/autostream-docker/worker",
	}
	raw := []byte(`{
	  "services": {
	    "worker": {
	      "image": "ghcr.io/kome-lab/autostream-docker/worker:v1.0.0",
	      "environment": {"AUTOSTREAM_BIND_ADDR": "0.0.0.0:8080"},
	      "ports": [{
	        "host_ip": "127.0.0.1",
	        "published": "8084",
	        "target": 8080,
	        "protocol": "tcp"
	      }]
	    }
	  }
	}`)
	if _, err := dockerPortComposePolicyHash(raw, target); err == nil {
		t.Fatal("Compose model without AUTOSTREAM_CONFIG_REVISION was approved")
	}
}

func TestDockerPortEnvBytesAreFixedAndCanonical(t *testing.T) {
	target := &DockerTarget{
		Service:                 "worker",
		ImageRepo:               "ghcr.io/kome-lab/autostream-docker/worker",
		PortEnvFile:             "/opt/autostream/local-executor/docker/ports/worker.env",
		PortComposePolicySHA256: strings.Repeat("a", 64),
		PortComposeRevision:     9,
	}
	adapter, err := dockerPortAdapterFor("worker", target)
	if err != nil {
		t.Fatal(err)
	}
	body, err := dockerPortEnvBytes(adapter, 18084, 18080, 12)
	if err != nil {
		t.Fatal(err)
	}
	want := "AUTOSTREAM_WORKER_PORT=18084\n" +
		"AUTOSTREAM_WORKER_CONTAINER_PORT=18080\n" +
		"AUTOSTREAM_CONFIG_REVISION=12\n"
	if string(body) != want {
		t.Fatalf("Docker port env = %q want %q", body, want)
	}
}
