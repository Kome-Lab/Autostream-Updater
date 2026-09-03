package hostruntime

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDockerNodeListenerRejectsRemovedEnvironmentInputs(t *testing.T) {
	base := mustDockerNodeListenerModel(
		t,
		[]byte(`{"services":{"worker":{"ports":[{"target":8080,"published":"8084","protocol":"tcp"}]}}}`),
		"worker",
		"0.0.0.0:8080",
		1,
	)
	for _, name := range []string{
		"AUTOSTREAM_BIND_ADDR",
		"OBSERVABILITY_BIND_ADDR",
		"AUTOSTREAM_CONFIG_REVISION",
	} {
		t.Run(name, func(t *testing.T) {
			var model map[string]any
			if err := json.Unmarshal(base, &model); err != nil {
				t.Fatal(err)
			}
			services := model["services"].(map[string]any)
			worker := services["worker"].(map[string]any)
			environment := worker["environment"].(map[string]any)
			environment[name] = "removed-input"
			raw, err := json.Marshal(model)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := dockerNodeListenerFromCompose(raw, "worker"); err == nil {
				t.Fatal("removed listener environment input was accepted")
			}
		})
	}
}

func TestDockerPortComposePolicyHashAllowsOnlyManagedMappingValues(t *testing.T) {
	target := &DockerTarget{
		Service:   "worker",
		ImageRepo: "ghcr.io/kome-lab/autostream-docker/worker",
	}
	first := mustDockerNodeListenerModel(t, []byte(`{
	  "services": {
	    "worker": {
	      "image": "ghcr.io/kome-lab/autostream-docker/worker:v1.0.0",
	      "environment": {
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
	}`), "worker", "0.0.0.0:8080", 7)
	second := mustDockerNodeListenerModel(t, []byte(`{
	  "services": {
	    "worker": {
	      "image": "ghcr.io/kome-lab/autostream-docker/worker:v2.0.0",
	      "environment": {
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
	}`), "worker", "0.0.0.0:18080", 8)
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
		`"host_ip":"127.0.0.1"`,
		`"host_ip":"0.0.0.0"`,
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

func TestDockerPortComposePolicyHashRequiresNodeListenerConfigRevision(t *testing.T) {
	target := &DockerTarget{
		Service:   "worker",
		ImageRepo: "ghcr.io/kome-lab/autostream-docker/worker",
	}
	raw := []byte(`{
	  "services": {
	    "worker": {
	      "image": "ghcr.io/kome-lab/autostream-docker/worker:v1.0.0",
	      "environment": {"CREDENTIALS_DIRECTORY": "/run/autostream-credentials"},
	      "configs": [{
	        "source": "worker-node-listener",
	        "target": "/run/autostream-credentials/node-listener.json"
	      }],
	      "ports": [{
	        "host_ip": "127.0.0.1",
	        "published": "8084",
	        "target": 8080,
	        "protocol": "tcp"
	      }]
	    }
	  },
	  "configs": {
	    "worker-node-listener": {
	      "content": "{\"schema_version\":2,\"service_type\":\"worker\",\"bind_address\":\"0.0.0.0:8080\"}\n"
	    }
	  }
	}`)
	if _, err := dockerPortComposePolicyHash(raw, target); err == nil {
		t.Fatal("Compose model without listener config_revision was approved")
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
