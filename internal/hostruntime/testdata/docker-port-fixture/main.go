package main

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"time"

	contracts "github.com/example/autostream-contracts/pkg/contracts"
)

type fixtureConfig struct {
	listenAddress  string
	port           int
	advertisedPort int
	configRevision int64
	version        string
	unhealthy      bool
}

func main() {
	listener := requiredFixtureNodeListener()
	address, err := netip.ParseAddrPort(listener.BindAddress)
	if err != nil || !address.Addr().IsUnspecified() || address.Port() < 1024 {
		panic("Node listener bind_address is invalid")
	}
	config := fixtureConfig{
		listenAddress:  listener.BindAddress,
		port:           int(address.Port()),
		advertisedPort: requiredInt("AUTOSTREAM_FIXTURE_ADVERTISED_PORT", 1, 65535),
		configRevision: listener.ConfigRevision,
		version:        os.Getenv("AUTOSTREAM_FIXTURE_VERSION"),
	}
	if unhealthyPort := os.Getenv("AUTOSTREAM_FIXTURE_UNHEALTHY_PORT"); unhealthyPort != "" {
		config.unhealthy = config.port == requiredInt(
			"AUTOSTREAM_FIXTURE_UNHEALTHY_PORT", 1024, 65535,
		)
	} else {
		config.unhealthy = os.Getenv("AUTOSTREAM_FIXTURE_UNHEALTHY") == "1"
	}
	if config.version == "" {
		panic("AUTOSTREAM_FIXTURE_VERSION is required")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		if config.unhealthy {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"status": "degraded",
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":       "ok",
			"service_id":   "worker-smoke",
			"service_type": "worker",
		})
	})
	mux.HandleFunc("/updater/version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"version":         config.version,
			"service_id":      "worker-smoke",
			"service_type":    "worker",
			"config_revision": config.configRevision,
		})
	})
	mux.HandleFunc("/config", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"advertised_port": config.advertisedPort,
			"container_port":  config.port,
			"config_revision": config.configRevision,
		})
	})
	server := &http.Server{
		Addr:              config.listenAddress,
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}
}

func requiredFixtureNodeListener() contracts.NodeListenerConfig {
	directory := os.Getenv("CREDENTIALS_DIRECTORY")
	if directory != "/run/autostream-credentials" {
		panic("CREDENTIALS_DIRECTORY is invalid")
	}
	body, err := os.ReadFile(filepath.Join(directory, "node-listener.json"))
	if err != nil {
		panic("Node listener credential is unavailable")
	}
	listener, err := contracts.ParseNodeListenerConfig(body)
	if err != nil || listener.ServiceType != "worker" {
		panic("Node listener credential is invalid")
	}
	return listener
}

func requiredInt(name string, minimum, maximum int) int {
	value, err := strconv.Atoi(os.Getenv(name))
	if err != nil || value < minimum || value > maximum {
		panic(name + " is invalid")
	}
	return value
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		panic(err)
	}
}
