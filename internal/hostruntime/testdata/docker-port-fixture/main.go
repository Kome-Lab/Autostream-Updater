package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"time"
)

type fixtureConfig struct {
	port           int
	advertisedPort int
	configRevision int64
	version        string
	unhealthy      bool
}

func main() {
	config := fixtureConfig{
		port:           requiredFixtureListenPort(),
		advertisedPort: requiredInt("AUTOSTREAM_FIXTURE_ADVERTISED_PORT", 1, 65535),
		configRevision: int64(requiredInt(
			"AUTOSTREAM_CONFIG_REVISION", 1, int(^uint(0)>>1),
		)),
		version: os.Getenv("AUTOSTREAM_FIXTURE_VERSION"),
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
		Addr:              fmt.Sprintf("0.0.0.0:%d", config.port),
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}
}

func requiredFixtureListenPort() int {
	if os.Getenv("AUTOSTREAM_FIXTURE_PORT") != "" {
		return requiredInt("AUTOSTREAM_FIXTURE_PORT", 1024, 65535)
	}
	address, err := netip.ParseAddrPort(os.Getenv("AUTOSTREAM_BIND_ADDR"))
	if err != nil || !address.Addr().IsUnspecified() || address.Port() < 1024 {
		panic("AUTOSTREAM_BIND_ADDR is invalid")
	}
	return int(address.Port())
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
