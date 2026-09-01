package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestApplicationIdentityRequiresNoStoreAndExactIdentity(t *testing.T) {
	tests := []struct {
		name      string
		cache     string
		body      string
		wantError string
	}{
		{name: "valid", cache: "private, NO-STORE", body: `{"version":"v1.2.3","service_id":"worker-a","service_type":"worker","config_revision":7}`},
		{name: "missing no-store", cache: "private", body: `{"version":"v1.2.3","service_id":"worker-a","service_type":"worker","config_revision":7}`, wantError: "no-store"},
		{name: "cross-service", cache: "no-store", body: `{"version":"v1.2.3","service_id":"worker-b","service_type":"worker","config_revision":7}`, wantError: "match policy"},
		{name: "unknown field", cache: "no-store", body: `{"version":"v1.2.3","service_id":"worker-a","service_type":"worker","config_revision":7,"path":"/tmp"}`, wantError: "invalid JSON"},
		{name: "trailing", cache: "no-store", body: `{"version":"v1.2.3","service_id":"worker-a","service_type":"worker","config_revision":7}{}`, wantError: "trailing"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/updater/version" || r.Header.Get("Accept") != "application/json" {
					t.Fatalf("request = %s Accept=%q", r.URL.Path, r.Header.Get("Accept"))
				}
				if test.cache != "" {
					w.Header().Set("Cache-Control", test.cache)
				}
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			identity, err := (Client{HTTP: server.Client()}).FetchApplicationIdentity(
				context.Background(), server.URL+"/updater/version",
				ExpectedIdentity{ServiceID: "worker-a", ServiceType: "worker", ConfigRevision: 7},
			)
			if test.wantError == "" {
				if err != nil || identity.Version != "v1.2.3" {
					t.Fatalf("identity=%+v err=%v", identity, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("err=%v, want %q", err, test.wantError)
			}
		})
	}
}

func TestApplicationIdentityRejectsRedirectWithoutFollowing(t *testing.T) {
	redirected := false
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected = true
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	_, err := (Client{HTTP: source.Client()}).FetchApplicationIdentity(
		context.Background(), source.URL+"/updater/version",
		ExpectedIdentity{ServiceID: "worker-a", ServiceType: "worker", ConfigRevision: 1},
	)
	if err == nil || redirected {
		t.Fatalf("err=%v redirected=%v", err, redirected)
	}
}

func TestApplicationIdentityRejectsUnsupportedServiceTypeBeforeNetwork(t *testing.T) {
	client := Client{HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unsupported service type reached the network")
		return nil, nil
	})}}
	_, err := client.FetchApplicationIdentity(
		context.Background(), "http://127.0.0.1:18084/updater/version",
		ExpectedIdentity{ServiceID: "custom-a", ServiceType: "custom", ConfigRevision: 1},
	)
	if err == nil || !strings.Contains(err.Error(), "expected application identity") {
		t.Fatalf("err=%v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestApplicationIdentityServiceTypeAllowlistIsExactlyFiveServices(t *testing.T) {
	for _, serviceType := range []string{
		"control_panel", "worker", "encoder_recorder", "discord_bot", "observability",
	} {
		if !validServiceType(serviceType) {
			t.Errorf("service type %q was rejected", serviceType)
		}
	}
	for _, serviceType := range []string{"", "updater", "custom", "worker "} {
		if validServiceType(serviceType) {
			t.Errorf("service type %q was accepted", serviceType)
		}
	}
}
