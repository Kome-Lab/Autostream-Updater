package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	contracts "github.com/example/autostream-contracts/pkg/contracts"
)

func TestClaimRequiresConfirmedNonCacheableContractV2(t *testing.T) {
	tests := []struct {
		name  string
		major string
		cache string
		ok    bool
	}{
		{name: "exact", major: "2", cache: "private, no-store", ok: true},
		{name: "missing major", cache: "no-store"},
		{name: "wrong major", major: "1", cache: "no-store"},
		{name: "cacheable", major: "2", cache: "private"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.Header.Get(ContractMajorHeader) != ContractMajorV2 {
					t.Fatalf("request contract major = %q", request.Header.Get(ContractMajorHeader))
				}
				if test.major != "" {
					w.Header().Set(ContractMajorHeader, test.major)
				}
				if test.cache != "" {
					w.Header().Set("Cache-Control", test.cache)
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			client := Client{
				BaseURL: server.URL,
				HTTP:    server.Client(),
				TokenProvider: func() string {
					return "runtime-token"
				},
			}
			lease, clear, err := client.Claim(
				context.Background(),
				contracts.UpdateAgentClaimRequest{ServiceID: "updater-01"},
			)
			if test.ok {
				if err != nil || lease != nil || clear {
					t.Fatalf("lease=%v clear=%v err=%v", lease, clear, err)
				}
				return
			}
			if err == nil {
				t.Fatal("unsafe response was accepted")
			}
		})
	}
}

func TestClaimRejectsLegacyBodyAndRedirect(t *testing.T) {
	legacy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(ContractMajorHeader, ContractMajorV2)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(`{"job":{"id":"legacy"},"lease_token":"secret"}`))
	}))
	defer legacy.Close()
	client := Client{BaseURL: legacy.URL, HTTP: legacy.Client(), TokenProvider: func() string { return "runtime-token" }}
	if _, _, err := client.Claim(context.Background(), contracts.UpdateAgentClaimRequest{ServiceID: "updater-01"}); err == nil {
		t.Fatal("legacy claim body was accepted as v2")
	}

	followed := false
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		followed = true
	}))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set(ContractMajorHeader, ContractMajorV2)
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, request, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	client = Client{BaseURL: redirect.URL, HTTP: redirect.Client(), TokenProvider: func() string { return "runtime-token" }}
	if _, _, err := client.Claim(context.Background(), contracts.UpdateAgentClaimRequest{ServiceID: "updater-01"}); err == nil || followed {
		t.Fatalf("redirect result err=%v followed=%v", err, followed)
	}
}
