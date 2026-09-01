package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/klauspost/compress/snappy"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	testBootstrapProvenanceVersion = "v1.2.3"
	testBootstrapProvenanceCommit  = "dddddddddddddddddddddddddddddddddddddddd"
	testBootstrapProvenanceDigest  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

const testUpdaterReleaseSigstoreBundleJSON = `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{"publicKey":{"hint":"IpekKjxVkmTfB4YqY8q5sGEAeVtF9x3m7jHdhAxpgjQ="},"timestampVerificationData":{"rfc3161Timestamps":[{"signedTimestamp":"MIICUjADAgEAMIICSQYJKoZIhvcNAQcCoIICOjCCAjYCAQMxDTALBglghkgBZQMEAgEwgYIGCyqGSIb3DQEJEAEEoHMEcTBvAgEBBgkrBgEEAYO/MAIwMTANBglghkgBZQMEAgEFAAQgWx/UuMGo7yYisk90zhADduhaw+akWftxZUllAEjCY5ICFQCoSv9NlN8sndmo5+s23ajiMXGB2xgPMjAyNjA2MDQxNzQzMjlaoASkAjAAoAAxggGZMIIBlQIBATBAMDsxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEiMCAGA1UEAxMZc2lnc3RvcmUtdHNhLWludGVybWVkaWF0ZQIBATALBglghkgBZQMEAgGggeowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNjA2MDQxNzQzMjlaMC8GCSqGSIb3DQEJBDEiBCAOfMXlQ1yWwSaKXwxfJmhXEX2uBb23gMHTP5PzFFV6tTB9BgsqhkiG9w0BCRACLzFuMGwwajBoBCAv6L3UtieF19pfcKNjzlpkdMUHYWii5G4JZRsbO2WJkjBEMD+kPTA7MRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxIjAgBgNVBAMTGXNpZ3N0b3JlLXRzYS1pbnRlcm1lZGlhdGUCAQEwCgYIKoZIzj0EAwIESDBGAiEAzu44CKxDXyCy/1cv+CTpGGPQj6QldIyO2U8lK1R+9GECIQC5cCbDnc0YFAldqXGoPXgocZdjqLQn3kNHax+r/K9I5A=="}]}},"messageSignature":{"messageDigest":{"algorithm":"SHA2_256","digest":"auinVVUgn9bEQVfArtgBbnY/9DWhnPGG92hjFAFD/3I="},"signature":"MEYCIQC459RMz4rqofBUcrYVc34gyNUJ7/M3ZU+qUIoLJl1THQIhAPSPwNGAHjgzXVhKrHrZWPufd1/v7PNAuWAAYv2ioIwT"}}`

func TestUpdaterReleaseCertificateIdentityPolicy(t *testing.T) {
	identity, err := updaterReleaseCertificateIdentity(
		testBootstrapProvenanceVersion,
		testBootstrapProvenanceCommit,
	)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	summary := trustedUpdaterReleaseCertificateSummary(identity)
	if err := identity.Verify(summary); err != nil {
		t.Fatalf("trusted identity was rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*certificate.Summary)
	}{
		{
			name: "subject alternative name",
			mutate: func(summary *certificate.Summary) {
				summary.SubjectAlternativeName = strings.Replace(
					summary.SubjectAlternativeName,
					updaterReleaseWorkflowPath,
					".github/workflows/untrusted.yml",
					1,
				)
			},
		},
		{
			name: "source digest",
			mutate: func(summary *certificate.Summary) {
				summary.SourceRepositoryDigest = strings.Repeat("e", 40)
			},
		},
		{
			name: "build signer",
			mutate: func(summary *certificate.Summary) {
				summary.BuildSignerURI = updaterReleaseRepositoryURI() +
					"/.github/workflows/untrusted.yml@refs/tags/" +
					testBootstrapProvenanceVersion
			},
		},
		{
			name: "repository id",
			mutate: func(summary *certificate.Summary) {
				summary.SourceRepositoryIdentifier = "1"
			},
		},
		{
			name: "runner",
			mutate: func(summary *certificate.Summary) {
				summary.RunnerEnvironment = "self-hosted"
			},
		},
		{
			name: "repository",
			mutate: func(summary *certificate.Summary) {
				summary.SourceRepositoryURI = "https://github.com/example/untrusted"
			},
		},
		{
			name: "ref",
			mutate: func(summary *certificate.Summary) {
				summary.SourceRepositoryRef = "refs/heads/main"
			},
		},
		{
			name: "event",
			mutate: func(summary *certificate.Summary) {
				summary.BuildTrigger = "workflow_dispatch"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := summary
			test.mutate(&changed)
			if err := identity.Verify(changed); err == nil {
				t.Fatal("untrusted certificate identity was accepted")
			}
		})
	}
}

func TestValidateHostAgentReleaseProvenanceResultPolicy(t *testing.T) {
	result, identity := trustedUpdaterReleaseVerificationResult(t, provenanceStatementFixture{})
	if err := validateTrustedReleaseManifestProvenanceResult(
		result,
		identity,
		hostAgentManifestName,
		testBootstrapProvenanceVersion,
		testBootstrapProvenanceDigest,
		testBootstrapProvenanceCommit,
	); err != nil {
		t.Fatalf("trusted provenance was rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*provenanceStatementFixture)
	}{
		{
			name: "workflow",
			mutate: func(fixture *provenanceStatementFixture) {
				fixture.workflowPath = ".github/workflows/untrusted.yml"
			},
		},
		{
			name: "repository",
			mutate: func(fixture *provenanceStatementFixture) {
				fixture.workflowRepository = "https://github.com/example/untrusted"
			},
		},
		{
			name: "ref",
			mutate: func(fixture *provenanceStatementFixture) {
				fixture.workflowRef = "refs/heads/main"
			},
		},
		{
			name: "commit",
			mutate: func(fixture *provenanceStatementFixture) {
				fixture.dependencyCommit = strings.Repeat("e", 40)
			},
		},
		{
			name: "event",
			mutate: func(fixture *provenanceStatementFixture) {
				fixture.eventName = "workflow_dispatch"
			},
		},
		{
			name: "builder",
			mutate: func(fixture *provenanceStatementFixture) {
				fixture.builderID = updaterReleaseRepositoryURI() +
					"/.github/workflows/untrusted.yml@refs/tags/" +
					testBootstrapProvenanceVersion
			},
		},
		{
			name: "repository id",
			mutate: func(fixture *provenanceStatementFixture) {
				fixture.repositoryID = "1"
			},
		},
		{
			name: "runner",
			mutate: func(fixture *provenanceStatementFixture) {
				fixture.runnerEnvironment = "self-hosted"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := provenanceStatementFixture{}
			test.mutate(&fixture)
			result, identity := trustedUpdaterReleaseVerificationResult(t, fixture)
			if err := validateTrustedReleaseManifestProvenanceResult(
				result,
				identity,
				hostAgentManifestName,
				testBootstrapProvenanceVersion,
				testBootstrapProvenanceDigest,
				testBootstrapProvenanceCommit,
			); err == nil {
				t.Fatal("untrusted provenance statement was accepted")
			}
		})
	}
}

func TestUpdaterReleaseAttestationBundleURLPolicy(t *testing.T) {
	downloader := ReleaseDownloader{}
	tests := []struct {
		name    string
		rawURL  string
		wantErr bool
	}{
		{
			name:   "trusted production storage",
			rawURL: "https://" + updaterReleaseBundleHost + "/sha256:abc/bundle.json",
		},
		{
			name:    "HTTP downgrade",
			rawURL:  "http://" + updaterReleaseBundleHost + "/sha256:abc/bundle.json",
			wantErr: true,
		},
		{
			name:    "foreign host",
			rawURL:  "https://example.com/sha256:abc/bundle.json",
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := downloader.validateUpdaterReleaseAttestationBundleURL(test.rawURL)
			if test.wantErr && err == nil {
				t.Fatal("untrusted bundle URL was accepted")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("trusted bundle URL was rejected: %v", err)
			}
		})
	}
}

func TestDownloadUpdaterReleaseAttestationBundleDecodesSnappyBundle(t *testing.T) {
	compressed := snappy.Encode(nil, []byte(testUpdaterReleaseSigstoreBundleJSON))
	headers := make(chan http.Header, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		headers <- request.Header.Clone()
		w.Header().Set("Content-Type", updaterReleaseBundleMediaType)
		_, _ = w.Write(compressed)
	}))
	defer server.Close()

	downloader := ReleaseDownloader{
		APIBase:          server.URL,
		Client:           server.Client(),
		Token:            "test-token",
		AllowHTTPForTest: true,
	}
	decoded, err := downloader.downloadUpdaterReleaseAttestationBundle(
		context.Background(),
		server.URL+"/bundle.json.sn",
	)
	if err != nil {
		t.Fatalf("download bundle: %v", err)
	}
	if string(decoded) != testUpdaterReleaseSigstoreBundleJSON {
		t.Fatal("decoded bundle does not match the compressed Sigstore fixture")
	}
	bundleHeaders := <-headers
	if accept := bundleHeaders.Get("Accept"); accept != updaterReleaseBundleMediaType {
		t.Fatalf("Accept = %q", accept)
	}
	if authorization := bundleHeaders.Get("Authorization"); authorization != "" {
		t.Fatalf("bundle request forwarded Authorization = %q", authorization)
	}
	if signedBundle, err := parseUpdaterReleaseAttestationBundle(decoded); err != nil {
		t.Fatalf("parse bundle: %v", err)
	} else if signedBundle == nil {
		t.Fatal("parsed bundle is nil")
	}
}

func TestDownloadUpdaterReleaseAttestationBundleRejectsMediaTypeAndDecodedLimit(t *testing.T) {
	t.Run("media type", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(snappy.Encode(nil, []byte("{}")))
		}))
		defer server.Close()

		downloader := ReleaseDownloader{
			APIBase:          server.URL,
			Client:           server.Client(),
			AllowHTTPForTest: true,
		}
		_, err := downloader.downloadUpdaterReleaseAttestationBundle(
			context.Background(),
			server.URL+"/bundle.json.sn",
		)
		if err == nil || !strings.Contains(err.Error(), "media type") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("decoded size", func(t *testing.T) {
		compressed := snappy.Encode(
			nil,
			make([]byte, updaterReleaseDecodedMaxBytes+1),
		)
		_, err := decodeUpdaterReleaseAttestationBundle(compressed)
		if err == nil || !strings.Contains(err.Error(), "size limit") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestListUpdaterReleaseAttestationsFollowsTrustedNextPage(t *testing.T) {
	var requests atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if authorization := request.Header.Get("Authorization"); authorization != "Bearer test-token" {
			t.Errorf("Authorization = %q", authorization)
		}
		if apiVersion := request.Header.Get("X-GitHub-Api-Version"); apiVersion != updaterReleaseAttestationAPI {
			t.Errorf("X-GitHub-Api-Version = %q", apiVersion)
		}
		if got := request.URL.Query()["per_page"]; len(got) != 1 ||
			got[0] != strconv.Itoa(updaterReleaseAttestationsPage) {
			t.Errorf("per_page = %#v", got)
		}
		if got := request.URL.Query()["predicate_type"]; len(got) != 1 ||
			got[0] != "provenance" {
			t.Errorf("predicate_type = %#v", got)
		}

		cursor := request.URL.Query().Get("before")
		if cursor == "" {
			cursor = request.URL.Query().Get("after")
		}
		page := updaterReleaseAttestationList{}
		if cursor == "" {
			page.Attestations = make(
				[]updaterReleaseAttestation,
				updaterReleaseAttestationsPage,
			)
			next := *request.URL
			next.Scheme = "http"
			next.Host = request.Host
			next.Path = "/repositories/" +
				strconv.FormatInt(updaterReleaseRepositoryID, 10) +
				"/attestations/sha256:" +
				testBootstrapProvenanceDigest
			query := next.Query()
			query.Set("after", "cursor-2")
			next.RawQuery = query.Encode()
			w.Header().Set(
				"Link",
				"<"+next.String()+`>; rel="next", `+
					`<https://docs.github.com/en/rest/about-the-rest-api/api-versions>; rel="deprecation"; type="text/html"`,
			)
		} else if cursor == "cursor-2" {
			page.Attestations = []updaterReleaseAttestation{
				{
					RepositoryID: updaterReleaseRepositoryID,
					BundleURL:    server.URL + "/trusted-bundle",
				},
			}
		} else {
			t.Errorf("unexpected cursor %q", cursor)
		}
		if err := json.NewEncoder(w).Encode(page); err != nil {
			t.Errorf("encode page: %v", err)
		}
	}))
	defer server.Close()

	downloader := ReleaseDownloader{
		APIBase:          server.URL,
		Client:           server.Client(),
		Token:            "test-token",
		AllowHTTPForTest: true,
	}
	attestations, err := downloader.listUpdaterReleaseAttestations(
		context.Background(),
		testBootstrapProvenanceDigest,
	)
	if err != nil {
		t.Fatalf("list attestations: %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("requests = %d", got)
	}
	if len(attestations) != updaterReleaseAttestationsPage+1 {
		t.Fatalf("attestation count = %d", len(attestations))
	}
	if last := attestations[len(attestations)-1]; last.RepositoryID != updaterReleaseRepositoryID {
		t.Fatalf("last attestation = %#v", last)
	}
}

func TestListUpdaterReleaseAttestationsRejectsForeignNextPage(t *testing.T) {
	var foreignRequests atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		foreignRequests.Add(1)
		t.Errorf("foreign pagination endpoint received a request")
	}))
	defer foreign.Close()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		next, err := url.Parse(foreign.URL)
		if err != nil {
			t.Errorf("foreign URL: %v", err)
			return
		}
		next.Path = request.URL.Path
		query := request.URL.Query()
		query.Set("before", "foreign")
		next.RawQuery = query.Encode()
		w.Header().Set("Link", "<"+next.String()+`>; rel="next"`)
		_ = json.NewEncoder(w).Encode(updaterReleaseAttestationList{})
	}))
	defer server.Close()

	downloader := ReleaseDownloader{
		APIBase:          server.URL,
		Client:           server.Client(),
		Token:            "must-not-leak",
		AllowHTTPForTest: true,
	}
	_, err := downloader.listUpdaterReleaseAttestations(
		context.Background(),
		testBootstrapProvenanceDigest,
	)
	if err == nil || !strings.Contains(err.Error(), "outside the trusted endpoint") {
		t.Fatalf("error = %v", err)
	}
	if got := foreignRequests.Load(); got != 0 {
		t.Fatalf("foreign requests = %d", got)
	}
}

func TestListUpdaterReleaseAttestationsDoesNotFollowRedirect(t *testing.T) {
	var foreignRequests atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		foreignRequests.Add(1)
		t.Errorf("foreign redirect endpoint received a request")
	}))
	defer foreign.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		http.Redirect(w, request, foreign.URL, http.StatusFound)
	}))
	defer server.Close()

	downloader := ReleaseDownloader{
		APIBase:          server.URL,
		Client:           server.Client(),
		Token:            "must-not-leak",
		AllowHTTPForTest: true,
	}
	_, err := downloader.listUpdaterReleaseAttestations(
		context.Background(),
		testBootstrapProvenanceDigest,
	)
	if err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("error = %v", err)
	}
	if got := foreignRequests.Load(); got != 0 {
		t.Fatalf("foreign requests = %d", got)
	}
}

func TestUpdaterReleaseAttestationNextLinkRejectsMalformedValues(t *testing.T) {
	if _, err := updaterReleaseNextLink([]string{"not-a-link"}); err == nil {
		t.Fatal("malformed Link header was accepted")
	}

	downloader := ReleaseDownloader{APIBase: "https://api.github.com"}
	initial, err := downloader.updaterReleaseAttestationEndpoint(
		testBootstrapProvenanceDigest,
	)
	if err != nil {
		t.Fatalf("initial endpoint: %v", err)
	}
	tests := []string{
		"https://api.github.com" + initial.Path +
			"?per_page=100&predicate_type=provenance",
		"https://api.github.com" + initial.Path +
			"?before=cursor&per_page=99&predicate_type=provenance",
		"https://api.github.com" + initial.Path +
			"?before=cursor&extra=value&per_page=100&predicate_type=provenance",
		"https://api.github.com" + initial.Path +
			"?after=cursor-a&before=cursor-b&per_page=100&predicate_type=provenance",
		"https://api.github.com/repos/example/untrusted/attestations/sha256:abc" +
			"?before=cursor&per_page=100&predicate_type=provenance",
		"https://api.github.com/repositories/1/attestations/sha256:" +
			testBootstrapProvenanceDigest +
			"?after=cursor&per_page=100&predicate_type=provenance",
	}
	for _, rawURL := range tests {
		if _, err := validateUpdaterReleaseAttestationNextURL(initial, rawURL); err == nil {
			t.Fatalf("malformed next URL was accepted: %s", rawURL)
		}
	}
}

func TestUpdaterReleaseNextLinkIgnoresGitHubDeprecationLink(t *testing.T) {
	next, err := updaterReleaseNextLink([]string{
		`<https://docs.github.com/en/rest/about-the-rest-api/api-versions>; rel="deprecation"; type="text/html"`,
	})
	if err != nil {
		t.Fatalf("parse deprecation Link: %v", err)
	}
	if next != "" {
		t.Fatalf("next = %q", next)
	}
}

func TestListUpdaterReleaseAttestationsFailsAtPageLimit(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requestNumber := requests.Add(1)
		next := *request.URL
		next.Scheme = "http"
		next.Host = request.Host
		query := next.Query()
		query.Set("before", fmt.Sprintf("cursor-%d", requestNumber+1))
		next.RawQuery = query.Encode()
		w.Header().Set("Link", "<"+next.String()+`>; rel="next"`)
		_ = json.NewEncoder(w).Encode(updaterReleaseAttestationList{
			Attestations: []updaterReleaseAttestation{{RepositoryID: 1}},
		})
	}))
	defer server.Close()

	downloader := ReleaseDownloader{
		APIBase:          server.URL,
		Client:           server.Client(),
		AllowHTTPForTest: true,
	}
	_, err := downloader.listUpdaterReleaseAttestations(
		context.Background(),
		testBootstrapProvenanceDigest,
	)
	if err == nil || !strings.Contains(err.Error(), "page limit") {
		t.Fatalf("error = %v", err)
	}
	if got := requests.Load(); got != updaterReleaseAttestationPages {
		t.Fatalf("requests = %d", got)
	}
}

func TestUpdaterReleaseProvenanceContextIsBounded(t *testing.T) {
	startedAt := time.Now()
	ctx, cancel, err := newUpdaterReleaseProvenanceContext(context.Background())
	returnedAt := time.Now()
	if err != nil {
		t.Fatalf("bounded context: %v", err)
	}
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("bounded context has no deadline")
	}
	earliest := startedAt.Add(updaterReleaseProvenanceTimeout)
	latest := returnedAt.Add(updaterReleaseProvenanceTimeout)
	if deadline.Before(earliest) || deadline.After(latest) {
		t.Fatalf(
			"bounded deadline = %v, want between %v and %v",
			deadline,
			earliest,
			latest,
		)
	}

	parent, parentCancel := context.WithTimeout(context.Background(), time.Minute)
	defer parentCancel()
	parentDeadline, _ := parent.Deadline()
	child, childCancel, err := newUpdaterReleaseProvenanceContext(parent)
	if err != nil {
		t.Fatalf("child context: %v", err)
	}
	defer childCancel()
	childDeadline, ok := child.Deadline()
	if !ok || !childDeadline.Equal(parentDeadline) {
		t.Fatalf("child deadline = %v, want %v", childDeadline, parentDeadline)
	}
}

func TestUpdaterReleaseTUFFetcherEnforcesHTTPTimeout(t *testing.T) {
	requestStarted := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		close(requestStarted)
		<-request.Context().Done()
	}))
	defer server.Close()

	metadataFetcher := testUpdaterReleaseTUFFetcher(
		t,
		context.Background(),
		25*time.Millisecond,
		server,
	)
	startedAt := time.Now()
	_, err := metadataFetcher.DownloadFile(server.URL, 1024, time.Hour)
	elapsed := time.Since(startedAt)
	if err == nil {
		t.Fatal("TUF metadata request without a response unexpectedly succeeded")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error = %v", err)
	}
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("TUF metadata request never reached the HTTP server")
	}
	if elapsed > time.Second {
		t.Fatalf("TUF metadata request exceeded its HTTP timeout: %s", elapsed)
	}
}

func TestUpdaterReleaseTUFFetcherHonorsCallerCancellation(t *testing.T) {
	requestStarted := make(chan struct{})
	requestStopped := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		close(requestStarted)
		<-request.Context().Done()
		close(requestStopped)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	metadataFetcher := testUpdaterReleaseTUFFetcher(
		t,
		ctx,
		updaterReleaseTUFHTTPTimeout,
		server,
	)
	result := make(chan error, 1)
	go func() {
		_, err := metadataFetcher.DownloadFile(server.URL, 1024, time.Hour)
		result <- err
	}()
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("TUF metadata request did not start")
	}

	cancelledAt := time.Now()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("caller cancellation did not stop the TUF request")
	}
	if elapsed := time.Since(cancelledAt); elapsed > time.Second {
		t.Fatalf("caller cancellation took %s", elapsed)
	}
	select {
	case <-requestStopped:
	case <-time.After(time.Second):
		t.Fatal("HTTP server did not observe caller cancellation")
	}
}

func TestUpdaterReleaseTUFFetcherHTTPPolicy(t *testing.T) {
	t.Run("User-Agent", func(t *testing.T) {
		headers := make(chan http.Header, 1)
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			headers <- request.Header.Clone()
			_, _ = w.Write([]byte("{}"))
		}))
		defer server.Close()

		metadataFetcher := testUpdaterReleaseTUFFetcher(
			t,
			context.Background(),
			time.Second,
			server,
		)
		data, err := metadataFetcher.DownloadFile(server.URL, 1024, time.Hour)
		if err != nil {
			t.Fatalf("download: %v", err)
		}
		if string(data) != "{}" {
			t.Fatalf("data = %q", data)
		}
		requestHeaders := <-headers
		if userAgent := requestHeaders.Get("User-Agent"); userAgent != updaterReleaseTUFUserAgent {
			t.Fatalf("User-Agent = %q", userAgent)
		}
		if accept := requestHeaders.Get("Accept"); accept != "application/json" {
			t.Fatalf("Accept = %q", accept)
		}
	})

	t.Run("HTTP status", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		}))
		defer server.Close()

		metadataFetcher := testUpdaterReleaseTUFFetcher(
			t,
			context.Background(),
			time.Second,
			server,
		)
		_, err := metadataFetcher.DownloadFile(server.URL, 1024, time.Hour)
		var statusErr *metadata.ErrDownloadHTTP
		if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("status error = %v", err)
		}
	})

	t.Run("body size", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			w.(http.Flusher).Flush()
			_, _ = w.Write([]byte("12345"))
		}))
		defer server.Close()

		metadataFetcher := testUpdaterReleaseTUFFetcher(
			t,
			context.Background(),
			time.Second,
			server,
		)
		_, err := metadataFetcher.DownloadFile(server.URL, 4, time.Hour)
		var lengthErr *metadata.ErrDownloadLengthMismatch
		if !errors.As(err, &lengthErr) {
			t.Fatalf("length error = %v", err)
		}
	})

	t.Run("redirect", func(t *testing.T) {
		var targetRequests atomic.Int32
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			targetRequests.Add(1)
			_, _ = w.Write([]byte("{}"))
		}))
		defer target.Close()
		source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			http.Redirect(w, request, target.URL, http.StatusFound)
		}))
		defer source.Close()

		metadataFetcher := testUpdaterReleaseTUFFetcher(
			t,
			context.Background(),
			time.Second,
			source,
		)
		if _, err := metadataFetcher.DownloadFile(source.URL, 1024, time.Hour); err == nil {
			t.Fatal("redirect was accepted")
		}
		if got := targetRequests.Load(); got != 0 {
			t.Fatalf("redirect target received %d requests", got)
		}
	})

	t.Run("origin", func(t *testing.T) {
		metadataFetcher := newUpdaterReleaseTUFFetcher(
			context.Background(),
			time.Second,
		)
		tests := []string{
			"http://" + metadataFetcher.expectedHost + "/timestamp.json",
			"https://example.com/timestamp.json",
		}
		for _, rawURL := range tests {
			if _, err := metadataFetcher.DownloadFile(rawURL, 1024, time.Hour); err == nil {
				t.Fatalf("untrusted origin was accepted: %s", rawURL)
			}
		}
	})
}

type provenanceStatementFixture struct {
	workflowPath       string
	workflowRepository string
	workflowRef        string
	eventName          string
	repositoryID       string
	runnerEnvironment  string
	builderID          string
	dependencyURI      string
	dependencyCommit   string
}

func testUpdaterReleaseTUFFetcher(
	t *testing.T,
	ctx context.Context,
	timeout time.Duration,
	server *httptest.Server,
) *updaterReleaseTUFFetcher {
	t.Helper()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("server URL: %v", err)
	}
	metadataFetcher := newUpdaterReleaseTUFFetcher(ctx, timeout)
	metadataFetcher.expectedScheme = serverURL.Scheme
	metadataFetcher.expectedHost = serverURL.Host
	metadataFetcher.client.Transport = server.Client().Transport
	return metadataFetcher
}

func trustedUpdaterReleaseCertificateSummary(identity verify.CertificateIdentity) certificate.Summary {
	summary := certificate.Summary{
		SubjectAlternativeName: identity.SubjectAlternativeName.SubjectAlternativeName,
		Extensions:             identity.Extensions,
	}
	summary.Extensions.Issuer = identity.Issuer.Issuer
	return summary
}

func trustedUpdaterReleaseVerificationResult(
	t *testing.T,
	fixture provenanceStatementFixture,
) (*verify.VerificationResult, verify.CertificateIdentity) {
	t.Helper()
	identity, err := updaterReleaseCertificateIdentity(
		testBootstrapProvenanceVersion,
		testBootstrapProvenanceCommit,
	)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	summary := trustedUpdaterReleaseCertificateSummary(identity)

	expectedRef := "refs/tags/" + testBootstrapProvenanceVersion
	expectedRepository := updaterReleaseRepositoryURI()
	expectedWorkflowURI := updaterReleaseWorkflowURI(testBootstrapProvenanceVersion)
	if fixture.workflowPath == "" {
		fixture.workflowPath = updaterReleaseWorkflowPath
	}
	if fixture.workflowRepository == "" {
		fixture.workflowRepository = expectedRepository
	}
	if fixture.workflowRef == "" {
		fixture.workflowRef = expectedRef
	}
	if fixture.eventName == "" {
		fixture.eventName = "push"
	}
	if fixture.repositoryID == "" {
		fixture.repositoryID = strconv.FormatInt(updaterReleaseRepositoryID, 10)
	}
	if fixture.runnerEnvironment == "" {
		fixture.runnerEnvironment = "github-hosted"
	}
	if fixture.builderID == "" {
		fixture.builderID = expectedWorkflowURI
	}
	if fixture.dependencyURI == "" {
		fixture.dependencyURI = "git+" + expectedRepository + "@" + expectedRef
	}
	if fixture.dependencyCommit == "" {
		fixture.dependencyCommit = testBootstrapProvenanceCommit
	}

	predicate, err := structpb.NewStruct(map[string]any{
		"buildDefinition": map[string]any{
			"buildType": updaterReleaseBuildType,
			"externalParameters": map[string]any{
				"workflow": map[string]any{
					"ref":        fixture.workflowRef,
					"repository": fixture.workflowRepository,
					"path":       fixture.workflowPath,
				},
			},
			"internalParameters": map[string]any{
				"github": map[string]any{
					"event_name":          fixture.eventName,
					"repository_id":       fixture.repositoryID,
					"repository_owner_id": updaterReleaseRepositoryOwnerID,
					"runner_environment":  fixture.runnerEnvironment,
				},
			},
			"resolvedDependencies": []any{
				map[string]any{
					"uri": fixture.dependencyURI,
					"digest": map[string]any{
						"gitCommit": fixture.dependencyCommit,
					},
				},
			},
		},
		"runDetails": map[string]any{
			"builder": map[string]any{
				"id": fixture.builderID,
			},
		},
	})
	if err != nil {
		t.Fatalf("predicate: %v", err)
	}
	statement := &intoto.Statement{
		Type:          "https://in-toto.io/Statement/v1",
		PredicateType: updaterReleaseSLSAPredicateType,
		Subject: []*intoto.ResourceDescriptor{
			{
				Name: hostAgentManifestName,
				Digest: map[string]string{
					"sha256": testBootstrapProvenanceDigest,
				},
			},
		},
		Predicate: predicate,
	}
	return &verify.VerificationResult{
		Statement: statement,
		Signature: &verify.SignatureVerificationResult{
			Certificate: &summary,
		},
		VerifiedIdentity: &identity,
	}, identity
}
