/*
 * Copyright 2026 Seamless Middleware Technologies S.L and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package integration provides end-to-end integration tests for the
// consent-filter plugin. Each test starts a mock consent API server,
// creates a real plugin instance with configuration pointing to it,
// and simulates the full RequestFilter → ResponseFilter lifecycle.
package integration

import (
	"consent-plugin/internal/consent"
	"consent-plugin/internal/plugin"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	pkgHTTP "github.com/apache/apisix-go-plugin-runner/pkg/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// integrationReqKey maps a numeric mock id to the request key used as the
// context-store key. It mirrors the Nginx $request_id the plugin reads via
// Var("request_id") to correlate the request and response phases.
func integrationReqKey(id uint32) string {
	return strconv.FormatUint(uint64(id), 10)
}

// --- Mock types for APISIX request/response interfaces ---

// mockRequestHeader implements pkgHTTP.Header for request mocking.
type mockRequestHeader struct {
	headers http.Header
}

func newMockRequestHeader() *mockRequestHeader {
	return &mockRequestHeader{headers: make(http.Header)}
}

// Set sets a header value.
func (h *mockRequestHeader) Set(key, value string) {
	h.headers.Set(key, value)
}

// Del deletes a header.
func (h *mockRequestHeader) Del(key string) {
	h.headers.Del(key)
}

// Get returns the first value for the given header key.
func (h *mockRequestHeader) Get(key string) string {
	return h.headers.Get(key)
}

// View returns headers as http.Header.
func (h *mockRequestHeader) View() http.Header {
	return h.headers
}

// mockRequest implements pkgHTTP.Request for integration testing.
type mockRequest struct {
	id     uint32
	method string
	path   []byte
	header *mockRequestHeader
}

func (r *mockRequest) ID() uint32             { return r.id }
func (r *mockRequest) SrcIP() net.IP          { return net.ParseIP("127.0.0.1") }
func (r *mockRequest) Method() string         { return r.method }
func (r *mockRequest) Path() []byte           { return r.path }
func (r *mockRequest) SetPath([]byte)         {}
func (r *mockRequest) Header() pkgHTTP.Header { return r.header }
func (r *mockRequest) Args() url.Values       { return nil }
func (r *mockRequest) Var(name string) ([]byte, error) {
	if name == "request_id" {
		return []byte(integrationReqKey(r.id)), nil
	}
	return nil, nil
}
func (r *mockRequest) Body() ([]byte, error)    { return nil, nil }
func (r *mockRequest) Context() context.Context { return context.Background() }
func (r *mockRequest) RespHeader() http.Header  { return nil }

// mockResponseHeader implements pkgHTTP.Header for response mocking.
type mockResponseHeader struct {
	headers http.Header
}

func newMockResponseHeader() *mockResponseHeader {
	return &mockResponseHeader{headers: make(http.Header)}
}

// Set sets a header value.
func (h *mockResponseHeader) Set(key, value string) {
	h.headers.Set(key, value)
}

// Del deletes a header.
func (h *mockResponseHeader) Del(key string) {
	h.headers.Del(key)
}

// Get returns the first value for the given header key.
func (h *mockResponseHeader) Get(key string) string {
	return h.headers.Get(key)
}

// View returns headers as http.Header.
func (h *mockResponseHeader) View() http.Header {
	return h.headers
}

// mockResponse implements pkgHTTP.Response for integration testing.
type mockResponse struct {
	id            uint32
	header        *mockResponseHeader
	body          []byte
	writtenBody   []byte
	writtenStatus int
}

func (r *mockResponse) ID() uint32             { return r.id }
func (r *mockResponse) StatusCode() int        { return http.StatusOK }
func (r *mockResponse) Header() pkgHTTP.Header { return r.header }
func (r *mockResponse) Var(name string) ([]byte, error) {
	switch name {
	case "request_id":
		return []byte(integrationReqKey(r.id)), nil
	case "upstream_http_content_type":
		return []byte(responseContentTypeJSON), nil
	}
	return nil, nil
}
func (r *mockResponse) ReadBody() ([]byte, error)  { return r.body, nil }
func (r *mockResponse) WriteHeader(statusCode int) { r.writtenStatus = statusCode }

// Write appends, as the runner's Response.Write does (it writes into a buffer).
func (r *mockResponse) Write(b []byte) (int, error) {
	r.writtenBody = append(r.writtenBody, b...)
	return len(b), nil
}

// --- Test helpers ---

// buildMockJWT creates a minimal JWT (header.payload.signature) with the given claims.
// No signature verification is performed by the plugin; this is sufficient for testing.
func buildMockJWT(claims map[string]interface{}) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, _ := json.Marshal(claims)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	return fmt.Sprintf("%s.%s.nosig", header, payloadB64)
}

// newConsentManager starts a mock consent-manager exposing the two endpoints
// the plugin calls. identifier-search returns userID (or 404 when empty) and,
// when wantSubject is non-empty, asserts the forwarded subject ("email");
// participant-consents returns one consent per entry in statuses.
func newConsentManager(t *testing.T, wantSubject, userID string, statuses []string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/users/identifier/search", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("failed to decode identifier search body: %v", err)
		}
		if wantSubject != "" {
			assert.Equal(t, wantSubject, body["email"], "subject must be forwarded as the user email")
		}
		if userID == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"userIdentifier": userID})
	})

	mux.HandleFunc("/v1/consents/participants/", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer itest-participant-token", r.Header.Get("Authorization"),
			"consents lookup must carry the participant token")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"consents": consentsGrantedTo(statuses)})
	})

	mux.HandleFunc("/v1/participants", participantRegistryHandler)

	return httptest.NewServer(mux)
}

// --- OwnerResolver mock (the source of data ownership) ---

// itestConsumerDID is the consuming participant named in the access token.
const itestConsumerDID = "did:key:zConsumer"

// itestConsumerSD is the self-description URL the participant registry maps
// itestConsumerDID to — the consumer every consent check is scoped to.
const itestConsumerSD = "http://catalog/participants/consumer"

// consentsGrantedTo builds consent records with the given statuses, each granted
// to the consuming participant the tests act as.
func consentsGrantedTo(statuses []string) []map[string]interface{} {
	consents := make([]map[string]interface{}, 0, len(statuses))
	for _, s := range statuses {
		consents = append(consents, map[string]interface{}{
			"status":   s,
			"consumer": map[string]string{"selfDescriptionURL": itestConsumerSD},
		})
	}
	return consents
}

// participantRegistryHandler serves the consent-manager's participant registry,
// which translates the consumer DID from the token into the self-description URL
// a contract names its parties by.
func participantRegistryHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode([]map[string]string{
		{"did": itestConsumerDID, "selfDescriptionURL": itestConsumerSD},
	})
}

// newFailingConsentManager returns a consent-manager whose CONSENT CHECK calls
// answer with the given status code (used to exercise the fail policy). The
// participant registry still answers, so the failure under test is the check
// itself and not the preceding contract lookup.
func newFailingConsentManager(status int) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/participants", participantRegistryHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	})
	return httptest.NewServer(mux)
}

// resolveEnvelope is the /resolve request the plugin sends, decoded so tests can
// assert on what the resolver was actually told.
type resolveEnvelope struct {
	Resource struct {
		Service     string `json:"service"`
		Method      string `json:"method"`
		Path        string `json:"path"`
		ContentType string `json:"contentType"`
	} `json:"resource"`
	Parties *struct {
		Consumer string `json:"consumer"`
		Provider string `json:"provider"`
	} `json:"parties"`
	Body *struct {
		Encoding string          `json:"encoding"`
		Content  json.RawMessage `json:"content"`
	} `json:"body"`
}

// newRecordingOwnerResolver starts a mock OwnerResolver that answers with the
// given JSON and records every envelope it received.
func newRecordingOwnerResolver(t *testing.T, reply map[string]interface{}, received *[]resolveEnvelope) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env resolveEnvelope
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			t.Errorf("failed to decode resolve request: %v", err)
		}
		mu.Lock()
		*received = append(*received, env)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(reply); err != nil {
			t.Errorf("failed to encode resolve response: %v", err)
		}
	}))
}

// newOwnerResolver starts a mock OwnerResolver that reports the given data
// owners for every payload. With no owners, it reports that no consent is
// required.
func newOwnerResolver(t *testing.T, owners ...string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		claims := make([]map[string]string, 0, len(owners))
		for _, o := range owners {
			claims = append(claims, map[string]string{"ownerId": o})
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"consentRequired": len(owners) > 0,
			"claims":          claims,
		}); err != nil {
			t.Errorf("failed to encode resolve response: %v", err)
		}
	}))
}

// baseConfig returns the minimal valid plugin configuration for the two-call
// check, pointing at the given consent-manager and OwnerResolver.
func baseConfig(consentURL, resolverURL string) map[string]interface{} {
	return map[string]interface{}{
		"consent_api_url":    consentURL,
		"owner_resolver_url": resolverURL,
		"participant_token":  "itest-participant-token",
		"provider_sd":        "http://consent-facade:8080/participants/org-itest",
	}
}

// marshalConfig serializes a config map to the JSON bytes APISIX would pass.
func marshalConfig(t *testing.T, cfg map[string]interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(cfg)
	require.NoError(t, err)
	return b
}

// responseContentTypeJSON is the Content-Type set on simulated upstream
// responses in the plugin lifecycle helper; personal-data responses are JSON.
const responseContentTypeJSON = "application/json"

// runPluginCycle simulates the full APISIX plugin lifecycle: ParseConf, RequestFilter,
// then ResponseFilter. Returns the mock response for assertion.
func runPluginCycle(
	t *testing.T,
	configJSON []byte,
	req *mockRequest,
	responseBody []byte,
) *mockResponse {
	t.Helper()

	p := &plugin.ConsentFilter{}

	// ParseConf
	conf, err := p.ParseConf(configJSON)
	require.NoError(t, err, "ParseConf should succeed")

	// RequestFilter — uses a no-op http.ResponseWriter since we don't
	// expect the plugin to write during the request phase.
	recorder := httptest.NewRecorder()
	p.RequestFilter(conf, recorder, req)

	// Build the mock response with the same request ID.
	respHeader := newMockResponseHeader()
	respHeader.Set("Content-Type", responseContentTypeJSON)
	resp := &mockResponse{
		id:     req.id,
		header: respHeader,
		body:   responseBody,
	}

	// ResponseFilter
	p.ResponseFilter(conf, resp)

	return resp
}

// consentRequest builds a GET request for a personal-data entity. The token
// names the CONSUMER (as the embedded credential's issuer) and its "sub"; neither
// determines the data owner — the OwnerResolver does, from the response payload.
func consentRequest(id uint32, caller string) *mockRequest {
	h := newMockRequestHeader()
	h.Set("Authorization", "Bearer "+buildMockJWT(map[string]interface{}{
		"sub":                  caller,
		"verifiableCredential": map[string]interface{}{"issuer": itestConsumerDID},
	}))
	return &mockRequest{
		id:     id,
		method: "GET",
		path:   []byte("/ngsi-ld/v1/entities/urn:ngsi-ld:PersonalProfile:alice"),
		header: h,
	}
}

const defaultDenyBody = `{"error":"access denied by consent policy"}`

// --- Integration test cases (two-call consent check) ---

// TestIntegration_GrantedConsentPassthrough verifies a granted consent lets the
// response through unchanged.
func TestIntegration_GrantedConsentPassthrough(t *testing.T) {
	srv := newConsentManager(t, "did:key:zAlice", "uid-1", []string{"granted"})
	defer srv.Close()
	resolver := newOwnerResolver(t, "did:key:zAlice")
	defer resolver.Close()

	resp := runPluginCycle(t, marshalConfig(t, baseConfig(srv.URL, resolver.URL+"/resolve")),
		consentRequest(1, "did:key:zCaller"), []byte(`{"email":"alice@example.org"}`))

	assert.Nil(t, resp.writtenBody, "granted consent should not modify the response")
	assert.Equal(t, 0, resp.writtenStatus)
}

// TestIntegration_NoGrantedConsentDenied verifies a subject with only a revoked
// consent is denied.
func TestIntegration_NoGrantedConsentDenied(t *testing.T) {
	srv := newConsentManager(t, "", "uid-1", []string{"revoked"})
	defer srv.Close()
	resolver := newOwnerResolver(t, "did:key:zAlice")
	defer resolver.Close()

	resp := runPluginCycle(t, marshalConfig(t, baseConfig(srv.URL, resolver.URL+"/resolve")),
		consentRequest(2, "did:key:zCaller"), []byte(`{"email":"alice@example.org"}`))

	assert.Equal(t, 403, resp.writtenStatus)
	assert.Equal(t, defaultDenyBody, string(resp.writtenBody))
}

// TestIntegration_UnknownSubjectDenied verifies a subject unknown to the
// consent-manager (404 on identifier search) is denied.
func TestIntegration_UnknownSubjectDenied(t *testing.T) {
	srv := newConsentManager(t, "", "", nil)
	defer srv.Close()
	resolver := newOwnerResolver(t, "did:key:zStranger")
	defer resolver.Close()

	resp := runPluginCycle(t, marshalConfig(t, baseConfig(srv.URL, resolver.URL+"/resolve")),
		consentRequest(3, "did:key:zCaller"), []byte(`{"email":"x@example.org"}`))

	assert.Equal(t, 403, resp.writtenStatus)
	assert.Equal(t, defaultDenyBody, string(resp.writtenBody))
}

// TestIntegration_CustomDenyResponse verifies the configured deny status/body are used.
func TestIntegration_CustomDenyResponse(t *testing.T) {
	srv := newConsentManager(t, "", "uid-1", []string{"revoked"})
	defer srv.Close()

	resolver := newOwnerResolver(t, "did:key:zAlice")
	defer resolver.Close()

	cfg := baseConfig(srv.URL, resolver.URL+"/resolve")
	cfg["deny_status_code"] = 451
	cfg["deny_response_body"] = `{"error":"legally restricted"}`
	cfg["deny_response_content_type"] = "application/json"

	resp := runPluginCycle(t, marshalConfig(t, cfg),
		consentRequest(4, "did:key:zCaller"), []byte(`{"secret":"x"}`))

	assert.Equal(t, 451, resp.writtenStatus)
	assert.Equal(t, `{"error":"legally restricted"}`, string(resp.writtenBody))
	assert.Equal(t, "application/json", resp.header.Get("Content-Type"))
}

// TestIntegration_ConsentManagerError_FailOpen verifies a consent-manager error
// passes through when fail-open is set.
func TestIntegration_ConsentManagerError_FailOpen(t *testing.T) {
	srv := newFailingConsentManager(http.StatusInternalServerError)
	defer srv.Close()

	resolver := newOwnerResolver(t, "did:key:zAlice")
	defer resolver.Close()

	cfg := baseConfig(srv.URL, resolver.URL+"/resolve")
	cfg["fail_open"] = true

	resp := runPluginCycle(t, marshalConfig(t, cfg),
		consentRequest(5, "did:key:zCaller"), []byte(`{"data":"passes"}`))

	assert.Nil(t, resp.writtenBody, "fail-open should pass through on consent-manager error")
	assert.Equal(t, 0, resp.writtenStatus)
}

// TestIntegration_ConsentManagerError_FailClosed verifies a consent-manager error
// is denied when fail-closed.
func TestIntegration_ConsentManagerError_FailClosed(t *testing.T) {
	srv := newFailingConsentManager(http.StatusServiceUnavailable)
	defer srv.Close()

	resolver := newOwnerResolver(t, "did:key:zAlice")
	defer resolver.Close()

	cfg := baseConfig(srv.URL, resolver.URL+"/resolve")
	cfg["fail_open"] = false

	resp := runPluginCycle(t, marshalConfig(t, cfg),
		consentRequest(6, "did:key:zCaller"), []byte(`{"data":"denied"}`))

	assert.Equal(t, 403, resp.writtenStatus)
	assert.Equal(t, defaultDenyBody, string(resp.writtenBody))
}

// TestIntegration_OwnerNotRequestor verifies the subject the consent-manager is
// asked about is the RESOLVED DATA OWNER, not the caller (asserted in the mock).
func TestIntegration_OwnerNotRequestor(t *testing.T) {
	srv := newConsentManager(t, "did:key:zBob", "uid-bob", []string{"granted"})
	defer srv.Close()
	resolver := newOwnerResolver(t, "did:key:zBob")
	defer resolver.Close()

	// The caller is Alice; the resolver says the data belongs to Bob, and the
	// mock asserts that Bob — not Alice — is the subject sent to the search.
	resp := runPluginCycle(t, marshalConfig(t, baseConfig(srv.URL, resolver.URL+"/resolve")),
		consentRequest(7, "did:key:zAlice"), []byte(`{"ok":true}`))

	assert.Nil(t, resp.writtenBody)
}

// TestIntegration_CustomJWTHeader verifies the plugin reads the JWT from a custom
// header when configured (the resolved owner's consent is granted).
func TestIntegration_CustomJWTHeader(t *testing.T) {
	srv := newConsentManager(t, "custom-user", "uid-c", []string{"granted"})
	defer srv.Close()
	resolver := newOwnerResolver(t, "custom-user")
	defer resolver.Close()

	cfg := baseConfig(srv.URL, resolver.URL+"/resolve")
	cfg["jwt_header_name"] = "X-Auth-Token"

	h := newMockRequestHeader()
	h.Set("X-Auth-Token", "Bearer "+buildMockJWT(map[string]interface{}{
		"verifiableCredential": map[string]interface{}{"issuer": itestConsumerDID},
	}))
	req := &mockRequest{id: 8, method: "POST", path: []byte("/api/v1/items"), header: h}

	resp := runPluginCycle(t, marshalConfig(t, cfg), req, []byte(`{"created":true}`))

	assert.Nil(t, resp.writtenBody, "granted consent via custom JWT header should pass through")
}

// TestIntegration_ContextCleanupAfterCycle verifies the request context is
// cleaned up after a full request-response cycle (no memory leak).
func TestIntegration_ContextCleanupAfterCycle(t *testing.T) {
	srv := newConsentManager(t, "", "uid-1", []string{"granted"})
	defer srv.Close()
	resolver := newOwnerResolver(t, "did:key:zAlice")
	defer resolver.Close()

	const id = uint32(999)
	_ = runPluginCycle(t, marshalConfig(t, baseConfig(srv.URL, resolver.URL+"/resolve")),
		consentRequest(id, "did:key:zCaller"), []byte(`{"data":"test"}`))

	assert.Equal(t, 0, plugin.RequestContextStoreSize(),
		"request context should be deleted after the response cycle")
}

// newConsentManagerCC starts a mock consent-manager exposing all four endpoints
// used by the client-credentials flow (login, me, identifier search, consents).
func newConsentManagerTokenService(t *testing.T, wantSubject, userID, selfDescriptionURL string, statuses []string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// The participant-local token service (the consent-facade's /internal/tokens),
	// served on the same test server for convenience. The plugin holds no
	// participant credentials - it asks for a token by audience NAME.
	mux.HandleFunc("/internal/tokens", func(w http.ResponseWriter, r *http.Request) {
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		assert.Equal(t, "consent-manager", b["audience"])
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "itest-token", "token_type": "Bearer", "expires_in": 3600,
		})
	})

	mux.HandleFunc("/v1/participants/me", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer itest-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"selfDescriptionURL": selfDescriptionURL})
	})

	mux.HandleFunc("/v1/users/identifier/search", func(w http.ResponseWriter, r *http.Request) {
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		if wantSubject != "" {
			assert.Equal(t, wantSubject, b["email"])
		}
		assert.Equal(t, selfDescriptionURL, b["selfDescription"], "derived SD is used in the search")
		if userID == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"userIdentifier": userID})
	})

	mux.HandleFunc("/v1/consents/participants/", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer itest-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"consents": consentsGrantedTo(statuses)})
	})

	mux.HandleFunc("/v1/participants", participantRegistryHandler)

	return httptest.NewServer(mux)
}

// ccConfig is a plugin config using participant client credentials (no static
// token, no explicit provider_sd — both are obtained from the consent-manager).
func tokenServiceConfig(consentURL, resolverURL string) map[string]interface{} {
	return map[string]interface{}{
		"consent_api_url":    consentURL,
		"owner_resolver_url": resolverURL,
		"token_service_url":  consentURL + "/internal/tokens",
	}
}

// TestIntegration_TokenServiceFlow drives the full OID4VP-token path: fetch a
// token from the participant-local token service, derive the provider SD from
// /me, then the two-call check.
func TestIntegration_TokenServiceFlow(t *testing.T) {
	srv := newConsentManagerTokenService(t, "did:key:zAlice", "uid-1",
		"http://consent-facade:8080/participants/derived", []string{"granted"})
	defer srv.Close()
	resolver := newOwnerResolver(t, "did:key:zAlice")
	defer resolver.Close()

	resp := runPluginCycle(t, marshalConfig(t, tokenServiceConfig(srv.URL, resolver.URL+"/resolve")),
		consentRequest(20, "did:key:zCaller"), []byte(`{"ok":true}`))

	assert.Nil(t, resp.writtenBody, "granted consent via client credentials should pass through")
}

// TestIntegration_TokenServiceDenied verifies a not-granted consent denies via
// the OID4VP-token path.
func TestIntegration_TokenServiceDenied(t *testing.T) {
	srv := newConsentManagerTokenService(t, "", "uid-1",
		"http://consent-facade:8080/participants/derived", []string{"revoked"})
	defer srv.Close()
	resolver := newOwnerResolver(t, "did:key:zAlice")
	defer resolver.Close()

	resp := runPluginCycle(t, marshalConfig(t, tokenServiceConfig(srv.URL, resolver.URL+"/resolve")),
		consentRequest(21, "did:key:zCaller"), []byte(`{"secret":"x"}`))

	assert.Equal(t, 403, resp.writtenStatus)
	assert.Equal(t, defaultDenyBody, string(resp.writtenBody))
}

// --- Resolver-mode integration tests ---

// perOwnerConsentManager starts a consent-manager whose consent status is looked
// up per data owner, so a multi-owner response can mix granted and revoked
// owners. It records the owners it was asked about, in order.
func perOwnerConsentManager(t *testing.T, statusByOwner map[string]string, asked *[]string) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	identifiers := map[string]string{}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/users/identifier/search", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		owner := body["email"]
		mu.Lock()
		*asked = append(*asked, owner)
		status, known := statusByOwner[owner]
		if known {
			identifiers["uid-"+owner] = status
		}
		mu.Unlock()
		if !known {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"userIdentifier": "uid-" + owner})
	})
	mux.HandleFunc("/v1/consents/participants/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/v1/consents/participants/")
		mu.Lock()
		status := identifiers[id]
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"consents": consentsGrantedTo([]string{status})})
	})
	mux.HandleFunc("/v1/participants", participantRegistryHandler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestIntegration_Resolver drives the resolver-mode decision matrix end to end:
// a real ParseConf -> RequestFilter -> ResponseFilter against a mock resolver
// and a mock consent-manager.
func TestIntegration_Resolver(t *testing.T) {
	const (
		ownerAlice = "did:key:zAlice"
		ownerBob   = "did:key:zBob"
	)

	tests := []struct {
		name          string
		resolverReply map[string]interface{}
		resolverCode  int // non-zero => the resolver answers with this status instead
		statusByOwner map[string]string
		failOpen      *bool
		wantDenied    bool
		wantOwners    []string // owners the consent-manager must have been asked about
	}{
		{
			name:          "every owner granted allows",
			resolverReply: resolveReply(ownerAlice, ownerBob),
			statusByOwner: map[string]string{ownerAlice: "granted", ownerBob: "granted"},
			wantOwners:    []string{ownerAlice, ownerBob},
		},
		{
			name:          "one revoked owner denies the whole response (deny_all)",
			resolverReply: resolveReply(ownerAlice, ownerBob),
			statusByOwner: map[string]string{ownerAlice: "granted", ownerBob: "revoked"},
			wantDenied:    true,
			// Which owners get asked depends on the concurrent short-circuit, so
			// only the decision is asserted here.
		},
		{
			name:          "an owner unknown to the consent-manager denies",
			resolverReply: resolveReply(ownerAlice, ownerBob),
			statusByOwner: map[string]string{ownerAlice: "granted"},
			wantDenied:    true,
		},
		{
			name:          "consentRequired false allows without any consent call",
			resolverReply: map[string]interface{}{"consentRequired": false},
			wantOwners:    nil,
		},
		{
			name:          "consent required with no claims denies",
			resolverReply: map[string]interface{}{"consentRequired": true, "claims": []map[string]string{}},
			wantDenied:    true,
			wantOwners:    nil,
		},
		{
			name: "a claim with an empty owner denies",
			resolverReply: map[string]interface{}{
				"consentRequired": true,
				"claims":          []map[string]string{{"ownerId": ""}},
			},
			wantDenied: true,
			wantOwners: nil,
		},
		{
			name:         "resolver 5xx denies by default",
			resolverCode: http.StatusInternalServerError,
			wantDenied:   true,
			wantOwners:   nil,
		},
		{
			name:         "resolver 5xx passes through with fail_open",
			resolverCode: http.StatusInternalServerError,
			failOpen:     boolPtr(true),
			wantOwners:   nil,
		},
		{
			name:          "duplicate owners are checked once",
			resolverReply: resolveReply(ownerAlice, ownerAlice, ownerAlice),
			statusByOwner: map[string]string{ownerAlice: "granted"},
			wantOwners:    []string{ownerAlice},
		},
	}

	// Each case needs its own request id, so the context store entries cannot
	// collide between subtests.
	nextRequestID := uint32(100)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			consent.ResetCaches()
			nextRequestID++

			var asked []string
			cm := perOwnerConsentManager(t, tt.statusByOwner, &asked)

			var resolver *httptest.Server
			if tt.resolverCode != 0 {
				resolver = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(tt.resolverCode)
				}))
			} else {
				var received []resolveEnvelope
				resolver = newRecordingOwnerResolver(t, tt.resolverReply, &received)
			}
			defer resolver.Close()

			cfg := baseConfig(cm.URL, resolver.URL+"/resolve")
			if tt.failOpen != nil {
				cfg["fail_open"] = *tt.failOpen
			}

			resp := runPluginCycle(t, marshalConfig(t, cfg),
				consentRequest(nextRequestID, "did:key:zCaller"), []byte(`{"id":"urn:entity:1"}`))

			if tt.wantDenied {
				assert.Equal(t, 403, resp.writtenStatus)
				assert.Equal(t, defaultDenyBody, string(resp.writtenBody))
			} else {
				assert.Nil(t, resp.writtenBody, "expected the response to pass through")
				assert.Equal(t, 0, resp.writtenStatus)
			}
			if tt.wantOwners != nil {
				// Checks run concurrently, so the order is not significant.
				assert.ElementsMatch(t, tt.wantOwners, asked, "the consent-manager must be asked about exactly these owners")
			}
		})
	}
}

// resolveReply builds a /resolve reply requiring consent from the given owners.
func resolveReply(owners ...string) map[string]interface{} {
	claims := make([]map[string]string, 0, len(owners))
	for _, o := range owners {
		claims = append(claims, map[string]string{"ownerId": o})
	}
	return map[string]interface{}{"consentRequired": true, "claims": claims}
}

// TestIntegration_ResolverReceivesPartiesAndPayload verifies what the plugin
// actually tells the resolver: the resource descriptor, the contract parties
// (resolved via the participant registry), and the upstream payload as JSON.
func TestIntegration_ResolverReceivesPartiesAndPayload(t *testing.T) {
	consent.ResetCaches()

	var asked []string
	cm := perOwnerConsentManager(t, map[string]string{"did:key:zAlice": "granted"}, &asked)

	var received []resolveEnvelope
	resolver := newRecordingOwnerResolver(t, resolveReply("did:key:zAlice"), &received)
	defer resolver.Close()

	cfg := baseConfig(cm.URL, resolver.URL+"/resolve")
	cfg["service"] = "personal-profiles"

	payload := []byte(`{"id":"urn:ngsi-ld:PersonalProfile:alice"}`)
	runPluginCycle(t, marshalConfig(t, cfg), consentRequest(150, "did:key:zCaller"), payload)

	require.Len(t, received, 1)
	env := received[0]
	assert.Equal(t, "personal-profiles", env.Resource.Service)
	assert.Equal(t, "GET", env.Resource.Method)
	assert.Equal(t, "/ngsi-ld/v1/entities/urn:ngsi-ld:PersonalProfile:alice", env.Resource.Path)
	require.NotNil(t, env.Parties, "the contract parties must be sent, or the resolver cannot identify the contract")
	assert.Equal(t, itestConsumerSD, env.Parties.Consumer, "the consumer DID must be mapped to its self-description")
	assert.Equal(t, "http://consent-facade:8080/participants/org-itest", env.Parties.Provider)
	require.NotNil(t, env.Body)
	assert.Equal(t, "json", env.Body.Encoding)
	assert.JSONEq(t, string(payload), string(env.Body.Content))
}

// TestIntegration_PartyResolutionFailureDenies verifies the fail-closed seam
// from H-1 end to end: when the consumer cannot be mapped to a participant, the
// resolver is never asked and the response is denied — even with fail_open,
// which must not turn a token naming an unregistered consumer into a bypass.
func TestIntegration_PartyResolutionFailureDenies(t *testing.T) {
	consent.ResetCaches()

	var asked []string
	cm := perOwnerConsentManager(t, map[string]string{}, &asked)

	resolverCalled := false
	resolver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resolverCalled = true
		w.Header().Set("Content-Type", "application/json")
		// An unidentified-party resolve could plausibly answer "no contract
		// governs this, so no consent is required" — an unconditional allow.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"consentRequired": false})
	}))
	defer resolver.Close()

	h := newMockRequestHeader()
	h.Set("Authorization", "Bearer "+buildMockJWT(map[string]interface{}{
		"verifiableCredential": map[string]interface{}{"issuer": "did:key:zUnregisteredConsumer"},
	}))
	req := &mockRequest{id: 160, method: "GET", path: []byte("/data"), header: h}

	cfg := baseConfig(cm.URL, resolver.URL+"/resolve")
	cfg["fail_open"] = true

	resp := runPluginCycle(t, marshalConfig(t, cfg), req, []byte(`{"a":1}`))

	assert.False(t, resolverCalled, "an unidentified consumer must not reach the resolver")
	assert.Equal(t, 403, resp.writtenStatus, "an unidentified consumer must deny")
}

// boolPtr returns a pointer to b, for the optional fail_open flag.
func boolPtr(b bool) *bool { return &b }
