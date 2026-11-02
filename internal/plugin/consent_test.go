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

package plugin

import (
	"consent-plugin/internal/audit"
	"consent-plugin/internal/consent"
	"consent-plugin/internal/logging"
	"consent-plugin/internal/metrics"
	"consent-plugin/internal/ownerresolver"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	pkgHTTP "github.com/apache/apisix-go-plugin-runner/pkg/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConsentFilter_Name(t *testing.T) {
	p := &ConsentFilter{}
	assert.Equal(t, "consent-filter", p.Name())
}

func TestConsentFilter_ParseConf(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "valid config returns parsed Config",
			input:   []byte(`{"consent_api_url": "https://consent.example.com", "owner_resolver_url": "https://resolver.example.com/resolve", "participant_token": "t"}`),
			wantErr: false,
		},
		{
			name:    "missing required field returns error",
			input:   []byte(`{}`),
			wantErr: true,
		},
		{
			name:    "missing owner_resolver_url returns error",
			input:   []byte(`{"consent_api_url": "https://consent.example.com"}`),
			wantErr: true,
		},
		{
			name:    "nil input returns error",
			input:   nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &ConsentFilter{}
			conf, err := p.ParseConf(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, conf)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, conf)
				_, ok := conf.(*Config)
				assert.True(t, ok, "ParseConf should return *Config type")
			}
		})
	}
}

func TestPluginName_Constant(t *testing.T) {
	assert.Equal(t, "consent-filter", pluginName)
}

// --- Mock implementations for testing ResponseFilter ---

// mockHeader implements pkgHTTP.Header for testing.
// mockHeader mirrors the runner's header implementation: View() returns the LIVE
// header map (not a copy), so a caller iterating it and deleting through Del
// behaves exactly as it does in production.
type mockHeader struct {
	headers http.Header
}

func newMockHeader() *mockHeader {
	return &mockHeader{headers: make(http.Header)}
}

func (h *mockHeader) Set(key, value string) { h.headers.Set(key, value) }
func (h *mockHeader) Del(key string)        { h.headers.Del(key) }
func (h *mockHeader) Get(key string) string { return h.headers.Get(key) }
func (h *mockHeader) View() http.Header     { return h.headers }

// mockResponse implements pkgHTTP.Response for testing.
type mockResponse struct {
	id         uint32
	statusCode int
	header     *mockHeader
	body       []byte
	readErr    error
	// headerReads counts Header() calls. The runner materialises its header map
	// on the first one and then reports the response as modified, so an allowed
	// response must not touch it.
	headerReads   int
	writtenBody   []byte
	writtenStatus int
	// suppressContentTypeVar makes Var() report no upstream Content-Type, to
	// exercise the header fallback.
	suppressContentTypeVar bool
	// suppressRequestIDVar makes Var() report no $request_id, as happens when the
	// two phases cannot be correlated.
	suppressRequestIDVar bool
}

// newMockResponse builds a JSON upstream response carrying body.
func newMockResponse(id uint32, body []byte) *mockResponse {
	h := newMockHeader()
	h.Set("Content-Type", responseContentTypeJSON)
	return &mockResponse{id: id, header: h, body: body}
}

func (r *mockResponse) ID() uint32      { return r.id }
func (r *mockResponse) StatusCode() int { return r.statusCode }
func (r *mockResponse) Header() pkgHTTP.Header {
	r.headerReads++
	return r.header
}

// Var returns the Nginx request id ($request_id) derived from the mock's id so
// correlationKey resolves to the same key the tests store under.
func (r *mockResponse) Var(name string) ([]byte, error) {
	switch name {
	case nginxRequestIDVar:
		if r.suppressRequestIDVar {
			return nil, nil
		}
		return []byte(testReqKey(r.id)), nil
	case nginxUpstreamContentTypeVar:
		if r.suppressContentTypeVar {
			return nil, nil
		}
		return []byte(responseContentTypeJSON), nil
	}
	return nil, nil
}

func (r *mockResponse) ReadBody() ([]byte, error) { return r.body, r.readErr }

// Write appends, as the runner's Response.Write does (it writes into a buffer).
// A mock that replaced the body would hide a double-write regression.
func (r *mockResponse) Write(b []byte) (int, error) {
	r.writtenBody = append(r.writtenBody, b...)
	return len(b), nil
}
func (r *mockResponse) WriteHeader(statusCode int) { r.writtenStatus = statusCode }

// testReqKey maps a numeric mock id to the string request key used as the
// context-store key (mirrors the Nginx $request_id used in production).
func testReqKey(id uint32) string {
	return strconv.FormatUint(uint64(id), 10)
}

// --- Consent-manager mock (the two endpoints the plugin calls) ---

// newConsentManager starts a mock consent-manager whose /consents list returns
// one consent per entry in statuses, each naming testConsumerDID as consumer.
func newConsentManager(t *testing.T, statuses []string) *httptest.Server {
	t.Helper()
	return newConsentListServer(func(*http.Request) []map[string]interface{} {
		return consentsGrantedTo(testConsumerDID, statuses)
	})
}

// newConsentListServer serves GET /v1/consents as a single ConsentPage built by
// content, plus the participant endpoints every client configuration calls.
func newConsentListServer(content func(*http.Request) []map[string]interface{}) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/consents", func(w http.ResponseWriter, r *http.Request) {
		records := content(r)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"content": records, "page": 0, "size": len(records), "totalElements": len(records), "totalPages": 1,
		})
	})
	registerParticipantEndpoints(mux)
	return httptest.NewServer(mux)
}

// newFailingConsentManager returns a consent-manager whose CONSENT CHECK calls
// answer 500 (used to exercise the fail policy). The participant registry still
// answers, so the failure under test is the check itself and not the preceding
// contract lookup.
func newFailingConsentManager() *httptest.Server {
	mux := http.NewServeMux()
	registerParticipantEndpoints(mux)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	return httptest.NewServer(mux)
}

// testProviderDID is the identifier /participants/me reports for this participant.
const testProviderDID = "did:key:zProvider"

// registerParticipantEndpoints serves the participant registry and
// /participants/me, which every client configuration now calls.
func registerParticipantEndpoints(mux *http.ServeMux) {
	mux.HandleFunc("/v1/participants", participantRegistryHandler)
	mux.HandleFunc("/v1/participants/me", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"identifier": testProviderDID, "selfDescriptionUri": "http://catalog/participants/provider",
		})
	})
}

// participantRegistryHandler serves the consent-manager's participant registry,
// which maps the consumer DID from the token to its self-description URI.
func participantRegistryHandler(w http.ResponseWriter, r *http.Request) {
	content := []map[string]string{}
	if r.URL.Query().Get("identifier") == testConsumerDID {
		content = append(content, map[string]string{"identifier": testConsumerDID, "selfDescriptionUri": testConsumerSD})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"content": content})
}

// newUncalledConsentManager fails the test if a CONSENT CHECK reaches the
// consent-manager. The participant registry is still served: mapping the
// consumer DID to a self-description is part of the contract lookup that
// precedes the check, and happens even when no check is performed.
func newUncalledConsentManager(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	registerParticipantEndpoints(mux)
	mux.HandleFunc("/", func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("consent-manager must not be called for a consent check (path %s)", r.URL.Path)
	})
	return httptest.NewServer(mux)
}

// --- OwnerResolver mock (the source of data ownership) ---

// resolverClaim is one (owner [x dataResource]) requirement in a mock /resolve reply.
type resolverClaim struct {
	OwnerID         string `json:"ownerId"`
	DataResource    string `json:"dataResource,omitempty"`
	Purpose         string `json:"purpose,omitempty"`
	ContractURI     string `json:"contractUri,omitempty"`
	PrivacyNoticeID string `json:"privacyNoticeId,omitempty"`
}

// resolverResponse is the mock OwnerResolver's /resolve reply.
type resolverResponse struct {
	ConsentRequired bool            `json:"consentRequired"`
	Claims          []resolverClaim `json:"claims"`
}

// ownedBy builds a resolve reply naming the given data owners (consent required).
func ownedBy(owners ...string) resolverResponse {
	claims := make([]resolverClaim, 0, len(owners))
	for _, o := range owners {
		claims = append(claims, resolverClaim{OwnerID: o})
	}
	return resolverResponse{ConsentRequired: true, Claims: claims}
}

// newOwnerResolver starts a mock OwnerResolver answering every /resolve with resp.
func newOwnerResolver(t *testing.T, resp resolverResponse) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("failed to encode resolve response: %v", err)
		}
	}))
}

// newFailingOwnerResolver returns a resolver answering every call with status.
func newFailingOwnerResolver(status int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	}))
}

// newUncalledOwnerResolver fails the test if the resolver is contacted.
func newUncalledOwnerResolver(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("owner resolver must not be called (path %s)", r.URL.Path)
	}))
}

// --- Helpers ---

func boolPtr(b bool) *bool { return &b }

// newTestConfig creates a valid plugin Config pointing at the given
// consent-manager and OwnerResolver.
func newTestConfig(consentAPIURL, resolverURL string) *Config {
	return &Config{
		ConsentAPIURL:           consentAPIURL,
		ConsentAPIPrefix:        DefaultConsentAPIPrefix,
		ConsentAPITimeout:       DefaultConsentAPITimeout,
		OwnerResolverURL:        resolverURL,
		OwnerResolverTimeout:    DefaultOwnerResolverTimeout,
		ResponsePhaseTimeout:    DefaultResponsePhaseTimeout,
		MaxOwnersPerResponse:    DefaultMaxOwnersPerResponse,
		MaxResolveBodyBytes:     DefaultMaxResolveBodyBytes,
		ConsumerClaim:           DefaultConsumerClaim,
		JWTHeaderName:           DefaultJWTHeaderName,
		ParticipantToken:        "test-participant-token",
		ProviderSD:              "http://consent-facade:8080/participants/org-1",
		DenyStatusCode:          DefaultDenyStatusCode,
		DenyResponseBody:        DefaultDenyResponseBody,
		DenyResponseContentType: DefaultDenyResponseContentType,
	}
}

// storeRequest stores a request context for the given mock id. The consuming
// participant is named in the claims; the data owner comes from the resolver.
func storeRequest(id uint32) {
	StoreRequestContext(testReqKey(id), &RequestContext{
		Method: "GET",
		Path:   "/ngsi-ld/v1/entities/urn:ngsi-ld:PersonalProfile:alice",
		JWTClaims: map[string]interface{}{
			"verifiableCredential": map[string]interface{}{"issuer": testConsumerDID},
		},
	})
}

// testOwnerDID is the data owner a mock resolver reports.
const testOwnerDID = "did:key:zOwner"

// testConsumerDID is the requesting participant named in the token claims.
const testConsumerDID = "did:key:zConsumer"

// testConsumerSD is the self-description URL the participant registry maps
// testConsumerDID to; only the resolver sees it, consents name the DID.
const testConsumerSD = "http://catalog/participants/consumer"

// consentsGrantedTo builds consent records with the given statuses, each naming
// this participant as provider and the given DID as consumer.
func consentsGrantedTo(consumer string, statuses []string) []map[string]interface{} {
	consents := make([]map[string]interface{}, 0, len(statuses))
	for _, s := range statuses {
		consents = append(consents, map[string]interface{}{
			"status":    strings.ToUpper(s),
			"consented": s == "granted",
			"provider":  testProviderDID,
			"consumer":  consumer,
		})
	}
	return consents
}

// --- ResponseFilter tests (coarse allow/deny gate) ---

func TestConsentFilter_ResponseFilter(t *testing.T) {
	tests := []struct {
		name              string
		setupContext      func(id uint32)
		consentServer     func(t *testing.T) *httptest.Server
		resolverServer    func(t *testing.T) *httptest.Server
		configFn          func(cfg *Config)
		invalidConfig     bool
		wantWrittenBody   string
		wantWrittenStatus int
		wantNoWrite       bool
	}{
		{
			name:           "granted consent for the resolved owner passes the response through",
			setupContext:   storeRequest,
			consentServer:  func(t *testing.T) *httptest.Server { return newConsentManager(t, []string{"granted"}) },
			resolverServer: func(t *testing.T) *httptest.Server { return newOwnerResolver(t, ownedBy(testOwnerDID)) },
			wantNoWrite:    true,
		},
		{
			name:              "no granted consent denies with the default response",
			setupContext:      storeRequest,
			consentServer:     func(t *testing.T) *httptest.Server { return newConsentManager(t, []string{"revoked"}) },
			resolverServer:    func(t *testing.T) *httptest.Server { return newOwnerResolver(t, ownedBy(testOwnerDID)) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name:              "owner without consents denies",
			setupContext:      storeRequest,
			consentServer:     func(t *testing.T) *httptest.Server { return newConsentManager(t, nil) },
			resolverServer:    func(t *testing.T) *httptest.Server { return newOwnerResolver(t, ownedBy(testOwnerDID)) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name:           "deny uses the custom status code and body",
			setupContext:   storeRequest,
			consentServer:  func(t *testing.T) *httptest.Server { return newConsentManager(t, []string{"revoked"}) },
			resolverServer: func(t *testing.T) *httptest.Server { return newOwnerResolver(t, ownedBy(testOwnerDID)) },
			configFn: func(cfg *Config) {
				cfg.DenyStatusCode = 451
				cfg.DenyResponseBody = `{"msg":"legally blocked"}`
			},
			wantWrittenBody:   `{"msg":"legally blocked"}`,
			wantWrittenStatus: 451,
		},
		{
			name:          "consent not required allows without contacting the consent-manager",
			setupContext:  storeRequest,
			consentServer: newUncalledConsentManager,
			resolverServer: func(t *testing.T) *httptest.Server {
				return newOwnerResolver(t, resolverResponse{ConsentRequired: false})
			},
			wantNoWrite: true,
		},
		{
			name:          "consent required but no owner resolved denies",
			setupContext:  storeRequest,
			consentServer: newUncalledConsentManager,
			resolverServer: func(t *testing.T) *httptest.Server {
				return newOwnerResolver(t, resolverResponse{ConsentRequired: true})
			},
			configFn:          func(cfg *Config) { cfg.FailOpen = boolPtr(false) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name:          "resolved claim without an owner id denies",
			setupContext:  storeRequest,
			consentServer: newUncalledConsentManager,
			resolverServer: func(t *testing.T) *httptest.Server {
				return newOwnerResolver(t, resolverResponse{ConsentRequired: true, Claims: []resolverClaim{{OwnerID: ""}}})
			},
			configFn:          func(cfg *Config) { cfg.FailOpen = boolPtr(false) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name:              "one denying owner denies the whole response (deny_all)",
			setupContext:      storeRequest,
			consentServer:     func(t *testing.T) *httptest.Server { return newConsentManager(t, []string{"revoked"}) },
			resolverServer:    func(t *testing.T) *httptest.Server { return newOwnerResolver(t, ownedBy("did:key:zA", "did:key:zB")) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name:              "resolver error denies by default (fail-closed)",
			setupContext:      storeRequest,
			consentServer:     newUncalledConsentManager,
			resolverServer:    func(t *testing.T) *httptest.Server { return newFailingOwnerResolver(http.StatusInternalServerError) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name:           "resolver error with fail-open explicitly enabled passes through",
			setupContext:   storeRequest,
			consentServer:  newUncalledConsentManager,
			resolverServer: func(t *testing.T) *httptest.Server { return newFailingOwnerResolver(http.StatusInternalServerError) },
			configFn:       func(cfg *Config) { cfg.FailOpen = boolPtr(true) },
			wantNoWrite:    true,
		},
		{
			name:              "resolver error with fail-closed denies",
			setupContext:      storeRequest,
			consentServer:     newUncalledConsentManager,
			resolverServer:    func(t *testing.T) *httptest.Server { return newFailingOwnerResolver(http.StatusInternalServerError) },
			configFn:          func(cfg *Config) { cfg.FailOpen = boolPtr(false) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name:              "consent-manager error denies by default (fail-closed)",
			setupContext:      storeRequest,
			consentServer:     func(t *testing.T) *httptest.Server { return newFailingConsentManager() },
			resolverServer:    func(t *testing.T) *httptest.Server { return newOwnerResolver(t, ownedBy(testOwnerDID)) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name:           "consent-manager error with fail-open explicitly enabled passes through",
			setupContext:   storeRequest,
			consentServer:  func(t *testing.T) *httptest.Server { return newFailingConsentManager() },
			resolverServer: func(t *testing.T) *httptest.Server { return newOwnerResolver(t, ownedBy(testOwnerDID)) },
			configFn:       func(cfg *Config) { cfg.FailOpen = boolPtr(true) },
			wantNoWrite:    true,
		},
		{
			name:              "consent-manager error with fail-closed denies",
			setupContext:      storeRequest,
			consentServer:     func(t *testing.T) *httptest.Server { return newFailingConsentManager() },
			resolverServer:    func(t *testing.T) *httptest.Server { return newOwnerResolver(t, ownedBy(testOwnerDID)) },
			configFn:          func(cfg *Config) { cfg.FailOpen = boolPtr(false) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			// Losing the request context is not an outage to ride out: the plugin
			// cannot gate at all, so fail_open must not turn it into a bypass.
			name:              "missing request context denies even with fail-open enabled",
			setupContext:      nil,
			consentServer:     newUncalledConsentManager,
			resolverServer:    newUncalledOwnerResolver,
			configFn:          func(cfg *Config) { cfg.FailOpen = boolPtr(true) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name:              "missing request context with fail-closed denies",
			setupContext:      nil,
			consentServer:     newUncalledConsentManager,
			resolverServer:    newUncalledOwnerResolver,
			configFn:          func(cfg *Config) { cfg.FailOpen = boolPtr(false) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name: "unresolvable consumer denies without asking the resolver",
			setupContext: func(id uint32) {
				StoreRequestContext(testReqKey(id), &RequestContext{
					Method: "GET", Path: "/data",
					JWTClaims: map[string]interface{}{
						"verifiableCredential": map[string]interface{}{"issuer": "did:key:zNotRegistered"},
					},
				})
			},
			consentServer:  newUncalledConsentManager,
			resolverServer: newUncalledOwnerResolver,
			// A consumer that is not in the registry is a permanent condition, so
			// fail_open must not grant it standing access.
			configFn:          func(cfg *Config) { cfg.FailOpen = boolPtr(true) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name: "no consumer claim in the token denies without asking the resolver",
			setupContext: func(id uint32) {
				StoreRequestContext(testReqKey(id), &RequestContext{
					Method: "GET", Path: "/data",
					JWTClaims: map[string]interface{}{"sub": "did:key:zCaller"},
				})
			},
			consentServer:     newUncalledConsentManager,
			resolverServer:    newUncalledOwnerResolver,
			configFn:          func(cfg *Config) { cfg.FailOpen = boolPtr(false) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			// A route with no way to authenticate as the participant is a
			// misconfiguration; fail_open must not make it a silent full bypass.
			name:           "missing participant credentials deny even with fail-open enabled",
			setupContext:   storeRequest,
			consentServer:  newUncalledConsentManager,
			resolverServer: newUncalledOwnerResolver,
			configFn: func(cfg *Config) {
				cfg.FailOpen = boolPtr(true)
				cfg.ParticipantToken = ""
				cfg.TokenServiceURL = ""
			},
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name:           "invalid config type passes through",
			setupContext:   storeRequest,
			consentServer:  newUncalledConsentManager,
			resolverServer: newUncalledOwnerResolver,
			invalidConfig:  true,
			wantNoWrite:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearContextStore()

			server := tt.consentServer(t)
			defer server.Close()
			resolver := tt.resolverServer(t)
			defer resolver.Close()

			var cfg interface{}
			if tt.invalidConfig {
				cfg = "not-a-config"
			} else {
				c := newTestConfig(server.URL, resolver.URL+"/resolve")
				if tt.configFn != nil {
					tt.configFn(c)
				}
				cfg = c
			}

			resp := newMockResponse(1, []byte(`{"id":"urn:ngsi-ld:PersonalProfile:alice"}`))
			if tt.setupContext != nil {
				tt.setupContext(resp.id)
			}

			p := &ConsentFilter{}
			p.ResponseFilter(cfg, resp)

			if tt.wantNoWrite {
				assert.Nil(t, resp.writtenBody, "expected no body written (passthrough)")
				assert.Equal(t, 0, resp.writtenStatus, "expected no status written (passthrough)")
				return
			}
			if tt.wantWrittenStatus != 0 {
				assert.Equal(t, tt.wantWrittenStatus, resp.writtenStatus)
			}
			if tt.wantWrittenBody != "" {
				assert.Equal(t, tt.wantWrittenBody, string(resp.writtenBody))
			}
		})
	}
}

// responseContentTypeJSON is the Content-Type of the simulated upstream responses.
const responseContentTypeJSON = "application/json"

func TestConsentFilter_ResponseFilter_ContextCleanup(t *testing.T) {
	clearContextStore()
	server := newConsentManager(t, []string{"granted"})
	defer server.Close()
	resolver := newOwnerResolver(t, ownedBy(testOwnerDID))
	defer resolver.Close()

	cfg := newTestConfig(server.URL, resolver.URL+"/resolve")
	const id = uint32(200)
	storeRequest(id)

	resp := newMockResponse(id, []byte(`{}`))
	(&ConsentFilter{}).ResponseFilter(cfg, resp)

	assert.Equal(t, 0, RequestContextStoreSize(), "request context should be deleted after ResponseFilter")
}

func TestConsentFilter_ResponseFilter_DenySetsContentType(t *testing.T) {
	clearContextStore()
	server := newConsentManager(t, []string{"revoked"})
	defer server.Close()
	resolver := newOwnerResolver(t, ownedBy(testOwnerDID))
	defer resolver.Close()

	cfg := newTestConfig(server.URL, resolver.URL+"/resolve")
	cfg.DenyResponseContentType = "text/plain"
	const id = uint32(201)
	storeRequest(id)

	resp := newMockResponse(id, []byte(`{}`))
	(&ConsentFilter{}).ResponseFilter(cfg, resp)

	assert.Equal(t, "text/plain", resp.header.Get("Content-Type"))
	assert.Equal(t, DefaultDenyStatusCode, resp.writtenStatus)
}

// TestResponseFilter_ConsentScopedToConsumer is the regression test for the
// consumer scoping: the owner's consent was granted to a DIFFERENT participant,
// so it is no authority for this consumer to read the data.
func TestResponseFilter_ConsentScopedToConsumer(t *testing.T) {
	clearContextStore()

	server := newConsentListServer(func(*http.Request) []map[string]interface{} {
		return consentsGrantedTo("did:key:zSomeoneElse", []string{"granted"})
	})
	defer server.Close()

	resolver := newOwnerResolver(t, ownedBy(testOwnerDID))
	defer resolver.Close()

	const id = uint32(203)
	storeRequest(id)
	resp := newMockResponse(id, []byte(`{"id":"urn:ngsi-ld:PersonalProfile:alice"}`))
	(&ConsentFilter{}).ResponseFilter(newTestConfig(server.URL, resolver.URL+"/resolve"), resp)

	assert.Equal(t, DefaultDenyStatusCode, resp.writtenStatus,
		"a consent granted to another participant must not authorise this consumer")
	assert.Equal(t, DefaultDenyResponseBody, string(resp.writtenBody))
}

// TestResponseFilter_OwnerNotRequestor is the regression test for the removed
// legacy mode: the consent that decides access must be the RESOLVED OWNER's, not
// the caller's. The resolver names Bob as the owner while the token's "sub" is
// Alice; the consent lookup must ask about Bob.
func TestResponseFilter_OwnerNotRequestor(t *testing.T) {
	clearContextStore()

	const owner = "did:key:zBob"
	var searchedSubjects []string

	server := newConsentListServer(func(r *http.Request) []map[string]interface{} {
		searchedSubjects = append(searchedSubjects, r.URL.Query().Get("userIdentifier"))
		return consentsGrantedTo(testConsumerDID, []string{"revoked"})
	})
	defer server.Close()

	resolver := newOwnerResolver(t, ownedBy(owner))
	defer resolver.Close()

	const id = uint32(202)
	// The caller is Alice; the data belongs to Bob.
	StoreRequestContext(testReqKey(id), &RequestContext{
		Method: "GET",
		Path:   "/ngsi-ld/v1/entities/urn:ngsi-ld:PersonalProfile:bob",
		JWTClaims: map[string]interface{}{
			"sub":                  "did:key:zAlice",
			"verifiableCredential": map[string]interface{}{"issuer": testConsumerDID},
		},
	})

	resp := newMockResponse(id, []byte(`{"id":"urn:ngsi-ld:PersonalProfile:bob"}`))
	(&ConsentFilter{}).ResponseFilter(newTestConfig(server.URL, resolver.URL+"/resolve"), resp)

	assert.Equal(t, []string{owner}, searchedSubjects,
		"consent must be checked for the resolved data owner, never for the token subject")
	assert.Equal(t, DefaultDenyStatusCode, resp.writtenStatus,
		"the owner has no granted consent, so the caller's own consent must not unlock the data")
}

// TestResponseFilter_OwnerCapDenies verifies a response resolving to more data
// owners than the cap is denied outright, rather than answered after an
// unbounded number of consent calls. A collection endpoint returning hundreds of
// entities is otherwise a latency and load amplifier any caller can trigger.
func TestResponseFilter_OwnerCapDenies(t *testing.T) {
	clearContextStore()

	owners := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		owners = append(owners, fmt.Sprintf("did:key:zOwner%d", i))
	}

	server := newUncalledConsentManager(t)
	defer server.Close()
	resolver := newOwnerResolver(t, ownedBy(owners...))
	defer resolver.Close()

	cfg := newTestConfig(server.URL, resolver.URL+"/resolve")
	cfg.MaxOwnersPerResponse = 3
	// Even with fail_open the cap must deny: it is a deliberate limit, not an outage.
	cfg.FailOpen = boolPtr(true)

	const id = uint32(210)
	storeRequest(id)
	resp := newMockResponse(id, []byte(`{}`))
	(&ConsentFilter{}).ResponseFilter(cfg, resp)

	assert.Equal(t, DefaultDenyStatusCode, resp.writtenStatus,
		"more owners than the cap must deny without running the checks")
}

// TestResponseFilter_ResponsePhaseDeadline verifies the whole response phase is
// bounded: a consent-manager that never answers must not let APISIX hold the
// buffered response for per-call-timeout x owner-count.
func TestResponseFilter_ResponsePhaseDeadline(t *testing.T) {
	clearContextStore()

	// The consent-manager never answers, so the phase budget is the only thing
	// that can end the wait.
	release := make(chan struct{})
	mux := http.NewServeMux()
	registerParticipantEndpoints(mux)
	mux.HandleFunc("/", func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	server := httptest.NewServer(mux)
	// Releasing the handlers must happen BEFORE Close, which waits for them.
	defer server.Close()
	defer close(release)

	resolver := newOwnerResolver(t, ownedBy("did:key:zA", "did:key:zB", "did:key:zC"))
	defer resolver.Close()

	cfg := newTestConfig(server.URL, resolver.URL+"/resolve")
	cfg.ResponsePhaseTimeout = 150
	cfg.ConsentAPITimeout = 60000 // far beyond the phase budget, so the phase budget must win

	const id = uint32(211)
	storeRequest(id)
	resp := newMockResponse(id, []byte(`{}`))

	start := time.Now()
	(&ConsentFilter{}).ResponseFilter(cfg, resp)
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 5*time.Second, "the response phase must be bounded by response_phase_timeout")
	assert.Equal(t, DefaultDenyStatusCode, resp.writtenStatus, "a timed-out phase must fail closed by default")
}

// TestDistinctClaims verifies the resolver's claims collapse to the distinct
// consent questions that actually need checking, in resolver order, keyed on
// every match criterion after the config fallbacks.
func TestDistinctClaims(t *testing.T) {
	tests := []struct {
		name    string
		cfgFn   func(cfg *Config)
		claims  []ownerresolver.Claim
		want    []ownerClaim
		wantErr bool
	}{
		{
			name:   "duplicates collapse",
			claims: []ownerresolver.Claim{{OwnerID: "a"}, {OwnerID: "a"}, {OwnerID: "b"}},
			want:   []ownerClaim{{owner: "a"}, {owner: "b"}},
		},
		{
			name:   "same owner with different resources stays distinct",
			claims: []ownerresolver.Claim{{OwnerID: "a", DataResource: "r1"}, {OwnerID: "a", DataResource: "r2"}},
			want:   []ownerClaim{{owner: "a", dataResource: "r1"}, {owner: "a", dataResource: "r2"}},
		},
		{
			name:   "the purpose is carried through",
			claims: []ownerresolver.Claim{{OwnerID: "a", Purpose: "p1"}},
			want:   []ownerClaim{{owner: "a", purpose: "p1"}},
		},
		{
			// Collapsing these would check purpose A only and release the
			// response under deny_all even when purpose B has no grant.
			name:   "same owner and resource with different purposes stays distinct",
			claims: []ownerresolver.Claim{{OwnerID: "a", Purpose: "p1"}, {OwnerID: "a", Purpose: "p2"}},
			want:   []ownerClaim{{owner: "a", purpose: "p1"}, {owner: "a", purpose: "p2"}},
		},
		{
			name:   "no purpose and the config purpose collapse after the fallback",
			cfgFn:  func(cfg *Config) { cfg.Purpose = "p1" },
			claims: []ownerresolver.Claim{{OwnerID: "a"}, {OwnerID: "a", Purpose: "p1"}},
			want:   []ownerClaim{{owner: "a", purpose: "p1"}},
		},
		{
			name:   "the claim purpose wins over the config purpose",
			cfgFn:  func(cfg *Config) { cfg.Purpose = "p1" },
			claims: []ownerresolver.Claim{{OwnerID: "a", Purpose: "p2"}},
			want:   []ownerClaim{{owner: "a", purpose: "p2"}},
		},
		{
			name:   "different contracts stay distinct",
			claims: []ownerresolver.Claim{{OwnerID: "a", ContractURI: "c1"}, {OwnerID: "a", ContractURI: "c2"}},
			want:   []ownerClaim{{owner: "a", contractURI: "c1"}, {owner: "a", contractURI: "c2"}},
		},
		{
			name:   "the route notice id is the fallback and the claim's is lower-cased",
			cfgFn:  func(cfg *Config) { cfg.PrivacyNoticeID = testRouteNoticeID },
			claims: []ownerresolver.Claim{{OwnerID: "a"}, {OwnerID: "b", PrivacyNoticeID: strings.ToUpper(testClaimNoticeID)}},
			want: []ownerClaim{
				{owner: "a", privacyNoticeID: testRouteNoticeID},
				{owner: "b", privacyNoticeID: testClaimNoticeID},
			},
		},
		{
			name:    "a claim without an owner is an error",
			claims:  []ownerresolver.Claim{{OwnerID: "a"}, {OwnerID: ""}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := newTestConfig("http://consent.invalid", "http://resolver.invalid/resolve")
			if tt.cfgFn != nil {
				tt.cfgFn(cfg)
			}
			got, err := distinctClaims(cfg, tt.claims)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestDenyResponse_StripsUpstreamHeaders verifies the denial does not inherit the
// upstream's headers. A denied caller must not be told that the entity exists
// (ETag/Last-Modified), how many records matched (X-Total-Count), that more
// pages follow (Link), or be handed a session cookie — that is a side channel
// straight around the gate. Content-Length must also describe the deny body, not
// the upstream's.
func TestDenyResponse_StripsUpstreamHeaders(t *testing.T) {
	clearContextStore()
	server := newConsentManager(t, []string{"revoked"})
	defer server.Close()
	resolver := newOwnerResolver(t, ownedBy(testOwnerDID))
	defer resolver.Close()

	const id = uint32(220)
	storeRequest(id)

	resp := newMockResponse(id, []byte(`{"records":[1,2,3]}`))
	resp.header.Set("ETag", `"v7"`)
	resp.header.Set("Last-Modified", "Wed, 27 Aug 2026 10:00:00 GMT")
	resp.header.Set("Set-Cookie", "session=abc123")
	resp.header.Set("Link", `</items?page=2>; rel="next"`)
	resp.header.Set("X-Total-Count", "4210")
	resp.header.Set("NGSILD-Results-Count", "4210")
	resp.header.Set("Content-Encoding", "gzip")
	resp.header.Set("Content-Length", "19")
	resp.header.Set("Access-Control-Allow-Origin", "https://app.example.org")

	(&ConsentFilter{}).ResponseFilter(newTestConfig(server.URL, resolver.URL+"/resolve"), resp)

	require.Equal(t, DefaultDenyStatusCode, resp.writtenStatus)
	for _, leaked := range []string{"ETag", "Last-Modified", "Set-Cookie", "Link", "X-Total-Count", "NGSILD-Results-Count", "Content-Encoding"} {
		assert.Empty(t, resp.header.Get(leaked), "%s must not survive a denial", leaked)
	}
	assert.Equal(t, "https://app.example.org", resp.header.Get("Access-Control-Allow-Origin"),
		"CORS headers describe the exchange, not the data, and must survive so the client sees the 403")
	assert.Equal(t, DefaultDenyResponseContentType, resp.header.Get("Content-Type"))
	assert.Equal(t, strconv.Itoa(len(DefaultDenyResponseBody)), resp.header.Get("Content-Length"),
		"Content-Length must describe the deny body, not the upstream's")
	assert.Equal(t, DefaultDenyResponseBody, string(resp.writtenBody))
}

// TestRecordAudit_RecordsEveryCheckedOwner verifies the audit log answers whose
// consent was checked and what each said. Recording only the response outcome
// named no owner at all on an allow, and only the first refusal on a deny —
// which is not what an access-decision log is for.
func TestRecordAudit_RecordsEveryCheckedOwner(t *testing.T) {
	type record struct {
		subject, decision, consentID string
	}
	var mu sync.Mutex
	var got []record

	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			ResourceLogs []struct {
				ScopeLogs []struct {
					LogRecords []struct {
						Attributes []struct {
							Key   string `json:"key"`
							Value struct {
								StringValue string `json:"stringValue"`
							} `json:"value"`
						} `json:"attributes"`
					} `json:"logRecords"`
				} `json:"scopeLogs"`
			} `json:"resourceLogs"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("failed to decode OTLP payload: %v", err)
		}
		mu.Lock()
		for _, rl := range payload.ResourceLogs {
			for _, sl := range rl.ScopeLogs {
				for _, lr := range sl.LogRecords {
					var rec record
					for _, attr := range lr.Attributes {
						switch attr.Key {
						case "enduser.id":
							rec.subject = attr.Value.StringValue
						case "consent.decision":
							rec.decision = attr.Value.StringValue
						case "consent.id":
							rec.consentID = attr.Value.StringValue
						}
					}
					got = append(got, rec)
				}
			}
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	cfg := &Config{
		AuditEnabled:      true,
		AuditOTLPEndpoint: collector.URL,
		AuditServiceName:  "consent-access-audit-test",
		ConsentAPITimeout: DefaultConsentAPITimeout,
	}
	recordAudit(cfg, responseOutcome{
		decision:  decisionDeny,
		requestID: "req-1",
		method:    "GET",
		checked: []checkedOwner{
			{subject: "did:key:zA", resource: "/r", decision: decisionAllow, consentID: testConsentID},
			{subject: "did:key:zB", resource: "/r", decision: decisionDeny, reason: "no granted consent"},
		},
	})
	audit.ShutdownAll()

	mu.Lock()
	defer mu.Unlock()
	assert.ElementsMatch(t, []record{
		{subject: "did:key:zA", decision: decisionAllow, consentID: testConsentID},
		{subject: "did:key:zB", decision: decisionDeny},
	}, got, "every consulted owner must appear in the audit log, not only the one that denied")
}

// TestRecordAudit_RecordsOutcomeWhenNoOwnerReached verifies a request that
// failed before any owner was consulted still appears in the record.
func TestRecordAudit_RecordsOutcomeWhenNoOwnerReached(t *testing.T) {
	var mu sync.Mutex
	records := 0
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			ResourceLogs []struct {
				ScopeLogs []struct {
					LogRecords []json.RawMessage `json:"logRecords"`
				} `json:"scopeLogs"`
			} `json:"resourceLogs"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		mu.Lock()
		for _, rl := range payload.ResourceLogs {
			for _, sl := range rl.ScopeLogs {
				records += len(sl.LogRecords)
			}
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	cfg := &Config{
		AuditEnabled:      true,
		AuditOTLPEndpoint: collector.URL,
		AuditServiceName:  "consent-access-audit-no-owner",
		ConsentAPITimeout: DefaultConsentAPITimeout,
	}
	recordAudit(cfg, responseOutcome{decision: decisionDeny, requestID: "req-2", reason: "owner resolver error"})
	audit.ShutdownAll()

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, records, "a failure before any owner was reached must still be recorded")
}

// TestConsumerFromClaims covers the claim-path walk, including the array shapes
// a real Verifiable Presentation uses. An object-only walk returned "" on an
// ordinary VP token, which fed straight into the fail-closed party seam and made
// every such request deny for no visible reason.
func TestConsumerFromClaims(t *testing.T) {
	const issuer = "did:key:zIssuer"

	objectClaims := map[string]interface{}{
		"verifiableCredential": map[string]interface{}{"issuer": issuer},
	}
	arrayClaims := map[string]interface{}{
		"verifiableCredential": []interface{}{
			map[string]interface{}{"issuer": issuer},
			map[string]interface{}{"issuer": "did:key:zOther"},
		},
	}

	tests := []struct {
		name      string
		claims    map[string]interface{}
		path      string
		want      string
		wantErr   bool
		errSubstr string
	}{
		{name: "object shape", claims: objectClaims, path: "verifiableCredential.issuer", want: issuer},
		{name: "array shape traverses the first element", claims: arrayClaims, path: "verifiableCredential.issuer", want: issuer},
		{name: "explicit index", claims: arrayClaims, path: "verifiableCredential[0].issuer", want: issuer},
		{name: "explicit non-zero index", claims: arrayClaims, path: "verifiableCredential[1].issuer", want: "did:key:zOther"},
		{name: "single segment", claims: map[string]interface{}{"iss": issuer}, path: "iss", want: issuer},
		{
			name:   "nested arrays",
			claims: map[string]interface{}{"a": []interface{}{[]interface{}{map[string]interface{}{"b": issuer}}}},
			path:   "a[0][0].b",
			want:   issuer,
		},
		{
			name:   "unset path is reported as unconfigured",
			claims: objectClaims, path: "",
			wantErr: true, errSubstr: "not configured",
		},
		{
			name:   "no claims at all",
			claims: nil, path: "verifiableCredential.issuer",
			wantErr: true, errSubstr: "no claims decoded",
		},
		{
			name:   "missing claim names the segment",
			claims: objectClaims, path: "verifiableCredential.subject",
			wantErr: true, errSubstr: `no claim "subject"`,
		},
		{
			name:   "index out of range",
			claims: arrayClaims, path: "verifiableCredential[9].issuer",
			wantErr: true, errSubstr: "out of range",
		},
		{
			name:   "non-string leaf",
			claims: map[string]interface{}{"iss": float64(42)}, path: "iss",
			wantErr: true, errSubstr: "non-empty string",
		},
		{
			name:   "empty-string leaf",
			claims: map[string]interface{}{"iss": ""}, path: "iss",
			wantErr: true, errSubstr: "non-empty string",
		},
		{
			name:   "descending into a scalar",
			claims: map[string]interface{}{"iss": issuer}, path: "iss.nested",
			wantErr: true, errSubstr: "is not an object",
		},
		{
			name:   "empty array",
			claims: map[string]interface{}{"vc": []interface{}{}}, path: "vc.issuer",
			wantErr: true, errSubstr: "is not an object",
		},
		{
			name:   "unterminated index",
			claims: arrayClaims, path: "verifiableCredential[0.issuer",
			wantErr: true, errSubstr: "unterminated",
		},
		{
			name:   "non-numeric index",
			claims: arrayClaims, path: "verifiableCredential[first].issuer",
			wantErr: true, errSubstr: "not an array index",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := consumerFromClaims(tt.claims, tt.path)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
				assert.Empty(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestClaimPathRoot verifies the top-level claim the request phase must decode
// is found even when the path starts with an array index.
func TestClaimPathRoot(t *testing.T) {
	tests := []struct{ path, want string }{
		{"verifiableCredential.issuer", "verifiableCredential"},
		{"verifiableCredential[0].issuer", "verifiableCredential"},
		{"iss", "iss"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, claimPathRoot(tt.path))
		})
	}
}

// TestResponseFilter_AllowDoesNotTouchHeaders verifies an allowed response never
// calls Header(). The runner materialises its header map on the first call and
// then reports HasChange() == true, so merely reading the Content-Type sent
// every gated response back to APISIX down the "this response was modified"
// path with an empty header diff.
func TestResponseFilter_AllowDoesNotTouchHeaders(t *testing.T) {
	clearContextStore()
	server := newConsentManager(t, []string{"granted"})
	defer server.Close()
	resolver := newOwnerResolver(t, ownedBy(testOwnerDID))
	defer resolver.Close()

	const id = uint32(230)
	storeRequest(id)
	resp := newMockResponse(id, []byte(`{"id":"x"}`))

	(&ConsentFilter{}).ResponseFilter(newTestConfig(server.URL, resolver.URL+"/resolve"), resp)

	assert.Equal(t, 0, resp.writtenStatus, "the response should have been allowed")
	assert.Zero(t, resp.headerReads, "an allowed response must not materialise the header map")
}

// TestResponseContentType covers both sources: the Nginx variable, and the
// header fallback for a deployment where the variable is unavailable.
func TestResponseContentType(t *testing.T) {
	t.Run("prefers the nginx variable", func(t *testing.T) {
		resp := newMockResponse(240, nil)
		assert.Equal(t, responseContentTypeJSON, responseContentType(resp))
		assert.Zero(t, resp.headerReads, "the variable must be enough")
	})

	t.Run("falls back to the header", func(t *testing.T) {
		resp := newMockResponse(241, nil)
		resp.suppressContentTypeVar = true
		resp.header.Set("Content-Type", "application/ld+json")
		assert.Equal(t, "application/ld+json", responseContentType(resp))
		assert.Positive(t, resp.headerReads)
	})

	t.Run("reports nothing when neither source has it", func(t *testing.T) {
		resp := newMockResponse(242, nil)
		resp.suppressContentTypeVar = true
		resp.header.Del("Content-Type")
		assert.Empty(t, responseContentType(resp))
	})
}

// TestResponseFilter_BodyCapDenies verifies an oversized upstream body is denied
// rather than forwarded. The resolver call holds the body whole, validates it
// and marshals it again, so forwarding a large collection response multiplies
// the runner's memory on top of APISIX's own buffering.
func TestResponseFilter_BodyCapDenies(t *testing.T) {
	clearContextStore()

	server := newUncalledConsentManager(t)
	defer server.Close()
	resolver := newUncalledOwnerResolver(t)
	defer resolver.Close()

	cfg := newTestConfig(server.URL, resolver.URL+"/resolve")
	cfg.MaxResolveBodyBytes = 32
	// The cap is a deliberate limit, not an outage, so fail_open must not lift it.
	cfg.FailOpen = boolPtr(true)

	const id = uint32(250)
	storeRequest(id)
	resp := newMockResponse(id, []byte(`{"padding":"`+strings.Repeat("x", 64)+`"}`))

	(&ConsentFilter{}).ResponseFilter(cfg, resp)

	assert.Equal(t, DefaultDenyStatusCode, resp.writtenStatus,
		"a body too large to examine must be denied, not forwarded")
}

// TestResponseFilter_CorrelationIdMissingInOnerPhase verifies the case where the
// two phases cannot be correlated: the request phase stored nothing (or the
// response phase cannot read $request_id), so there is no context to decide on.
// The plugin is structurally unable to gate here, so it must deny even with
// fail_open — this is not an outage to ride out.
func TestResponseFilter_CorrelationIDMissingInOnePhase(t *testing.T) {
	server := newUncalledConsentManager(t)
	defer server.Close()
	resolver := newUncalledOwnerResolver(t)
	defer resolver.Close()

	cfg := newTestConfig(server.URL, resolver.URL+"/resolve")
	cfg.FailOpen = boolPtr(true)

	t.Run("response phase cannot read the correlation id", func(t *testing.T) {
		clearContextStore()
		resp := newMockResponse(260, []byte(`{}`))
		resp.suppressRequestIDVar = true
		storeRequest(260)

		(&ConsentFilter{}).ResponseFilter(cfg, resp)

		assert.Equal(t, DefaultDenyStatusCode, resp.writtenStatus,
			"without a correlation id the phases cannot be matched, so nothing can be verified")
	})

	t.Run("request phase never stored a context", func(t *testing.T) {
		clearContextStore()
		resp := newMockResponse(261, []byte(`{}`))

		(&ConsentFilter{}).ResponseFilter(cfg, resp)

		assert.Equal(t, DefaultDenyStatusCode, resp.writtenStatus,
			"a response whose request phase left no context must not be released")
	})
}

// mockRequest implements pkgHTTP.Request. correlationID is what Var() reports
// for $request_id; empty means the variable is unavailable.
type mockRequest struct {
	header        *mockHeader
	correlationID string
}

func (r *mockRequest) ID() uint32             { return 1 }
func (r *mockRequest) SrcIP() net.IP          { return net.ParseIP("127.0.0.1") }
func (r *mockRequest) Method() string         { return "GET" }
func (r *mockRequest) Path() []byte           { return []byte("/data") }
func (r *mockRequest) SetPath([]byte)         {}
func (r *mockRequest) Header() pkgHTTP.Header { return r.header }
func (r *mockRequest) Args() url.Values       { return nil }
func (r *mockRequest) Var(name string) ([]byte, error) {
	if name == nginxRequestIDVar && r.correlationID != "" {
		return []byte(r.correlationID), nil
	}
	return nil, nil
}
func (r *mockRequest) Body() ([]byte, error)    { return nil, nil }
func (r *mockRequest) Context() context.Context { return context.Background() }
func (r *mockRequest) RespHeader() http.Header  { return nil }

// TestRequestFilter_CorrelationID verifies the request phase stores a context
// only when it can be correlated with the response phase. Storing one it could
// never retrieve would leak an entry per request into the context store.
func TestRequestFilter_CorrelationID(t *testing.T) {
	cfg := newTestConfig("http://consent.invalid", "http://resolver.invalid/resolve")

	t.Run("no correlation id stores nothing", func(t *testing.T) {
		clearContextStore()
		req := &mockRequest{header: newMockHeader()}

		(&ConsentFilter{}).RequestFilter(cfg, httptest.NewRecorder(), req)

		assert.Equal(t, 0, RequestContextStoreSize(),
			"a context that could never be correlated must not be stored")
	})

	t.Run("a correlation id stores the context", func(t *testing.T) {
		clearContextStore()
		defer clearContextStore()
		req := &mockRequest{header: newMockHeader(), correlationID: "req-abc"}

		(&ConsentFilter{}).RequestFilter(cfg, httptest.NewRecorder(), req)

		stored, found := LoadAndDeleteRequestContext("req-abc")
		require.True(t, found)
		assert.Equal(t, "/data", stored.Path)
		assert.Equal(t, "GET", stored.Method)
	})
}

// TestReduceOwnerResults is the regression test for the ordering hole the
// concurrency work opened, exercised at the level where the ranking actually
// lives.
//
// Driving it through two concurrent HTTP checks turned out to be inherently
// racy: whichever owner finishes first cancels the other, so a sibling's deny
// can arrive as a cancellation instead — the test passed or failed on timing
// rather than on the property. Reducing scripted results is deterministic and
// pins the rule directly.
func TestReduceOwnerResults(t *testing.T) {
	reqCtx := &RequestContext{Method: "GET", Path: "/data"}

	denied := func(owner string) ownerCheckResult {
		return ownerCheckResult{
			attempted: true,
			problem:   true,
			outcome: responseOutcome{
				decision: decisionDeny, reason: "no granted consent", requestID: "req-1",
				subject: owner, resource: "/data", method: "GET",
			},
			record: checkedOwner{subject: owner, resource: "/data", decision: decisionDeny},
		}
	}
	allowed := func(owner string) ownerCheckResult {
		return ownerCheckResult{
			attempted: true,
			record:    checkedOwner{subject: owner, resource: "/data", decision: decisionAllow},
		}
	}
	errored := func(owner string, err error) ownerCheckResult {
		return ownerCheckResult{
			attempted: true,
			problem:   true,
			err:       err,
			request:   consent.ConsentRequest{Subject: owner, Resource: "/data", Method: "GET"},
		}
	}

	dependencyErr := errors.New("consent client: consents lookup returned status 500")

	tests := []struct {
		name         string
		failOpen     bool
		phaseErr     error
		results      []ownerCheckResult
		wantDecision string
		wantSubject  string
		wantChecked  int
	}{
		{
			name: "every owner allows", failOpen: false,
			results:      []ownerCheckResult{allowed("a"), allowed("b")},
			wantDecision: decisionAllow, wantChecked: 2,
		},
		{
			name: "one deny denies them all", failOpen: false,
			results:      []ownerCheckResult{allowed("a"), denied("b")},
			wantDecision: decisionDeny, wantSubject: "b", wantChecked: 2,
		},
		{
			// The finding: with fail_open the error path allows, so ranking the
			// error first releases data owner b has explicitly refused.
			name: "a deny at a higher index outranks an error at a lower one", failOpen: true,
			results:      []ownerCheckResult{errored("a", dependencyErr), denied("b")},
			wantDecision: decisionDeny, wantSubject: "b", wantChecked: 1,
		},
		{
			name: "a deny at a lower index still wins", failOpen: true,
			results:      []ownerCheckResult{denied("a"), errored("b", dependencyErr)},
			wantDecision: decisionDeny, wantSubject: "a", wantChecked: 1,
		},
		{
			name: "the lowest-indexed deny is reported", failOpen: false,
			results:      []ownerCheckResult{denied("a"), denied("b")},
			wantDecision: decisionDeny, wantSubject: "a", wantChecked: 2,
		},
		{
			name: "with no deny anywhere, fail-open allows on an error", failOpen: true,
			results:      []ownerCheckResult{allowed("a"), errored("b", dependencyErr)},
			wantDecision: decisionAllow, wantChecked: 1,
		},
		{
			name: "with no deny anywhere, fail-closed denies on an error", failOpen: false,
			results:      []ownerCheckResult{allowed("a"), errored("b", dependencyErr)},
			wantDecision: decisionDeny, wantChecked: 1,
		},
		{
			// A sibling deny cancels the rest; those cancellations are not
			// failures, and the deny that caused them is what gets reported.
			name: "a cancellation caused by a sibling deny is ignored", failOpen: true,
			results:      []ownerCheckResult{errored("a", context.Canceled), denied("b")},
			wantDecision: decisionDeny, wantSubject: "b", wantChecked: 1,
		},
		{
			// But a cancellation from the phase deadline IS a failure.
			name: "a cancellation from the phase deadline applies the fail policy", failOpen: false,
			phaseErr:     context.DeadlineExceeded,
			results:      []ownerCheckResult{errored("a", context.Canceled), allowed("b")},
			wantDecision: decisionDeny, wantChecked: 1,
		},
		{
			name: "owners whose check never started are ignored", failOpen: false,
			results:      []ownerCheckResult{allowed("a"), {}},
			wantDecision: decisionAllow, wantChecked: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{FailOpen: boolPtr(tt.failOpen)}

			got := reduceOwnerResults(cfg, "req-1", reqCtx, tt.phaseErr, tt.results)

			assert.Equal(t, tt.wantDecision, got.decision)
			if tt.wantSubject != "" {
				assert.Equal(t, tt.wantSubject, got.subject, "the reported owner must be the deciding one")
			}
			assert.Len(t, got.checked, tt.wantChecked,
				"every consulted owner must reach the audit log, and only those")
		})
	}
}

// TestCheckOwners_ErrorStillAppliesFailPolicy verifies the reordering did not
// swallow the error path: with no deny anywhere, a dependency error is still
// what decides, and fail_open still governs it.
func TestCheckOwners_ErrorStillAppliesFailPolicy(t *testing.T) {
	server := newFailingConsentManager()
	defer server.Close()
	resolver := newOwnerResolver(t, ownedBy(testOwnerDID))
	defer resolver.Close()

	tests := []struct {
		name       string
		failOpen   bool
		wantDenied bool
	}{
		{name: "fail-closed denies", failOpen: false, wantDenied: true},
		{name: "fail-open passes through", failOpen: true, wantDenied: false},
	}

	// Each case needs its own request id so the context-store entries cannot
	// collide between subtests.
	nextRequestID := uint32(280)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearContextStore()
			consent.ResetCaches()

			cfg := newTestConfig(server.URL, resolver.URL+"/resolve")
			cfg.FailOpen = boolPtr(tt.failOpen)

			nextRequestID++
			id := nextRequestID
			storeRequest(id)
			resp := newMockResponse(id, []byte(`{"id":"x"}`))

			(&ConsentFilter{}).ResponseFilter(cfg, resp)

			if tt.wantDenied {
				assert.Equal(t, DefaultDenyStatusCode, resp.writtenStatus)
				return
			}
			assert.Equal(t, 0, resp.writtenStatus, "a dependency error with fail_open must still pass through")
		})
	}
}

// TestCheckPurposeScoping covers what happens when the resolver names no
// processing purpose for a claim.
//
// Purpose matching depends on a different service populating an optional field,
// so a resolver whose rules stop emitting it silently disables half of the
// consumer/purpose scoping — a consent granted for one purpose then authorises
// release for any other. Without require_purpose that is counted and logged;
// with it, it denies.
func TestCheckPurposeScoping(t *testing.T) {
	tests := []struct {
		name             string
		requirePurpose   bool
		failOpen         bool
		claims           []ownerClaim
		wantOK           bool
		wantUnconstained int
	}{
		{
			name:   "every claim carries a purpose",
			claims: []ownerClaim{{owner: "a", purpose: "insurance-quote"}, {owner: "b", purpose: "insurance-quote"}},
			wantOK: true,
		},
		{
			name:             "a missing purpose is counted when not required",
			claims:           []ownerClaim{{owner: "a"}, {owner: "b", purpose: "research"}},
			wantOK:           true,
			wantUnconstained: 1,
		},
		{
			name:             "every unscoped claim is counted",
			claims:           []ownerClaim{{owner: "a"}, {owner: "b"}},
			wantOK:           true,
			wantUnconstained: 2,
		},
		{
			name:           "a missing purpose denies when required",
			requirePurpose: true,
			claims:         []ownerClaim{{owner: "a", purpose: "research"}, {owner: "b"}},
			wantOK:         false,
		},
		{
			// require_purpose is a policy the operator asked for, not an outage,
			// so fail_open must not lift it.
			name:           "require_purpose denies even with fail-open",
			requirePurpose: true,
			failOpen:       true,
			claims:         []ownerClaim{{owner: "a"}},
			wantOK:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics.Reset()
			t.Cleanup(metrics.Reset)
			logging.ResetSuppression()

			cfg := newTestConfig("http://consent.invalid", "http://resolver.invalid/resolve")
			cfg.RequirePurpose = tt.requirePurpose
			cfg.FailOpen = boolPtr(tt.failOpen)

			outcome, ok := checkPurposeScoping(cfg, "req-1", tt.claims)

			assert.Equal(t, tt.wantOK, ok)
			if !tt.wantOK {
				assert.Equal(t, decisionDeny, outcome.decision,
					"require_purpose is a policy, not an outage — fail_open must not lift it")
				return
			}
			assert.Contains(t, metricsExposition(), fmt.Sprintf("consent_purpose_unconstrained_total %d", tt.wantUnconstained))
		})
	}
}

// metricsExposition renders the current metrics for assertion.
func metricsExposition() string {
	recorder := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil))
	return recorder.Body.String()
}

// TestAuditReasonCarriesNoDependencyBody verifies a dependency's response body
// cannot reach the audit sink through the decision reason.
//
// Errors from the consent client become the reason, and the reason is exported.
// A consent-manager 500 that echoes the user's identifier in its body would
// therefore land in the audit record and on stdout — and truncating it, as an
// earlier version did, is not redaction: the surviving prefix of a JSON error
// body is usually exactly the part with the identifiers in it. The reason must
// be a stable classification instead.
func TestAuditReasonCarriesNoDependencyBody(t *testing.T) {
	clearContextStore()
	consent.ResetCaches()

	const leakedIdentifier = "alice@example.org"

	var mu sync.Mutex
	var reasons []string
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		reasons = append(reasons, string(body))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	mux := http.NewServeMux()
	registerParticipantEndpoints(mux)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		// A dependency echoing personal data in its error page.
		_, _ = w.Write([]byte(`{"error":"lookup failed for ` + leakedIdentifier + `","trace":"..."}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	resolver := newOwnerResolver(t, ownedBy(testOwnerDID))
	defer resolver.Close()

	cfg := newTestConfig(server.URL, resolver.URL+"/resolve")
	cfg.AuditEnabled = true
	cfg.AuditOTLPEndpoint = collector.URL
	cfg.AuditServiceName = "consent-access-audit-leak-test"

	const id = uint32(290)
	storeRequest(id)
	(&ConsentFilter{}).ResponseFilter(cfg, newMockResponse(id, []byte(`{"id":"x"}`)))
	audit.ShutdownAll()

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, reasons, "the decision should have been audited")
	for _, payload := range reasons {
		assert.NotContains(t, payload, leakedIdentifier,
			"a dependency response body must not reach the audit sink through the reason")
	}
	assert.Contains(t, strings.Join(reasons, ""), "consents list returned status 500",
		"the reason should classify the failure instead")
}

// TestFailModeForError pins which dependency errors fail_open may never release on.
func TestFailModeForError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want failMode
	}{
		{"no credentials", consent.ErrNoCredentials, failAlwaysClosed},
		{"participant not registered", fmt.Errorf("wrapped: %w", consent.ErrParticipantNotRegistered), failAlwaysClosed},
		{"consent-manager auth", fmt.Errorf("wrapped: %w", consent.ErrConsentManagerAuth), failAlwaysClosed},
		{"consent-manager rejected", fmt.Errorf("wrapped: %w", consent.ErrConsentManagerRejected), failAlwaysClosed},
		{"outage", errors.New("consent client: participants lookup returned status 503"), failByPolicy},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, failModeForError(tt.err))
		})
	}
}

// --- dsc-consent-manager modes ---

// Fixed UUIDs for the mode tests.
const (
	testClaimNoticeID = "3f1e2d4c-5b6a-4789-8abc-def012345678"
	testRouteNoticeID = "9a8b7c6d-5e4f-4321-8fed-cba987654321"
	testConsentID     = "0f0e0d0c-0b0a-4908-8706-050403020100"
	testContractURI   = "https://contracts.example/c1"
)

// consentScript drives scriptedConsentManager. A zero status answers 200.
type consentScript struct {
	listStatus  int
	listRecords []map[string]interface{}
	checkStatus int
	validity    map[string]interface{}
	readRecord  map[string]interface{}
	delay       time.Duration
}

// consentCall is one request scriptedConsentManager received on a consent endpoint.
type consentCall struct {
	path  string
	query url.Values
}

// scriptedConsentManager serves the dsc-consent-manager consent endpoints from a
// script and records every consent call, so tests can assert which mode ran.
type scriptedConsentManager struct {
	*httptest.Server
	mu    sync.Mutex
	calls []consentCall
}

// newScriptedConsentManager starts a scriptedConsentManager. The participant
// endpoints always answer, so failures under test come from the consent calls.
func newScriptedConsentManager(script consentScript) *scriptedConsentManager {
	m := &scriptedConsentManager{}
	mux := http.NewServeMux()
	registerParticipantEndpoints(mux)
	mux.HandleFunc("/v1/consents", func(w http.ResponseWriter, r *http.Request) {
		if !m.record(w, r, script.delay, script.listStatus) {
			return
		}
		writeJSON(w, map[string]interface{}{
			"content": script.listRecords, "page": 0, "size": len(script.listRecords),
			"totalElements": len(script.listRecords), "totalPages": 1,
		})
	})
	mux.HandleFunc("/v1/consents/check", func(w http.ResponseWriter, r *http.Request) {
		if m.record(w, r, script.delay, script.checkStatus) {
			writeJSON(w, script.validity)
		}
	})
	mux.HandleFunc("/v1/consents/{id}", func(w http.ResponseWriter, r *http.Request) {
		if m.record(w, r, script.delay, 0) {
			writeJSON(w, script.readRecord)
		}
	})
	m.Server = httptest.NewServer(mux)
	return m
}

// record logs the call, waits delay (or until the client gives up) and writes a
// non-zero status. It reports whether the handler should still write a body.
func (m *scriptedConsentManager) record(w http.ResponseWriter, r *http.Request, delay time.Duration, status int) bool {
	m.mu.Lock()
	m.calls = append(m.calls, consentCall{path: r.URL.Path, query: r.URL.Query()})
	m.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return false
		}
	}
	if status != 0 {
		w.WriteHeader(status)
		return false
	}
	return true
}

// recordedCalls returns the consent calls received so far.
func (m *scriptedConsentManager) recordedCalls() []consentCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]consentCall(nil), m.calls...)
}

// writeJSON writes v as a JSON 200 response.
func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// grant builds a consented record for testOwnerDID's consent to testConsumerDID,
// with the optional scope fields set from fields.
func grant(fields map[string]interface{}) map[string]interface{} {
	record := map[string]interface{}{
		"id": testConsentID, "status": "GRANTED", "consented": true,
		"provider": testProviderDID, "consumer": testConsumerDID,
	}
	for k, v := range fields {
		record[k] = v
	}
	return record
}

// runResponseFilter resolves claims with a mock resolver, runs the response phase
// against server and returns the mock response.
func runResponseFilter(t *testing.T, serverURL string, claims []resolverClaim, cfgFn func(cfg *Config)) *mockResponse {
	t.Helper()
	clearContextStore()
	consent.ResetCaches()
	resolver := newOwnerResolver(t, resolverResponse{ConsentRequired: true, Claims: claims})
	t.Cleanup(resolver.Close)

	cfg := newTestConfig(serverURL, resolver.URL+"/resolve")
	cfg.CheckMode = DefaultCheckMode
	if cfgFn != nil {
		cfgFn(cfg)
	}
	const id = uint32(300)
	storeRequest(id)
	resp := newMockResponse(id, []byte(`{"id":"x"}`))
	(&ConsentFilter{}).ResponseFilter(cfg, resp)
	return resp
}

// TestResponseFilter_ModeSelection verifies check_mode alone picks the endpoint,
// that list mode sends the effective notice id as a filter, and that check mode
// without a notice id denies without calling the consent-manager.
func TestResponseFilter_ModeSelection(t *testing.T) {
	listGrant := func(notice string) consentScript {
		return consentScript{listRecords: []map[string]interface{}{grant(map[string]interface{}{"privacyNoticeId": notice})}}
	}
	checkGrant := consentScript{
		validity:   map[string]interface{}{"valid": true, "consentId": testConsentID},
		readRecord: grant(map[string]interface{}{"privacyNoticeId": testClaimNoticeID}),
	}
	tests := []struct {
		name       string
		script     consentScript
		claim      resolverClaim
		cfgFn      func(cfg *Config)
		wantPaths  []string
		wantNotice string
		wantDenied bool
	}{
		{
			name:      "unset check_mode is list mode",
			script:    listGrant(""),
			claim:     resolverClaim{OwnerID: testOwnerDID},
			cfgFn:     func(cfg *Config) { cfg.CheckMode = "" },
			wantPaths: []string{"/v1/consents"},
		},
		{
			name:      "default list mode without a notice id sends no filter",
			script:    listGrant(""),
			claim:     resolverClaim{OwnerID: testOwnerDID},
			wantPaths: []string{"/v1/consents"},
		},
		{
			name:       "a claim notice id is a list filter and does not switch to check",
			script:     listGrant(testClaimNoticeID),
			claim:      resolverClaim{OwnerID: testOwnerDID, PrivacyNoticeID: testClaimNoticeID},
			wantPaths:  []string{"/v1/consents"},
			wantNotice: testClaimNoticeID,
		},
		{
			name:       "the route notice id is a list filter",
			script:     listGrant(testRouteNoticeID),
			claim:      resolverClaim{OwnerID: testOwnerDID},
			cfgFn:      func(cfg *Config) { cfg.PrivacyNoticeID = testRouteNoticeID },
			wantPaths:  []string{"/v1/consents"},
			wantNotice: testRouteNoticeID,
		},
		{
			name:       "forced check mode checks and then reads the consent",
			script:     checkGrant,
			claim:      resolverClaim{OwnerID: testOwnerDID, PrivacyNoticeID: testClaimNoticeID},
			cfgFn:      func(cfg *Config) { cfg.CheckMode = CheckModeCheck },
			wantPaths:  []string{"/v1/consents/check", "/v1/consents/" + testConsentID},
			wantNotice: testClaimNoticeID,
		},
		{
			// The check cannot be made at all, so fail_open must not release it.
			name:   "forced check mode without a notice id denies even with fail-open",
			script: checkGrant,
			claim:  resolverClaim{OwnerID: testOwnerDID},
			cfgFn: func(cfg *Config) {
				cfg.CheckMode = CheckModeCheck
				cfg.FailOpen = boolPtr(true)
			},
			wantDenied: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newScriptedConsentManager(tt.script)
			defer server.Close()

			resp := runResponseFilter(t, server.URL, []resolverClaim{tt.claim}, tt.cfgFn)

			calls := server.recordedCalls()
			paths := make([]string, 0, len(calls))
			for _, call := range calls {
				paths = append(paths, call.path)
			}
			assert.Equal(t, tt.wantPaths, slicesOrNil(paths))
			if tt.wantDenied {
				assert.Equal(t, DefaultDenyStatusCode, resp.writtenStatus)
				return
			}
			assert.Equal(t, 0, resp.writtenStatus, "a matching consent must pass the response through")
			require.NotEmpty(t, calls)
			assert.Equal(t, tt.wantNotice, calls[0].query.Get("privacyNoticeId"))
		})
	}
}

// slicesOrNil maps an empty slice to nil so it compares equal to an unset want.
func slicesOrNil(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

// TestResponseFilter_PurposeScoping verifies the effective purpose (claim, else
// config) is what a consent must cover, and what require_purpose checks.
func TestResponseFilter_PurposeScoping(t *testing.T) {
	const (
		claimPurpose  = "Trip planning"
		configPurpose = "Route optimisation"
	)
	tests := []struct {
		name           string
		grantPurposes  []string
		claims         []resolverClaim
		configPurpose  string
		requirePurpose bool
		wantDenied     bool
	}{
		{
			name:           "the config purpose satisfies require_purpose and must be granted",
			grantPurposes:  []string{configPurpose},
			claims:         []resolverClaim{{OwnerID: testOwnerDID}},
			configPurpose:  configPurpose,
			requirePurpose: true,
		},
		{
			name:           "no purpose anywhere denies under require_purpose",
			grantPurposes:  []string{configPurpose},
			claims:         []resolverClaim{{OwnerID: testOwnerDID}},
			requirePurpose: true,
			wantDenied:     true,
		},
		{
			name:          "the claim purpose wins over the config purpose",
			grantPurposes: []string{configPurpose},
			claims:        []resolverClaim{{OwnerID: testOwnerDID, Purpose: claimPurpose}},
			configPurpose: configPurpose,
			wantDenied:    true,
		},
		{
			name:          "a grant for one of two purposes denies the response (deny_all)",
			grantPurposes: []string{claimPurpose},
			claims: []resolverClaim{
				{OwnerID: testOwnerDID, Purpose: claimPurpose},
				{OwnerID: testOwnerDID, Purpose: configPurpose},
			},
			wantDenied: true,
		},
		{
			name:          "grants for both purposes allow",
			grantPurposes: []string{claimPurpose, configPurpose},
			claims: []resolverClaim{
				{OwnerID: testOwnerDID, Purpose: claimPurpose},
				{OwnerID: testOwnerDID, Purpose: configPurpose},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newScriptedConsentManager(consentScript{
				listRecords: []map[string]interface{}{grant(map[string]interface{}{"purposes": tt.grantPurposes})},
			})
			defer server.Close()

			resp := runResponseFilter(t, server.URL, tt.claims, func(cfg *Config) {
				cfg.Purpose = tt.configPurpose
				cfg.RequirePurpose = tt.requirePurpose
			})

			if tt.wantDenied {
				assert.Equal(t, DefaultDenyStatusCode, resp.writtenStatus)
				return
			}
			assert.Equal(t, 0, resp.writtenStatus)
		})
	}
}

// TestResponseFilter_DistinctClaimsCheckOnce verifies a claim without a purpose
// and one naming the config purpose are one consent question, not two.
func TestResponseFilter_DistinctClaimsCheckOnce(t *testing.T) {
	const purpose = "Trip planning"
	server := newScriptedConsentManager(consentScript{
		listRecords: []map[string]interface{}{grant(map[string]interface{}{"purposes": []string{purpose}})},
	})
	defer server.Close()

	resp := runResponseFilter(t, server.URL,
		[]resolverClaim{{OwnerID: testOwnerDID}, {OwnerID: testOwnerDID, Purpose: purpose}},
		func(cfg *Config) { cfg.Purpose = purpose })

	assert.Equal(t, 0, resp.writtenStatus)
	assert.Len(t, server.recordedCalls(), 1)
}

// TestResponseFilter_ContractScoping verifies an unscoped claim is counted and
// checked, or denied under require_contract whatever the fail policy, and that a
// claim contractUri, claim notice id or route privacy_notice_id each scope it.
func TestResponseFilter_ContractScoping(t *testing.T) {
	scopedGrant := grant(map[string]interface{}{"contractUri": testContractURI, "privacyNoticeId": testClaimNoticeID})
	routeGrant := grant(map[string]interface{}{"privacyNoticeId": testRouteNoticeID})
	tests := []struct {
		name            string
		claim           resolverClaim
		record          map[string]interface{}
		routeNotice     string
		requireContract bool
		wantDenied      bool
		wantCalls       int
		wantUnscoped    int
	}{
		{
			name:         "an unscoped claim is checked and counted",
			claim:        resolverClaim{OwnerID: testOwnerDID},
			record:       scopedGrant,
			wantCalls:    1,
			wantUnscoped: 1,
		},
		{
			name:            "an unscoped claim denies under require_contract even with fail-open",
			claim:           resolverClaim{OwnerID: testOwnerDID},
			record:          scopedGrant,
			requireContract: true,
			wantDenied:      true,
		},
		{
			name:            "a claim contractUri scopes it",
			claim:           resolverClaim{OwnerID: testOwnerDID, ContractURI: testContractURI},
			record:          scopedGrant,
			requireContract: true,
			wantCalls:       1,
		},
		{
			name:            "a claim notice id scopes it",
			claim:           resolverClaim{OwnerID: testOwnerDID, PrivacyNoticeID: testClaimNoticeID},
			record:          scopedGrant,
			requireContract: true,
			wantCalls:       1,
		},
		{
			name:            "the route privacy_notice_id scopes it",
			claim:           resolverClaim{OwnerID: testOwnerDID},
			record:          routeGrant,
			routeNotice:     testRouteNoticeID,
			requireContract: true,
			wantCalls:       1,
		},
		{
			name:            "a consent under another contract denies",
			claim:           resolverClaim{OwnerID: testOwnerDID, ContractURI: "https://contracts.example/other"},
			record:          scopedGrant,
			requireContract: true,
			wantDenied:      true,
			wantCalls:       1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics.Reset()
			t.Cleanup(metrics.Reset)
			server := newScriptedConsentManager(consentScript{listRecords: []map[string]interface{}{tt.record}})
			defer server.Close()

			resp := runResponseFilter(t, server.URL, []resolverClaim{tt.claim}, func(cfg *Config) {
				cfg.PrivacyNoticeID = tt.routeNotice
				cfg.RequireContract = tt.requireContract
				cfg.FailOpen = boolPtr(true)
			})

			assert.Len(t, server.recordedCalls(), tt.wantCalls)
			assert.Contains(t, metricsExposition(), fmt.Sprintf("consent_contract_unconstrained_total %d", tt.wantUnscoped))
			if tt.wantDenied {
				assert.Equal(t, DefaultDenyStatusCode, resp.writtenStatus)
				return
			}
			assert.Equal(t, 0, resp.writtenStatus)
		})
	}
}

// TestResponseFilter_FailureMapping pins the consent-manager failure mapping end
// to end: a definite deny and every permanent rejection deny whatever the fail
// policy, while a retryable failure follows fail_open.
func TestResponseFilter_FailureMapping(t *testing.T) {
	// consentTimeoutMs is the per-call budget the slow cases overrun.
	const consentTimeoutMs = 50
	slowDelay := 20 * consentTimeoutMs * time.Millisecond

	tests := []struct {
		name     string
		script   consentScript
		check    bool
		failOpen bool
		wantPass bool
	}{
		{name: "no matching consent", script: consentScript{listRecords: []map[string]interface{}{grant(map[string]interface{}{"consumer": "did:key:zOther"})}}, failOpen: true},
		{name: "valid:false", script: consentScript{validity: map[string]interface{}{"valid": false, "reason": "revoked"}}, check: true, failOpen: true},
		{name: "401", script: consentScript{listStatus: http.StatusUnauthorized}, failOpen: true},
		{name: "403", script: consentScript{listStatus: http.StatusForbidden}, failOpen: true},
		{name: "400", script: consentScript{listStatus: http.StatusBadRequest}, failOpen: true},
		{name: "404 on the list", script: consentScript{listStatus: http.StatusNotFound}, failOpen: true},
		{name: "403 on check", script: consentScript{checkStatus: http.StatusForbidden}, check: true, failOpen: true},
		{name: "429 fail-closed", script: consentScript{listStatus: http.StatusTooManyRequests}},
		{name: "429 fail-open", script: consentScript{listStatus: http.StatusTooManyRequests}, failOpen: true, wantPass: true},
		{name: "5xx fail-closed", script: consentScript{listStatus: http.StatusBadGateway}},
		{name: "5xx fail-open", script: consentScript{listStatus: http.StatusServiceUnavailable}, failOpen: true, wantPass: true},
		{name: "5xx on check fail-open", script: consentScript{checkStatus: http.StatusInternalServerError}, check: true, failOpen: true, wantPass: true},
		{name: "timeout fail-closed", script: consentScript{delay: slowDelay}},
		{name: "timeout fail-open", script: consentScript{delay: slowDelay}, failOpen: true, wantPass: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newScriptedConsentManager(tt.script)
			defer server.Close()

			resp := runResponseFilter(t, server.URL,
				[]resolverClaim{{OwnerID: testOwnerDID, PrivacyNoticeID: testClaimNoticeID}},
				func(cfg *Config) {
					cfg.FailOpen = boolPtr(tt.failOpen)
					cfg.ConsentAPITimeout = consentTimeoutMs
					if tt.check {
						cfg.CheckMode = CheckModeCheck
					}
				})

			require.NotEmpty(t, server.recordedCalls(), "the failure must come from a consent call")
			if tt.wantPass {
				assert.Equal(t, 0, resp.writtenStatus)
				return
			}
			assert.Equal(t, DefaultDenyStatusCode, resp.writtenStatus)
		})
	}
}
