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
// consent-filter plugin. Each test starts a stateful dsc-consent-manager fake
// and a mock OwnerResolver, creates a real plugin instance pointing at them,
// and simulates the full RequestFilter → ResponseFilter lifecycle.
package integration

import (
	"consent-plugin/internal/consent"
	"consent-plugin/internal/plugin"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

// --- dsc-consent-manager fake ---

// Identities of the parties in the test scenario.
const (
	// itestConsumerDID is the consuming participant named in the access token.
	itestConsumerDID = "did:key:zConsumer"
	// itestConsumerSD is the self-description URI the registry maps itestConsumerDID
	// to. Only the resolver sees it, because consents name the DID.
	itestConsumerSD = "http://catalog/participants/consumer"
	// itestProviderDID is the identifier /participants/me reports for this participant.
	itestProviderDID = "did:key:zProvider"
	// itestProviderSD is this participant's self-description URI.
	itestProviderSD = "http://consent-facade:8080/participants/org-itest"
	// itestOtherConsumerDID is a consumer the requests never come from.
	itestOtherConsumerDID = "did:key:zOtherConsumer"
	// itestOtherProviderDID is a provider other than this participant.
	itestOtherProviderDID = "did:key:zOtherProvider"
	// itestNoticeID is the privacy notice every granted consent is given under.
	itestNoticeID = "3f2a6c1e-0b7d-4c8e-9a51-2d4e6f708192"
	// itestCaller is the token's sub, which must never be taken as the data owner.
	itestCaller = "did:key:zCaller"
	// itestPurpose is the route-level purpose a consent must list to be matched.
	itestPurpose = "Provide the trip history to the consumer"
	// itestOtherPurpose is a purpose the route never asks for.
	itestOtherPurpose = "Marketing"
)

// Wire values of the fake.
const (
	itestStaticToken  = "itest-participant-token"
	itestFetchedToken = "itest-token"
	tokenServicePath  = "/internal/tokens"
	consentStatusOK   = "GRANTED"
	consentRevoked    = "REVOKED"
	// legacyConsentKeyHeader is the Visions consent key the plugin must no longer send.
	legacyConsentKeyHeader = "x-visionstrust-consent-key"
	// consentIDFmt renders the fake's sequence number as a UUID.
	consentIDFmt = "00000000-0000-4000-8000-%012d"
	// noticeCategory is the personal-data category a notice copies into data[].
	noticeCategory = "Trip records"
)

// itestRegistry is the participant registry: DID -> self-description URI.
var itestRegistry = map[string]string{
	itestConsumerDID: itestConsumerSD,
	itestProviderDID: itestProviderSD,
}

// dscConsent is one consent held by the fake.
type dscConsent struct {
	id, subject, noticeID, provider, consumer, status string
	purposes                                          []string
}

// visible reports whether the caller (always this participant) is a party to c,
// which is how the real server scopes every consent answer.
func (c *dscConsent) visible() bool {
	return c.provider == itestProviderDID || c.consumer == itestProviderDID
}

// record renders c as a dsc-consent-manager ConsentResponse.
func (c *dscConsent) record() map[string]interface{} {
	return map[string]interface{}{
		"id":              c.id,
		"privacyNoticeId": c.noticeID,
		"status":          c.status,
		"consented":       c.status == consentStatusOK,
		"provider":        c.provider,
		"consumer":        c.consumer,
		"purposes":        c.purposes,
		"data":            []string{noticeCategory},
	}
}

// consentOption adjusts a consent before the fake stores it.
type consentOption func(*dscConsent)

// toConsumer names did as the consent's consumer.
func toConsumer(did string) consentOption { return func(c *dscConsent) { c.consumer = did } }

// fromProvider names did as the consent's provider.
func fromProvider(did string) consentOption { return func(c *dscConsent) { c.provider = did } }

// withPurposes sets the purposes the consent was given for.
func withPurposes(purposes ...string) consentOption {
	return func(c *dscConsent) { c.purposes = purposes }
}

// dscConsentManager is a stateful fake of dsc-consent-manager /v1 whose consent
// set tests mutate between plugin cycles. Every request it serves is checked
// for the bearer token and for the absence of Visions-era headers.
type dscConsentManager struct {
	*httptest.Server
	t        *testing.T
	wantAuth string

	mu         sync.Mutex
	consents   []*dscConsent
	asked      []string
	failStatus int
}

// newDSCConsentManager starts the fake for a static participant token.
func newDSCConsentManager(t *testing.T) *dscConsentManager {
	return startDSCConsentManager(t, itestStaticToken, false)
}

// newDSCConsentManagerWithTokenService starts the fake with the consent-facade
// token service served on the same address.
func newDSCConsentManagerWithTokenService(t *testing.T) *dscConsentManager {
	return startDSCConsentManager(t, itestFetchedToken, true)
}

func startDSCConsentManager(t *testing.T, token string, tokenService bool) *dscConsentManager {
	t.Helper()
	m := &dscConsentManager{t: t, wantAuth: "Bearer " + token}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/participants", m.serveRegistry)
	mux.HandleFunc("GET /v1/participants/me", m.serveMe)
	mux.HandleFunc("GET /v1/consents", m.serveList)
	mux.HandleFunc("GET /v1/consents/check", m.serveCheck)
	mux.HandleFunc("GET /v1/consents/{id}", m.serveRead)
	if tokenService {
		mux.HandleFunc("POST "+tokenServicePath, m.serveToken)
	}
	m.Server = httptest.NewServer(m.checkProtocol(mux))
	t.Cleanup(m.Close)
	return m
}

// checkProtocol asserts what every request must (not) carry: the bearer token
// on the API, no Visions consent key and no Host rewrite.
func (m *dscConsentManager) checkProtocol(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			assert.Equal(m.t, m.wantAuth, r.Header.Get("Authorization"), "%s must carry the participant token", r.URL.Path)
		}
		assert.Empty(m.t, r.Header.Get(legacyConsentKeyHeader), "%s must not carry the Visions consent key", r.URL.Path)
		assert.Equal(m.t, m.Listener.Addr().String(), r.Host, "%s must not override Host", r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// grant stores a GRANTED consent of subject under itestNoticeID, from this
// participant to itestConsumerDID unless opts say otherwise, and returns its id.
func (m *dscConsentManager) grant(subject string, opts ...consentOption) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := &dscConsent{
		id:       fmt.Sprintf(consentIDFmt, len(m.consents)+1),
		subject:  subject,
		noticeID: itestNoticeID,
		provider: itestProviderDID,
		consumer: itestConsumerDID,
		status:   consentStatusOK,
	}
	for _, opt := range opts {
		opt(c)
	}
	m.consents = append(m.consents, c)
	return c.id
}

// revoke marks the consent id as REVOKED.
func (m *dscConsentManager) revoke(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.consents {
		if c.id == id {
			c.status = consentRevoked
			return
		}
	}
	m.t.Fatalf("revoke: unknown consent %s", id)
}

// failWith makes every consent endpoint answer status; the registry keeps working.
func (m *dscConsentManager) failWith(status int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failStatus = status
}

// askedSubjects returns the userIdentifiers the consent endpoints were asked about.
func (m *dscConsentManager) askedSubjects() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.asked)
}

// begin records subject and reports false once it has written the configured failure.
func (m *dscConsentManager) begin(w http.ResponseWriter, subject string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if subject != "" {
		m.asked = append(m.asked, subject)
	}
	if m.failStatus != 0 {
		w.WriteHeader(m.failStatus)
		return false
	}
	return true
}

func (m *dscConsentManager) serveRegistry(w http.ResponseWriter, r *http.Request) {
	content := []map[string]string{}
	did := r.URL.Query().Get("identifier")
	if sd, ok := itestRegistry[did]; ok {
		content = append(content, map[string]string{"identifier": did, "selfDescriptionUri": sd})
	}
	writeJSON(w, map[string]interface{}{"content": content})
}

func (m *dscConsentManager) serveMe(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]string{"identifier": itestProviderDID, "selfDescriptionUri": itestProviderSD})
}

func (m *dscConsentManager) serveToken(w http.ResponseWriter, r *http.Request) {
	var b map[string]string
	_ = json.NewDecoder(r.Body).Decode(&b)
	assert.Equal(m.t, plugin.DefaultTokenAudience, b["audience"])
	writeJSON(w, map[string]interface{}{"access_token": itestFetchedToken, "token_type": "Bearer", "expires_in": 3600})
}

// serveList answers GET /consents with the caller-visible consents of the
// subject, filtered by status (default GRANTED) and, when given, the notice.
func (m *dscConsentManager) serveList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	subject := q.Get("userIdentifier")
	if !m.begin(w, subject) {
		return
	}
	status := q.Get("status")
	if status == "" {
		status = consentStatusOK
	}
	notice := q.Get("privacyNoticeId")

	m.mu.Lock()
	records := []map[string]interface{}{}
	for _, c := range m.consents {
		if c.subject == subject && c.status == status && (notice == "" || c.noticeID == notice) && c.visible() {
			records = append(records, c.record())
		}
	}
	m.mu.Unlock()
	writeJSON(w, map[string]interface{}{
		"content": records, "page": 0, "size": len(records), "totalElements": len(records), "totalPages": 1,
	})
}

// serveCheck answers GET /consents/check. Like the real endpoint, it says
// nothing about the consumer, so a valid answer alone must not release data.
func (m *dscConsentManager) serveCheck(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	subject := q.Get("userIdentifier")
	if !m.begin(w, subject) {
		return
	}
	notice, purpose := q.Get("privacyNoticeId"), q.Get("purpose")
	if notice == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	validity := map[string]interface{}{"valid": false, "reason": "no consent in force"}
	for _, c := range m.consents {
		if c.subject == subject && c.noticeID == notice && c.status == consentStatusOK && c.visible() &&
			(purpose == "" || slices.Contains(c.purposes, purpose)) {
			validity = map[string]interface{}{"valid": true, "consentId": c.id, "status": c.status}
			break
		}
	}
	m.mu.Unlock()
	writeJSON(w, validity)
}

// serveRead answers GET /consents/{id}, with 404 when the caller is no party.
func (m *dscConsentManager) serveRead(w http.ResponseWriter, r *http.Request) {
	if !m.begin(w, "") {
		return
	}
	assert.Equal(m.t, "full", r.URL.Query().Get("format"), "the consent read must ask for the full record")
	id := r.PathValue("id")

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.consents {
		if c.id == id && c.visible() {
			writeJSON(w, c.record())
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
}

// writeJSON encodes v as the JSON response body.
func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// --- OwnerResolver mock (the source of data ownership) ---

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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env resolveEnvelope
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			t.Errorf("failed to decode resolve request: %v", err)
		}
		mu.Lock()
		*received = append(*received, env)
		mu.Unlock()
		writeJSON(w, reply)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newOwnerResolver starts a mock OwnerResolver that reports the given data
// owners for every payload.
func newOwnerResolver(t *testing.T, owners ...string) *httptest.Server {
	t.Helper()
	var received []resolveEnvelope
	return newRecordingOwnerResolver(t, resolveReply(owners...), &received)
}

// resolveReply builds a /resolve reply requiring consent from the given owners.
func resolveReply(owners ...string) map[string]interface{} {
	claims := make([]map[string]string, 0, len(owners))
	for _, o := range owners {
		claims = append(claims, map[string]string{"ownerId": o})
	}
	return map[string]interface{}{"consentRequired": true, "claims": claims}
}

// --- Plugin configuration and lifecycle ---

// checkModes are the consent lookup modes every scenario runs in. Check mode
// needs a notice id, which the route supplies here.
var checkModes = []struct {
	mode   string
	config map[string]interface{}
}{
	{mode: plugin.CheckModeList, config: map[string]interface{}{"check_mode": plugin.CheckModeList}},
	{mode: plugin.CheckModeCheck, config: map[string]interface{}{
		"check_mode": plugin.CheckModeCheck, "privacy_notice_id": itestNoticeID,
	}},
}

// baseConfig returns the minimal valid plugin configuration with a static
// participant token, plus the given overrides.
func baseConfig(consentURL, resolverURL string, overrides ...map[string]interface{}) map[string]interface{} {
	cfg := map[string]interface{}{
		"consent_api_url":    consentURL,
		"owner_resolver_url": resolverURL + "/resolve",
		"participant_token":  itestStaticToken,
		"provider_sd":        itestProviderSD,
	}
	for _, o := range overrides {
		maps.Copy(cfg, o)
	}
	return cfg
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

// lastRequestID hands out request ids, so context-store entries never collide.
var lastRequestID atomic.Uint32

// nextRequestID returns a request id no other cycle in this package uses.
func nextRequestID() uint32 { return lastRequestID.Add(1) }

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

	conf, err := p.ParseConf(configJSON)
	require.NoError(t, err, "ParseConf should succeed")

	// The plugin is not expected to write during the request phase.
	p.RequestFilter(conf, httptest.NewRecorder(), req)

	respHeader := newMockResponseHeader()
	respHeader.Set("Content-Type", responseContentTypeJSON)
	resp := &mockResponse{
		id:     req.id,
		header: respHeader,
		body:   responseBody,
	}

	p.ResponseFilter(conf, resp)

	return resp
}

// consentRequest builds a GET request for a personal-data entity from
// itestConsumerDID. The token's "sub" is itestCaller, which never determines the
// data owner; the OwnerResolver does, from the response payload.
func consentRequest() *mockRequest {
	return consentRequestFrom(itestConsumerDID)
}

// consentRequestFrom is consentRequest with consumer as the credential issuer.
func consentRequestFrom(consumer string) *mockRequest {
	h := newMockRequestHeader()
	h.Set("Authorization", "Bearer "+buildMockJWT(map[string]interface{}{
		"sub":                  itestCaller,
		"verifiableCredential": map[string]interface{}{"issuer": consumer},
	}))
	return &mockRequest{
		id:     nextRequestID(),
		method: "GET",
		path:   []byte("/ngsi-ld/v1/entities/urn:ngsi-ld:PersonalProfile:alice"),
		header: h,
	}
}

const defaultDenyBody = `{"error":"access denied by consent policy"}`

// assertAllowed asserts the response passed through untouched.
func assertAllowed(t *testing.T, resp *mockResponse, msgAndArgs ...interface{}) {
	t.Helper()
	assert.Nil(t, resp.writtenBody, msgAndArgs...)
	assert.Equal(t, 0, resp.writtenStatus, msgAndArgs...)
}

// assertDenied asserts the response was replaced by the default deny.
func assertDenied(t *testing.T, resp *mockResponse, msgAndArgs ...interface{}) {
	t.Helper()
	assert.Equal(t, http.StatusForbidden, resp.writtenStatus, msgAndArgs...)
	assert.Equal(t, defaultDenyBody, string(resp.writtenBody), msgAndArgs...)
}

// --- Integration test cases ---

// TestIntegration_ConsentLifecycle drives one owner through deny without
// consent -> grant -> allow -> revoke -> deny against one fake, in each mode.
// Consent answers are not cached, so each change takes effect on the next cycle.
func TestIntegration_ConsentLifecycle(t *testing.T) {
	const owner = "did:key:zAlice"
	body := []byte(`{"email":"alice@example.org"}`)

	for _, mode := range checkModes {
		t.Run(mode.mode, func(t *testing.T) {
			consent.ResetCaches()
			cm := newDSCConsentManager(t)
			resolver := newOwnerResolver(t, owner)
			cfg := marshalConfig(t, baseConfig(cm.URL, resolver.URL, mode.config))

			assertDenied(t, runPluginCycle(t, cfg, consentRequest(), body), "no consent yet")

			id := cm.grant(owner)
			assertAllowed(t, runPluginCycle(t, cfg, consentRequest(), body), "after grant")

			cm.revoke(id)
			assertDenied(t, runPluginCycle(t, cfg, consentRequest(), body), "after revoke")

			assert.Equal(t, []string{owner, owner, owner}, cm.askedSubjects(),
				"the resolved owner, not the caller, must be the userIdentifier")
		})
	}
}

// TestIntegration_ConsentScoping verifies a consent of the right owner still
// denies when it binds another consumer or another provider, or lacks the route
// purpose, in each mode. In check mode the route-level notice id makes
// /consents/check answer valid for the scoping cases, so only the mandatory
// consent read can catch the mismatch.
func TestIntegration_ConsentScoping(t *testing.T) {
	const owner = "did:key:zAlice"
	routePurpose := map[string]interface{}{"purpose": itestPurpose}

	tests := []struct {
		name       string
		grant      []consentOption
		consumer   string
		config     map[string]interface{}
		wantDenied bool
	}{
		{name: "consent to this consumer allows", consumer: itestConsumerDID},
		{
			name:       "consent to another consumer denies",
			grant:      []consentOption{toConsumer(itestOtherConsumerDID)},
			consumer:   itestConsumerDID,
			wantDenied: true,
		},
		{
			// The request names this participant as consumer, and the owner's consent
			// names it as consumer too, but of another provider's contract.
			name:       "consent where this participant is the consumer of another provider denies",
			grant:      []consentOption{fromProvider(itestOtherProviderDID), toConsumer(itestProviderDID)},
			consumer:   itestProviderDID,
			wantDenied: true,
		},
		{
			name:     "consent listing the route purpose allows",
			grant:    []consentOption{withPurposes(itestOtherPurpose, itestPurpose)},
			consumer: itestConsumerDID,
			config:   routePurpose,
		},
		{
			name:       "consent lacking the route purpose denies",
			grant:      []consentOption{withPurposes(itestOtherPurpose)},
			consumer:   itestConsumerDID,
			config:     routePurpose,
			wantDenied: true,
		},
	}

	for _, mode := range checkModes {
		for _, tt := range tests {
			t.Run(mode.mode+"/"+tt.name, func(t *testing.T) {
				consent.ResetCaches()
				cm := newDSCConsentManager(t)
				cm.grant(owner, tt.grant...)
				resolver := newOwnerResolver(t, owner)

				resp := runPluginCycle(t, marshalConfig(t, baseConfig(cm.URL, resolver.URL, mode.config, tt.config)),
					consentRequestFrom(tt.consumer), []byte(`{"email":"alice@example.org"}`))

				if tt.wantDenied {
					assertDenied(t, resp)
				} else {
					assertAllowed(t, resp)
				}
			})
		}
	}
}

// TestIntegration_ConsentManagerFailure maps consent-manager failures to a
// decision in each mode: retryable ones follow fail_open, auth errors and
// permanent rejections deny even with it.
func TestIntegration_ConsentManagerFailure(t *testing.T) {
	const owner = "did:key:zAlice"

	tests := []struct {
		name       string
		status     int
		failOpen   bool
		wantDenied bool
	}{
		{name: "5xx passes with fail_open", status: http.StatusInternalServerError, failOpen: true},
		{name: "5xx denies fail-closed", status: http.StatusServiceUnavailable, wantDenied: true},
		{name: "429 passes with fail_open", status: http.StatusTooManyRequests, failOpen: true},
		{name: "401 denies even with fail_open", status: http.StatusUnauthorized, failOpen: true, wantDenied: true},
		{name: "403 denies even with fail_open", status: http.StatusForbidden, failOpen: true, wantDenied: true},
		{name: "400 denies even with fail_open", status: http.StatusBadRequest, failOpen: true, wantDenied: true},
		{name: "404 denies even with fail_open", status: http.StatusNotFound, failOpen: true, wantDenied: true},
	}

	for _, mode := range checkModes {
		for _, tt := range tests {
			t.Run(mode.mode+"/"+tt.name, func(t *testing.T) {
				consent.ResetCaches()
				cm := newDSCConsentManager(t)
				cm.grant(owner)
				cm.failWith(tt.status)
				resolver := newOwnerResolver(t, owner)

				cfg := baseConfig(cm.URL, resolver.URL, mode.config, map[string]interface{}{"fail_open": tt.failOpen})
				resp := runPluginCycle(t, marshalConfig(t, cfg), consentRequest(), []byte(`{"data":"x"}`))

				if tt.wantDenied {
					assertDenied(t, resp)
				} else {
					assertAllowed(t, resp, "fail_open should pass through a retryable error")
				}
			})
		}
	}
}

// TestIntegration_CustomDenyResponse verifies the configured deny status/body are used.
func TestIntegration_CustomDenyResponse(t *testing.T) {
	consent.ResetCaches()
	cm := newDSCConsentManager(t)
	resolver := newOwnerResolver(t, "did:key:zAlice")

	cfg := baseConfig(cm.URL, resolver.URL, map[string]interface{}{
		"deny_status_code":           http.StatusUnavailableForLegalReasons,
		"deny_response_body":         `{"error":"legally restricted"}`,
		"deny_response_content_type": "application/json",
	})

	resp := runPluginCycle(t, marshalConfig(t, cfg), consentRequest(), []byte(`{"secret":"x"}`))

	assert.Equal(t, http.StatusUnavailableForLegalReasons, resp.writtenStatus)
	assert.Equal(t, `{"error":"legally restricted"}`, string(resp.writtenBody))
	assert.Equal(t, "application/json", resp.header.Get("Content-Type"))
}

// TestIntegration_CustomJWTHeader verifies the plugin reads the JWT from a custom
// header when configured (the resolved owner's consent is granted).
func TestIntegration_CustomJWTHeader(t *testing.T) {
	consent.ResetCaches()
	cm := newDSCConsentManager(t)
	cm.grant("custom-user")
	resolver := newOwnerResolver(t, "custom-user")

	cfg := baseConfig(cm.URL, resolver.URL, map[string]interface{}{"jwt_header_name": "X-Auth-Token"})

	h := newMockRequestHeader()
	h.Set("X-Auth-Token", "Bearer "+buildMockJWT(map[string]interface{}{
		"verifiableCredential": map[string]interface{}{"issuer": itestConsumerDID},
	}))
	req := &mockRequest{id: nextRequestID(), method: "POST", path: []byte("/api/v1/items"), header: h}

	resp := runPluginCycle(t, marshalConfig(t, cfg), req, []byte(`{"created":true}`))

	assertAllowed(t, resp, "granted consent via custom JWT header should pass through")
}

// TestIntegration_ContextCleanupAfterCycle verifies the request context is
// cleaned up after a full request-response cycle (no memory leak).
func TestIntegration_ContextCleanupAfterCycle(t *testing.T) {
	consent.ResetCaches()
	cm := newDSCConsentManager(t)
	cm.grant("did:key:zAlice")
	resolver := newOwnerResolver(t, "did:key:zAlice")

	_ = runPluginCycle(t, marshalConfig(t, baseConfig(cm.URL, resolver.URL)),
		consentRequest(), []byte(`{"data":"test"}`))

	assert.Equal(t, 0, plugin.RequestContextStoreSize(),
		"request context should be deleted after the response cycle")
}

// TestIntegration_TokenServiceFlow drives the token-service path: fetch a token
// by audience from the consent-facade, derive the provider identity from
// /participants/me, then check the consent with the fetched token.
func TestIntegration_TokenServiceFlow(t *testing.T) {
	const owner = "did:key:zAlice"

	for _, mode := range checkModes {
		t.Run(mode.mode, func(t *testing.T) {
			consent.ResetCaches()
			cm := newDSCConsentManagerWithTokenService(t)
			resolver := newOwnerResolver(t, owner)
			cfg := maps.Clone(mode.config)
			maps.Copy(cfg, map[string]interface{}{
				"consent_api_url":    cm.URL,
				"owner_resolver_url": resolver.URL + "/resolve",
				"token_service_url":  cm.URL + tokenServicePath,
			})
			cfgJSON := marshalConfig(t, cfg)
			body := []byte(`{"ok":true}`)

			assertDenied(t, runPluginCycle(t, cfgJSON, consentRequest(), body), "no consent yet")
			cm.grant(owner)
			assertAllowed(t, runPluginCycle(t, cfgJSON, consentRequest(), body), "after grant")
		})
	}
}

// TestIntegration_Resolver drives the resolver decision matrix end to end in
// each mode: a real ParseConf -> RequestFilter -> ResponseFilter against a mock
// resolver and the consent-manager fake.
func TestIntegration_Resolver(t *testing.T) {
	const (
		ownerAlice = "did:key:zAlice"
		ownerBob   = "did:key:zBob"
	)

	tests := []struct {
		name          string
		resolverReply map[string]interface{}
		resolverCode  int // non-zero => the resolver answers with this status instead
		granted       []string
		revoked       []string
		failOpen      bool
		wantDenied    bool
		wantOwners    []string // owners the consent-manager must have been asked about
	}{
		{
			name:          "every owner granted allows",
			resolverReply: resolveReply(ownerAlice, ownerBob),
			granted:       []string{ownerAlice, ownerBob},
			wantOwners:    []string{ownerAlice, ownerBob},
		},
		{
			name:          "one revoked owner denies the whole response (deny_all)",
			resolverReply: resolveReply(ownerAlice, ownerBob),
			granted:       []string{ownerAlice},
			revoked:       []string{ownerBob},
			wantDenied:    true,
			// Which owners get asked depends on the concurrent short-circuit, so
			// only the decision is asserted here.
		},
		{
			name:          "an owner without any consent denies",
			resolverReply: resolveReply(ownerAlice, ownerBob),
			granted:       []string{ownerAlice},
			wantDenied:    true,
		},
		{
			name:          "an owner unknown to the consent-manager denies",
			resolverReply: resolveReply("did:key:zStranger"),
			granted:       []string{ownerAlice},
			wantDenied:    true,
			wantOwners:    []string{"did:key:zStranger"},
		},
		{
			name:          "consentRequired false allows without any consent call",
			resolverReply: map[string]interface{}{"consentRequired": false},
			wantOwners:    []string{},
		},
		{
			name:          "consent required with no claims denies",
			resolverReply: map[string]interface{}{"consentRequired": true, "claims": []map[string]string{}},
			wantDenied:    true,
			wantOwners:    []string{},
		},
		{
			name: "a claim with an empty owner denies",
			resolverReply: map[string]interface{}{
				"consentRequired": true,
				"claims":          []map[string]string{{"ownerId": ""}},
			},
			wantDenied: true,
			wantOwners: []string{},
		},
		{
			name:         "resolver 5xx denies by default",
			resolverCode: http.StatusInternalServerError,
			wantDenied:   true,
			wantOwners:   []string{},
		},
		{
			name:         "resolver 5xx passes through with fail_open",
			resolverCode: http.StatusInternalServerError,
			failOpen:     true,
			wantOwners:   []string{},
		},
		{
			name:          "duplicate owners are checked once",
			resolverReply: resolveReply(ownerAlice, ownerAlice, ownerAlice),
			granted:       []string{ownerAlice},
			wantOwners:    []string{ownerAlice},
		},
	}

	for _, mode := range checkModes {
		for _, tt := range tests {
			t.Run(mode.mode+"/"+tt.name, func(t *testing.T) {
				consent.ResetCaches()
				cm := newDSCConsentManager(t)
				for _, o := range tt.granted {
					cm.grant(o)
				}
				for _, o := range tt.revoked {
					cm.revoke(cm.grant(o))
				}

				var resolver *httptest.Server
				if tt.resolverCode != 0 {
					resolver = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(tt.resolverCode)
					}))
					t.Cleanup(resolver.Close)
				} else {
					var received []resolveEnvelope
					resolver = newRecordingOwnerResolver(t, tt.resolverReply, &received)
				}

				cfg := baseConfig(cm.URL, resolver.URL, mode.config, map[string]interface{}{"fail_open": tt.failOpen})
				resp := runPluginCycle(t, marshalConfig(t, cfg), consentRequest(), []byte(`{"id":"urn:entity:1"}`))

				if tt.wantDenied {
					assertDenied(t, resp)
				} else {
					assertAllowed(t, resp, "expected the response to pass through")
				}
				if tt.wantOwners != nil {
					// Checks run concurrently, so the order is not significant.
					assert.ElementsMatch(t, tt.wantOwners, cm.askedSubjects(),
						"the consent-manager must be asked about exactly these owners")
				}
			})
		}
	}
}

// TestIntegration_ResolverReceivesPartiesAndPayload verifies what the plugin
// actually tells the resolver: the resource descriptor, the contract parties
// (resolved via the participant registry), and the upstream payload as JSON.
func TestIntegration_ResolverReceivesPartiesAndPayload(t *testing.T) {
	consent.ResetCaches()
	cm := newDSCConsentManager(t)
	cm.grant("did:key:zAlice")

	var received []resolveEnvelope
	resolver := newRecordingOwnerResolver(t, resolveReply("did:key:zAlice"), &received)

	cfg := baseConfig(cm.URL, resolver.URL, map[string]interface{}{"service": "personal-profiles"})

	payload := []byte(`{"id":"urn:ngsi-ld:PersonalProfile:alice"}`)
	runPluginCycle(t, marshalConfig(t, cfg), consentRequest(), payload)

	require.Len(t, received, 1)
	env := received[0]
	assert.Equal(t, "personal-profiles", env.Resource.Service)
	assert.Equal(t, "GET", env.Resource.Method)
	assert.Equal(t, "/ngsi-ld/v1/entities/urn:ngsi-ld:PersonalProfile:alice", env.Resource.Path)
	require.NotNil(t, env.Parties, "the contract parties must be sent, or the resolver cannot identify the contract")
	assert.Equal(t, itestConsumerSD, env.Parties.Consumer, "the consumer DID must be mapped to its self-description")
	assert.Equal(t, itestProviderSD, env.Parties.Provider)
	require.NotNil(t, env.Body)
	assert.Equal(t, "json", env.Body.Encoding)
	assert.JSONEq(t, string(payload), string(env.Body.Content))
}

// TestIntegration_PartyResolutionFailureDenies verifies the fail-closed seam
// end to end: when the consumer cannot be mapped to a participant, the
// resolver is never asked and the response is denied — even with fail_open,
// which must not turn a token naming an unregistered consumer into a bypass.
func TestIntegration_PartyResolutionFailureDenies(t *testing.T) {
	consent.ResetCaches()
	cm := newDSCConsentManager(t)

	var resolverCalled atomic.Bool
	resolver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resolverCalled.Store(true)
		// An unidentified-party resolve could plausibly answer "no contract
		// governs this, so no consent is required" — an unconditional allow.
		writeJSON(w, map[string]interface{}{"consentRequired": false})
	}))
	t.Cleanup(resolver.Close)

	cfg := baseConfig(cm.URL, resolver.URL, map[string]interface{}{"fail_open": true})

	resp := runPluginCycle(t, marshalConfig(t, cfg),
		consentRequestFrom("did:key:zUnregisteredConsumer"), []byte(`{"a":1}`))

	assert.False(t, resolverCalled.Load(), "an unidentified consumer must not reach the resolver")
	assert.Equal(t, http.StatusForbidden, resp.writtenStatus, "an unidentified consumer must deny")
}
