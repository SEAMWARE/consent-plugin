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

package consent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tokenServicePath is where the mock serves the participant-local token service.
const tokenServicePath = "/internal/tokens"

// testAudience is the configured token-service target the tests ask for.
const testAudience = "consent-manager"

// testConsumerSD is the self-description URL of the participant the data is
// released to — the consumer every check is scoped to.
const testConsumerSD = "http://catalog/participants/consumer"

// mockCM is a configurable mock covering the four endpoints the client uses: the
// participant-local token service (/internal/tokens, served here for convenience
// on the same test server), plus the consent-manager's /participants/me,
// /users/identifier/search and /consents/participants/{id}.
type mockCM struct {
	mu sync.Mutex
	// behaviour
	userID              string     // identifier-search result ("" => 404)
	statuses            []string   // consents statuses
	resourcesPerConsent [][]string // optional data[].resource per consent (index-aligned with statuses)
	selfDescriptionURL  string     // /me result
	consentConsumer     string     // consumer the returned consents name (defaults to testConsumerSD)
	// consentUsesRecipients emits the REAL ?receipt=true shape: `dataConsumer` as a
	// bare Mongo id plus `recipients: [<sd>]`, instead of an expanded `consumer`.
	consentUsesRecipients bool
	consentPurposes       []string // optional purposes the returned consents cover
	tokenStatus           int      // non-200 => the token service fails with this status
	failFirstConsents     bool     // first consents call 401s, then succeeds
	// recording
	tokenCalls, meCalls, searchCalls, consentsCalls int
	lastSearchEmail, lastSearchSD                   string
	lastConsentsAuth, lastTokenAudience             string
	tokenCounter                                    int
}

func newMockCM(t *testing.T, m *mockCM) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc(tokenServicePath, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		m.mu.Lock()
		m.tokenCalls++
		m.lastTokenAudience = body["audience"]
		st := m.tokenStatus
		m.tokenCounter++
		tok := fmt.Sprintf("token-%d", m.tokenCounter)
		m.mu.Unlock()
		if st != 0 && st != http.StatusOK {
			w.WriteHeader(st)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": tok, "token_type": "Bearer", "expires_in": 3600,
		})
	})

	mux.HandleFunc("/v1/participants/me", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.meCalls++
		sd := m.selfDescriptionURL
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"selfDescriptionURL": sd})
	})

	mux.HandleFunc("/v1/users/identifier/search", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		m.mu.Lock()
		m.searchCalls++
		m.lastSearchEmail = body["email"]
		m.lastSearchSD = body["selfDescription"]
		uid := m.userID
		m.mu.Unlock()
		if uid == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"userIdentifier": uid})
	})

	mux.HandleFunc("/v1/consents/participants/", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.consentsCalls++
		n := m.consentsCalls
		m.lastConsentsAuth = r.Header.Get("Authorization")
		fail := m.failFirstConsents
		sts := append([]string(nil), m.statuses...)
		res := append([][]string(nil), m.resourcesPerConsent...)
		useRecipients := m.consentUsesRecipients
		consumer := m.consentConsumer
		if consumer == "" {
			consumer = testConsumerSD
		}
		// "none" makes the mock return a consent record that names no consumer.
		omitConsumer := consumer == "none"
		purposes := append([]string(nil), m.consentPurposes...)
		m.mu.Unlock()
		if fail && n == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		consents := make([]map[string]interface{}, 0, len(sts))
		for i, s := range sts {
			consent := map[string]interface{}{"status": s}
			if !omitConsumer {
				if useRecipients {
					// The real ?receipt=true shape: the consumer appears as a bare
					// Mongo id in dataConsumer, and only `recipients` carries the
					// self-description URL the plugin can compare against.
					consent["dataConsumer"] = "6a95131a0a7640f7f6dee2d2"
					consent["recipients"] = []string{consumer}
				} else {
					consent["consumer"] = map[string]string{"selfDescriptionURL": consumer}
				}
			}
			if len(purposes) > 0 {
				ps := make([]map[string]string, 0, len(purposes))
				for _, p := range purposes {
					ps = append(ps, map[string]string{"purpose": p})
				}
				consent["purposes"] = ps
			}
			if i < len(res) {
				data := make([]map[string]string, 0, len(res[i]))
				for _, r := range res[i] {
					data = append(data, map[string]string{"resource": r})
				}
				consent["data"] = data
			}
			consents = append(consents, consent)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"consents": consents})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// resetCredCache clears the package-wide caches between tests.
func resetCredCache() { ResetCaches() }

// TestCheckConsent_ResourceScoped verifies the (owner × dataResource) check: a
// granted consent authorizes only the resources it covers, while an empty
// DataResource is owner-level (any granted consent counts).
func TestCheckConsent_ResourceScoped(t *testing.T) {
	resetCredCache()
	m := &mockCM{
		userID:              "uid-1",
		selfDescriptionURL:  "http://provider/sd",
		statuses:            []string{"granted"},
		resourcesPerConsent: [][]string{{"urn:ngsi-ld:PersonalProfile:alice"}},
	}
	srv := newMockCM(t, m)
	c := NewClient(ClientConfig{BaseURL: srv.URL, TokenServiceURL: srv.URL + tokenServicePath, TokenAudience: testAudience})

	// resource covered by a granted consent -> allow
	resp, err := c.CheckConsent(context.Background(), ConsentRequest{Subject: "alice-42", Consumer: testConsumerSD, DataResource: "urn:ngsi-ld:PersonalProfile:alice"})
	require.NoError(t, err)
	assert.Equal(t, DecisionAllow, resp.Decision)

	// a different resource -> deny (the consent does not cover it)
	resp, err = c.CheckConsent(context.Background(), ConsentRequest{Subject: "alice-42", Consumer: testConsumerSD, DataResource: "urn:ngsi-ld:PersonalProfile:bob"})
	require.NoError(t, err)
	assert.Equal(t, DecisionDeny, resp.Decision)

	// owner-level (no resource) -> allow on any granted consent
	resp, err = c.CheckConsent(context.Background(), ConsentRequest{Subject: "alice-42", Consumer: testConsumerSD})
	require.NoError(t, err)
	assert.Equal(t, DecisionAllow, resp.Decision)
}

// TestNewClient verifies the constructor applies defaults and stores parameters.
func TestNewClient(t *testing.T) {
	c := NewClient(ClientConfig{BaseURL: "http://cm:3000", TokenServiceURL: "http://consent-facade:8080" + tokenServicePath, TokenAudience: testAudience})
	assert.Equal(t, "http://cm:3000", c.baseURL)
	assert.Equal(t, DefaultAPIPrefix, c.apiPrefix, "empty prefix defaults to /v1")
	assert.Equal(t, DefaultTokenTTL, c.tokenTTL, "zero ttl defaults")
	assert.Equal(t, time.Duration(DefaultTimeoutMs)*time.Millisecond, c.httpClient.Timeout, "zero timeout defaults")

	c2 := NewClient(ClientConfig{APIPrefix: "/v2", TokenTTL: time.Minute, TimeoutMs: 1234})
	assert.Equal(t, "/v2", c2.apiPrefix)
	assert.Equal(t, time.Minute, c2.tokenTTL)
	assert.Equal(t, 1234*time.Millisecond, c2.httpClient.Timeout)
}

// TestCheckConsent covers the two-call decision matrix using a static token + SD
// (no login/me involved).
func TestCheckConsent(t *testing.T) {
	const (
		subject = "did:key:zSubject"
		provSD  = "http://consent-facade:8080/participants/org-1"
		uid     = "6a71e3567917ddaef2e2c866"
	)
	tests := []struct {
		name            string
		userID          string
		statuses        []string
		consentConsumer string // consumer the mock's consents were granted to
		requestConsumer string // consumer the check is made for
		wantDecision    Decision
	}{
		{name: "granted -> allow", userID: uid, statuses: []string{"granted"}, wantDecision: DecisionAllow},
		{name: "one of many granted -> allow", userID: uid, statuses: []string{"revoked", "granted"}, wantDecision: DecisionAllow},
		{name: "only revoked -> deny", userID: uid, statuses: []string{"revoked"}, wantDecision: DecisionDeny},
		{name: "no consents -> deny", userID: uid, statuses: []string{}, wantDecision: DecisionDeny},
		{name: "unknown subject (404) -> deny", userID: "", statuses: nil, wantDecision: DecisionDeny},
		{
			name: "granted to another consumer -> deny", userID: uid, statuses: []string{"granted"},
			consentConsumer: "http://catalog/participants/someone-else", wantDecision: DecisionDeny,
		},
		{
			name: "consent naming no consumer -> deny", userID: uid, statuses: []string{"granted"},
			consentConsumer: "none", wantDecision: DecisionDeny,
		},
		{
			name: "no consumer in the request -> deny", userID: uid, statuses: []string{"granted"},
			requestConsumer: "none", wantDecision: DecisionDeny,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCredCache()
			m := &mockCM{userID: tt.userID, statuses: tt.statuses, consentConsumer: tt.consentConsumer}
			srv := newMockCM(t, m)
			c := NewClient(ClientConfig{BaseURL: srv.URL, ParticipantToken: "static-token", ProviderSD: provSD})

			requestConsumer := testConsumerSD
			if tt.requestConsumer == "none" {
				requestConsumer = ""
			}
			resp, err := c.CheckConsent(context.Background(), ConsentRequest{Subject: subject, Consumer: requestConsumer})
			require.NoError(t, err)
			assert.Equal(t, tt.wantDecision, resp.Decision)

			m.mu.Lock()
			defer m.mu.Unlock()
			assert.Equal(t, 0, m.tokenCalls, "static token must not call the token service")
			assert.Equal(t, 0, m.meCalls, "static SD must not trigger /me")
			if tt.requestConsumer == "none" {
				assert.Equal(t, 0, m.searchCalls, "a check without a consumer must not reach the consent-manager")
				return
			}
			assert.Equal(t, provSD, m.lastSearchSD)
			assert.Equal(t, subject, m.lastSearchEmail)
			if tt.userID != "" {
				assert.Equal(t, "Bearer static-token", m.lastConsentsAuth)
			}
		})
	}
}

// TestCheckConsent_ClientCredentials verifies the full client-credentials flow:
// login for a token, derive the provider SD from /me, then run the two calls.
// TestCheckConsent_ConsumerNamedOnlyInRecipients is the shape the consent-manager
// actually returns from `?receipt=true`: the consumer appears as a bare Mongo id in
// `dataConsumer`, and the self-description URL the plugin holds appears only in
// `recipients`. Matching on consumer/dataConsumer alone denies a perfectly valid
// consent - which is what made step 4 of the demo answer 403 with a granted consent
// in place.
func TestCheckConsent_ConsumerNamedOnlyInRecipients(t *testing.T) {
	const providerSD = "http://consent-facade:8080/participants/org-1"
	resetCredCache()
	m := &mockCM{
		userID: "uid-1", selfDescriptionURL: providerSD, statuses: []string{"granted"},
		consentUsesRecipients: true,
	}
	srv := newMockCM(t, m)
	c := NewClient(ClientConfig{BaseURL: srv.URL, ParticipantToken: "static", ProviderSD: providerSD})

	resp, err := c.CheckConsent(context.Background(),
		ConsentRequest{Subject: "alice-42", Consumer: testConsumerSD})
	require.NoError(t, err)
	assert.Equal(t, DecisionAllow, resp.Decision,
		"a consent whose consumer is named in recipients must be honoured")
}

// TestCheckConsent_RecipientsNameADifferentConsumer guards the other direction: the
// recipients fallback must not authorise a participant the consent was not granted to.
func TestCheckConsent_RecipientsNameADifferentConsumer(t *testing.T) {
	const providerSD = "http://consent-facade:8080/participants/org-1"
	resetCredCache()
	m := &mockCM{
		userID: "uid-1", selfDescriptionURL: providerSD, statuses: []string{"granted"},
		consentUsesRecipients: true, consentConsumer: "http://consent-facade:8080/participants/someone-else",
	}
	srv := newMockCM(t, m)
	c := NewClient(ClientConfig{BaseURL: srv.URL, ParticipantToken: "static", ProviderSD: providerSD})

	resp, err := c.CheckConsent(context.Background(),
		ConsentRequest{Subject: "alice-42", Consumer: testConsumerSD})
	require.NoError(t, err)
	assert.Equal(t, DecisionDeny, resp.Decision,
		"a consent granted to another participant is not authority for this one")
}

func TestCheckConsent_TokenService(t *testing.T) {
	resetCredCache()
	m := &mockCM{userID: "uid-1", statuses: []string{"granted"}, selfDescriptionURL: "http://facade/participants/derived"}
	srv := newMockCM(t, m)
	c := NewClient(ClientConfig{BaseURL: srv.URL, TokenServiceURL: srv.URL + tokenServicePath, TokenAudience: testAudience})

	resp, err := c.CheckConsent(context.Background(), ConsentRequest{Subject: "did:key:z", Consumer: testConsumerSD})
	require.NoError(t, err)
	assert.Equal(t, DecisionAllow, resp.Decision)

	m.mu.Lock()
	defer m.mu.Unlock()
	assert.Equal(t, 1, m.tokenCalls)
	assert.Equal(t, testAudience, m.lastTokenAudience)
	assert.Equal(t, 1, m.meCalls)
	assert.Equal(t, "http://facade/participants/derived", m.lastSearchSD, "SD derived from /me is used in the search")
	assert.Equal(t, "Bearer token-1", m.lastConsentsAuth, "the fetched token is used on the consents call")
}

// TestCheckConsent_TokenAndSDCached verifies the token and derived SD are cached
// across calls (login + /me happen once).
func TestCheckConsent_TokenAndSDCached(t *testing.T) {
	resetCredCache()
	m := &mockCM{userID: "uid-1", statuses: []string{"granted"}, selfDescriptionURL: "http://facade/participants/derived"}
	srv := newMockCM(t, m)
	c := NewClient(ClientConfig{BaseURL: srv.URL, TokenServiceURL: srv.URL + tokenServicePath, TokenAudience: testAudience})

	for i := 0; i < 3; i++ {
		resp, err := c.CheckConsent(context.Background(), ConsentRequest{Subject: "did:key:z", Consumer: testConsumerSD})
		require.NoError(t, err)
		assert.Equal(t, DecisionAllow, resp.Decision)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	assert.Equal(t, 1, m.tokenCalls, "token should be cached across calls")
	assert.Equal(t, 1, m.meCalls, "provider SD should be cached across calls")
	assert.Equal(t, 3, m.consentsCalls)
}

// TestCheckConsent_401RefreshRetry verifies a 401 on the consents call triggers a
// re-login and a single retry.
func TestCheckConsent_401RefreshRetry(t *testing.T) {
	resetCredCache()
	m := &mockCM{userID: "uid-1", statuses: []string{"granted"}, selfDescriptionURL: "http://facade/sd", failFirstConsents: true}
	srv := newMockCM(t, m)
	c := NewClient(ClientConfig{BaseURL: srv.URL, TokenServiceURL: srv.URL + tokenServicePath, TokenAudience: testAudience})

	resp, err := c.CheckConsent(context.Background(), ConsentRequest{Subject: "did:key:z", Consumer: testConsumerSD})
	require.NoError(t, err)
	assert.Equal(t, DecisionAllow, resp.Decision)

	m.mu.Lock()
	defer m.mu.Unlock()
	assert.Equal(t, 2, m.tokenCalls, "401 should force a token refresh")
	assert.Equal(t, 2, m.consentsCalls, "the consents call should be retried once")
	assert.Equal(t, "Bearer token-2", m.lastConsentsAuth, "the retry uses the refreshed token")
}

// TestCheckConsent_LoginFailure surfaces a login error.
func TestCheckConsent_TokenServiceFailure(t *testing.T) {
	resetCredCache()
	m := &mockCM{userID: "uid-1", statuses: []string{"granted"}, tokenStatus: http.StatusNotFound}
	srv := newMockCM(t, m)
	c := NewClient(ClientConfig{BaseURL: srv.URL, TokenServiceURL: srv.URL + tokenServicePath, TokenAudience: testAudience})

	_, err := c.CheckConsent(context.Background(), ConsentRequest{Subject: "did:key:z", Consumer: testConsumerSD})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token service returned status 404")
}

// TestCheckConsent_ProviderSDOverride verifies an explicit provider_sd skips /me
// while still using client credentials for the token.
func TestCheckConsent_ProviderSDOverride(t *testing.T) {
	resetCredCache()
	m := &mockCM{userID: "uid-1", statuses: []string{"granted"}}
	srv := newMockCM(t, m)
	c := NewClient(ClientConfig{BaseURL: srv.URL, TokenServiceURL: srv.URL + tokenServicePath, TokenAudience: testAudience, ProviderSD: "http://facade/explicit"})

	resp, err := c.CheckConsent(context.Background(), ConsentRequest{Subject: "did:key:z", Consumer: testConsumerSD})
	require.NoError(t, err)
	assert.Equal(t, DecisionAllow, resp.Decision)

	m.mu.Lock()
	defer m.mu.Unlock()
	assert.Equal(t, 1, m.tokenCalls, "token still comes from the token service")
	assert.Equal(t, 0, m.meCalls, "explicit provider_sd skips /me")
	assert.Equal(t, "http://facade/explicit", m.lastSearchSD)
}

// TestCheckConsent_EmptySubject denies without contacting the consent-manager.
func TestCheckConsent_EmptySubject(t *testing.T) {
	resetCredCache()
	m := &mockCM{userID: "uid", statuses: []string{"granted"}}
	srv := newMockCM(t, m)
	c := NewClient(ClientConfig{BaseURL: srv.URL, TokenServiceURL: srv.URL + tokenServicePath, TokenAudience: testAudience})

	resp, err := c.CheckConsent(context.Background(), ConsentRequest{Subject: "", Consumer: testConsumerSD})
	require.NoError(t, err)
	assert.Equal(t, DecisionDeny, resp.Decision)
	m.mu.Lock()
	defer m.mu.Unlock()
	assert.Equal(t, 0, m.tokenCalls)
	assert.Equal(t, 0, m.searchCalls)
}

// TestCheckConsent_MissingTokenSource errors when neither a static token nor a
// token service is configured.
func TestCheckConsent_MissingTokenSource(t *testing.T) {
	resetCredCache()
	c := NewClient(ClientConfig{BaseURL: "http://cm:3000"})
	_, err := c.CheckConsent(context.Background(), ConsentRequest{Subject: "did:key:z", Consumer: testConsumerSD})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no participant_token and no token_service_url")
}

// TestCheckConsent_ConcurrentLoginCoalesced verifies that concurrent first
// requests for the same participant coalesce onto a single client-credentials
// login (no stampede) and a single /me fetch, rather than one per goroutine.
func TestCheckConsent_ConcurrentTokenFetchCoalesced(t *testing.T) {
	resetCredCache()
	m := &mockCM{userID: "uid-1", statuses: []string{"granted"}, selfDescriptionURL: "sd"}
	srv := newMockCM(t, m)

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Same base URL + client id => same cache key, so the login must coalesce.
			c := NewClient(ClientConfig{BaseURL: srv.URL, TokenServiceURL: srv.URL + tokenServicePath, TokenAudience: testAudience})
			resp, err := c.CheckConsent(context.Background(), ConsentRequest{Subject: "did:key:z", Consumer: testConsumerSD})
			if err != nil {
				errs <- err
			} else if resp.Decision != DecisionAllow {
				errs <- fmt.Errorf("decision = %v, want allow", resp.Decision)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	assert.Equal(t, 1, m.tokenCalls, "concurrent first requests must coalesce onto one token fetch")
	assert.Equal(t, 1, m.meCalls, "provider SD should be fetched once and cached")
}

// TestCheckConsentTransportFailure verifies an unreachable consent-manager errors.
func TestCheckConsentTransportFailure(t *testing.T) {
	resetCredCache()
	c := NewClient(ClientConfig{BaseURL: "http://localhost:1", ParticipantToken: "t", ProviderSD: "sd", TimeoutMs: MinTimeoutMs})
	_, err := c.CheckConsent(context.Background(), ConsentRequest{Subject: "did:key:z", Consumer: testConsumerSD})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP request failed")
}

// TestCheckConsentContextCancellation verifies context cancellation is honored.
func TestCheckConsentContextCancellation(t *testing.T) {
	resetCredCache()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := NewClient(ClientConfig{BaseURL: srv.URL, ParticipantToken: "t", ProviderSD: "sd"})
	_, err := c.CheckConsent(ctx, ConsentRequest{Subject: "did:key:z", Consumer: testConsumerSD})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP request failed")
}

// TestCacheKeyDistinguishesCredentialIdentities verifies that two clients that
// differ in any input feeding the cached token or provider self-description get
// distinct cache keys. Sharing an entry across credential identities would make
// one route run its lookups as the wrong participant (see cacheKey).
func TestCacheKeyDistinguishesCredentialIdentities(t *testing.T) {
	base := ClientConfig{
		BaseURL:         "http://consent-manager:3000",
		APIPrefix:       "/v1",
		ProviderSD:      "http://facade/participants/a",
		TokenServiceURL: "http://facade-a:8080/internal/tokens",
		TokenAudience:   testAudience,
	}

	tests := []struct {
		name   string
		mutate func(cfg *ClientConfig)
	}{
		{"base url", func(cfg *ClientConfig) { cfg.BaseURL = "http://other-manager:3000" }},
		{"api prefix", func(cfg *ClientConfig) { cfg.APIPrefix = "/v2" }},
		{"provider sd", func(cfg *ClientConfig) { cfg.ProviderSD = "http://facade/participants/b" }},
		{"token service url", func(cfg *ClientConfig) { cfg.TokenServiceURL = "http://facade-b:8080/internal/tokens" }},
		{"token audience", func(cfg *ClientConfig) { cfg.TokenAudience = "other-audience" }},
		{"static token", func(cfg *ClientConfig) { cfg.ParticipantToken = "static-b" }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			other := base
			tc.mutate(&other)
			assert.NotEqual(t, NewClient(base).cacheKey(), NewClient(other).cacheKey(),
				"clients differing in %s must not share a credential cache entry", tc.name)
		})
	}

	t.Run("identical config shares an entry", func(t *testing.T) {
		assert.Equal(t, NewClient(base).cacheKey(), NewClient(base).cacheKey())
	})

	t.Run("secrets are not embedded verbatim", func(t *testing.T) {
		withSecrets := base
		withSecrets.ParticipantToken = "super-secret-token"
		key := NewClient(withSecrets).cacheKey()
		assert.NotContains(t, key, "super-secret-token")
	})
}

// TestCheckConsent_SeparateTokenServicesDoNotShareToken is the regression test
// for the cross-participant cache collision: two routes fronting the SAME
// consent-manager but authenticating through their own token service must each
// present their own participant token.
func TestCheckConsent_SeparateTokenServicesDoNotShareToken(t *testing.T) {
	resetCredCache()

	var mu sync.Mutex
	var consentsAuth []string

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/users/identifier/search", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"userIdentifier": "uid-1"})
	})
	mux.HandleFunc("/v1/consents/participants/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		consentsAuth = append(consentsAuth, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"consents": []map[string]interface{}{
				{"status": grantedStatus, "consumer": map[string]string{"selfDescriptionURL": testConsumerSD}},
			},
		})
	})
	consentManager := httptest.NewServer(mux)
	t.Cleanup(consentManager.Close)

	// One token service per participant, each minting a distinguishable token.
	newTokenService := func(token string) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": token, "token_type": "Bearer", "expires_in": 3600,
			})
		}))
		t.Cleanup(srv.Close)
		return srv
	}

	for _, token := range []string{"token-participant-a", "token-participant-b"} {
		c := NewClient(ClientConfig{
			BaseURL:         consentManager.URL,
			ProviderSD:      "http://facade/participants/" + token,
			TokenServiceURL: newTokenService(token).URL,
			TokenAudience:   testAudience,
		})
		resp, err := c.CheckConsent(context.Background(), ConsentRequest{Subject: "did:key:z", Consumer: testConsumerSD})
		require.NoError(t, err)
		require.Equal(t, DecisionAllow, resp.Decision)
	}

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"Bearer token-participant-a", "Bearer token-participant-b"}, consentsAuth,
		"each participant must authenticate with its own token, not the first one cached")
}

// --- Participant registry lookup (the contract-side party mapping) ---

// newParticipantRegistry starts a mock consent-manager participant registry that
// counts its calls and can 401 the first one.
func newParticipantRegistry(t *testing.T, entries []map[string]string, calls *int, fail401First *bool) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		*calls++
		n := *calls
		mu.Unlock()
		if fail401First != nil && *fail401First && n == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(entries)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestParticipantSelfDescriptionByDID_401RefreshRetry verifies a rejected cached
// token is refreshed and the registry lookup retried, rather than failing
// terminally — a stale token must not take the whole exchange down.
func TestParticipantSelfDescriptionByDID_401RefreshRetry(t *testing.T) {
	resetCredCache()

	var registryCalls int
	fail := true
	registry := newParticipantRegistry(t,
		[]map[string]string{{"did": "did:key:zConsumer", "selfDescriptionURL": testConsumerSD}},
		&registryCalls, &fail)

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok", "token_type": "Bearer", "expires_in": 3600,
		})
	}))
	t.Cleanup(tokenSrv.Close)

	c := NewClient(ClientConfig{
		BaseURL: registry.URL, APIPrefix: "", ProviderSD: "sd",
		TokenServiceURL: tokenSrv.URL, TokenAudience: testAudience,
	})

	sd, err := c.ParticipantSelfDescriptionByDID(context.Background(), "did:key:zConsumer")
	require.NoError(t, err)
	assert.Equal(t, testConsumerSD, sd)
	assert.Equal(t, 2, registryCalls, "the 401 must trigger one refresh and retry")
}

// TestParticipantSelfDescriptionByDID_NegativeCaching verifies an unknown DID is
// remembered as unknown, so a misconfiguration does not re-fetch the whole
// participant list on every request.
func TestParticipantSelfDescriptionByDID_NegativeCaching(t *testing.T) {
	resetCredCache()

	var registryCalls int
	registry := newParticipantRegistry(t, []map[string]string{}, &registryCalls, nil)

	c := NewClient(ClientConfig{
		BaseURL: registry.URL, APIPrefix: "", ParticipantToken: "static", ProviderSD: "sd",
	})

	for i := 0; i < 3; i++ {
		_, err := c.ParticipantSelfDescriptionByDID(context.Background(), "did:key:zUnregistered")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no participant registered")
	}
	assert.Equal(t, 1, registryCalls, "an unknown DID must be remembered, not re-fetched per request")
}

// TestDecodeParticipants verifies both registry shapes are accepted: the
// consent-manager has returned a bare array and a wrapped list at different
// times, and a plugin that understands only one silently loses the ability to
// identify the consumer.
func TestDecodeParticipants(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    []participantListEntry
		wantErr bool
	}{
		{
			name: "bare array",
			body: `[{"did":"did:key:zA","selfDescriptionURL":"http://catalog/a"}]`,
			want: []participantListEntry{{DID: "did:key:zA", SelfDescriptionURL: "http://catalog/a"}},
		},
		{
			name: "wrapped list",
			body: `{"participants":[{"did":"did:key:zB","selfDescriptionURL":"http://catalog/b"}]}`,
			want: []participantListEntry{{DID: "did:key:zB", SelfDescriptionURL: "http://catalog/b"}},
		},
		{
			name: "empty array",
			body: `[]`,
			want: []participantListEntry{},
		},
		{
			name:    "not JSON at all",
			body:    `<html>gateway error</html>`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeParticipants([]byte(tt.body))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestResolveUserIdentifier_MemoisedPerSubject verifies the subject ->
// userIdentifier mapping is reused, so one response resolving to the same owner
// under several data resources searches once instead of once per resource.
func TestResolveUserIdentifier_MemoisedPerSubject(t *testing.T) {
	resetCredCache()
	m := &mockCM{userID: "uid-1", statuses: []string{"granted"}, resourcesPerConsent: [][]string{{"r1", "r2"}}}
	srv := newMockCM(t, m)
	c := NewClient(ClientConfig{BaseURL: srv.URL, ParticipantToken: "static", ProviderSD: "sd"})

	for _, resource := range []string{"r1", "r2"} {
		resp, err := c.CheckConsent(context.Background(),
			ConsentRequest{Subject: "did:key:zOwner", Consumer: testConsumerSD, DataResource: resource})
		require.NoError(t, err)
		assert.Equal(t, DecisionAllow, resp.Decision)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	assert.Equal(t, 1, m.searchCalls, "the same owner must be resolved to an identifier once")
	assert.Equal(t, 2, m.consentsCalls, "each resource still needs its own consent decision")
}

// TestResolveUserIdentifier_UnknownSubjectNotCached verifies an unknown subject
// is re-asked every time. A data subject can register at any moment, and
// remembering that they were unknown would keep denying them after they had
// consented.
func TestResolveUserIdentifier_UnknownSubjectNotCached(t *testing.T) {
	resetCredCache()
	m := &mockCM{userID: "", statuses: nil}
	srv := newMockCM(t, m)
	c := NewClient(ClientConfig{BaseURL: srv.URL, ParticipantToken: "static", ProviderSD: "sd"})

	for i := 0; i < 3; i++ {
		resp, err := c.CheckConsent(context.Background(),
			ConsentRequest{Subject: "did:key:zStranger", Consumer: testConsumerSD})
		require.NoError(t, err)
		assert.Equal(t, DecisionDeny, resp.Decision)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	assert.Equal(t, 3, m.searchCalls, "an unknown subject must not be cached as unknown")
}

// TestCheckConsent_PurposeScoped verifies the purpose leg of the consumer /
// purpose / resource match. It is load-bearing once the resolver names a
// purpose: a consent granted for "insurance quote" must not authorise a release
// for research.
func TestCheckConsent_PurposeScoped(t *testing.T) {
	const (
		grantedPurpose = "insurance-quote"
		otherPurpose   = "research"
	)

	tests := []struct {
		name            string
		consentPurposes []string
		requestPurpose  string
		wantDecision    Decision
	}{
		{
			name:            "matching purpose allows",
			consentPurposes: []string{grantedPurpose},
			requestPurpose:  grantedPurpose,
			wantDecision:    DecisionAllow,
		},
		{
			name:            "a different purpose denies",
			consentPurposes: []string{grantedPurpose},
			requestPurpose:  otherPurpose,
			wantDecision:    DecisionDeny,
		},
		{
			name:            "one of several purposes matching allows",
			consentPurposes: []string{otherPurpose, grantedPurpose},
			requestPurpose:  grantedPurpose,
			wantDecision:    DecisionAllow,
		},
		{
			name:            "a consent covering no purpose denies a purpose-scoped check",
			consentPurposes: nil,
			requestPurpose:  grantedPurpose,
			wantDecision:    DecisionDeny,
		},
		{
			// The caller could not determine a purpose, so it is not part of the
			// match; the consumer match still applies.
			name:            "no requested purpose leaves the check unscoped",
			consentPurposes: []string{grantedPurpose},
			requestPurpose:  "",
			wantDecision:    DecisionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCredCache()
			m := &mockCM{userID: "uid-1", statuses: []string{"granted"}, consentPurposes: tt.consentPurposes}
			srv := newMockCM(t, m)
			c := NewClient(ClientConfig{BaseURL: srv.URL, ParticipantToken: "static", ProviderSD: "sd"})

			resp, err := c.CheckConsent(context.Background(), ConsentRequest{
				Subject: "did:key:zOwner", Consumer: testConsumerSD, Purpose: tt.requestPurpose,
			})
			require.NoError(t, err)
			assert.Equal(t, tt.wantDecision, resp.Decision)
			if tt.wantDecision == DecisionDeny {
				assert.Contains(t, resp.Reason, "no granted consent")
			}
		})
	}
}

// TestFetchProviderSD_Failures covers the derivation of the provider
// self-description from /participants/me. It runs before any consent check, so
// a failure here takes the whole exchange down (fail-closed) — the branches are
// worth pinning.
func TestFetchProviderSD_Failures(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		wantErr    string
		wantNoBody bool
	}{
		{
			name:   "a 401 is reported as unauthorized so the caller can refresh",
			status: http.StatusUnauthorized,
			body:   `{}`,
			// CheckConsent maps the retried-and-still-401 case to this message.
			wantErr: "participant token rejected (401)",
		},
		{
			name:    "a 500 is classified without its body",
			status:  http.StatusInternalServerError,
			body:    `{"error":"boom for alice@example.org"}`,
			wantErr: "participant lookup (/me) returned status 500",
		},
		{
			name:    "an unparseable body errors",
			status:  http.StatusOK,
			body:    `not json`,
			wantErr: "failed to unmarshal /me response",
		},
		{
			name:    "an empty selfDescriptionURL errors",
			status:  http.StatusOK,
			body:    `{"selfDescriptionURL":""}`,
			wantErr: "/me returned no selfDescriptionURL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCredCache()

			mux := http.NewServeMux()
			mux.HandleFunc("/v1/participants/me", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			})
			mux.HandleFunc(tokenServicePath, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token": "tok", "token_type": "Bearer", "expires_in": 3600,
				})
			})
			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)

			c := NewClient(ClientConfig{BaseURL: srv.URL, TokenServiceURL: srv.URL + tokenServicePath, TokenAudience: testAudience})

			_, err := c.CheckConsent(context.Background(), ConsentRequest{Subject: "did:key:z", Consumer: testConsumerSD})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
			assert.NotContains(t, err.Error(), "alice@example.org",
				"a dependency response body must not travel in the error")
		})
	}
}

// TestProviderSelfDescription_StaticOverride verifies a configured provider SD
// is returned without any HTTP call at all.
func TestProviderSelfDescription_StaticOverride(t *testing.T) {
	resetCredCache()
	m := &mockCM{userID: "uid-1", statuses: []string{"granted"}}
	srv := newMockCM(t, m)
	c := NewClient(ClientConfig{BaseURL: srv.URL, ParticipantToken: "static", ProviderSD: "http://catalog/participants/static"})

	sd, err := c.ProviderSelfDescription(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "http://catalog/participants/static", sd)

	m.mu.Lock()
	defer m.mu.Unlock()
	assert.Equal(t, 0, m.meCalls, "a static provider SD must not trigger /me")
	assert.Equal(t, 0, m.tokenCalls, "a static token must not trigger the token service")
}
