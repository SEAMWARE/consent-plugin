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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
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

// testProviderDID is the identifier /participants/me reports for this participant.
const testProviderDID = "did:key:zProvider"

// writeMe answers /participants/me with this participant's identifier and sd.
func writeMe(w http.ResponseWriter, sd string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"identifier": testProviderDID, "selfDescriptionUri": sd})
}

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
		writeMe(w, sd)
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
			if tt.requestConsumer == "none" {
				assert.Equal(t, 0, m.meCalls, "a check without a consumer must not reach the consent-manager")
				assert.Equal(t, 0, m.searchCalls, "a check without a consumer must not reach the consent-manager")
				return
			}
			assert.Equal(t, 1, m.meCalls, "static SD still needs /me for this participant's identifier")
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

// TestCheckConsent_ProviderSDOverride verifies an explicit provider_sd wins over
// the SD from /me, which is still called for this participant's identifier.
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
	assert.Equal(t, 1, m.meCalls, "/me is called for the identifier even with provider_sd")
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
	mux.HandleFunc("/v1/participants/me", func(w http.ResponseWriter, _ *http.Request) { writeMe(w, "") })
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

// registryParticipant is one participant record the mock registry holds.
type registryParticipant struct {
	Identifier         string `json:"identifier"`
	SelfDescriptionURI string `json:"selfDescriptionUri,omitempty"`
	DeregisteredAt     string `json:"deregisteredAt,omitempty"`
}

// participantRegistry is a mock dsc-consent-manager participant registry plus
// /participants/me. status, when set, is returned instead of a page.
type participantRegistry struct {
	mu           sync.Mutex
	entries      []registryParticipant
	status       int
	body         string
	fail401First bool
	calls        int
	lastQuery    string
}

func (r *participantRegistry) set(entries []registryParticipant) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = entries
}

func (r *participantRegistry) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// newParticipantRegistry serves r on /v1/participants (filtered by identifier,
// like the real registry) and /v1/participants/me.
func newParticipantRegistry(t *testing.T, r *participantRegistry) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/participants/me", func(w http.ResponseWriter, _ *http.Request) { writeMe(w, "") })
	mux.HandleFunc("/v1/participants", func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.calls++
		n := r.calls
		r.lastQuery = req.URL.RawQuery
		status, body, entries := r.status, r.body, append([]registryParticipant(nil), r.entries...)
		fail := r.fail401First
		r.mu.Unlock()
		if fail && n == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if status != 0 {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
			return
		}
		if body != "" {
			_, _ = w.Write([]byte(body))
			return
		}
		content := []registryParticipant{}
		for _, e := range entries {
			if e.Identifier == req.URL.Query().Get("identifier") {
				content = append(content, e)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"content": content, "totalElements": len(content)})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// newStaticTokenService serves a token service that always mints "tok".
func newStaticTokenService(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok", "token_type": "Bearer", "expires_in": 3600,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestParticipantSelfDescriptionByDID covers the registry answers: a usable
// participant maps to its SD URI, every final negative is ErrParticipantNotRegistered,
// and statuses are classified by statusError.
func TestParticipantSelfDescriptionByDID(t *testing.T) {
	const did = "did:key:zConsumer"

	tests := []struct {
		name         string
		registry     *participantRegistry
		wantSD       string
		wantSentinel error
		wantErr      string
		wantCalls    int
	}{
		{
			name:      "found",
			registry:  &participantRegistry{entries: []registryParticipant{{Identifier: did, SelfDescriptionURI: testConsumerSD}}},
			wantSD:    testConsumerSD,
			wantCalls: 1,
		},
		{
			name: "first entry with the exact identifier wins",
			registry: &participantRegistry{body: `{"content":[{"identifier":"did:key:zOther","selfDescriptionUri":"http://catalog/other"},` +
				`{"identifier":"` + did + `","selfDescriptionUri":"` + testConsumerSD + `"}]}`},
			wantSD:    testConsumerSD,
			wantCalls: 1,
		},
		{
			name:         "not found",
			registry:     &participantRegistry{},
			wantSentinel: ErrParticipantNotRegistered,
			wantErr:      reasonNotRegistered,
			wantCalls:    1,
		},
		{
			name:         "missing SD URI",
			registry:     &participantRegistry{entries: []registryParticipant{{Identifier: did}}},
			wantSentinel: ErrParticipantNotRegistered,
			wantErr:      reasonNoSelfDescription,
			wantCalls:    1,
		},
		{
			name: "deregistered keeps its SD URI but is not registered",
			registry: &participantRegistry{entries: []registryParticipant{
				{Identifier: did, SelfDescriptionURI: testConsumerSD, DeregisteredAt: "2026-10-01T12:00:00Z"},
			}},
			wantSentinel: ErrParticipantNotRegistered,
			wantErr:      reasonDeregistered,
			wantCalls:    1,
		},
		{
			name: "401 refreshes the token and retries once",
			registry: &participantRegistry{
				entries:      []registryParticipant{{Identifier: did, SelfDescriptionURI: testConsumerSD}},
				fail401First: true,
			},
			wantSD:    testConsumerSD,
			wantCalls: 2,
		},
		{
			name:         "401 after the refresh is an auth error",
			registry:     &participantRegistry{status: http.StatusUnauthorized},
			wantSentinel: ErrConsentManagerAuth,
			wantCalls:    2,
		},
		{
			name:         "403 is an auth error",
			registry:     &participantRegistry{status: http.StatusForbidden},
			wantSentinel: ErrConsentManagerAuth,
			wantErr:      "may be deregistered",
			wantCalls:    1,
		},
		{
			name:         "404 from a wrong prefix is rejected",
			registry:     &participantRegistry{status: http.StatusNotFound},
			wantSentinel: ErrConsentManagerRejected,
			wantCalls:    1,
		},
		{
			name:      "429 is retryable",
			registry:  &participantRegistry{status: http.StatusTooManyRequests},
			wantErr:   "participants lookup returned status 429",
			wantCalls: 1,
		},
		{
			name:      "5xx is retryable and keeps the body out",
			registry:  &participantRegistry{status: http.StatusBadGateway, body: `{"error":"boom for alice@example.org"}`},
			wantErr:   "participants lookup returned status 502",
			wantCalls: 1,
		},
		{
			name:      "malformed JSON",
			registry:  &participantRegistry{body: `<html>gateway error</html>`},
			wantErr:   "failed to unmarshal participants response",
			wantCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCredCache()
			registry := tt.registry
			srv := newParticipantRegistry(t, registry)
			c := NewClient(ClientConfig{
				BaseURL: srv.URL, ProviderSD: "sd",
				TokenServiceURL: newStaticTokenService(t).URL, TokenAudience: testAudience,
			})

			sd, err := c.ParticipantSelfDescriptionByDID(context.Background(), did)
			assert.Equal(t, tt.wantCalls, registry.callCount())
			if tt.wantSentinel == nil && tt.wantErr == "" {
				require.NoError(t, err)
				assert.Equal(t, tt.wantSD, sd)
				assert.Equal(t, "identifier="+url.QueryEscape(did), registry.lastQuery)
				return
			}
			require.Error(t, err)
			if tt.wantSentinel != nil {
				assert.ErrorIs(t, err, tt.wantSentinel)
			} else {
				for _, final := range []error{ErrParticipantNotRegistered, ErrConsentManagerAuth, ErrConsentManagerRejected} {
					assert.NotErrorIs(t, err, final, "a retryable failure must stay subject to fail_open")
				}
			}
			assert.Contains(t, err.Error(), tt.wantErr)
			assert.NotContains(t, err.Error(), did, "the DID is fingerprinted, never embedded")
			assert.NotContains(t, err.Error(), "alice@example.org", "a dependency body must not travel in the error")
		})
	}
}

// TestParticipantSelfDescriptionByDID_NegativeCaching verifies every negative
// answer is remembered, so a misconfigured or departed DID does not query the
// registry on every request.
func TestParticipantSelfDescriptionByDID_NegativeCaching(t *testing.T) {
	const did = "did:key:zConsumer"
	tests := []struct {
		name    string
		entries []registryParticipant
		reason  string
	}{
		{"unknown", nil, reasonNotRegistered},
		{"deregistered", []registryParticipant{{Identifier: did, SelfDescriptionURI: testConsumerSD, DeregisteredAt: "2026-10-01T12:00:00Z"}}, reasonDeregistered},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCredCache()
			registry := &participantRegistry{entries: tt.entries}
			srv := newParticipantRegistry(t, registry)
			c := NewClient(ClientConfig{BaseURL: srv.URL, ParticipantToken: "static", ProviderSD: "sd"})

			for i := 0; i < 3; i++ {
				_, err := c.ParticipantSelfDescriptionByDID(context.Background(), did)
				require.ErrorIs(t, err, ErrParticipantNotRegistered)
				assert.Contains(t, err.Error(), tt.reason)
			}
			assert.Equal(t, 1, registry.callCount(), "a negative answer must be remembered, not re-fetched per request")
		})
	}
}

// TestParticipantSelfDescriptionByDID_DeregisteredAfterCaching pins the accepted
// window: a DID cached as registered keeps passing until its positive entry
// expires, and is then denied as deregistered.
func TestParticipantSelfDescriptionByDID_DeregisteredAfterCaching(t *testing.T) {
	const did = "did:key:zConsumer"
	resetCredCache()
	registry := &participantRegistry{entries: []registryParticipant{{Identifier: did, SelfDescriptionURI: testConsumerSD}}}
	srv := newParticipantRegistry(t, registry)
	c := NewClient(ClientConfig{BaseURL: srv.URL, ParticipantToken: "static", ProviderSD: "sd"})

	sd, err := c.ParticipantSelfDescriptionByDID(context.Background(), did)
	require.NoError(t, err)
	require.Equal(t, testConsumerSD, sd)

	registry.set([]registryParticipant{{Identifier: did, SelfDescriptionURI: testConsumerSD, DeregisteredAt: "2026-10-01T12:00:00Z"}})

	sd, err = c.ParticipantSelfDescriptionByDID(context.Background(), did)
	require.NoError(t, err, "the positive entry still holds before participantSDCacheTTL")
	assert.Equal(t, testConsumerSD, sd)
	assert.Equal(t, 1, registry.callCount())

	key := c.cacheKey() + credentialKeySeparator + did
	participantSDMu.Lock()
	entry := participantSDCache[key]
	entry.expiry = time.Now().Add(-time.Second)
	participantSDCache[key] = entry
	participantSDMu.Unlock()

	_, err = c.ParticipantSelfDescriptionByDID(context.Background(), did)
	require.ErrorIs(t, err, ErrParticipantNotRegistered)
	assert.Contains(t, err.Error(), reasonDeregistered)
	assert.Equal(t, 2, registry.callCount())
}

// TestStatusError pins the status classification shared by every consent-manager call.
func TestStatusError(t *testing.T) {
	tests := []struct {
		status       int
		wantSentinel error
	}{
		{http.StatusBadRequest, ErrConsentManagerRejected},
		{http.StatusUnauthorized, ErrConsentManagerAuth},
		{http.StatusForbidden, ErrConsentManagerAuth},
		{http.StatusNotFound, ErrConsentManagerRejected},
		{http.StatusMethodNotAllowed, ErrConsentManagerRejected},
		{http.StatusUnprocessableEntity, ErrConsentManagerRejected},
		{http.StatusTooManyRequests, nil},
		{http.StatusInternalServerError, nil},
		{http.StatusServiceUnavailable, nil},
	}
	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.status), func(t *testing.T) {
			err := statusError("op", tt.status, []byte(`{"secret":"alice@example.org"}`))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "op returned status "+strconv.Itoa(tt.status))
			assert.NotContains(t, err.Error(), "alice@example.org")
			assert.Equal(t, tt.status == http.StatusUnauthorized, errors.Is(err, errParticipantUnauthorized),
				"only a 401 is worth a token refresh")
			if tt.wantSentinel != nil {
				assert.ErrorIs(t, err, tt.wantSentinel)
				return
			}
			assert.NotErrorIs(t, err, ErrConsentManagerAuth)
			assert.NotErrorIs(t, err, ErrConsentManagerRejected)
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

// TestFetchSelf_Failures covers GET /participants/me. It runs before any
// consent check, so a failure here takes the whole exchange down — the branches,
// and which of them fail_open may never release on, are worth pinning.
func TestFetchSelf_Failures(t *testing.T) {
	tests := []struct {
		name         string
		status       int
		body         string
		wantErr      string
		wantSentinel error
	}{
		{
			name:         "a 401 after one refresh is an auth error",
			status:       http.StatusUnauthorized,
			body:         `{}`,
			wantErr:      "participant lookup (/me) returned status 401",
			wantSentinel: ErrConsentManagerAuth,
		},
		{
			name:         "a 403 is an auth error",
			status:       http.StatusForbidden,
			body:         `{}`,
			wantErr:      "may be deregistered",
			wantSentinel: ErrConsentManagerAuth,
		},
		{
			name:         "a 404 from a wrong prefix is rejected",
			status:       http.StatusNotFound,
			body:         `{}`,
			wantErr:      "participant lookup (/me) returned status 404",
			wantSentinel: ErrConsentManagerRejected,
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
			name:         "a missing identifier is rejected",
			status:       http.StatusOK,
			body:         `{"selfDescriptionUri":"http://facade/sd"}`,
			wantErr:      "/me returned no identifier",
			wantSentinel: ErrConsentManagerRejected,
		},
		{
			name:    "an empty selfDescriptionUri errors without a configured provider_sd",
			status:  http.StatusOK,
			body:    `{"identifier":"did:key:zProvider","selfDescriptionUri":""}`,
			wantErr: "/me returned no selfDescriptionUri",
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
			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)

			c := NewClient(ClientConfig{BaseURL: srv.URL, TokenServiceURL: newStaticTokenService(t).URL, TokenAudience: testAudience})

			_, err := c.ProviderSelfDescription(context.Background())
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
			if tt.wantSentinel != nil {
				assert.ErrorIs(t, err, tt.wantSentinel)
			}
			assert.NotContains(t, err.Error(), "alice@example.org",
				"a dependency response body must not travel in the error")
		})
	}
}

// TestCredentials_SelfIdentifier verifies credentials carries this participant's
// identifier from /me in every configuration, including a fully static one.
func TestCredentials_SelfIdentifier(t *testing.T) {
	tests := []struct {
		name   string
		cfg    func(srvURL string) ClientConfig
		wantSD string
	}{
		{
			name: "token service, SD from /me",
			cfg: func(u string) ClientConfig {
				return ClientConfig{BaseURL: u, TokenServiceURL: u + tokenServicePath, TokenAudience: testAudience}
			},
			wantSD: "http://facade/derived",
		},
		{
			name: "static token and provider_sd",
			cfg: func(u string) ClientConfig {
				return ClientConfig{BaseURL: u, ParticipantToken: "static", ProviderSD: "http://facade/explicit"}
			},
			wantSD: "http://facade/explicit",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCredCache()
			m := &mockCM{selfDescriptionURL: "http://facade/derived"}
			srv := newMockCM(t, m)
			c := NewClient(tt.cfg(srv.URL))

			for i := 0; i < 2; i++ {
				creds, err := c.credentials(context.Background(), false)
				require.NoError(t, err)
				assert.Equal(t, testProviderDID, creds.self)
				assert.Equal(t, tt.wantSD, creds.providerSD)
			}
			m.mu.Lock()
			defer m.mu.Unlock()
			assert.Equal(t, 1, m.meCalls, "/me is called once and cached with the token")
		})
	}
}

// TestProviderSelfDescription_StaticOverride verifies a configured provider SD
// wins, and that a static token skips the token service but not /me.
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
	assert.Equal(t, 1, m.meCalls, "/me is still called for this participant's identifier")
	assert.Equal(t, 0, m.tokenCalls, "a static token must not trigger the token service")
}
