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
	"strings"
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

// testConsumerSD is the self-description URL of the consuming participant; it is
// what the registry maps testConsumerDID to, and never what a consent names.
const testConsumerSD = "http://catalog/participants/consumer"

// testProviderDID is the identifier /participants/me reports for this participant.
const testProviderDID = "did:key:zProvider"

// Identities and scopes of the consent the tests grant.
const (
	testConsumerDID  = "did:key:zConsumer"
	testOwnerDID     = "did:key:zOwner"
	testConsentID    = "3f2b8c1e-5a4d-4e6f-9b7a-1c2d3e4f5a6b"
	testNoticeID     = "7d9e0f1a-2b3c-4d5e-8f6a-7b8c9d0e1f2a"
	testContractURI  = "https://catalog/contracts/trip-insurance"
	testPurpose      = "Calculating an insurance quote from trip records."
	testDataCategory = "Trip records"
)

// legacyConsentKeyMarker is part of the name of the consent-key header the old
// consent-manager required; no request may carry such a header any more.
const legacyConsentKeyMarker = "consent-key"

// malformedJSONBody is a 200 body that does not decode as JSON.
const malformedJSONBody = `{"content": [`

// writeMe answers /participants/me with this participant's identifier and sd.
func writeMe(w http.ResponseWriter, sd string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"identifier": testProviderDID, "selfDescriptionUri": sd})
}

// writeJSON answers with v as a JSON body.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// grantedConsent is a consent that matches every scope of matchingRequest.
func grantedConsent() consentRecord {
	return consentRecord{
		ID:              testConsentID,
		PrivacyNoticeID: testNoticeID,
		Consented:       true,
		Provider:        testProviderDID,
		Consumer:        testConsumerDID,
		Purposes:        []string{testPurpose},
		ContractURI:     testContractURI,
	}
}

// matchingRequest is a fully scoped request that grantedConsent satisfies.
func matchingRequest(mode Mode) ConsentRequest {
	return ConsentRequest{
		Subject:         testOwnerDID,
		Consumer:        testConsumerDID,
		Mode:            mode,
		PrivacyNoticeID: testNoticeID,
		ContractURI:     testContractURI,
		Purpose:         testPurpose,
	}
}

// wireConsent is the ConsentResponse JSON the mock serves for r, with data[]
// set to a notice category that matches no resource identifier.
func wireConsent(r consentRecord) map[string]any {
	raw, _ := json.Marshal(r)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	out["data"] = []string{testDataCategory}
	return out
}

// mockCM is a configurable dsc-consent-manager fake: the participant-local token
// service (served on the same test server for convenience), /participants/me,
// GET /consents (list), GET /consents/check and GET /consents/{id}.
type mockCM struct {
	mu sync.Mutex
	// behaviour
	consents           []consentRecord          // what GET /consents pages through
	pageSize           int                      // overrides the requested page size when > 0
	validity           consentValidity          // what GET /consents/check answers
	byID               map[string]consentRecord // what GET /consents/{id} answers (missing => 404)
	selfDescriptionURL string                   // /me result
	tokenStatus        int                      // non-200 => the token service fails with this status
	// failStatuses are answered, in order, by the list/check endpoint before it succeeds.
	failStatuses []int
	readStatus   int // non-zero => GET /consents/{id} answers with it
	// malformedBody / malformedRead answer 200 with an undecodable body on the
	// list/check endpoint / the consent read.
	malformedBody, malformedRead bool
	delay                        time.Duration // delays every consent endpoint
	// recording
	tokenCalls, meCalls, listCalls, checkCalls, readCalls int
	lastQuery, lastReadQuery                              url.Values
	lastAuth, lastTokenAudience                           string
	sawConsentKey                                         bool
	tokenCounter                                          int
}

// record notes a consent-endpoint request; the caller holds m.mu.
func (m *mockCM) record(r *http.Request) {
	m.lastAuth = r.Header.Get("Authorization")
	for name := range r.Header {
		if strings.Contains(strings.ToLower(name), legacyConsentKeyMarker) {
			m.sawConsentKey = true
		}
	}
}

// nextFailure pops the next queued failure status, or 0; the caller holds m.mu.
func (m *mockCM) nextFailure() int {
	if len(m.failStatuses) == 0 {
		return 0
	}
	st := m.failStatuses[0]
	m.failStatuses = m.failStatuses[1:]
	return st
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
		writeJSON(w, map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": 3600})
	})

	mux.HandleFunc("GET /v1/participants/me", func(w http.ResponseWriter, _ *http.Request) {
		m.mu.Lock()
		m.meCalls++
		sd := m.selfDescriptionURL
		m.mu.Unlock()
		writeMe(w, sd)
	})

	mux.HandleFunc("GET /v1/consents", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.listCalls++
		m.record(r)
		m.lastQuery = r.URL.Query()
		fail := m.nextFailure()
		consents := append([]consentRecord(nil), m.consents...)
		size := m.pageSize
		delay, malformed := m.delay, m.malformedBody
		m.mu.Unlock()
		time.Sleep(delay)
		if fail != 0 {
			w.WriteHeader(fail)
			return
		}
		if malformed {
			writeMalformed(w)
			return
		}
		if size <= 0 {
			size, _ = strconv.Atoi(r.URL.Query().Get(sizeQueryParam))
		}
		page, _ := strconv.Atoi(r.URL.Query().Get(pageQueryParam))
		content := []map[string]any{}
		for i := page * size; i < (page+1)*size && i < len(consents); i++ {
			content = append(content, wireConsent(consents[i]))
		}
		writeJSON(w, map[string]any{
			"content": content, "page": page, "size": size,
			"totalElements": len(consents), "totalPages": (len(consents) + size - 1) / size,
		})
	})

	mux.HandleFunc("GET /v1/consents/check", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.checkCalls++
		m.record(r)
		m.lastQuery = r.URL.Query()
		fail := m.nextFailure()
		validity := m.validity
		delay, malformed := m.delay, m.malformedBody
		m.mu.Unlock()
		time.Sleep(delay)
		if fail != 0 {
			w.WriteHeader(fail)
			return
		}
		if malformed {
			writeMalformed(w)
			return
		}
		writeJSON(w, map[string]any{
			"valid": validity.Valid, "consentId": validity.ConsentID, "reason": validity.Reason,
			"checkedAt": "2026-11-02T08:00:00Z",
		})
	})

	mux.HandleFunc("GET /v1/consents/{id}", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.readCalls++
		m.record(r)
		m.lastReadQuery = r.URL.Query()
		record, found := m.byID[r.PathValue("id")]
		status, malformed := m.readStatus, m.malformedRead
		m.mu.Unlock()
		switch {
		case status != 0:
			w.WriteHeader(status)
		case malformed:
			writeMalformed(w)
		case !found:
			w.WriteHeader(http.StatusNotFound)
		default:
			writeJSON(w, wireConsent(record))
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// writeMalformed answers 200 with a body that does not decode as JSON.
func writeMalformed(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(malformedJSONBody))
}

// grantingMock serves grantedConsent in both modes.
func grantingMock() *mockCM {
	return &mockCM{
		selfDescriptionURL: "http://facade/participants/provider",
		consents:           []consentRecord{grantedConsent()},
		validity:           consentValidity{Valid: true, ConsentID: testConsentID},
		byID:               map[string]consentRecord{testConsentID: grantedConsent()},
	}
}

// staticClient is a client with a static token, so only /me precedes a check.
func staticClient(srvURL string) *Client {
	return NewClient(ClientConfig{BaseURL: srvURL, ParticipantToken: "static-token", ProviderSD: "http://facade/sd"})
}

// tokenServiceClient fetches its token from the mock's token service.
func tokenServiceClient(srvURL string) *Client {
	return NewClient(ClientConfig{BaseURL: srvURL, TokenServiceURL: srvURL + tokenServicePath, TokenAudience: testAudience})
}

// bothModes are the modes every mode-independent behaviour is checked in.
var bothModes = []Mode{ModeList, ModeCheck}

// resetCredCache clears the package-wide caches between tests.
func resetCredCache() { ResetCaches() }

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

// TestMatchConsent pins every leg of the matcher both modes share.
func TestMatchConsent(t *testing.T) {
	tests := []struct {
		name   string
		noSelf bool
		req    func(*ConsentRequest)
		record func(*consentRecord)
		want   bool
	}{
		{name: "fully scoped match", want: true},
		{name: "unscoped request matches on consumer and provider", want: true, req: func(r *ConsentRequest) {
			r.ContractURI, r.PrivacyNoticeID, r.Purpose = "", "", ""
		}},
		{name: "one of several purposes", want: true, record: func(c *consentRecord) {
			c.Purposes = []string{"Research.", testPurpose}
		}},
		{name: "data resource is never matched", want: true, req: func(r *ConsentRequest) {
			r.DataResource = "urn:ngsi-ld:Trip:1"
		}},
		{name: "notice id ignored when the request has none", want: true, req: func(r *ConsentRequest) {
			r.PrivacyNoticeID = ""
		}, record: func(c *consentRecord) { c.PrivacyNoticeID = "11111111-2222-4333-8444-555555555555" }},
		{name: "not consented", record: func(c *consentRecord) { c.Consented = false }},
		{
			// This participant is the consumer of another provider's consent.
			name: "wrong provider", req: func(r *ConsentRequest) { r.Consumer = testProviderDID },
			record: func(c *consentRecord) { c.Provider, c.Consumer = "did:key:zOtherProvider", testProviderDID },
		},
		{name: "unknown self", noSelf: true},
		{name: "wrong consumer", record: func(c *consentRecord) { c.Consumer = "did:key:zSomeoneElse" }},
		{name: "consumer SD URL instead of DID", req: func(r *ConsentRequest) { r.Consumer = testConsumerSD }},
		{
			name: "no consumer on either side", req: func(r *ConsentRequest) { r.Consumer = "" },
			record: func(c *consentRecord) { c.Consumer = "" },
		},
		{name: "wrong contract", record: func(c *consentRecord) { c.ContractURI = "https://catalog/contracts/other" }},
		{name: "wrong notice id", record: func(c *consentRecord) {
			c.PrivacyNoticeID = "11111111-2222-4333-8444-555555555555"
		}},
		{name: "wrong purpose", record: func(c *consentRecord) { c.Purposes = []string{"Research."} }},
		{name: "purpose differs in case", req: func(r *ConsentRequest) { r.Purpose = strings.ToUpper(testPurpose) }},
		{name: "no purposes on the consent", record: func(c *consentRecord) { c.Purposes = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, record, self := matchingRequest(ModeList), grantedConsent(), testProviderDID
			if tt.req != nil {
				tt.req(&req)
			}
			if tt.record != nil {
				tt.record(&record)
			}
			if tt.noSelf {
				self = ""
			}
			assert.Equal(t, tt.want, matchConsent(req, self, record))
		})
	}
}

// TestCheckConsent_ListMode covers GET /consents: query, paging and matching.
func TestCheckConsent_ListMode(t *testing.T) {
	otherConsumer := grantedConsent()
	otherConsumer.Consumer = "did:key:zSomeoneElse"
	// A consent in which this participant is the consumer of another provider.
	asConsumer := grantedConsent()
	asConsumer.Provider, asConsumer.Consumer = "did:key:zOtherProvider", testProviderDID

	tests := []struct {
		name          string
		consents      []consentRecord
		pageSize      int
		req           func(*ConsentRequest)
		wantDecision  Decision
		wantListCalls int
	}{
		{name: "match", consents: []consentRecord{grantedConsent()}, wantDecision: DecisionAllow, wantListCalls: 1},
		{name: "no consents", wantDecision: DecisionDeny, wantListCalls: 1},
		{name: "granted to another consumer", consents: []consentRecord{otherConsumer}, wantDecision: DecisionDeny, wantListCalls: 1},
		{
			name: "this participant as consumer of another provider", consents: []consentRecord{asConsumer},
			req: func(r *ConsentRequest) { r.Consumer = testProviderDID }, wantDecision: DecisionDeny, wantListCalls: 1,
		},
		{
			name: "match on page 2", consents: []consentRecord{otherConsumer, grantedConsent()}, pageSize: 1,
			wantDecision: DecisionAllow, wantListCalls: 2,
		},
		{
			name: "no match across pages", consents: []consentRecord{otherConsumer, otherConsumer}, pageSize: 1,
			wantDecision: DecisionDeny, wantListCalls: 2,
		},
		{
			name: "data categories do not block a resource-scoped request", consents: []consentRecord{grantedConsent()},
			req: func(r *ConsentRequest) { r.DataResource = "urn:ngsi-ld:Trip:1" }, wantDecision: DecisionAllow, wantListCalls: 1,
		},
		{
			name: "no notice id sends no notice filter", consents: []consentRecord{grantedConsent()},
			req: func(r *ConsentRequest) { r.PrivacyNoticeID = "" }, wantDecision: DecisionAllow, wantListCalls: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCredCache()
			m := &mockCM{consents: tt.consents, pageSize: tt.pageSize}
			srv := newMockCM(t, m)
			req := matchingRequest(ModeList)
			if tt.req != nil {
				tt.req(&req)
			}

			resp, err := staticClient(srv.URL).CheckConsent(context.Background(), req)
			require.NoError(t, err)
			assert.Equal(t, tt.wantDecision, resp.Decision)
			if tt.wantDecision == DecisionAllow {
				assert.Equal(t, testConsentID, resp.ConsentID)
			} else {
				assert.Contains(t, resp.Reason, "no granted consent for consumer "+req.Consumer)
			}

			m.mu.Lock()
			defer m.mu.Unlock()
			assert.Equal(t, tt.wantListCalls, m.listCalls)
			assert.Equal(t, 0, m.checkCalls+m.readCalls, "list mode never calls check or read")
			assert.Equal(t, testOwnerDID, m.lastQuery.Get(userIdentifierQueryParam))
			assert.Equal(t, strconv.Itoa(consentListPageSize), m.lastQuery.Get(sizeQueryParam))
			assert.Equal(t, strconv.Itoa(tt.wantListCalls-1), m.lastQuery.Get(pageQueryParam))
			assert.Equal(t, req.PrivacyNoticeID, m.lastQuery.Get(privacyNoticeIDQueryParam))
			assert.Equal(t, req.PrivacyNoticeID != "", m.lastQuery.Has(privacyNoticeIDQueryParam))
		})
	}
}

// TestCheckConsent_ListPageCap verifies paging stops at maxConsentListPages and
// denies, even when a match would follow.
func TestCheckConsent_ListPageCap(t *testing.T) {
	resetCredCache()
	other := grantedConsent()
	other.Consumer = "did:key:zSomeoneElse"
	consents := make([]consentRecord, 0, maxConsentListPages+1)
	for range maxConsentListPages {
		consents = append(consents, other)
	}
	m := &mockCM{consents: append(consents, grantedConsent()), pageSize: 1}
	srv := newMockCM(t, m)

	resp, err := staticClient(srv.URL).CheckConsent(context.Background(), matchingRequest(ModeList))
	require.NoError(t, err)
	assert.Equal(t, DecisionDeny, resp.Decision)
	assert.Contains(t, resp.Reason, fmt.Sprintf("in the first %d consent pages", maxConsentListPages))
	m.mu.Lock()
	defer m.mu.Unlock()
	assert.Equal(t, maxConsentListPages, m.listCalls)
}

// TestCheckConsent_CheckMode covers GET /consents/check and the mandatory
// consent read whose record must pass matchConsent.
func TestCheckConsent_CheckMode(t *testing.T) {
	tests := []struct {
		name         string
		validity     consentValidity
		record       func(*consentRecord) // mutates the record the read returns
		readMissing  bool
		req          func(*ConsentRequest)
		wantDecision Decision
		wantReason   string
		wantRead     bool
	}{
		{
			name: "valid and matching", validity: consentValidity{Valid: true, ConsentID: testConsentID},
			wantDecision: DecisionAllow, wantRead: true,
		},
		{
			name: "valid, no purpose sent", validity: consentValidity{Valid: true, ConsentID: testConsentID},
			req: func(r *ConsentRequest) { r.Purpose = "" }, wantDecision: DecisionAllow, wantRead: true,
		},
		{
			name: "provider mismatch", validity: consentValidity{Valid: true, ConsentID: testConsentID},
			record: func(c *consentRecord) { c.Provider = "did:key:zOtherProvider" }, wantDecision: DecisionDeny,
			wantReason: "does not match", wantRead: true,
		},
		{
			name: "consumer mismatch", validity: consentValidity{Valid: true, ConsentID: testConsentID},
			record: func(c *consentRecord) { c.Consumer = "did:key:zSomeoneElse" }, wantDecision: DecisionDeny,
			wantReason: "does not match", wantRead: true,
		},
		{
			name: "contract mismatch", validity: consentValidity{Valid: true, ConsentID: testConsentID},
			record: func(c *consentRecord) { c.ContractURI = "https://catalog/contracts/other" }, wantDecision: DecisionDeny,
			wantReason: "does not match", wantRead: true,
		},
		{
			name: "notice id mismatch", validity: consentValidity{Valid: true, ConsentID: testConsentID},
			record:       func(c *consentRecord) { c.PrivacyNoticeID = "11111111-2222-4333-8444-555555555555" },
			wantDecision: DecisionDeny, wantReason: "does not match", wantRead: true,
		},
		{
			name: "not valid", validity: consentValidity{Valid: false, Reason: "No consent is in force for did:key:zOwner."},
			wantDecision: DecisionDeny, wantReason: consentNotInForceReason,
		},
		{
			name: "valid without consentId", validity: consentValidity{Valid: true},
			wantDecision: DecisionDeny, wantReason: "no usable consentId",
		},
		{
			name: "valid with a non-UUID consentId", validity: consentValidity{Valid: true, ConsentID: "../participants/me"},
			wantDecision: DecisionDeny, wantReason: "no usable consentId",
		},
		{
			name: "404 on the consent read", validity: consentValidity{Valid: true, ConsentID: testConsentID},
			readMissing: true, wantDecision: DecisionDeny, wantReason: "not readable", wantRead: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCredCache()
			record := grantedConsent()
			if tt.record != nil {
				tt.record(&record)
			}
			m := &mockCM{validity: tt.validity, byID: map[string]consentRecord{testConsentID: record}}
			if tt.readMissing {
				m.byID = nil
			}
			srv := newMockCM(t, m)
			req := matchingRequest(ModeCheck)
			if tt.req != nil {
				tt.req(&req)
			}

			resp, err := staticClient(srv.URL).CheckConsent(context.Background(), req)
			require.NoError(t, err)
			assert.Equal(t, tt.wantDecision, resp.Decision)
			assert.Contains(t, resp.Reason, tt.wantReason)
			if tt.validity.Reason != "" {
				assert.NotContains(t, resp.Reason, tt.validity.Reason, "the server's free-text reason stays out of the verdict")
			}
			if tt.wantDecision == DecisionAllow {
				assert.Equal(t, testConsentID, resp.ConsentID)
			}

			m.mu.Lock()
			defer m.mu.Unlock()
			assert.Equal(t, 1, m.checkCalls)
			assert.Equal(t, 0, m.listCalls, "check mode never lists")
			assert.Equal(t, testOwnerDID, m.lastQuery.Get(userIdentifierQueryParam))
			assert.Equal(t, testNoticeID, m.lastQuery.Get(privacyNoticeIDQueryParam))
			assert.Equal(t, req.Purpose, m.lastQuery.Get(purposeQueryParam))
			assert.Equal(t, req.Purpose != "", m.lastQuery.Has(purposeQueryParam))
			if !tt.wantRead {
				assert.Equal(t, 0, m.readCalls, "no consent read without a usable consentId")
				return
			}
			assert.Equal(t, 1, m.readCalls)
			assert.Equal(t, url.Values{formatQueryParam: {consentFormatFull}}, m.lastReadQuery)
		})
	}
}

// TestCheckConsent_ZeroModeIsList verifies an unset Mode is list mode.
func TestCheckConsent_ZeroModeIsList(t *testing.T) {
	resetCredCache()
	m := grantingMock()
	srv := newMockCM(t, m)
	req := matchingRequest(ModeList)
	req.Mode = ""

	resp, err := staticClient(srv.URL).CheckConsent(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, DecisionAllow, resp.Decision)

	m.mu.Lock()
	defer m.mu.Unlock()
	assert.Equal(t, 1, m.listCalls)
	assert.Zero(t, m.checkCalls)
}

// TestCheckConsent_RequestGuards verifies the requests that deny before any call.
func TestCheckConsent_RequestGuards(t *testing.T) {
	tests := []struct {
		name       string
		req        func(*ConsentRequest)
		wantReason string
	}{
		{name: "no subject", req: func(r *ConsentRequest) { r.Subject = "" }, wantReason: "no subject"},
		{name: "no consumer", req: func(r *ConsentRequest) { r.Consumer = "" }, wantReason: "no consuming participant"},
		{name: "check mode without notice id", req: func(r *ConsentRequest) {
			r.Mode, r.PrivacyNoticeID = ModeCheck, ""
		}, wantReason: "needs a privacy notice id"},
		{name: "non-UUID notice id", req: func(r *ConsentRequest) { r.PrivacyNoticeID = "notice-1" }, wantReason: "not a UUID"},
		{name: "unknown mode", req: func(r *ConsentRequest) { r.Mode = "lsit" }, wantReason: "unknown consent check mode"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCredCache()
			m := grantingMock()
			srv := newMockCM(t, m)
			req := matchingRequest(ModeList)
			tt.req(&req)

			resp, err := tokenServiceClient(srv.URL).CheckConsent(context.Background(), req)
			require.NoError(t, err)
			assert.Equal(t, DecisionDeny, resp.Decision)
			assert.Contains(t, resp.Reason, tt.wantReason)

			m.mu.Lock()
			defer m.mu.Unlock()
			assert.Zero(t, m.tokenCalls+m.meCalls+m.listCalls+m.checkCalls+m.readCalls, "a guarded request reaches nothing")
		})
	}
}

// TestCheckConsent_StatusMapping verifies, in both modes, how consent-endpoint
// statuses map to a refresh, a final sentinel or a retryable error.
func TestCheckConsent_StatusMapping(t *testing.T) {
	tests := []struct {
		name           string
		failStatuses   []int
		readStatus     int  // check mode only
		malformedBody  bool // 200 with an undecodable body on the list/check endpoint
		malformedRead  bool // check mode only
		wantAllow      bool
		wantSentinel   error
		wantTokenCalls int
	}{
		{name: "401 then ok refreshes once", failStatuses: []int{http.StatusUnauthorized}, wantAllow: true, wantTokenCalls: 2},
		{
			name: "401 twice", failStatuses: []int{http.StatusUnauthorized, http.StatusUnauthorized},
			wantSentinel: ErrConsentManagerAuth, wantTokenCalls: 2,
		},
		{name: "403", failStatuses: []int{http.StatusForbidden}, wantSentinel: ErrConsentManagerAuth, wantTokenCalls: 1},
		{name: "400", failStatuses: []int{http.StatusBadRequest}, wantSentinel: ErrConsentManagerRejected, wantTokenCalls: 1},
		{name: "404 on the endpoint", failStatuses: []int{http.StatusNotFound}, wantSentinel: ErrConsentManagerRejected, wantTokenCalls: 1},
		{name: "429", failStatuses: []int{http.StatusTooManyRequests}, wantTokenCalls: 1},
		{name: "500", failStatuses: []int{http.StatusInternalServerError}, wantTokenCalls: 1},
		{name: "403 on the consent read", readStatus: http.StatusForbidden, wantSentinel: ErrConsentManagerAuth, wantTokenCalls: 1},
		{name: "400 on the consent read", readStatus: http.StatusBadRequest, wantSentinel: ErrConsentManagerRejected, wantTokenCalls: 1},
		{name: "500 on the consent read", readStatus: http.StatusInternalServerError, wantTokenCalls: 1},
		{name: "malformed 200 body", malformedBody: true, wantTokenCalls: 1},
		{name: "malformed 200 body on the consent read", malformedRead: true, wantTokenCalls: 1},
	}
	for _, mode := range bothModes {
		for _, tt := range tests {
			if (tt.readStatus != 0 || tt.malformedRead) && mode != ModeCheck {
				continue
			}
			t.Run(string(mode)+"/"+tt.name, func(t *testing.T) {
				resetCredCache()
				m := grantingMock()
				m.failStatuses, m.readStatus = tt.failStatuses, tt.readStatus
				m.malformedBody, m.malformedRead = tt.malformedBody, tt.malformedRead
				srv := newMockCM(t, m)

				resp, err := tokenServiceClient(srv.URL).CheckConsent(context.Background(), matchingRequest(mode))

				m.mu.Lock()
				defer m.mu.Unlock()
				assert.Equal(t, tt.wantTokenCalls, m.tokenCalls)
				if tt.wantAllow {
					require.NoError(t, err)
					assert.Equal(t, DecisionAllow, resp.Decision)
					assert.Equal(t, "Bearer token-2", m.lastAuth, "the retry uses the refreshed token")
					return
				}
				require.Error(t, err)
				if tt.wantSentinel != nil {
					assert.ErrorIs(t, err, tt.wantSentinel)
					return
				}
				assert.NotErrorIs(t, err, ErrConsentManagerAuth)
				assert.NotErrorIs(t, err, ErrConsentManagerRejected)
			})
		}
	}
}

// TestCheckConsent_Timeout verifies a slow consent-manager is a retryable error.
func TestCheckConsent_Timeout(t *testing.T) {
	const (
		clientTimeoutMs = 50
		serverDelay     = 200 * time.Millisecond
	)
	for _, mode := range bothModes {
		t.Run(string(mode), func(t *testing.T) {
			resetCredCache()
			m := grantingMock()
			m.delay = serverDelay
			srv := newMockCM(t, m)
			c := NewClient(ClientConfig{BaseURL: srv.URL, ParticipantToken: "static", ProviderSD: "sd", TimeoutMs: clientTimeoutMs})

			_, err := c.CheckConsent(context.Background(), matchingRequest(mode))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "HTTP request failed")
			assert.NotErrorIs(t, err, ErrConsentManagerAuth)
			assert.NotErrorIs(t, err, ErrConsentManagerRejected)
		})
	}
}

// TestCheckConsent_BearerOnly verifies every consent call carries the bearer
// token and no legacy consent-key header.
func TestCheckConsent_BearerOnly(t *testing.T) {
	for _, mode := range bothModes {
		t.Run(string(mode), func(t *testing.T) {
			resetCredCache()
			m := grantingMock()
			srv := newMockCM(t, m)

			resp, err := staticClient(srv.URL).CheckConsent(context.Background(), matchingRequest(mode))
			require.NoError(t, err)
			assert.Equal(t, DecisionAllow, resp.Decision)

			m.mu.Lock()
			defer m.mu.Unlock()
			assert.Equal(t, "Bearer static-token", m.lastAuth)
			assert.False(t, m.sawConsentKey)
			assert.Equal(t, 0, m.tokenCalls, "static token must not call the token service")
			assert.Equal(t, 1, m.meCalls, "static token still needs /me for this participant's identifier")
		})
	}
}

// TestCheckConsent_NotCached verifies a revocation takes effect on the next check.
func TestCheckConsent_NotCached(t *testing.T) {
	for _, mode := range bothModes {
		t.Run(string(mode), func(t *testing.T) {
			resetCredCache()
			m := grantingMock()
			srv := newMockCM(t, m)
			c := staticClient(srv.URL)

			resp, err := c.CheckConsent(context.Background(), matchingRequest(mode))
			require.NoError(t, err)
			require.Equal(t, DecisionAllow, resp.Decision)

			m.mu.Lock()
			m.consents, m.validity = nil, consentValidity{Valid: false, Reason: "revoked"}
			m.mu.Unlock()

			resp, err = c.CheckConsent(context.Background(), matchingRequest(mode))
			require.NoError(t, err)
			assert.Equal(t, DecisionDeny, resp.Decision)
		})
	}
}

func TestCheckConsent_TokenService(t *testing.T) {
	resetCredCache()
	m := grantingMock()
	m.selfDescriptionURL = "http://facade/participants/derived"
	srv := newMockCM(t, m)

	resp, err := tokenServiceClient(srv.URL).CheckConsent(context.Background(), matchingRequest(ModeList))
	require.NoError(t, err)
	assert.Equal(t, DecisionAllow, resp.Decision)

	m.mu.Lock()
	defer m.mu.Unlock()
	assert.Equal(t, 1, m.tokenCalls)
	assert.Equal(t, testAudience, m.lastTokenAudience)
	assert.Equal(t, 1, m.meCalls)
	assert.Equal(t, "Bearer token-1", m.lastAuth, "the fetched token is used on the consents call")
}

// TestCheckConsent_TokenAndSDCached verifies the token and derived SD are cached
// across calls (token fetch + /me happen once), while consents are re-read.
func TestCheckConsent_TokenAndSDCached(t *testing.T) {
	resetCredCache()
	m := grantingMock()
	srv := newMockCM(t, m)
	c := tokenServiceClient(srv.URL)

	for i := 0; i < 3; i++ {
		resp, err := c.CheckConsent(context.Background(), matchingRequest(ModeList))
		require.NoError(t, err)
		assert.Equal(t, DecisionAllow, resp.Decision)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	assert.Equal(t, 1, m.tokenCalls, "token should be cached across calls")
	assert.Equal(t, 1, m.meCalls, "/me should be cached across calls")
	assert.Equal(t, 3, m.listCalls)
}

// TestCheckConsent_TokenServiceFailure surfaces a token service error.
func TestCheckConsent_TokenServiceFailure(t *testing.T) {
	resetCredCache()
	m := grantingMock()
	m.tokenStatus = http.StatusNotFound
	srv := newMockCM(t, m)

	_, err := tokenServiceClient(srv.URL).CheckConsent(context.Background(), matchingRequest(ModeList))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token service returned status 404")
}

// TestCheckConsent_MissingTokenSource errors when neither a static token nor a
// token service is configured.
func TestCheckConsent_MissingTokenSource(t *testing.T) {
	resetCredCache()
	c := NewClient(ClientConfig{BaseURL: "http://cm:3000"})
	_, err := c.CheckConsent(context.Background(), matchingRequest(ModeList))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no participant_token and no token_service_url")
}

// TestCheckConsent_ConcurrentTokenFetchCoalesced verifies that concurrent first
// requests for the same participant coalesce onto a single token fetch (no
// stampede) and a single /me fetch, rather than one per goroutine.
func TestCheckConsent_ConcurrentTokenFetchCoalesced(t *testing.T) {
	resetCredCache()
	m := grantingMock()
	srv := newMockCM(t, m)

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Same base URL + token service => same cache key, so the fetch must coalesce.
			resp, err := tokenServiceClient(srv.URL).CheckConsent(context.Background(), matchingRequest(ModeList))
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
	assert.Equal(t, 1, m.meCalls, "/me should be fetched once and cached")
}

// TestCheckConsentTransportFailure verifies an unreachable consent-manager errors.
func TestCheckConsentTransportFailure(t *testing.T) {
	resetCredCache()
	c := NewClient(ClientConfig{BaseURL: "http://localhost:1", ParticipantToken: "t", ProviderSD: "sd", TimeoutMs: MinTimeoutMs})
	_, err := c.CheckConsent(context.Background(), matchingRequest(ModeList))
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
	_, err := c.CheckConsent(ctx, matchingRequest(ModeList))
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
	mux.HandleFunc("/v1/consents", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		consentsAuth = append(consentsAuth, r.Header.Get("Authorization"))
		mu.Unlock()
		writeJSON(w, map[string]any{"content": []map[string]any{wireConsent(grantedConsent())}, "totalPages": 1})
	})
	consentManager := httptest.NewServer(mux)
	t.Cleanup(consentManager.Close)

	// One token service per participant, each minting a distinguishable token.
	newTokenService := func(token string) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 3600})
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
		resp, err := c.CheckConsent(context.Background(), matchingRequest(ModeList))
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
	m := &mockCM{}
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
