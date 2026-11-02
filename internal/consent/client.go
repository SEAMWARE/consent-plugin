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
	"bytes"
	"consent-plugin/internal/logging"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Endpoint paths and constants.
const (
	// DefaultAPIPrefix is the consent-manager API prefix prepended to every
	// endpoint path (matches the consent-manager's API_PREFIX).
	DefaultAPIPrefix = "/v1"

	// consentsPath lists the consents the caller is a party to (list mode).
	consentsPath = "/consents"

	// consentCheckPath answers whether a subject's consent to one notice is in force (check mode).
	consentCheckPath = "/consents/check"

	// consentByIDPathFmt reads one consent; %s is the path-escaped consent id.
	consentByIDPathFmt = "/consents/%s"

	// Query keys of the consent endpoints.
	userIdentifierQueryParam  = "userIdentifier"
	privacyNoticeIDQueryParam = "privacyNoticeId"
	purposeQueryParam         = "purpose"
	pageQueryParam            = "page"
	sizeQueryParam            = "size"
	formatQueryParam          = "format"

	// consentFormatFull asks the consent read for a ConsentResponse; the receipt
	// formats carry no provider, consumer or consented field to match on.
	consentFormatFull = "full"

	// consentListPageSize is the page size asked of GET /consents. The server
	// clamps it to its own ceiling, and paging follows its totalPages.
	consentListPageSize = 50

	// maxConsentListPages caps how many pages one list-mode check reads, so an
	// owner with a huge consent history cannot turn one check into an unbounded
	// scan. Hitting the cap without a match denies.
	maxConsentListPages = 20

	// consentNotInForceReason is the fixed deny reason for valid:false; the
	// server's own reason is free text and is only logged at debug level.
	consentNotInForceReason = "consent not in force (check endpoint)"

	// participantMePath returns the calling participant (identifier and selfDescriptionUri).
	participantMePath = "/participants/me"

	// participantsPath is the participant registry, used to map a participant
	// DID to its self-description URI.
	participantsPath = "/participants"

	// identifierQueryParam filters the participant registry by DID.
	identifierQueryParam = "identifier"

	// DefaultTimeoutMs is the default per-call HTTP timeout in milliseconds.
	DefaultTimeoutMs = 5000

	// MinTimeoutMs is the minimum allowed timeout in milliseconds.
	MinTimeoutMs = 1

	// DefaultTokenTTL is how long a participant token obtained via client
	// credentials is cached before re-login. The consent-manager issues 1h
	// tokens, so the default keeps a safety margin.
	DefaultTokenTTL = 50 * time.Minute

	// tokenRefreshSkew is subtracted from a token's cached lifetime so it is never
	// presented in the last moments before it expires.
	tokenRefreshSkew = 60 * time.Second

	// ContentTypeJSON is the Content-Type used for JSON request bodies.
	ContentTypeJSON = "application/json"
)

// ErrConsentManagerAuth signals that the consent-manager refused the participant
// credentials: a 401 that survived one token refresh, or a 403 (the caller may be
// deregistered). Retrying will not fix it, so callers must always fail closed.
var ErrConsentManagerAuth = errors.New("consent client: consent-manager refused the participant credentials")

// ErrConsentManagerRejected signals a permanent 4xx (other than 401, 403 and 429)
// or an unusable answer, e.g. a wrong consent_api_prefix. It is a
// misconfiguration, so callers must always fail closed rather than fail open.
var ErrConsentManagerRejected = errors.New("consent client: consent-manager rejected the request")

// errParticipantUnauthorized signals that the participant token was rejected
// (HTTP 401), so a cached token should be refreshed and the call retried. It
// wraps ErrConsentManagerAuth, so a 401 that survives the retry is already final.
var errParticipantUnauthorized = fmt.Errorf("%w: participant token unauthorized", ErrConsentManagerAuth)

// ErrNoCredentials signals that the client has no way to authenticate as the
// participant at all. It is a misconfiguration, not an availability failure:
// callers must never treat it as a transient error to be failed open on, or a
// mistyped route config becomes a silent, total bypass of the gate.
var ErrNoCredentials = errors.New("consent client: no participant_token and no token_service_url configured")

// ErrParticipantNotRegistered signals that the participant registry answered and
// holds no participant for the requested DID. Like ErrNoCredentials it is a
// permanent condition rather than an outage: retrying will not fix it, so
// callers must not treat it as a transient error to be failed open on.
var ErrParticipantNotRegistered = errors.New("consent client: participant not registered")

// ClientConfig holds everything needed to verify consent against the
// dsc-consent-manager.
type ClientConfig struct {
	// BaseURL is the consent-manager root (e.g. "http://consent-manager:3000").
	BaseURL string
	// APIPrefix is prepended to endpoint paths (defaults to DefaultAPIPrefix).
	APIPrefix string
	// ProviderSD, if empty, is derived from GET /participants/me after login.
	ProviderSD string
	// ParticipantToken, if set, is used as a static token (nothing is fetched).
	// Otherwise a token is obtained from TokenServiceURL.
	ParticipantToken string
	// TokenServiceURL is the participant-local OID4VP token service that mints an
	// access token for this participant (the consent-facade's /internal/tokens).
	TokenServiceURL string
	// TokenAudience is the audience name asked of the token service.
	TokenAudience string
	// TokenTTL caps how long a fetched token is cached (defaults to
	// DefaultTokenTTL); the token service's own expiry wins when shorter.
	TokenTTL time.Duration
	// TimeoutMs is the per-call HTTP timeout (defaults to DefaultTimeoutMs).
	TimeoutMs int
}

// Client verifies consent against the dsc-consent-manager. Each data owner is
// checked as a userIdentifier in one of two modes (ConsentRequest.Mode):
//
//   - list:  GET {base}/consents?userIdentifier=[&privacyNoticeId=], paged;
//   - check: GET {base}/consents/check, then the mandatory GET {base}/consents/{id}.
//
// Either way a release needs one consent record that passes matchConsent, so the
// consumer and provider binding never rests on the server's answer alone.
//
// The access token is obtained from the participant-local OID4VP token service
// (POST {TokenServiceURL} with the configured audience), so this plugin holds no
// participant credentials of its own. GET /participants/me then yields this
// participant's own identifier and its selfDescriptionUri. Tokens are cached
// package-wide (keyed by the full credential identity, see cacheKey) and
// refreshed on expiry or a 401. Consent answers are never cached, so a
// revocation takes effect on the next request.
type Client struct {
	baseURL         string
	apiPrefix       string
	providerSD      string
	staticToken     string
	tokenServiceURL string
	tokenAudience   string
	tokenTTL        time.Duration
	httpClient      *http.Client
}

// NewClient creates a consent-manager client from cfg, applying defaults for
// APIPrefix, TokenTTL and TimeoutMs.
func NewClient(cfg ClientConfig) *Client {
	timeout := cfg.TimeoutMs
	if timeout < MinTimeoutMs {
		timeout = DefaultTimeoutMs
	}
	prefix := cfg.APIPrefix
	if prefix == "" {
		prefix = DefaultAPIPrefix
	}
	ttl := cfg.TokenTTL
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}
	return &Client{
		baseURL:         cfg.BaseURL,
		apiPrefix:       prefix,
		providerSD:      cfg.ProviderSD,
		staticToken:     cfg.ParticipantToken,
		tokenServiceURL: cfg.TokenServiceURL,
		tokenAudience:   cfg.TokenAudience,
		tokenTTL:        ttl,
		httpClient:      &http.Client{Timeout: time.Duration(timeout) * time.Millisecond},
	}
}

// --- package-wide credential cache (token + derived provider SD) -------------

type cacheEntry struct {
	// mu serializes the login / provider-SD refresh for this one cache key, so
	// concurrent first requests for the same participant coalesce onto a single
	// login instead of stampeding the consent-manager — while requests for other
	// participants, and cache hits, never block on it.
	mu          sync.Mutex
	token       string
	tokenExpiry time.Time
	providerSD  string
	// self is this participant's identifier from /participants/me; "" until fetched.
	self string
}

// participantCredentials is what the client authenticates and identifies itself with.
type participantCredentials struct {
	token      string
	providerSD string
	// self is this participant's own identifier (DID): the provider a consent
	// must name before it can authorise a release by this participant.
	self string
}

var (
	credCacheMu sync.Mutex
	credCache   = map[string]*cacheEntry{}
)

// credentialKeySeparator joins the components of a credential cache key. It is a
// character that cannot occur in a URL or an audience name, so no two distinct
// credential identities can produce the same joined key.
const credentialKeySeparator = "\x00"

// cacheKey identifies the credential the cached entry belongs to.
//
// The entry holds both the participant access token and the provider
// self-description derived from it, so the key MUST cover every input that can
// change either of them - otherwise two routes fronting different participants
// but the same consent-manager share one entry, and whichever warms it first
// makes the other match consents against the wrong provider identity and read
// them as the wrong participant (silently wrong decisions in both directions).
//
// Secrets are hashed rather than embedded so the key can be logged or ranged
// over without leaking a token.
func (c *Client) cacheKey() string {
	return strings.Join([]string{
		c.baseURL,
		c.apiPrefix,
		c.tokenAudience,
		c.tokenServiceURL,
		c.providerSD,
		hashSecret(c.staticToken),
	}, credentialKeySeparator)
}

// hashSecret returns a stable, non-reversible fingerprint of a secret, so it can
// distinguish cache identities without the secret itself being retained in the
// key. An empty secret maps to the empty string.
func hashSecret(secret string) string {
	if secret == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// CheckConsent checks req.Subject's consent in req.Mode, allowing only when a
// consent record passes matchConsent. A missing subject, consumer or (in check
// mode) notice id, or an unknown mode, is a definite deny, not an error. A 401 triggers one token
// refresh and retry. Other failures are returned as errors (see statusError) so
// the caller can apply its fail policy.
func (c *Client) CheckConsent(ctx context.Context, req ConsentRequest) (*ConsentResponse, error) {
	if req.Subject == "" {
		return deny("no subject in request"), nil
	}
	// Without a named consumer the check degenerates into "does this subject have
	// any consent at all?", which authorises the wrong agreement. Deny instead.
	if req.Consumer == "" {
		return deny("no consuming participant identified"), nil
	}
	switch req.Mode {
	case "", ModeList, ModeCheck:
	default:
		return deny("unknown consent check mode " + logging.Sanitize(string(req.Mode))), nil
	}
	if req.Mode == ModeCheck && req.PrivacyNoticeID == "" {
		return deny("check mode needs a privacy notice id"), nil
	}
	// The API types privacyNoticeId as a UUID; anything else would be a 400.
	if req.PrivacyNoticeID != "" && !IsUUID(req.PrivacyNoticeID) {
		return deny("privacy notice id is not a UUID"), nil
	}

	resp, err := c.check(ctx, req, false)
	if errors.Is(err, errParticipantUnauthorized) && c.staticToken == "" {
		// The cached token was rejected — refresh it and retry once. A second 401
		// is returned as is: it already wraps ErrConsentManagerAuth.
		resp, err = c.check(ctx, req, true)
	}
	return resp, err
}

// check performs one verification attempt in req.Mode. forceLogin refreshes a
// cached token before use.
func (c *Client) check(ctx context.Context, req ConsentRequest, forceLogin bool) (*ConsentResponse, error) {
	creds, err := c.credentials(ctx, forceLogin)
	if err != nil {
		return nil, err
	}
	if req.Mode == ModeCheck {
		return c.checkValidity(ctx, creds, req)
	}
	return c.listConsents(ctx, creds, req)
}

// deny builds a deny verdict with reason.
func deny(reason string) *ConsentResponse {
	return &ConsentResponse{Decision: DecisionDeny, Reason: reason}
}

// noMatchingConsentReason explains which scope the deny was decided at, so the
// audit record distinguishes "this subject consented to someone else" from
// "this subject did not consent to this purpose".
func noMatchingConsentReason(req ConsentRequest) string {
	reason := "no granted consent for consumer " + req.Consumer
	if req.Purpose != "" {
		reason += " and purpose " + req.Purpose
	}
	if req.ContractURI != "" {
		reason += " under contract " + req.ContractURI
	}
	if req.PrivacyNoticeID != "" {
		reason += " under privacy notice " + req.PrivacyNoticeID
	}
	return reason
}

// credentials resolves the participant token, the provider self-description and
// this participant's own identifier. The token is static or fetched from the
// token service (cached; forceFetch bypasses the cached token). GET
// /participants/me runs once per cache entry even when a static token and
// ProviderSD are configured, because only it yields the identifier that binds a
// consent to this provider. A configured ProviderSD wins over the fetched one.
//
// The global map lock is held only long enough to get-or-create this key's cache
// entry; the token/me HTTP calls run under the entry's own lock. So a refresh for
// one participant never blocks cache hits (or refreshes) for another, and
// concurrent first requests for the same participant coalesce onto one fetch.
func (c *Client) credentials(ctx context.Context, forceFetch bool) (participantCredentials, error) {
	if c.staticToken == "" && c.tokenServiceURL == "" {
		return participantCredentials{}, ErrNoCredentials
	}

	// Get-or-create the per-key entry under the map lock (brief), then release it
	// before any HTTP so other keys are not blocked.
	credCacheMu.Lock()
	entry := credCache[c.cacheKey()]
	if entry == nil {
		entry = &cacheEntry{}
		credCache[c.cacheKey()] = entry
	}
	credCacheMu.Unlock()

	// Serialize only this participant's refresh; the double-check inside means
	// followers return the freshly-cached token without a second login.
	entry.mu.Lock()
	defer entry.mu.Unlock()

	// Participant token: static override, or a cached/refreshed login token.
	token := c.staticToken
	if token == "" {
		if forceFetch {
			entry.token = ""
		}
		if entry.token == "" || time.Now().After(entry.tokenExpiry) {
			fetched, lifetime, err := c.fetchToken(ctx)
			if err != nil {
				return participantCredentials{}, err
			}
			entry.token = fetched
			entry.tokenExpiry = time.Now().Add(cacheFor(lifetime, c.tokenTTL))
		}
		token = entry.token
	}

	if entry.self == "" {
		me, err := c.fetchSelf(ctx, token)
		if err != nil {
			return participantCredentials{}, err
		}
		providerSD := c.providerSD
		if providerSD == "" {
			if me.SelfDescriptionURI == "" {
				return participantCredentials{}, fmt.Errorf("consent client: /me returned no selfDescriptionUri")
			}
			providerSD = me.SelfDescriptionURI
		}
		entry.self, entry.providerSD = me.Identifier, providerSD
	}

	return participantCredentials{token: token, providerSD: entry.providerSD, self: entry.self}, nil
}

// credentialsWithRetry is credentials with one token refresh when /me rejects a
// cached token.
func (c *Client) credentialsWithRetry(ctx context.Context) (participantCredentials, error) {
	creds, err := c.credentials(ctx, false)
	if errors.Is(err, errParticipantUnauthorized) && c.staticToken == "" {
		creds, err = c.credentials(ctx, true)
	}
	return creds, err
}

// participantSDCacheTTL bounds how long a DID -> self-description mapping is
// reused. Participants change rarely, so a generous TTL keeps the registry call
// off the request path.
//
// It is also the window in which a participant deregistered after its mapping
// was cached still passes the registry gate. That is accepted: the consent check
// itself runs uncached on every request, so the window only delays the explicit
// "deregistered" deny reason and never skips the consent decision.
const participantSDCacheTTL = 10 * time.Minute

// participantSDNegativeTTL bounds how long a "no usable participant" answer is
// reused. Without it a single misconfigured DID queries the registry on every
// request; with it, a participant that is genuinely registered later is still
// picked up promptly.
const participantSDNegativeTTL = 30 * time.Second

// Reasons a registry answer yields no usable self-description. Each one is final
// (ErrParticipantNotRegistered), so none of them may be failed open on.
const (
	reasonNotRegistered     = "no participant registered"
	reasonNoSelfDescription = "participant has no selfDescriptionUri"
	reasonDeregistered      = "participant is deregistered"
)

type participantSDEntry struct {
	selfDescriptionURL string
	expiry             time.Time
	// notRegisteredReason marks a negative result: the registry answered, and
	// had no usable participant for this DID.
	notRegisteredReason string
}

var (
	participantSDMu    sync.Mutex
	participantSDCache = map[string]participantSDEntry{}
)

// participant is the (subset of the) dsc-consent-manager Participant record.
type participant struct {
	Identifier         string `json:"identifier"`
	SelfDescriptionURI string `json:"selfDescriptionUri"`
	// DeregisteredAt is set once the participant left; the registry keeps the
	// record, and its selfDescriptionUri, after that.
	DeregisteredAt string `json:"deregisteredAt"`
}

// participantPage is the dsc-consent-manager ParticipantPage.
type participantPage struct {
	Content []participant `json:"content"`
}

// ParticipantSelfDescriptionByDID maps a participant DID to its self-description
// URI using the consent-manager's participant registry. Contracts name their
// parties by self-description, so a DID taken from a credential must be
// translated before it can be used in a contract lookup. An unknown,
// SD-less or deregistered participant returns ErrParticipantNotRegistered.
// Results are cached for participantSDCacheTTL, and negative answers for
// participantSDNegativeTTL.
func (c *Client) ParticipantSelfDescriptionByDID(ctx context.Context, did string) (string, error) {
	if did == "" {
		return "", fmt.Errorf("consent client: empty participant did")
	}
	cacheKey := c.cacheKey() + credentialKeySeparator + did

	participantSDMu.Lock()
	entry, hit := participantSDCache[cacheKey]
	participantSDMu.Unlock()
	if hit && time.Now().Before(entry.expiry) {
		if entry.notRegisteredReason != "" {
			return "", notRegistered(did, entry.notRegisteredReason)
		}
		return entry.selfDescriptionURL, nil
	}

	// A cached token that has since been revoked would otherwise make the mapping
	// terminally fail, and with it the whole exchange — so refresh and retry once,
	// exactly as CheckConsent does for the check itself.
	sd, reason, err := c.lookupParticipantSD(ctx, did, false)
	if errors.Is(err, errParticipantUnauthorized) && c.staticToken == "" {
		sd, reason, err = c.lookupParticipantSD(ctx, did, true)
	}
	if err != nil {
		return "", err
	}

	participantSDMu.Lock()
	if reason != "" {
		participantSDCache[cacheKey] = participantSDEntry{notRegisteredReason: reason, expiry: time.Now().Add(participantSDNegativeTTL)}
	} else {
		participantSDCache[cacheKey] = participantSDEntry{selfDescriptionURL: sd, expiry: time.Now().Add(participantSDCacheTTL)}
	}
	participantSDMu.Unlock()

	if reason != "" {
		return "", notRegistered(did, reason)
	}
	return sd, nil
}

// notRegistered builds the "no usable participant" error, wrapping the sentinel
// so callers can tell a misconfigured or departed DID from an unreachable
// registry.
//
// The DID is fingerprinted rather than embedded: this error is both logged to
// stdout and used as an audit reason, and a participant DID is an identifier
// that belongs in the audit record's own field, not in free text.
func notRegistered(did, reason string) error {
	return fmt.Errorf("%w: %s for did %s", ErrParticipantNotRegistered, reason, logging.Redact(did))
}

// lookupParticipantSD queries the participant registry for did. It returns the
// self-description URI, or a non-empty reason when the registry answered but has
// no usable participant (a definite negative, not an error). forceLogin
// refreshes a cached token first.
func (c *Client) lookupParticipantSD(ctx context.Context, did string, forceLogin bool) (sd, reason string, err error) {
	creds, err := c.credentials(ctx, forceLogin)
	if err != nil {
		return "", "", err
	}
	query := url.Values{identifierQueryParam: {did}}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint(participantsPath)+"?"+query.Encode(), nil)
	if err != nil {
		return "", "", fmt.Errorf("consent client: failed to create participants request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+creds.token)

	status, body, err := c.do(httpReq)
	if err != nil {
		return "", "", err
	}
	if status != http.StatusOK {
		return "", "", statusError("participants lookup", status, body)
	}

	var page participantPage
	if err := json.Unmarshal(body, &page); err != nil {
		return "", "", fmt.Errorf("consent client: failed to unmarshal participants response: %w", err)
	}
	for _, p := range page.Content {
		if p.Identifier != did {
			continue
		}
		switch {
		case p.DeregisteredAt != "":
			// The registry keeps departed participants with their SD URI; only
			// deregisteredAt tells them apart.
			return "", reasonDeregistered, nil
		case p.SelfDescriptionURI == "":
			return "", reasonNoSelfDescription, nil
		default:
			return p.SelfDescriptionURI, "", nil
		}
	}
	return "", reasonNotRegistered, nil
}

// ProviderSelfDescription returns this participant's self-description URL - the
// static override when configured, otherwise the value derived from
// GET /participants/me (cached with the participant token). Callers use it to
// name the provider side of a contract lookup.
func (c *Client) ProviderSelfDescription(ctx context.Context) (string, error) {
	creds, err := c.credentialsWithRetry(ctx)
	if err != nil {
		return "", err
	}
	return creds.providerSD, nil
}

// tokenResponse is the OAuth2-shaped reply of the participant-local token service.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// tokenRequest asks the token service for a token for one configured audience.
// The audience is a NAME the token service resolves against its own configuration,
// never a URL - a caller that could name an arbitrary host would make the token
// service present this participant's credential to it.
type tokenRequest struct {
	Audience string `json:"audience"`
}

// cacheFor returns how long a fetched token may be cached: the shorter of the
// lifetime the token service reported and the configured cap, less a small skew
// so a token is never presented in the last moments of its life. A service that
// reports no usable lifetime falls back to the cap.
func cacheFor(lifetime, maxLifetime time.Duration) time.Duration {
	ttl := maxLifetime
	if lifetime > 0 && lifetime < maxLifetime {
		ttl = lifetime
	}
	if ttl > tokenRefreshSkew {
		return ttl - tokenRefreshSkew
	}
	return ttl
}

// fetchToken asks the participant-local token service for an access token,
// returning the token and the lifetime it reported.
//
// The plugin fails closed, so the returned error names the status: the token
// service answers 502 when the verifier could not be reached (retryable) and
// 403/400/500 when the credential was refused or it is misconfigured (terminal).
func (c *Client) fetchToken(ctx context.Context) (string, time.Duration, error) {
	payload, err := json.Marshal(tokenRequest{Audience: c.tokenAudience})
	if err != nil {
		return "", 0, fmt.Errorf("consent client: failed to marshal token request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenServiceURL, bytes.NewReader(payload))
	if err != nil {
		return "", 0, fmt.Errorf("consent client: failed to create token request: %w", err)
	}
	httpReq.Header.Set("Content-Type", ContentTypeJSON)

	// Deliberately not c.endpoint(): the token service is a local, same-namespace
	// service, not the consent-manager, so the API prefix must not be applied.
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", 0, fmt.Errorf("consent client: token service request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, fmt.Errorf("consent client: failed to read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, unexpectedStatus("token service", resp.StatusCode, body)
	}
	var out tokenResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", 0, fmt.Errorf("consent client: failed to unmarshal token response: %w", err)
	}
	if out.AccessToken == "" {
		return "", 0, fmt.Errorf("consent client: token service returned no access token")
	}
	return out.AccessToken, time.Duration(out.ExpiresIn) * time.Second, nil
}

// fetchSelf reads the calling participant from GET /participants/me. An empty
// identifier is ErrConsentManagerRejected: without it no consent can be bound to
// this provider.
func (c *Client) fetchSelf(ctx context.Context, token string) (participant, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint(participantMePath), nil)
	if err != nil {
		return participant{}, fmt.Errorf("consent client: failed to create /me request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)

	status, body, err := c.do(httpReq)
	if err != nil {
		return participant{}, err
	}
	if status != http.StatusOK {
		return participant{}, statusError("participant lookup (/me)", status, body)
	}
	var out participant
	if err := json.Unmarshal(body, &out); err != nil {
		return participant{}, fmt.Errorf("consent client: failed to unmarshal /me response: %w", err)
	}
	if out.Identifier == "" {
		return participant{}, fmt.Errorf("%w: /me returned no identifier", ErrConsentManagerRejected)
	}
	return out, nil
}

// consentRecord is the subset of the dsc-consent-manager ConsentResponse the
// plugin decides on. Its data[] holds the notice's personal-data categories, not
// resource identifiers, so it is not decoded and never matched.
type consentRecord struct {
	ID              string `json:"id"`
	PrivacyNoticeID string `json:"privacyNoticeId"`
	// Consented is derived from status by the server, and is the field the API
	// designates for "may data be processed under this record now".
	Consented bool `json:"consented"`
	// Provider and Consumer are participant identifiers (DIDs).
	Provider    string   `json:"provider"`
	Consumer    string   `json:"consumer"`
	Purposes    []string `json:"purposes"`
	ContractURI string   `json:"contractUri"`
}

// consentPage is the dsc-consent-manager ConsentPage.
type consentPage struct {
	Content    []consentRecord `json:"content"`
	TotalPages int             `json:"totalPages"`
}

// consentValidity is the dsc-consent-manager ConsentValidity.
type consentValidity struct {
	Valid     bool   `json:"valid"`
	ConsentID string `json:"consentId"`
	Reason    string `json:"reason"`
}

// matchConsent reports whether record authorises releasing req.Subject's data
// to req.Consumer on behalf of this participant (self). Both modes use it, so a
// release never rests on the server's filters alone:
//
//   - consented must be true;
//   - provider must be self: the consent endpoints also return consents in
//     which this participant is the CONSUMER of another provider's contract;
//   - consumer must be req.Consumer: a consent granted to participant X is no
//     authority for participant Y;
//   - contractUri, privacyNoticeId and purposes must match req's values when
//     those are set.
//
// Matching is verbatim and case-sensitive.
func matchConsent(req ConsentRequest, self string, record consentRecord) bool {
	return record.Consented &&
		self != "" && record.Provider == self &&
		req.Consumer != "" && record.Consumer == req.Consumer &&
		(req.ContractURI == "" || record.ContractURI == req.ContractURI) &&
		(req.PrivacyNoticeID == "" || record.PrivacyNoticeID == req.PrivacyNoticeID) &&
		(req.Purpose == "" || slices.Contains(record.Purposes, req.Purpose))
}

// listConsents is list mode: it pages through GET /consents for req.Subject
// until a record passes matchConsent, the last page is read, or
// maxConsentListPages is reached (a deny).
func (c *Client) listConsents(ctx context.Context, creds participantCredentials, req ConsentRequest) (*ConsentResponse, error) {
	for page := 0; page < maxConsentListPages; page++ {
		query := url.Values{
			userIdentifierQueryParam: {req.Subject},
			pageQueryParam:           {strconv.Itoa(page)},
			sizeQueryParam:           {strconv.Itoa(consentListPageSize)},
		}
		if req.PrivacyNoticeID != "" {
			query.Set(privacyNoticeIDQueryParam, req.PrivacyNoticeID)
		}
		var out consentPage
		if _, err := c.getJSON(ctx, creds.token, c.endpoint(consentsPath)+"?"+query.Encode(), "consents list", &out); err != nil {
			return nil, err
		}
		for _, record := range out.Content {
			if matchConsent(req, creds.self, record) {
				return &ConsentResponse{Decision: DecisionAllow, ConsentID: record.ID}, nil
			}
		}
		if len(out.Content) == 0 || page+1 >= out.TotalPages {
			return deny(noMatchingConsentReason(req)), nil
		}
	}
	return deny(fmt.Sprintf("%s in the first %d consent pages", noMatchingConsentReason(req), maxConsentListPages)), nil
}

// checkValidity is check mode: GET /consents/check, then, on valid:true, the
// mandatory GET /consents/{consentId}?format=full whose record must pass
// matchConsent. The check endpoint says nothing about the consumer, so valid:true
// alone would let any consumer through on another consumer's grant. A 404 on
// the read means this participant is not a party to that consent: a deny.
func (c *Client) checkValidity(ctx context.Context, creds participantCredentials, req ConsentRequest) (*ConsentResponse, error) {
	query := url.Values{
		userIdentifierQueryParam:  {req.Subject},
		privacyNoticeIDQueryParam: {req.PrivacyNoticeID},
	}
	if req.Purpose != "" {
		query.Set(purposeQueryParam, req.Purpose)
	}
	var validity consentValidity
	if _, err := c.getJSON(ctx, creds.token, c.endpoint(consentCheckPath)+"?"+query.Encode(), "consent check", &validity); err != nil {
		return nil, err
	}
	if !validity.Valid {
		// reason is free text from a response body, so it stays out of the audit
		// reason (see unexpectedStatus) and is only logged at debug level.
		logging.DebugfEvery("consent-check-reason",
			"consent client: consent check not valid, reason: %s", logging.Sanitize(validity.Reason))
		return deny(consentNotInForceReason), nil
	}
	// consentId comes from a response body and ends up in a URL path.
	if !IsUUID(validity.ConsentID) {
		return deny("consent check returned no usable consentId"), nil
	}

	target := c.endpoint(fmt.Sprintf(consentByIDPathFmt, url.PathEscape(validity.ConsentID))) +
		"?" + url.Values{formatQueryParam: {consentFormatFull}}.Encode()
	var record consentRecord
	status, err := c.getJSON(ctx, creds.token, target, "consent read", &record)
	if status == http.StatusNotFound {
		return deny("consent " + validity.ConsentID + " is not readable by this participant"), nil
	}
	if err != nil {
		return nil, err
	}
	if !matchConsent(req, creds.self, record) {
		return deny(fmt.Sprintf("consent %s does not match: %s", validity.ConsentID, noMatchingConsentReason(req))), nil
	}
	return &ConsentResponse{Decision: DecisionAllow, ConsentID: validity.ConsentID}, nil
}

// getJSON GETs target with the bearer token and decodes a 200 body into out. A
// non-200 status is returned together with its statusError classification.
func (c *Client) getJSON(ctx context.Context, token, target, operation string, out any) (int, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, fmt.Errorf("consent client: failed to create %s request: %w", operation, err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)

	status, body, err := c.do(httpReq)
	if err != nil {
		return 0, err
	}
	if status != http.StatusOK {
		return status, statusError(operation, status, body)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return status, fmt.Errorf("consent client: failed to unmarshal %s response: %w", operation, err)
	}
	return status, nil
}

// endpoint builds a full URL from the base URL, the API prefix and a path.
func (c *Client) endpoint(path string) string {
	return strings.TrimRight(c.baseURL, "/") + c.apiPrefix + path
}

// do executes the request and returns the response status code together with
// its fully read body, closing the body before returning. It intentionally does
// not surface the *http.Response: the body is already consumed and closed, so
// callers only need the status code and body bytes.
func (c *Client) do(httpReq *http.Request) (statusCode int, body []byte, err error) {
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return 0, nil, fmt.Errorf("consent client: HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("consent client: failed to read response body: %w", err)
	}
	return resp.StatusCode, body, nil
}

// unexpectedStatus builds the error for an unexpected response status from a
// dependency, and sends the response BODY to a debug log rather than into the
// error.
//
// These errors do not stay in the process: the plugin wraps them into the
// decision reason, which is exported to the audit sink and written to stdout. A
// consent-manager 500 that echoes the user identifier in its body would
// therefore land in both — and truncating it, as an earlier version did, is not
// redaction: the first surviving characters of a JSON error body are usually
// exactly the part with the identifiers in it.
//
// The error text is instead a stable, low-cardinality classification, which is
// what an audit reason wants anyway — it is queried, not read. The body is still
// available at debug level, rate-limited per operation so a failing dependency
// cannot flood the log with it.
func unexpectedStatus(operation string, status int, body []byte) error {
	logging.DebugfEvery("dependency-body:"+operation,
		"consent client: %s returned status %d, body: %s", operation, status, logging.Sanitize(string(body)))
	return fmt.Errorf("consent client: %s returned status %d", operation, status)
}

// statusError classifies a non-200 consent-manager status for every endpoint
// alike, so fail-open can never apply to a permanent failure on one of them:
//
//   - 401: errParticipantUnauthorized (refresh and retry once; then final)
//   - 403: ErrConsentManagerAuth, the caller may be deregistered
//   - any other 4xx except 429: ErrConsentManagerRejected (misconfiguration)
//   - 429, 5xx and anything else: a plain, retryable error
//
// The body stays out of the error, as with unexpectedStatus.
func statusError(operation string, status int, body []byte) error {
	plain := unexpectedStatus(operation, status, body)
	switch {
	case status == http.StatusUnauthorized:
		return fmt.Errorf("%w (%w)", errParticipantUnauthorized, plain)
	case status == http.StatusForbidden:
		return fmt.Errorf("%w, the caller may be deregistered (%w)", ErrConsentManagerAuth, plain)
	case status == http.StatusTooManyRequests:
		return plain
	case status >= http.StatusBadRequest && status < http.StatusInternalServerError:
		return fmt.Errorf("%w (%w)", ErrConsentManagerRejected, plain)
	default:
		return plain
	}
}
