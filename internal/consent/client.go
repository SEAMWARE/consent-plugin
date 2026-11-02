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
	"strings"
	"sync"
	"time"
)

// Endpoint paths and constants.
const (
	// DefaultAPIPrefix is the consent-manager API prefix prepended to every
	// endpoint path (matches the consent-manager's API_PREFIX).
	DefaultAPIPrefix = "/v1"

	// identifierSearchPath resolves a subject to the provider-scoped user
	// identifier. Carries the participant token only.
	identifierSearchPath = "/users/identifier/search"

	// participantConsentsPathFmt lists a user identifier's consents as seen by
	// the participant. Authenticated with the participant JWT. %s = identifier.
	participantConsentsPathFmt = "/consents/participants/%s"

	// participantMePath returns the calling participant (identifier and selfDescriptionUri).
	participantMePath = "/participants/me"

	// participantsPath is the participant registry, used to map a participant
	// DID to its self-description URI.
	participantsPath = "/participants"

	// identifierQueryParam filters the participant registry by DID.
	identifierQueryParam = "identifier"

	// grantedStatus is the consent status that authorizes access.
	grantedStatus = "granted"

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
// (Prometheus-X / Visions) consent-manager.
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

// Client verifies consent against the consent-manager. The consent-manager has
// no single "is there consent?" endpoint, so a check is a two-call chain:
//
//  1. POST {base}/users/identifier/search  — resolve the subject (a DID carried
//     as the user "email") to the provider-scoped user identifier, scoped by the
//     provider self-description.
//  2. GET  {base}/consents/participants/{id}?receipt=true — list that user's
//     consents, authenticated with the participant JWT.
//
// The access token is obtained from the participant-local OID4VP token service
// (POST {TokenServiceURL} with the configured audience), so this plugin holds no
// participant credentials of its own: the token service presents the
// participant's verifiable credential and returns a short-lived token. GET
// /participants/me then yields this participant's own identifier and its
// selfDescriptionUri. Tokens are cached package-wide (keyed by the full
// credential identity, see cacheKey) and refreshed on expiry or a 401. Access is allowed iff a returned consent is
// "granted" AND was granted to the consuming participant named in the request
// (see hasGrantedConsent).
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
// makes the other run its identifier search scoped to the wrong provider and its
// consents lookup as the wrong participant (silently wrong decisions in both
// directions).
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

// CheckConsent runs the two-call consent verification for req.Subject, allowing
// when a granted consent exists and denying otherwise. An unknown subject is a
// definite deny (not an error). A 401 from the participant-authenticated calls
// triggers one token refresh + retry. Transport/protocol failures are returned
// as errors so the caller can apply its fail policy.
func (c *Client) CheckConsent(ctx context.Context, req ConsentRequest) (*ConsentResponse, error) {
	if req.Subject == "" {
		return &ConsentResponse{Decision: DecisionDeny, Reason: "no subject in request"}, nil
	}
	// Without a named consumer the check degenerates into "does this subject have
	// any consent at all?", which authorises the wrong agreement. Deny instead.
	if req.Consumer == "" {
		return &ConsentResponse{Decision: DecisionDeny, Reason: "no consuming participant identified"}, nil
	}

	resp, err := c.check(ctx, req, false)
	if errors.Is(err, errParticipantUnauthorized) && c.staticToken == "" {
		// The cached token was rejected — refresh it and retry once. A second 401
		// is returned as is: it already wraps ErrConsentManagerAuth.
		resp, err = c.check(ctx, req, true)
	}
	return resp, err
}

// check performs one full verification attempt. forceLogin refreshes a cached
// token before use. The check is scoped by req: a granted consent counts only if
// it was granted to req.Consumer and, when set, covers req.DataResource and
// req.Purpose.
func (c *Client) check(ctx context.Context, req ConsentRequest, forceLogin bool) (*ConsentResponse, error) {
	creds, err := c.credentials(ctx, forceLogin)
	if err != nil {
		return nil, err
	}
	token := creds.token

	userIdentifier, found, err := c.resolveUserIdentifier(ctx, req.Subject, creds.providerSD, token)
	if err != nil {
		return nil, err
	}
	if !found {
		return &ConsentResponse{Decision: DecisionDeny, Reason: "no user identifier for subject"}, nil
	}

	granted, err := c.hasGrantedConsent(ctx, token, userIdentifier, req)
	if err != nil {
		return nil, err
	}
	if granted {
		return &ConsentResponse{Decision: DecisionAllow}, nil
	}
	return &ConsentResponse{Decision: DecisionDeny, Reason: noGrantedConsentReason(req)}, nil
}

// noGrantedConsentReason explains which scope the deny was decided at, so the
// audit record distinguishes "this subject consented to someone else" from
// "this subject did not consent to this resource".
func noGrantedConsentReason(req ConsentRequest) string {
	reason := "no granted consent for consumer " + req.Consumer
	if req.Purpose != "" {
		reason += " and purpose " + req.Purpose
	}
	if req.DataResource != "" {
		reason += " covering resource " + req.DataResource
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

// identifierCacheTTL bounds how long a (provider, subject) -> userIdentifier
// mapping is reused. The mapping is stable for the life of the registration, so
// a short TTL is enough to collapse the repeated searches a single multi-owner
// response would otherwise make, without holding a stale identifier.
//
// Only POSITIVE results are cached. "Unknown subject" must be re-asked every
// time: a data subject can register at any moment, and remembering that they
// were unknown would keep denying them after they had consented.
const identifierCacheTTL = 60 * time.Second

type identifierEntry struct {
	userIdentifier string
	expiry         time.Time
}

var (
	identifierMu    sync.Mutex
	identifierCache = map[string]identifierEntry{}
)

// identifierCacheKey scopes a cached identifier to the credential identity and
// the provider it was resolved for - the identifier is provider-scoped, so it
// must never be reused across providers.
func (c *Client) identifierCacheKey(providerSD, subject string) string {
	return strings.Join([]string{c.cacheKey(), providerSD, subject}, credentialKeySeparator)
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

// loginResponse is the consent-manager response to POST /participants/login.
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

	// Deliberately not c.do(): the token service is a local, same-namespace
	// service, not the consent-manager, so the Host override and API prefix that
	// c.do() applies for the gateway route must not be used here.
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

// identifierSearchResponse is the consent-manager response to the identifier search.
type identifierSearchResponse struct {
	UserIdentifier string `json:"userIdentifier"`
}

// resolveUserIdentifier performs call 1: it maps the subject (a DID, sent as the
// user "email") to the provider-scoped user identifier. A 404 or empty identifier
// means the subject is unknown (found == false).
//
// A positive result is cached for identifierCacheTTL, so a response resolving to
// the same owner under several data resources searches once instead of once per
// resource.
//
// It carries the participant token as a Bearer credential, so an authenticating
// facade in front of the consent-manager can validate the participant JWT on
// this call too.
func (c *Client) resolveUserIdentifier(ctx context.Context, subject, providerSD, token string) (identifier string, found bool, err error) {
	cacheKey := c.identifierCacheKey(providerSD, subject)
	identifierMu.Lock()
	entry, hit := identifierCache[cacheKey]
	identifierMu.Unlock()
	if hit && time.Now().Before(entry.expiry) {
		return entry.userIdentifier, true, nil
	}

	payload, err := json.Marshal(map[string]string{"selfDescription": providerSD, "email": subject})
	if err != nil {
		return "", false, fmt.Errorf("consent client: failed to marshal identifier search: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(identifierSearchPath), bytes.NewReader(payload))
	if err != nil {
		return "", false, fmt.Errorf("consent client: failed to create identifier search request: %w", err)
	}
	httpReq.Header.Set("Content-Type", ContentTypeJSON)
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}

	status, body, err := c.do(httpReq)
	if err != nil {
		return "", false, err
	}
	if status == http.StatusNotFound {
		return "", false, nil
	}
	if status == http.StatusUnauthorized {
		// a facade in front of the consent-manager rejected the participant token
		return "", false, errParticipantUnauthorized
	}
	if status != http.StatusOK {
		return "", false, unexpectedStatus("identifier search", status, body)
	}
	var out identifierSearchResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", false, fmt.Errorf("consent client: failed to unmarshal identifier search response: %w", err)
	}
	if out.UserIdentifier == "" {
		return "", false, nil
	}
	identifierMu.Lock()
	identifierCache[cacheKey] = identifierEntry{userIdentifier: out.UserIdentifier, expiry: time.Now().Add(identifierCacheTTL)}
	identifierMu.Unlock()
	return out.UserIdentifier, true, nil
}

// participantConsentsResponse is the consent-manager response to call 2. The
// ?receipt=true form returns the raw consents, each carrying its status, the
// consumer it was granted to, the purposes it covers and the data resources it
// covers.
type participantConsentsResponse struct {
	Consents []consentRecord `json:"consents"`
}

// consentRecord is the (subset of the) consent receipt the plugin decides on.
type consentRecord struct {
	Status string `json:"status"`
	Data   []struct {
		Resource string `json:"resource"`
	} `json:"data"`
	// Consumer / DataConsumer are the two field names the consent-manager has
	// used for the participant the data is released to; either may be present.
	Consumer     participantRef `json:"consumer"`
	DataConsumer participantRef `json:"dataConsumer"`
	// Recipients names the parties the data is released to, by self-description
	// URL. It is the only place the consumer appears in a form the plugin can
	// compare: on the `?receipt=true` records, `dataConsumer` is a bare Mongo id,
	// which matches nothing the plugin holds.
	Recipients []string `json:"recipients"`
	Purposes   []struct {
		ID      string `json:"_id"`
		Purpose string `json:"purpose"`
	} `json:"purposes"`
}

// participantRef is a participant named inside a consent record. The
// consent-manager returns it either as a bare identifier string or as an
// embedded object, so it decodes both shapes and matches on any of the
// identifiers it carries.
type participantRef struct {
	ID                 string `json:"_id"`
	DID                string `json:"did"`
	SelfDescriptionURL string `json:"selfDescriptionURL"`
	// literal holds the value when the field was a bare string rather than an object.
	literal string
}

// UnmarshalJSON accepts either a bare identifier string or a participant object.
func (p *participantRef) UnmarshalJSON(data []byte) error {
	var literal string
	if err := json.Unmarshal(data, &literal); err == nil {
		p.literal = literal
		return nil
	}
	// Alias avoids recursing into this method while decoding the object form.
	type participantRefObject participantRef
	var obj participantRefObject
	if err := json.Unmarshal(data, &obj); err != nil {
		return fmt.Errorf("consent client: failed to unmarshal participant reference: %w", err)
	}
	*p = participantRef(obj)
	return nil
}

// matches reports whether this reference denotes the given participant identity
// (a self-description URL, but a record may name the participant by its id or
// DID instead). An empty reference matches nothing.
func (p participantRef) matches(identity string) bool {
	if identity == "" {
		return false
	}
	for _, candidate := range []string{p.SelfDescriptionURL, p.ID, p.DID, p.literal} {
		if candidate != "" && candidate == identity {
			return true
		}
	}
	return false
}

// grantedTo reports whether the consent was granted to the given consumer.
//
// The consumer arrives as a self-description URL (mapped from the presented
// credential's DID). On a `?receipt=true` record the consent-manager names the
// consumer only as an internal id in `dataConsumer`, so the SD comparison has to
// fall back to `recipients`.
//
// Only the FIRST recipient counts, because that is exactly how the authority
// itself reads the field: the consent-manager resolves the data consumer as
// `recipients[0]` (consentsController). Matching any recipient would authorise a
// party the authority would not treat as the consumer.
func (r consentRecord) grantedTo(consumer string) bool {
	if r.Consumer.matches(consumer) || r.DataConsumer.matches(consumer) {
		return true
	}
	return len(r.Recipients) > 0 && r.Recipients[0] != "" && r.Recipients[0] == consumer
}

// coversPurpose reports whether the consent covers the given processing purpose.
// An empty purpose means the caller could not determine one, so the purpose is
// not part of the match.
func (r consentRecord) coversPurpose(purpose string) bool {
	if purpose == "" {
		return true
	}
	for _, p := range r.Purposes {
		if p.Purpose == purpose || p.ID == purpose {
			return true
		}
	}
	return false
}

// coversResource reports whether the consent covers the given data resource. An
// empty resource means the check is owner-level and any resource qualifies.
func (r consentRecord) coversResource(dataResource string) bool {
	if dataResource == "" {
		return true
	}
	for _, d := range r.Data {
		if d.Resource == dataResource {
			return true
		}
	}
	return false
}

// hasGrantedConsent performs call 2: it lists the user identifier's consents as
// seen by the participant and reports whether any of them authorizes THIS
// access. A consent qualifies only when all of the following hold:
//
//   - its status is "granted";
//   - it was granted to req.Consumer — a consent names one consumer, and one
//     granted to participant X is not authority for participant Y to read the
//     same data;
//   - it covers req.Purpose, when the caller could determine one;
//   - it covers req.DataResource, when the check is resource-scoped.
//
// A record that names no consumer therefore never qualifies: the plugin cannot
// tell whose agreement it is, and guessing would authorise a processing purpose
// the subject never agreed to. A 401 is returned as errParticipantUnauthorized
// so the caller can refresh the token and retry.
func (c *Client) hasGrantedConsent(ctx context.Context, token, userIdentifier string, req ConsentRequest) (bool, error) {
	endpoint := c.endpoint(fmt.Sprintf(participantConsentsPathFmt, url.PathEscape(userIdentifier))) + "?receipt=true"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, fmt.Errorf("consent client: failed to create consents request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)

	status, body, err := c.do(httpReq)
	if err != nil {
		return false, err
	}
	if status == http.StatusUnauthorized {
		return false, errParticipantUnauthorized
	}
	if status != http.StatusOK {
		return false, unexpectedStatus("consents lookup", status, body)
	}
	var out participantConsentsResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return false, fmt.Errorf("consent client: failed to unmarshal consents response: %w", err)
	}
	for _, record := range out.Consents {
		if record.Status != grantedStatus {
			continue
		}
		if record.grantedTo(req.Consumer) && record.coversPurpose(req.Purpose) && record.coversResource(req.DataResource) {
			return true, nil
		}
	}
	return false, nil
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
