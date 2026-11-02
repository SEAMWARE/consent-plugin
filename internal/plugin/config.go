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
	"consent-plugin/internal/consent"
	"consent-plugin/internal/logging"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Default values for optional configuration fields.
const (
	// DefaultConsentAPITimeout is the default timeout in milliseconds for consent API calls.
	DefaultConsentAPITimeout = 5000

	// DefaultOwnerResolverTimeout is the default timeout in milliseconds for
	// OwnerResolver calls.
	DefaultOwnerResolverTimeout = 2000

	// DefaultResponsePhaseTimeout is the default budget in milliseconds for the
	// ENTIRE response phase - the party lookups, the resolve call and every
	// per-owner consent check together. APISIX holds the buffered response for
	// this whole time, so it must be bounded independently of the per-call
	// timeouts, which multiply by the number of owners.
	DefaultResponsePhaseTimeout = 10000

	// DefaultMaxOwnersPerResponse is the default cap on how many distinct data
	// owners are checked for one response. A collection endpoint returning
	// hundreds of entities would otherwise issue hundreds of consent checks
	// before answering.
	DefaultMaxOwnersPerResponse = 50

	// MinMaxOwnersPerResponse and MaxMaxOwnersPerResponse bound the cap itself.
	MinMaxOwnersPerResponse = 1
	MaxMaxOwnersPerResponse = 1000

	// DefaultMaxResolveBodyBytes is the default cap on the upstream body
	// forwarded to the OwnerResolver (1 MiB).
	DefaultMaxResolveBodyBytes = 1 << 20

	// MinMaxResolveBodyBytes and MaxMaxResolveBodyBytes bound that cap (up to
	// 100 MiB, which is already well past what a gated route should return).
	MinMaxResolveBodyBytes = 1
	MaxMaxResolveBodyBytes = 100 << 20

	// MinResponsePhaseTimeout and MaxResponsePhaseTimeout bound the response-phase
	// budget in milliseconds (120s is already far beyond any sane gateway timeout).
	MinResponsePhaseTimeout = 1
	MaxResponsePhaseTimeout = 120000

	// MinOwnerResolverTimeout and MaxOwnerResolverTimeout bound the per-call
	// OwnerResolver timeout in milliseconds.
	MinOwnerResolverTimeout = 1
	MaxOwnerResolverTimeout = 60000

	// DefaultParticipantTokenTTL is how long, in seconds, a fetched participant
	// token is cached when the route does not say. It matches the consent
	// client's own default.
	DefaultParticipantTokenTTL = 3000

	// MinParticipantTokenTTL and MaxParticipantTokenTTL bound the token cache
	// lifetime in seconds. The upper bound is a day — far longer than any token
	// this plugin is issued — and it also keeps the value away from the range
	// where `time.Duration(ttl) * time.Second` overflows into a negative
	// duration, which would make every cached token instantly expired.
	MinParticipantTokenTTL = 1
	MaxParticipantTokenTTL = 86400

	// apiPrefixSeparator is the path separator an API prefix must start with. A
	// prefix without it is silently concatenated into a malformed URL.
	apiPrefixSeparator = "/"

	// DefaultConsumerClaim is the dotted claim path holding the consuming
	// participant's identity. The provider's verifier embeds the presented
	// credential in the access token (jwtInclusion.fullInclusion), so the
	// credential's issuer is the consumer.
	DefaultConsumerClaim = "verifiableCredential.issuer"

	// DefaultTokenAudience is the audience asked of the token service when none is
	// configured. It names the token service's configured target for the
	// consent-manager, not a URL.
	DefaultTokenAudience = "consent-manager"

	// CheckModeList looks consents up via GET /consents?userIdentifier=.
	CheckModeList = "list"

	// CheckModeCheck looks consents up via GET /consents/check.
	CheckModeCheck = "check"

	// DefaultCheckMode is the lookup mode used when check_mode is omitted.
	DefaultCheckMode = CheckModeList

	// DefaultJWTHeaderName is the default HTTP header containing the JWT token.
	DefaultJWTHeaderName = "Authorization"

	// DefaultConsentAPIPrefix is the default consent-manager API prefix,
	// prepended to every endpoint path (matches the consent-manager's API_PREFIX).
	DefaultConsentAPIPrefix = "/v1"

	// DefaultDenyStatusCode is the default HTTP status code returned when consent is denied.
	DefaultDenyStatusCode = 403

	// DefaultDenyResponseBody is the default JSON body returned when consent is denied.
	DefaultDenyResponseBody = `{"error":"access denied by consent policy"}`

	// DefaultDenyResponseContentType is the default Content-Type header for denial responses.
	DefaultDenyResponseContentType = "application/json"

	// MinConsentAPITimeout is the minimum allowed timeout in milliseconds.
	MinConsentAPITimeout = 1

	// MaxConsentAPITimeout is the maximum allowed timeout in milliseconds (60 seconds).
	MaxConsentAPITimeout = 60000

	// MinHTTPStatusCode is the minimum valid HTTP status code for denial responses.
	MinHTTPStatusCode = 100

	// MaxHTTPStatusCode is the maximum valid HTTP status code for denial responses.
	MaxHTTPStatusCode = 599
)

// Environment variables that provide the token service and audit endpoints
// out-of-band, so they need not live in the route config (plaintext in
// etcd). A value set in the route config always takes precedence; the env var
// is only consulted when the corresponding field is empty. The plugin runner
// inherits these from the APISIX container, which sources them from a Secret.
const (
	// EnvTokenServiceURL supplies TokenServiceURL (the participant-local OID4VP
	// token service).
	//
	// #nosec G101 -- this is the NAME of an environment variable, not a
	// credential; it trips the hardcoded-credentials heuristic only because it
	// contains "TOKEN". The value it names is read from the environment at
	// ParseConfig time (see applyEnv) and never appears in the source.
	EnvTokenServiceURL = "CONSENT_TOKEN_SERVICE_URL"

	// EnvAuditOTLPEndpoint supplies AuditOTLPEndpoint (the OTLP/HTTP Collector
	// endpoint access-decision audit events are exported to).
	EnvAuditOTLPEndpoint = "CONSENT_AUDIT_OTLP_ENDPOINT"
)

// Accepted URL schemes for the configured endpoints.
const (
	// schemeHTTP is the plain-HTTP URL scheme.
	schemeHTTP = "http"

	// schemeHTTPS is the TLS-protected URL scheme.
	schemeHTTPS = "https"
)

// Config holds the plugin configuration that APISIX passes as JSON.
// It defines how the consent-filter plugin connects to the external consent API
// and how it handles denial responses.
type Config struct {
	// ConsentAPIURL is the base URL of the external consent API (required).
	ConsentAPIURL string `json:"consent_api_url"`

	// ConsentAPITimeout is the timeout in milliseconds for consent API calls.
	// Defaults to DefaultConsentAPITimeout (5000ms).
	ConsentAPITimeout int `json:"consent_api_timeout,omitempty"`

	// JWTHeaderName is the name of the HTTP header containing the JWT token.
	// Defaults to DefaultJWTHeaderName ("Authorization").
	JWTHeaderName string `json:"jwt_header_name,omitempty"`

	// JWTClaimsToForward lists the JWT claims the request phase decodes and keeps.
	// An empty list decodes every claim. The claims identify the CONSUMER (see
	// ConsumerClaim) for the contract lookup; they never identify the data owner.
	JWTClaimsToForward []string `json:"jwt_claims_to_forward,omitempty"`

	// ConsentAPIPrefix is the consent-manager API prefix prepended to endpoint
	// paths. Defaults to DefaultConsentAPIPrefix ("/v1").
	ConsentAPIPrefix string `json:"consent_api_prefix,omitempty"`

	// OwnerResolverURL is the external OwnerResolver /resolve endpoint (required).
	// The data owner is resolved from the RESPONSE DATA, never from the requestor:
	// the plugin posts the payload, gets back (owner[, dataResource]) claims, and
	// checks consent per owner.
	//
	// It is required because the only alternative — treating the access token's
	// "sub" as the data subject — asks whether the CALLER has consented, which
	// establishes no link between the caller and the data being returned and so
	// gates nothing (any subject with one granted consent becomes a universal
	// reader).
	OwnerResolverURL string `json:"owner_resolver_url"`

	// OwnerResolverTimeout is the per-call timeout in milliseconds for the
	// OwnerResolver (defaults to DefaultOwnerResolverTimeout).
	OwnerResolverTimeout int `json:"owner_resolver_timeout,omitempty"`

	// ResponsePhaseTimeout bounds, in milliseconds, the whole response phase:
	// the party lookups, the resolve call and every per-owner consent check
	// together. Without it the worst case is the per-call timeout multiplied by
	// the number of owners, all while APISIX holds the buffered response.
	// Defaults to DefaultResponsePhaseTimeout.
	ResponsePhaseTimeout int `json:"response_phase_timeout,omitempty"`

	// RequirePurpose makes a resolved claim that names no processing purpose a
	// denial instead of an unscoped check.
	//
	// Purpose matching depends on the OwnerResolver populating an optional field,
	// so a resolver whose rules never set it silently runs with purpose scoping
	// disabled — a consent granted for one purpose then authorises release for
	// any other. Defaults to false, because requiring it would break every
	// deployment whose resolver does not emit it yet; turn it on once yours does,
	// and the property becomes enforced rather than hoped for. The
	// consent_purpose_unconstrained_total metric counts the checks this would
	// have denied.
	RequirePurpose bool `json:"require_purpose,omitempty"`

	// RequireContract makes a resolved claim that names neither a contractUri
	// nor a privacyNoticeId (with no route-level PrivacyNoticeID either) a
	// denial instead of a check unscoped to any contract.
	//
	// Without it such a claim matches any consent this owner granted this
	// consumer under this provider, whatever contract it was given for. Defaults
	// to false, like RequirePurpose, because today's resolvers do not emit
	// either field; turn it on once yours does.
	RequireContract bool `json:"require_contract,omitempty"`

	// CheckMode selects how a consent is looked up: CheckModeList (the default)
	// lists the owner's granted consents, CheckModeCheck asks /consents/check
	// and then reads the consent it names. Both apply the same match.
	CheckMode string `json:"check_mode,omitempty"`

	// PrivacyNoticeID is the route-level privacy notice (a UUID) consents are
	// scoped to when a resolved claim names none.
	PrivacyNoticeID string `json:"privacy_notice_id,omitempty"`

	// Purpose is the processing purpose matched when a resolved claim names none.
	Purpose string `json:"purpose,omitempty"`

	// MaxResolveBodyBytes caps the upstream body forwarded to the OwnerResolver.
	//
	// The body is read whole, validated as JSON, and marshalled again into the
	// resolve envelope, so the peak footprint is roughly 3x its size per in-flight
	// request — on top of APISIX's own buffering of the same response. A handful
	// of concurrent large-collection responses can therefore drive the runner's
	// memory well past what the response size suggests. A body above this is
	// denied rather than forwarded. Defaults to DefaultMaxResolveBodyBytes.
	MaxResolveBodyBytes int `json:"max_resolve_body_bytes,omitempty"`

	// MaxOwnersPerResponse caps how many distinct data owners are checked for a
	// single response. A response resolving to more owners than this is denied
	// rather than answered after an unbounded number of consent calls.
	// Defaults to DefaultMaxOwnersPerResponse.
	MaxOwnersPerResponse int `json:"max_owners_per_response,omitempty"`

	// Service is the logical dataset id sent to the OwnerResolver as
	// resource.service, so it can select the right rule for this route.
	Service string `json:"service,omitempty"`

	// ConsumerClaim is the dotted path of the token claim identifying the
	// consuming participant, forwarded to the OwnerResolver as parties.consumer so
	// it can find the governing contract. Defaults to DefaultConsumerClaim. It is
	// used for contract lookup ONLY - never to determine the data owner.
	ConsumerClaim string `json:"consumer_claim,omitempty"`

	// TokenServiceURL is the participant-local OID4VP token service the plugin
	// asks for an access token — the consent-facade's POST /internal/tokens. The
	// plugin holds no participant credentials of its own: the facade presents the
	// participant's verifiable credential and returns a short-lived token, which
	// the plugin caches and refreshes. Falls back to EnvTokenServiceURL when
	// empty. Required unless a static ParticipantToken is configured.
	TokenServiceURL string `json:"token_service_url,omitempty"`

	// TokenAudience is the audience name asked of the token service (its
	// configured target, not a URL). Defaults to DefaultTokenAudience.
	TokenAudience string `json:"token_audience,omitempty"`

	// ParticipantTokenTTL caps, in seconds, how long a fetched token is cached
	// (defaults to DefaultParticipantTokenTTL). The token service reports its own
	// lifetime; the shorter of the two wins. Ignored for a static token. Bounded
	// by Validate, so it cannot overflow when converted to a time.Duration.
	ParticipantTokenTTL int `json:"participant_token_ttl,omitempty"`

	// ParticipantToken is an optional *static*, pre-obtained access token for the
	// consents-lookup call. An override for tests and manual runs; normally the
	// token comes from TokenServiceURL so it is refreshed automatically.
	ParticipantToken string `json:"participant_token,omitempty"`

	// ProviderSD is the provider self-description URL sent on the
	// identifier-search call. Optional: when empty it is derived from
	// /participants/me using the participant token.
	ProviderSD string `json:"provider_sd,omitempty"`

	// DenyStatusCode is the HTTP status code returned when consent is denied.
	// Defaults to DefaultDenyStatusCode (403).
	DenyStatusCode int `json:"deny_status_code,omitempty"`

	// DenyResponseBody is the body returned when consent is denied.
	// Defaults to DefaultDenyResponseBody.
	DenyResponseBody string `json:"deny_response_body,omitempty"`

	// DenyResponseContentType is the Content-Type header for denial responses.
	// Defaults to DefaultDenyResponseContentType ("application/json").
	DenyResponseContentType string `json:"deny_response_content_type,omitempty"`

	// FailOpen controls what happens when a dependency is unavailable or errors.
	// It defaults to FALSE (fail-closed): the failure mode of a consent gate must
	// not be "release the personal data", and it must certainly not be reached by
	// omitting a field. Setting it to true is a deliberate, logged decision to
	// prefer availability over the gate, and even then it does not apply to
	// conditions that are misconfigurations rather than outages (see failMode).
	FailOpen *bool `json:"fail_open,omitempty"`

	// AuditEnabled turns on emitting an access-decision audit event to an
	// OpenTelemetry Collector (as an OTLP/HTTP log record) for every consent
	// decision. Emission is asynchronous and best-effort, so it never blocks or
	// changes the access decision.
	AuditEnabled bool `json:"audit_enabled,omitempty"`

	// AuditOTLPEndpoint is the base OTLP/HTTP endpoint of the Collector
	// (e.g. http://otel-collector:4318); "/v1/logs" is appended. Required when
	// AuditEnabled. Falls back to the EnvAuditOTLPEndpoint env var when empty.
	AuditOTLPEndpoint string `json:"audit_otlp_endpoint,omitempty"`

	// AuditOTLPHeaders are extra HTTP headers sent on every audit export, for a
	// Collector that requires authentication (e.g. {"Authorization": "Bearer ..."}
	// or a tenant header).
	AuditOTLPHeaders map[string]string `json:"audit_otlp_headers,omitempty"`

	// AuditServiceName is the resource service.name stamped on audit records -
	// the marker the Collector routes on to keep audit logs separate from traces.
	// Empty defaults to the audit package's DefaultServiceName.
	AuditServiceName string `json:"audit_service_name,omitempty"`
}

// IsFailOpen returns whether the plugin should fail-open when a dependency is
// unavailable. Returns false (fail-closed) by default when FailOpen is nil.
func (c *Config) IsFailOpen() bool {
	if c.FailOpen == nil {
		return false
	}
	return *c.FailOpen
}

// applyDefaults sets default values for optional fields that were not provided
// in the JSON configuration.
func (c *Config) applyDefaults() {
	if c.ConsentAPITimeout == 0 {
		c.ConsentAPITimeout = DefaultConsentAPITimeout
	}
	if c.JWTHeaderName == "" {
		c.JWTHeaderName = DefaultJWTHeaderName
	}
	if c.ConsentAPIPrefix == "" {
		c.ConsentAPIPrefix = DefaultConsentAPIPrefix
	}
	// The prefix is concatenated directly with the endpoint path, so a trailing
	// separator would produce a double slash in every URL.
	if c.ConsentAPIPrefix != apiPrefixSeparator {
		c.ConsentAPIPrefix = strings.TrimRight(c.ConsentAPIPrefix, apiPrefixSeparator)
	}
	if c.OwnerResolverTimeout == 0 {
		c.OwnerResolverTimeout = DefaultOwnerResolverTimeout
	}
	if c.ResponsePhaseTimeout == 0 {
		c.ResponsePhaseTimeout = DefaultResponsePhaseTimeout
	}
	if c.MaxOwnersPerResponse == 0 {
		c.MaxOwnersPerResponse = DefaultMaxOwnersPerResponse
	}
	if c.MaxResolveBodyBytes == 0 {
		c.MaxResolveBodyBytes = DefaultMaxResolveBodyBytes
	}
	if c.ParticipantTokenTTL == 0 {
		c.ParticipantTokenTTL = DefaultParticipantTokenTTL
	}
	if c.ConsumerClaim == "" {
		c.ConsumerClaim = DefaultConsumerClaim
	}
	if c.TokenAudience == "" {
		c.TokenAudience = DefaultTokenAudience
	}
	if c.CheckMode == "" {
		c.CheckMode = DefaultCheckMode
	}
	if c.DenyStatusCode == 0 {
		c.DenyStatusCode = DefaultDenyStatusCode
	}
	if c.DenyResponseBody == "" {
		c.DenyResponseBody = DefaultDenyResponseBody
	}
	if c.DenyResponseContentType == "" {
		c.DenyResponseContentType = DefaultDenyResponseContentType
	}
}

// applyEnv fills the credential fields from environment variables when they are
// not set in the route config. This keeps the token service and audit
// endpoints out of the APISIX route config (and thus out of etcd): they are
// delivered to the plugin runner via the APISIX container's env, sourced from a
// Kubernetes Secret. A value present in the config always wins.
func (c *Config) applyEnv() {
	if c.TokenServiceURL == "" {
		c.TokenServiceURL = os.Getenv(EnvTokenServiceURL)
	}
	if c.AuditOTLPEndpoint == "" {
		c.AuditOTLPEndpoint = os.Getenv(EnvAuditOTLPEndpoint)
	}
}

// Validate checks that the configuration is valid. It returns an error if any
// required field is missing or any field value is out of the allowed range.
func (c *Config) Validate() error {
	if c.ConsentAPIURL == "" {
		return errors.New("config validation: consent_api_url is required")
	}

	parsedURL, err := url.ParseRequestURI(c.ConsentAPIURL)
	if err != nil {
		return fmt.Errorf("config validation: consent_api_url is not a valid URL: %w", err)
	}
	if parsedURL.Scheme != schemeHTTP && parsedURL.Scheme != schemeHTTPS {
		return fmt.Errorf("config validation: consent_api_url must use http or https scheme, got %q", parsedURL.Scheme)
	}

	// The resolver is the only source of data ownership, so a route without one
	// cannot gate anything and must not load.
	if c.OwnerResolverURL == "" {
		return errors.New("config validation: owner_resolver_url is required — " +
			"the data owner is resolved from the response data, and without a resolver the plugin cannot determine whose consent to check")
	}
	resolverURL, err := url.ParseRequestURI(c.OwnerResolverURL)
	if err != nil {
		return fmt.Errorf("config validation: owner_resolver_url is not a valid URL: %w", err)
	}
	if resolverURL.Scheme != schemeHTTP && resolverURL.Scheme != schemeHTTPS {
		return fmt.Errorf("config validation: owner_resolver_url must use http or https scheme, got %q", resolverURL.Scheme)
	}

	// The prefix is concatenated with the endpoint path rather than joined, so a
	// missing leading separator silently yields a malformed URL and every call
	// fails with a confusing 404.
	if !strings.HasPrefix(c.ConsentAPIPrefix, apiPrefixSeparator) {
		return fmt.Errorf("config validation: consent_api_prefix must start with %q, got %q",
			apiPrefixSeparator, c.ConsentAPIPrefix)
	}

	if c.ConsentAPITimeout < MinConsentAPITimeout || c.ConsentAPITimeout > MaxConsentAPITimeout {
		return fmt.Errorf("config validation: consent_api_timeout must be between %d and %d, got %d",
			MinConsentAPITimeout, MaxConsentAPITimeout, c.ConsentAPITimeout)
	}

	if c.DenyStatusCode < MinHTTPStatusCode || c.DenyStatusCode > MaxHTTPStatusCode {
		return fmt.Errorf("config validation: deny_status_code must be between %d and %d, got %d",
			MinHTTPStatusCode, MaxHTTPStatusCode, c.DenyStatusCode)
	}

	if c.OwnerResolverTimeout < MinOwnerResolverTimeout || c.OwnerResolverTimeout > MaxOwnerResolverTimeout {
		return fmt.Errorf("config validation: owner_resolver_timeout must be between %d and %d, got %d",
			MinOwnerResolverTimeout, MaxOwnerResolverTimeout, c.OwnerResolverTimeout)
	}

	if c.ResponsePhaseTimeout < MinResponsePhaseTimeout || c.ResponsePhaseTimeout > MaxResponsePhaseTimeout {
		return fmt.Errorf("config validation: response_phase_timeout must be between %d and %d, got %d",
			MinResponsePhaseTimeout, MaxResponsePhaseTimeout, c.ResponsePhaseTimeout)
	}

	if c.MaxResolveBodyBytes < MinMaxResolveBodyBytes || c.MaxResolveBodyBytes > MaxMaxResolveBodyBytes {
		return fmt.Errorf("config validation: max_resolve_body_bytes must be between %d and %d, got %d",
			MinMaxResolveBodyBytes, MaxMaxResolveBodyBytes, c.MaxResolveBodyBytes)
	}

	if c.ParticipantTokenTTL < MinParticipantTokenTTL || c.ParticipantTokenTTL > MaxParticipantTokenTTL {
		return fmt.Errorf("config validation: participant_token_ttl must be between %d and %d, got %d",
			MinParticipantTokenTTL, MaxParticipantTokenTTL, c.ParticipantTokenTTL)
	}

	if c.MaxOwnersPerResponse < MinMaxOwnersPerResponse || c.MaxOwnersPerResponse > MaxMaxOwnersPerResponse {
		return fmt.Errorf("config validation: max_owners_per_response must be between %d and %d, got %d",
			MinMaxOwnersPerResponse, MaxMaxOwnersPerResponse, c.MaxOwnersPerResponse)
	}

	if c.AuditEnabled && c.AuditOTLPEndpoint == "" {
		return errors.New("config validation: audit_otlp_endpoint is required when audit_enabled is true")
	}

	if c.TokenServiceURL != "" {
		tokenServiceURL, err := url.ParseRequestURI(c.TokenServiceURL)
		if err != nil {
			return fmt.Errorf("config validation: token_service_url is not a valid URL: %w", err)
		}
		if tokenServiceURL.Scheme != schemeHTTP && tokenServiceURL.Scheme != schemeHTTPS {
			return fmt.Errorf("config validation: token_service_url must use http or https scheme, got %q", tokenServiceURL.Scheme)
		}
	}

	// Call 2 is authenticated as the participant, so a route with neither a token
	// service nor a static token cannot complete a single check. Loading it
	// cleanly and discovering that per request — as one log line, on the data
	// path — is how a typo becomes an outage or, with fail_open, a silent bypass.
	if c.TokenServiceURL == "" && c.ParticipantToken == "" {
		return errors.New("config validation: one of token_service_url or participant_token is required — " +
			"without a way to authenticate as the participant no consent check can succeed")
	}

	// check_mode=check without privacy_notice_id stays valid: the resolver may
	// supply the notice id per claim.
	if c.CheckMode != CheckModeList && c.CheckMode != CheckModeCheck {
		return fmt.Errorf("config validation: check_mode must be %q or %q, got %q",
			CheckModeList, CheckModeCheck, c.CheckMode)
	}

	if c.PrivacyNoticeID != "" && !consent.IsUUID(c.PrivacyNoticeID) {
		return fmt.Errorf("config validation: privacy_notice_id must be a UUID, got %q", c.PrivacyNoticeID)
	}

	return nil
}

// ParseConfig deserializes JSON bytes into a Config struct, applies default
// values for omitted optional fields, and validates the result.
func ParseConfig(in []byte) (*Config, error) {
	if len(in) == 0 {
		return nil, errors.New("config parsing: input is empty")
	}

	var conf Config
	if err := json.Unmarshal(in, &conf); err != nil {
		return nil, fmt.Errorf("config parsing: failed to unmarshal JSON: %w", err)
	}

	conf.applyDefaults()
	conf.applyEnv()

	if err := conf.Validate(); err != nil {
		return nil, err
	}

	if conf.IsFailOpen() {
		logging.Warnf("fail_open is enabled for %s — a consent-manager or resolver outage will RELEASE personal data instead of denying it",
			conf.ConsentAPIURL)
	}

	return &conf, nil
}
