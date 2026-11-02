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

// Package plugin implements the APISIX consent-filter plugin.
//
// The plugin gates a personal-data response on the consent of the DATA OWNER.
// The request phase captures the token's claims; the response phase asks the
// OwnerResolver who owns the payload and checks, per owner, that the consuming
// participant has a granted consent. The verdict is coarse — the whole response
// is allowed or replaced with a denial. Despite the plugin's registered name
// there is no field-level filtering or redaction: a gate that removes fields
// silently misses the one it does not know about, while a coarse gate still
// covers an empty or non-JSON personal-data response.
package plugin

import (
	"consent-plugin/internal/audit"
	"consent-plugin/internal/consent"
	"consent-plugin/internal/jwt"
	"consent-plugin/internal/logging"
	"consent-plugin/internal/metrics"
	"consent-plugin/internal/ownerresolver"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	pkgHTTP "github.com/apache/apisix-go-plugin-runner/pkg/http"
	"github.com/apache/apisix-go-plugin-runner/pkg/plugin"
)

// pluginName is the registered name for this plugin in APISIX configuration.
const pluginName = "consent-filter"

// nginxRequestIDVar is the Nginx variable ($request_id) holding a unique id
// per HTTP request. Unlike the runner's per-RPC ID(), it is identical in the
// RequestFilter (ext-plugin-pre-req) and ResponseFilter (ext-plugin-post-resp)
// phases, so it is used to correlate the context captured in one phase with
// the other.
const nginxRequestIDVar = "request_id"

// nginxUpstreamContentTypeVar is the Nginx variable ($upstream_http_content_type)
// holding the Content-Type the upstream answered with.
//
// It is read in preference to Response.Header() because that method lazily
// materialises the runner's header map, and the runner then reports
// HasChange() == true for the response — so merely LOOKING at a header sent
// every allowed response back to APISIX down the "this response was modified"
// path, carrying an empty header diff. Reading a variable has no such effect.
const nginxUpstreamContentTypeVar = "upstream_http_content_type"

// varReader is the subset of the runner's Request/Response interfaces that
// exposes Nginx variables. Both pkgHTTP.Request and pkgHTTP.Response satisfy it.
type varReader interface {
	Var(name string) ([]byte, error)
}

// correlationKey returns a key that stably identifies the HTTP request across
// the request and response phases, based on the Nginx $request_id variable.
// It returns false if the variable cannot be read, in which case the two
// phases cannot be correlated.
func correlationKey(v varReader) (string, bool) {
	id, err := v.Var(nginxRequestIDVar)
	if err != nil || len(id) == 0 {
		return "", false
	}
	return string(id), true
}

func init() {
	if err := plugin.RegisterPlugin(&ConsentFilter{}); err != nil {
		panic("failed to register consent-filter plugin: " + err.Error())
	}
}

// ConsentFilter is the APISIX plugin that intercepts HTTP responses,
// consults an external consent API, and filters or denies responses
// based on consent decisions for personal data fields.
type ConsentFilter struct {
	plugin.DefaultPlugin
}

// Name returns the unique name of this plugin as registered with APISIX.
func (c *ConsentFilter) Name() string {
	return pluginName
}

// ParseConf deserializes and validates the plugin configuration from
// the JSON bytes provided by APISIX. Returns the parsed configuration
// or an error if the configuration is invalid.
func (c *ConsentFilter) ParseConf(in []byte) (interface{}, error) {
	return ParseConfig(in)
}

// RequestFilter intercepts incoming HTTP requests to capture the context the
// response phase needs: the method, the path, and the claims decoded from the
// configured JWT header, stored under the request's correlation key.
//
// The JWT is decoded, NOT verified (see internal/jwt): the claims are used only
// to name the consuming participant for the contract lookup, and the route MUST
// have an authentication plugin in front of this one that validates the token.
func (c *ConsentFilter) RequestFilter(conf interface{}, w http.ResponseWriter, r pkgHTTP.Request) {
	cfg, ok := conf.(*Config)
	if !ok {
		logging.Errorf("RequestFilter: invalid config type, skipping request %d", r.ID())
		return
	}

	reqCtx := &RequestContext{
		Method: r.Method(),
		Path:   string(r.Path()),
	}

	// Only the configured JWT header is read, and only the claims are kept. The
	// full header set is deliberately not retained: it would put the caller's
	// bearer token in a process-lifetime map that nothing ever reads.

	// Extract JWT token and decode claims from the configured header.
	jwtHeaderValue := r.Header().Get(cfg.JWTHeaderName)
	if jwtHeaderValue != "" {
		token, err := jwt.ExtractToken(jwtHeaderValue)
		if err != nil {
			logging.WarnfEvery("jwt-extract", "RequestFilter: failed to extract JWT from header %q: %s",
				cfg.JWTHeaderName, logging.Sanitize(err.Error()))
		} else {
			claims, err := jwt.DecodeClaims(token, claimKeysToDecode(cfg))
			if err != nil {
				logging.WarnfEvery("jwt-decode", "RequestFilter: failed to decode JWT claims: %s",
					logging.Sanitize(err.Error()))
			} else {
				reqCtx.JWTClaims = claims
			}
		}
	}

	// Correlate with the response phase via the stable Nginx $request_id, not
	// the runner's per-RPC ID() (which differs between pre-req and post-resp).
	key, ok := correlationKey(r)
	if !ok {
		logging.ErrorfEvery("no-request-id-req", "RequestFilter: could not read %q; consent context not stored",
			nginxRequestIDVar)
		return
	}

	StoreRequestContext(key, reqCtx)
}

// responseContentType reports the Content-Type of the upstream response,
// preferring the Nginx variable so an allowed response is not marked as
// modified (see nginxUpstreamContentTypeVar). The header is only consulted when
// the variable is unavailable, which is a degraded case rather than the norm.
func responseContentType(w pkgHTTP.Response) string {
	if value, err := w.Var(nginxUpstreamContentTypeVar); err == nil && len(value) > 0 {
		return string(value)
	}
	if header := w.Header(); header != nil {
		return header.Get("Content-Type")
	}
	return ""
}

// decisionAllow and decisionDeny are the audit-facing labels for the decision.
const (
	decisionAllow = "allow"
	decisionDeny  = "deny"
)

// responseOutcome is the result of evaluating consent for one response: the
// decision to enforce plus the fields needed to record it in the audit log.
//
// checked carries one entry per data owner whose consent was actually consulted.
// Recording only the outcome answered "was this response allowed?" but not
// "whose consent was checked, and what did each say?" — which is the question an
// access-decision audit log exists to answer. On an allow it named no owner at
// all, and on a deny only the first owner to refuse.
type responseOutcome struct {
	decision  string // decisionAllow | decisionDeny
	reason    string
	requestID string
	subject   string
	resource  string
	method    string
	checked   []checkedOwner
	// failMode names why the decision could not be reached normally, so a deny
	// caused by an outage is not counted as a deny caused by consent. Empty for
	// an ordinary consent verdict.
	failMode string
}

// checkedOwner is one data owner's consent decision within a response.
type checkedOwner struct {
	subject  string
	resource string
	decision string
	reason   string
}

// ResponseFilter gates the upstream response on the data owner's consent.
//
// The flow is:
//  1. Correlate with the request phase and load (and delete) the stored context.
//  2. Ask the OwnerResolver, from the RESPONSE DATA, whether consent is required
//     and who the data owner(s) are.
//  3. Run the two-call consent check per resolved owner (deny_all: every owner
//     must have a granted consent).
//  4. Allow → pass the response through unchanged; deny → replace it with the
//     configured denial response.
//  5. On unresolved context, a resolver error, or a consent-manager error, apply
//     the fail policy (deny unless explicitly fail-open).
//
// The requestor's identity is NEVER used to determine ownership: the token's
// "sub" says who is asking, not whose data is being returned, so a check against
// it would let any subject holding one granted consent read everyone's data.
//
// Every decision is recorded to the audit sink (when enabled) before it is
// enforced. The check is a coarse allow/deny and is independent of the response
// body's shape, so — unlike a field-level filter — an empty or non-JSON
// personal-data response is still gated rather than passed through.
func (c *ConsentFilter) ResponseFilter(conf interface{}, w pkgHTTP.Response) {
	cfg, ok := conf.(*Config)
	if !ok {
		logging.Errorf("ResponseFilter: invalid config type, skipping request %d", w.ID())
		return
	}

	outcome := c.evaluate(cfg, w)
	metrics.RecordDecision(outcome.decision, outcome.failMode)
	recordAudit(cfg, outcome)
	if outcome.decision == decisionDeny {
		denyResponse(w, cfg)
	}
}

// evaluate runs the consent decision for the current response and returns the
// outcome to enforce; it does not write the response. A missing correlation id,
// missing request context, or a consent-manager error falls back to the fail
// policy (deny unless explicitly fail-open).
func (c *ConsentFilter) evaluate(cfg *Config, w pkgHTTP.Response) responseOutcome {
	// Correlate with the request phase via the stable Nginx $request_id.
	key, ok := correlationKey(w)
	if !ok {
		logging.ErrorfEvery("no-request-id-resp", "ResponseFilter: could not read %q; cannot verify consent", nginxRequestIDVar)
		return failOutcome(cfg, failAlwaysClosed, "no request correlation id", "", nil)
	}

	// Load and delete stored request context (cleanup to prevent memory leaks).
	reqCtx, found := LoadAndDeleteRequestContext(key)
	if !found {
		// The request phase did not capture context for this request; the
		// consent decision cannot be made, so honor the fail policy instead
		// of silently passing the response through.
		logging.WarnfEvery("no-request-context", "ResponseFilter: no request context found for request %s; cannot verify consent", key)
		return failOutcome(cfg, failAlwaysClosed, "no request context", key, nil)
	}

	// Resolve the data owner(s) from the response DATA and check consent per
	// owner. ParseConfig guarantees a resolver is configured.
	consentClient := consent.NewClient(clientConfigFromCfg(cfg))
	return c.evaluateWithResolver(cfg, w, key, reqCtx, consentClient)
}

// evaluateWithResolver reads the upstream body, asks the OwnerResolver who owns
// the data (and whether consent is required), and enforces deny_all: every
// distinct (owner, dataResource) claim must have a granted consent, or the whole
// response is denied. The requestor identity is never consulted for ownership.
func (c *ConsentFilter) evaluateWithResolver(cfg *Config, w pkgHTTP.Response, key string, reqCtx *RequestContext, consentClient *consent.Client) responseOutcome {
	// One deadline for the whole phase. Every call below derives from it, so the
	// total time APISIX holds the buffered response is bounded no matter how many
	// owners the payload resolves to, and a client that has already given up
	// cancels the work rather than leaving it running against the dependencies.
	phaseCtx, cancelPhase := context.WithTimeout(context.Background(), time.Duration(cfg.ResponsePhaseTimeout)*time.Millisecond)
	defer cancelPhase()

	body, err := w.ReadBody()
	if err != nil {
		logging.ErrorfEvery("read-body", "ResponseFilter: could not read the upstream body for request %s: %s", key, logging.Sanitize(err.Error()))
		return failOutcome(cfg, failByPolicy, "read upstream body: "+err.Error(), key, nil)
	}

	if len(body) > cfg.MaxResolveBodyBytes {
		// Forwarding it would copy the body twice more (json.Valid, then the
		// marshalled envelope) on top of APISIX's own buffering. Deny instead:
		// a body too large to examine is not a body we can vouch for.
		logging.WarnfEvery("resolve-body-cap", "ResponseFilter: upstream body of %d bytes for request %s exceeds max_resolve_body_bytes=%d; denying",
			len(body), key, cfg.MaxResolveBodyBytes)
		return failOutcome(cfg, failAlwaysClosed,
			fmt.Sprintf("upstream body of %d bytes exceeds max_resolve_body_bytes=%d", len(body), cfg.MaxResolveBodyBytes),
			key, nil)
	}

	contentType := responseContentType(w)

	// Parties are for CONTRACT identification only - never for ownership. The
	// token names the consumer by DID, while contracts name their parties by
	// self-description URL, so translate it via the participant registry.
	//
	// Both sides are resolved BEFORE the resolver is asked anything, and a failure
	// on either is terminal. Proceeding with an empty Parties would omit the field
	// from /resolve entirely, and a resolver that cannot identify a contract may
	// answer consentRequired:false — which is an unconditional allow. That would
	// put a fail-open seam in the middle of a fail-closed design, reachable by
	// nothing more than a briefly unreachable consent-manager or a revoked token.
	resolveParties := ownerresolver.Parties{}
	consumerDID, claimErr := consumerFromClaims(reqCtx.JWTClaims, cfg.ConsumerClaim)
	if claimErr != nil {
		logging.WarnfEvery("consumer-claim", "ResponseFilter: could not read the consuming participant for request %s: %s", key, logging.Sanitize(claimErr.Error()))
		return failOutcome(cfg, failAlwaysClosed, "no consuming participant identified: "+claimErr.Error(), key, nil)
	}
	consumerSD, sdErr := consentClient.ParticipantSelfDescriptionByDID(phaseCtx, consumerDID)
	if sdErr != nil {
		logging.WarnfEvery("consumer-lookup", "ResponseFilter: could not map the consumer to a participant for request %s: %s", key, logging.Sanitize(sdErr.Error()))
		return failOutcome(cfg, failModeForError(sdErr), "consumer participant lookup failed: "+sdErr.Error(), key, nil)
	}
	// The consumer also scopes the consent match itself: a consent names the one
	// participant it was granted to, so releasing data to any other participant
	// on the strength of it would authorise an agreement the subject never made.
	resolveParties.Consumer = consumerSD

	providerSD, sdErr := consentClient.ProviderSelfDescription(phaseCtx)
	if sdErr != nil {
		logging.ErrorfEvery("provider-sd", "ResponseFilter: could not determine the provider self-description for request %s: %s", key, logging.Sanitize(sdErr.Error()))
		return failOutcome(cfg, failModeForError(sdErr), "provider self-description lookup failed: "+sdErr.Error(), key, nil)
	}
	resolveParties.Provider = providerSD

	resolverClient := ownerresolver.NewClient(cfg.OwnerResolverURL, cfg.OwnerResolverTimeout)
	resolveStarted := time.Now()
	result, err := resolverClient.Resolve(phaseCtx, ownerresolver.Resource{
		Service:     cfg.Service,
		Method:      reqCtx.Method,
		Path:        reqCtx.Path,
		ContentType: contentType,
	}, resolveParties, body)
	metrics.RecordDependencyCall(metrics.DependencyOwnerResolver, outcomeOf(err), time.Since(resolveStarted))
	if err != nil {
		logging.ErrorfEvery("resolver-error", "ResponseFilter: owner resolver error for request %s: %s", key, logging.Sanitize(err.Error()))
		return failOutcome(cfg, failByPolicy, "owner resolver error: "+err.Error(), key, nil)
	}

	if !result.ConsentRequired {
		return responseOutcome{decision: decisionAllow, reason: "no consent required", requestID: key, resource: reqCtx.Path, method: reqCtx.Method}
	}
	if len(result.Claims) == 0 {
		// Consent required but no owner could be resolved — fail closed.
		return failOutcome(cfg, failAlwaysClosed, "consent required but no data owner resolved", key, nil)
	}

	claims, err := distinctClaims(result.Claims)
	if err != nil {
		return failOutcome(cfg, failAlwaysClosed, err.Error(), key, nil)
	}
	if outcome, ok := checkPurposeScoping(cfg, key, claims); !ok {
		return outcome
	}

	if len(claims) > cfg.MaxOwnersPerResponse {
		logging.WarnfEvery("owner-cap", "ResponseFilter: %d distinct data owners for request %s exceeds max_owners_per_response=%d; denying",
			len(claims), key, cfg.MaxOwnersPerResponse)
		return failOutcome(cfg, failAlwaysClosed,
			fmt.Sprintf("response resolves to %d data owners, above max_owners_per_response=%d", len(claims), cfg.MaxOwnersPerResponse),
			key, nil)
	}

	return checkOwners(phaseCtx, cfg, key, reqCtx, consentClient, claims, consumerSD)
}

// checkPurposeScoping reports whether every resolved claim carries a processing
// purpose, and what to do when one does not.
//
// With require_purpose set, a claim without a purpose denies: it is a policy the
// operator asked for, not an outage, so the fail policy does not apply to it.
// Otherwise the check proceeds unscoped by purpose and is counted, so a resolver
// that has silently stopped emitting purposes is visible in the metrics instead
// of quietly widening what a consent authorises.
func checkPurposeScoping(cfg *Config, key string, claims []ownerClaim) (responseOutcome, bool) {
	for _, claim := range claims {
		if claim.purpose != "" {
			continue
		}
		if cfg.RequirePurpose {
			logging.WarnfEvery("purpose-required", "ResponseFilter: resolved claim without a processing purpose for request %s and require_purpose is set; denying", key)
			return failOutcome(cfg, failAlwaysClosed, "resolved claim without a processing purpose", key, nil), false
		}
		metrics.RecordPurposeUnconstrained()
		logging.WarnfEvery("purpose-unconstrained", "ResponseFilter: the resolver named no processing purpose, so consent is matched on the consumer alone; set require_purpose once the resolver emits one")
	}
	return responseOutcome{}, true
}

// ownerClaim is one distinct (owner, dataResource) pair to check.
type ownerClaim struct {
	owner        string
	dataResource string
	purpose      string
}

// distinctClaims collapses the resolver's claims to the distinct
// (owner, dataResource) pairs that must be checked, preserving the resolver's
// order so the reported denial is stable. A claim naming no owner is an error:
// the resolver said consent is required but not whose.
func distinctClaims(claims []ownerresolver.Claim) ([]ownerClaim, error) {
	type pair struct{ owner, resource string }
	seen := make(map[pair]bool, len(claims))
	distinct := make([]ownerClaim, 0, len(claims))
	for _, claim := range claims {
		if claim.OwnerID == "" {
			return nil, errors.New("resolved claim without a data owner")
		}
		p := pair{owner: claim.OwnerID, resource: claim.DataResource}
		if seen[p] {
			continue
		}
		seen[p] = true
		distinct = append(distinct, ownerClaim{owner: claim.OwnerID, dataResource: claim.DataResource, purpose: claim.Purpose})
	}
	return distinct, nil
}

// outcomeOf maps a call's error to the metric's outcome label.
func outcomeOf(err error) string {
	if err != nil {
		return metrics.OutcomeError
	}
	return metrics.OutcomeSuccess
}

// maxConcurrentConsentChecks bounds how many per-owner checks are in flight at
// once. Serial checks made the response latency the sum of every owner's; an
// unbounded fan-out would instead make one response a burst against the
// consent-manager. A small fixed width keeps both bounded.
const maxConcurrentConsentChecks = 8

// checkOwners enforces deny_all across the resolved claims: every one must have
// a granted consent for this consumer, or the whole response is denied.
//
// Checks run concurrently up to maxConcurrentConsentChecks and short-circuit on
// the first problem — the remaining calls are cancelled, since nothing they
// could return would change the answer. The results are then reduced by
// reduceOwnerResults, which ranks them so the verdict does not depend on which
// goroutine happened to finish first.
func checkOwners(ctx context.Context, cfg *Config, key string, reqCtx *RequestContext, client *consent.Client, claims []ownerClaim, consumerSD string) responseOutcome {
	results := make([]ownerCheckResult, len(claims))
	checksCtx, cancelChecks := context.WithCancel(ctx)
	defer cancelChecks()

	slots := make(chan struct{}, maxConcurrentConsentChecks)
	var wg sync.WaitGroup

	for i, claim := range claims {
		wg.Add(1)
		go func(i int, claim ownerClaim) {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-checksCtx.Done():
				return
			}

			req := consent.ConsentRequest{
				Subject:      claim.owner,
				Resource:     reqCtx.Path,
				Method:       reqCtx.Method,
				DataResource: claim.dataResource,
				Consumer:     consumerSD,
				Purpose:      claim.purpose,
			}
			results[i].attempted = true
			results[i].request = req
			ownerResource := resourceOrPath(claim.dataResource, reqCtx.Path)

			started := time.Now()
			resp, err := client.CheckConsent(checksCtx, req)
			metrics.RecordDependencyCall(metrics.DependencyConsentManager, outcomeOf(err), time.Since(started))
			switch {
			case err != nil:
				results[i].err = err
				results[i].problem = true
			case resp.Decision != consent.DecisionAllow:
				results[i].record = checkedOwner{
					subject: claim.owner, resource: ownerResource, decision: decisionDeny, reason: resp.Reason,
				}
				results[i].outcome = responseOutcome{
					decision:  decisionDeny,
					reason:    resp.Reason,
					requestID: key,
					subject:   claim.owner,
					resource:  ownerResource,
					method:    reqCtx.Method,
				}
				results[i].problem = true
			default:
				results[i].record = checkedOwner{
					subject: claim.owner, resource: ownerResource, decision: decisionAllow, reason: resp.Reason,
				}
			}
			if results[i].problem {
				// Nothing the other owners could say would change a deny_all
				// verdict, so stop paying for their calls.
				cancelChecks()
			}
		}(i, claim)
	}
	wg.Wait()

	return reduceOwnerResults(cfg, key, reqCtx, ctx.Err(), results)
}

// ownerCheckResult is one owner's consent check within a response.
type ownerCheckResult struct {
	// outcome is the deny to enforce, set only when the owner denied.
	outcome responseOutcome
	// err is the dependency failure, set only when the check could not complete.
	err error
	// request is the check that was made, for the audit record on an error.
	request consent.ConsentRequest
	// record is this owner's audit entry (allow or deny).
	record checkedOwner
	// problem is true for a deny or an error, i.e. anything but a plain allow.
	problem bool
	// attempted is false for an owner whose check never started because the
	// phase was already cancelled.
	attempted bool
}

// reduceOwnerResults collapses the per-owner results into the response outcome,
// enforcing deny_all.
//
// Results are ranked by DECISIVENESS first and index second. A deny is a
// definite answer; an error is the absence of one, and only the absence is
// subject to the operator's fail policy. Reducing by index alone ranked the two
// purely by position, so an error at a lower index could mask a deny at a higher
// one — and under `fail_open: true` that released data an owner had explicitly
// refused, with the audit record showing the contradiction (a per-owner deny
// alongside an enforced allow). Scanning for a deny across all results first
// removes the ordering dependency; within each pass the lowest index still wins,
// so the verdict stays deterministic rather than depending on which goroutine
// finished first.
//
// phaseErr is the response phase's own context error, which distinguishes a call
// cancelled because a sibling already denied (not a failure in itself) from one
// cancelled because the whole phase ran out of budget (which is).
func reduceOwnerResults(cfg *Config, key string, reqCtx *RequestContext, phaseErr error, results []ownerCheckResult) responseOutcome {
	// Every owner that was actually consulted is recorded, whatever the verdict,
	// so the audit log names them all rather than only the first refusal.
	checked := make([]checkedOwner, 0, len(results))
	for _, result := range results {
		if result.attempted && result.record.subject != "" {
			checked = append(checked, result.record)
		}
	}

	for _, result := range results {
		if result.attempted && result.problem && result.err == nil {
			outcome := result.outcome
			outcome.checked = checked
			return outcome
		}
	}

	for _, result := range results {
		if !result.attempted || result.err == nil {
			continue
		}
		// A call cancelled because a *different* owner already denied is not
		// itself a failure; that deny was returned by the pass above.
		if errors.Is(result.err, context.Canceled) && phaseErr == nil {
			continue
		}
		logging.ErrorfEvery("consent-check", "ResponseFilter: consent check error for request %s: %s", key, logging.Sanitize(result.err.Error()))
		req := result.request
		outcome := failOutcome(cfg, failModeForError(result.err), "consent check error: "+result.err.Error(), key, &req)
		outcome.checked = checked
		return outcome
	}
	return responseOutcome{decision: decisionAllow, requestID: key, resource: reqCtx.Path, method: reqCtx.Method, checked: checked}
}

// clientConfigFromCfg builds the consent-manager client config from the plugin config.
func clientConfigFromCfg(cfg *Config) consent.ClientConfig {
	return consent.ClientConfig{
		BaseURL:          cfg.ConsentAPIURL,
		APIPrefix:        cfg.ConsentAPIPrefix,
		ProviderSD:       cfg.ProviderSD,
		ParticipantToken: cfg.ParticipantToken,
		TokenServiceURL:  cfg.TokenServiceURL,
		TokenAudience:    cfg.TokenAudience,
		// Safe to convert: Validate bounds ParticipantTokenTTL well below the
		// point where the multiplication overflows a time.Duration.
		TokenTTL:  time.Duration(cfg.ParticipantTokenTTL) * time.Second,
		TimeoutMs: cfg.ConsentAPITimeout,
	}
}

// resourceOrPath returns dataResource when set, else the request path (for audit).
func resourceOrPath(dataResource, path string) string {
	if dataResource != "" {
		return dataResource
	}
	return path
}

// failMode classifies why a consent decision could not be reached, because not
// every unresolved situation deserves the same policy.
type failMode int

const (
	// failByPolicy is an availability failure of a dependency — the resolver or
	// the consent-manager is down, slow, or erroring. Whether that releases the
	// data is the operator's call, so cfg.FailOpen decides.
	failByPolicy failMode = iota

	// failAlwaysClosed is a situation in which the plugin is structurally unable
	// to gate: it cannot correlate the two phases, it never captured the request,
	// it has no credentials at all, or the resolver says consent is required but
	// names no owner. None of these are outages to ride out — fail_open must not
	// turn a misconfiguration or a lost request into a silent bypass, so these
	// always deny.
	failAlwaysClosed
)

// String names the fail mode for metrics and logs.
func (m failMode) String() string {
	if m == failAlwaysClosed {
		return "always_closed"
	}
	return "by_policy"
}

// failOutcome builds the outcome for an unresolved consent check. mode decides
// whether the operator's fail policy applies at all. req may be nil when no
// request context was captured.
func failOutcome(cfg *Config, mode failMode, reason, requestID string, req *consent.ConsentRequest) responseOutcome {
	decision := decisionDeny
	if mode == failByPolicy && cfg.IsFailOpen() {
		decision = decisionAllow
	}
	o := responseOutcome{decision: decision, reason: reason, requestID: requestID, failMode: mode.String()}
	if req != nil {
		o.subject = req.Subject
		o.resource = req.Resource
		o.method = req.Method
	}
	return o
}

// failModeForError maps a dependency error to its fail mode. A missing
// credential or a consumer that is not in the participant registry is a
// permanent misconfiguration: retrying will not fix it, so failing it open would
// not ride out an outage, it would grant that consumer standing access. Anything
// else is treated as an outage the operator's policy governs.
func failModeForError(err error) failMode {
	if errors.Is(err, consent.ErrNoCredentials) || errors.Is(err, consent.ErrParticipantNotRegistered) {
		return failAlwaysClosed
	}
	return failByPolicy
}

// recordAudit emits the decision to the audit sink when auditing is enabled.
// The emit is asynchronous and best-effort, so it never affects the decision.
//
// One record is emitted per data owner whose consent was consulted, so the log
// can answer whose consent was checked and what each said — not merely whether
// the response was released. When no owner was reached (a failure before or
// during resolution) the outcome itself is recorded instead, so the request
// still appears in the record.
func recordAudit(cfg *Config, outcome responseOutcome) {
	if !cfg.AuditEnabled {
		return
	}
	emitter := audit.Get(audit.Config{
		Endpoint:    cfg.AuditOTLPEndpoint,
		ServiceName: cfg.AuditServiceName,
		Timeout:     time.Duration(cfg.ConsentAPITimeout) * time.Millisecond,
		Headers:     cfg.AuditOTLPHeaders,
	})
	now := time.Now()

	if len(outcome.checked) == 0 {
		emitter.Emit(audit.Event{
			Time:      now,
			RequestID: outcome.requestID,
			Subject:   outcome.subject,
			Resource:  outcome.resource,
			Method:    outcome.method,
			Decision:  outcome.decision,
			Reason:    outcome.reason,
		})
		return
	}
	for _, checked := range outcome.checked {
		emitter.Emit(audit.Event{
			Time:      now,
			RequestID: outcome.requestID,
			Subject:   checked.subject,
			Resource:  checked.resource,
			Method:    outcome.method,
			Decision:  checked.decision,
			Reason:    checked.reason,
		})
	}
}

// deniedResponseHeaderPrefixes are the only upstream response headers allowed to
// survive a denial. CORS headers describe the exchange rather than the resource,
// and dropping them would show a browser client a CORS error instead of the 403
// it was actually given.
var deniedResponseHeaderPrefixes = []string{"Access-Control-"}

// denyResponse replaces the upstream response with the configured denial.
//
// Every other upstream header is removed first. A denied caller must not learn
// anything about the data they were refused, and the upstream's headers say
// plenty: Set-Cookie, ETag and Last-Modified (the entity exists, and this is its
// version), Link (there are more pages), and application counters such as
// X-Total-Count or NGSILD-Results-Count (how many records matched) — a side
// channel straight around the gate. Content-Encoding and the upstream's
// Content-Length are also actively wrong once the body is replaced, so
// Content-Length is set to the deny body's own size.
func denyResponse(w pkgHTTP.Response, cfg *Config) {
	body := []byte(cfg.DenyResponseBody)

	header := w.Header()
	if view := header.View(); view != nil {
		// Collect first: the names are read from the same map Del mutates.
		names := make([]string, 0, len(view))
		for name := range view {
			names = append(names, name)
		}
		for _, name := range names {
			if !survivesDenial(name) {
				header.Del(name)
			}
		}
	}
	header.Set("Content-Type", cfg.DenyResponseContentType)
	header.Set("Content-Length", strconv.Itoa(len(body)))

	w.WriteHeader(cfg.DenyStatusCode)
	if _, err := w.Write(body); err != nil {
		logging.Errorf("ResponseFilter: failed to write the deny body for request %d: %s", w.ID(), logging.Sanitize(err.Error()))
	}
}

// survivesDenial reports whether an upstream response header may be kept on a
// denial.
func survivesDenial(name string) bool {
	for _, prefix := range deniedResponseHeaderPrefixes {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), prefix) {
			return true
		}
	}
	return false
}

// claimKeysToDecode returns the claim keys the request phase must decode: the
// configured forward list plus the root of the consumer-claim path, so the
// consumer can be read in the response phase. An empty result means "all claims".
func claimKeysToDecode(cfg *Config) []string {
	if len(cfg.JWTClaimsToForward) == 0 {
		// DecodeClaims returns every claim in this case - nothing to add.
		return nil
	}
	keys := append([]string(nil), cfg.JWTClaimsToForward...)
	if cfg.ConsumerClaim == "" {
		return keys
	}
	root := claimPathRoot(cfg.ConsumerClaim)
	for _, k := range keys {
		if k == root {
			return keys
		}
	}
	return append(keys, root)
}

// Claim-path syntax. A path is dot-separated segments, each optionally followed
// by bracketed array indices, e.g. "verifiableCredential[0].issuer".
const (
	// claimPathSeparator separates the segments of a dotted claim path.
	claimPathSeparator = "."

	// claimIndexOpen and claimIndexClose bracket an explicit array index.
	claimIndexOpen  = "["
	claimIndexClose = "]"

	// firstElementIndex is the element used when a segment resolves to an array
	// and the path names no index.
	firstElementIndex = 0
)

// errClaimPathUnset signals that no consumer claim path is configured, as
// distinct from a configured path that did not resolve. Both deny, but only one
// is a configuration mistake worth reporting as such.
var errClaimPathUnset = errors.New("consumer_claim is not configured")

// consumerFromClaims reads the consuming participant from a dotted claim path
// (e.g. "verifiableCredential.issuer").
//
// A Verifiable Presentation commonly carries "verifiableCredential" as a JSON
// ARRAY, so a walk that only ever descends into objects fails on an ordinary
// token — silently, returning "" with no indication of which segment gave up.
// Two forms of array traversal are therefore supported: an explicit index
// ("verifiableCredential[0].issuer"), and an implicit first element when a bare
// segment lands on an array.
//
// The error names the segment that failed, so a mistyped path is diagnosable
// rather than appearing as a consumer that simply is not there.
func consumerFromClaims(claims map[string]interface{}, path string) (string, error) {
	if path == "" {
		return "", errClaimPathUnset
	}
	if len(claims) == 0 {
		return "", errors.New("no claims decoded from the token")
	}

	var current interface{} = claims
	for _, segment := range strings.Split(path, claimPathSeparator) {
		name, indices, err := parseClaimSegment(segment)
		if err != nil {
			return "", err
		}
		if name != "" {
			node, ok := descendIntoObject(current)
			if !ok {
				return "", fmt.Errorf("claim path %q: %q is not an object", path, segment)
			}
			current, ok = node[name]
			if !ok {
				return "", fmt.Errorf("claim path %q: no claim %q", path, name)
			}
		}
		for _, index := range indices {
			array, ok := current.([]interface{})
			if !ok {
				return "", fmt.Errorf("claim path %q: %q is not an array", path, name)
			}
			if index >= len(array) {
				return "", fmt.Errorf("claim path %q: index %d is out of range (%d element(s))", path, index, len(array))
			}
			current = array[index]
		}
	}

	if value, ok := current.(string); ok && value != "" {
		return value, nil
	}
	return "", fmt.Errorf("claim path %q did not resolve to a non-empty string", path)
}

// descendIntoObject returns node as an object, stepping into the first element
// of an array first. A Verifiable Presentation's "verifiableCredential" is
// routinely an array of one, and requiring an explicit "[0]" for that common
// shape would make the default path wrong for most real tokens.
func descendIntoObject(node interface{}) (map[string]interface{}, bool) {
	if array, ok := node.([]interface{}); ok {
		if len(array) == 0 {
			return nil, false
		}
		node = array[firstElementIndex]
	}
	object, ok := node.(map[string]interface{})
	return object, ok
}

// parseClaimSegment splits one path segment into its claim name and any explicit
// array indices, e.g. "verifiableCredential[0]" -> ("verifiableCredential", [0]).
func parseClaimSegment(segment string) (name string, indices []int, err error) {
	name, rest, found := strings.Cut(segment, claimIndexOpen)
	if !found {
		return segment, nil, nil
	}
	for rest != "" {
		digits, remainder, closed := strings.Cut(rest, claimIndexClose)
		if !closed {
			return "", nil, fmt.Errorf("claim path segment %q: unterminated %q", segment, claimIndexOpen)
		}
		index, convErr := strconv.Atoi(digits)
		if convErr != nil || index < 0 {
			return "", nil, fmt.Errorf("claim path segment %q: %q is not an array index", segment, digits)
		}
		indices = append(indices, index)
		if remainder == "" {
			break
		}
		if !strings.HasPrefix(remainder, claimIndexOpen) {
			return "", nil, fmt.Errorf("claim path segment %q: unexpected %q after an index", segment, remainder)
		}
		rest = strings.TrimPrefix(remainder, claimIndexOpen)
	}
	return name, indices, nil
}

// claimPathRoot returns the first claim name in a dotted path, without any array
// index, so the request phase knows which top-level claim to decode.
func claimPathRoot(path string) string {
	root := strings.SplitN(path, claimPathSeparator, 2)[0]
	if name, _, found := strings.Cut(root, claimIndexOpen); found {
		return name
	}
	return root
}
