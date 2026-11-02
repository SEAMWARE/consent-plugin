# Implementation Plan: update consent-filter plugin for dsc-consent-manager

## Overview
Move the plugin from the Prometheus-X/Visions consent-manager to **dsc-consent-manager**
(`/v1`, spec: https://github.com/wistefan/dsc-consent-manager/blob/main/api/openapi.yaml).
The OwnerResolver call stays. After it, each resolved owner DID is checked as `userIdentifier`,
either through `GET /consents?userIdentifier=` (**list** mode) or `GET /consents/check`
(**check** mode). The plugin authenticates only with the bearer token from `token_service_url`.
The consent key, the identifier search, `?receipt=true`/`recipients[0]` matching and the
`consent_api_host` Host rewrite are removed.

### Facts from the new API that shape the plan
- `GET /consents` takes `userIdentifier`, `privacyNoticeId`, `status` (default `GRANTED`),
  `page` and `size`, and returns `ConsentPage{content[], page, size, totalElements, totalPages}`.
  `content[]` is `ConsentResponse{id, privacyNoticeId, status, provider, consumer, purposes[]string,
  data[]string, contractUri, consented, ...}`. `provider` and `consumer` are participant
  **identifiers** (DIDs), not SD URLs. `consented` is derived from `status` and is the field
  the spec designates for "may data be processed under this record now". `data[]` holds the
  personal-data **categories** copied off the notice (e.g. `"Trip records"`), not resource
  identifiers. The list is scoped to consents that name the caller as provider or consumer.
- Notices are per contract (`/privacy-notices/by-contract`, one active notice per contract and
  provider), but a route-level `privacy_notice_id` is fixed and not tied to the requester.
- `GET /consents/check?userIdentifier&privacyNoticeId(uuid, required)[&purpose]` returns
  `ConsentValidity{valid, consentId, status, purposes, reason, checkedAt}`. It is marked
  `no-store` and says nothing about the consumer. `403` means the caller is deregistered.
- `GET /consents/{id}` (format `full`|`receipt`|`receipt-kantara`) answers `404` when the caller is
  not a party to that consent.
- Participant registry: `GET /participants?identifier=<did>` returns
  `ParticipantPage{content[Participant{identifier, selfDescriptionUri, deregisteredAt, ...}]}`,
  including deregistered participants.
  `GET /participants/me` returns a `Participant`. The field is now `selfDescriptionUri`
  (it was `selfDescriptionURL`), so the DID→SD mapping the resolver's `parties` rely on is
  **kept and adapted**, not deleted.
- All of these operations require a bearer token with role `PARTICIPANT` and the
  participant-identifier claim. The token still comes from the consent-facade
  (`token_service_url`, `token_audience`).

### Design decisions (for review)
1. **Mode selection.** Add `check_mode`, either `list` (the default) or `check`. List mode
   adds `privacyNoticeId` to the query whenever a notice id is known (from the resolver claim
   or `privacy_notice_id`), so it needs one round trip per owner and runs the same
   `matchConsent`. Check mode needs two (`/consents/check`, then the mandatory consent read in
   decision 2), and the spec allows only one record per subject and notice in force, so both
   give the same decision. Check mode is therefore opt-in, as the ticket's "alternative", and
   never picked automatically. When `check_mode` is `check` and a claim has no notice id, the
   response always gets a closed deny.
2. **Consumer binding stays mandatory, and both modes share one matcher.**
   - `matchConsent(req, self, ConsentResponse)` accepts a record only when `consented == true`,
     its `provider` equals this participant's own identifier (`self`), its
     `consumer` equals the requesting consumer's DID (from `consumer_claim`), its
     `contractUri` equals the resolver's `contractUri` when that is set, its `privacyNoticeId`
     equals the effective notice id when one is set, and its `purposes[]` contains the
     effective purpose when one is set. The notice id is compared on the client too, like
     `consented`, so the notice scoping that `require_contract` counts on does not rest only
     on the server applying the query filter. The consumer's SD URL is never compared:
     `consumer` is always an identifier, so the SD URL is only passed to the resolver.
   - The `provider` check is needed because `/consents` and `/consents/check` also return
     consents that name this participant as the *consumer* of another provider's contract.
     Without it, a request whose consumer claim is this participant's own DID could be
     released on a consent that covers someone else's processing. `self` is the `identifier`
     from `GET /participants/me`. The client always fetches it, even with a static
     `participant_token`/`provider_sd`, so there is no configuration without the check.
   - `dataResource` is **not** matched against `data[]`. `data[]` holds notice categories, not
     resource identifiers, so a verbatim match would deny every request that sets
     `dataResource`, and check mode could not apply it anyway.
   - **Contract scoping.** The ticket asks for a match on the resolved contract, but today's
     `ownerresolver.Claim` carries neither `contractUri` nor `privacyNoticeId`. A claim with
     neither (and no route-level `privacy_notice_id`) would match any consent from this owner
     to this consumer under this provider. This is treated like a missing purpose: a new
     `require_contract` flag (default `false`, like `require_purpose`) denies such a claim, and
     without it the check is counted (`consent_contract_unconstrained_total`) and logged with a
     rate-limited `contract-unconstrained` warning. A route-level `privacy_notice_id` counts as
     scoped, because a notice belongs to one contract.
   - List mode runs `matchConsent` on each `ConsentPage` entry.
   - Check mode: `valid:true` alone doesn't say which consumer the consent names, and
     `/consents/check` is only scoped to the caller being *a* party. The client therefore
     **always** reads `GET /consents/{consentId}` and runs `matchConsent` on it. This read is
     mandatory: without it, a route-level `privacy_notice_id` would let any consumer through
     on another consumer's grant. The read sends `format=full`, because the receipt formats would decode as a
     `ConsentResponse` with `consented`, `provider` and `consumer` zeroed. `consentId` comes
     from a response body, so it must be a UUID (else deny) and is `url.PathEscape`d.
   - **Receipts are out of scope.** The `format=full` read returns a `ConsentResponse`, not a
     signed receipt (`receipt`/`receipt-kantara` return `{receipt, jws}`), and list mode makes
     no read at all. The ticket's optional receipt fetch is not implemented. Instead the audit
     record carries `consentId` (Step 4), so a receipt can be fetched by id later.
3. **No caching of consent answers** in either mode, so "deny after revoke" takes effect
   immediately. The token and participant-SD caches stay.
4. **Failure mapping.**
   - `200` with no match, `valid:false`, or `404` on the consent read: **deny**, and the reason
     is logged.
   - `401` after one token refresh, or `403`: new sentinel `consent.ErrConsentManagerAuth`.
     A 403 also notes the caller may be deregistered.
   - **Every other `4xx`** except `429` (e.g. `400`, a `404` on `/consents`, `/consents/check`
     or the registry from a wrong `consent_api_prefix`, `405`, `422`): new sentinel
     `consent.ErrConsentManagerRejected`. These are permanent misconfigurations, so
     `fail_open` must not release data on them.
   - Both sentinels map to `failAlwaysClosed` and are logged as config/auth errors.
   - `429`, `5xx`, transport error or timeout: a plain error, mapped to `failByPolicy`
     (`fail_open` governs) and logged as retryable.
   - One shared helper (`statusError(operation, status, body)`) applies this mapping on every
     endpoint, so the registry, `/participants/me` and both consent modes cannot diverge.
5. **Purpose.** A claim's own `purpose` wins, and `purpose` in the config is the fallback.
   `require_purpose` checks the result of that fallback. Matching is verbatim, which is also
   how the `purpose` query parameter of `/consents/check` is applied.
6. **To confirm with the OwnerResolver owners** (recorded in the Step 4 PR): the claim field
   names `contractUri` and `privacyNoticeId`, and the `purpose` format. Notice purposes are
   full sentences, while `Claim.Purpose` is currently documented as "purpose (or contract)",
   so the resolver must emit the notice's purpose string for a purpose match to succeed.
   The resolver must also emit at least one of `contractUri` or `privacyNoticeId` per claim
   (unless the route sets `privacy_notice_id`), so `require_contract` can be turned on.
7. **Release.** Config fields are removed, so the work→main PR needs the **`major`**
   semver label. The release workflow then publishes the new image tag.

## Steps

### Step 1: Config surface — drop Visions-only options, add check-mode options
Files: `internal/plugin/config.go`, `internal/plugin/config_test.go`, `internal/plugin/consent.go`
(`clientConfigFromCfg` only), `internal/plugin/consent_test.go`, `internal/consent/client.go`,
`internal/consent/client_test.go`, `internal/integration/integration_test.go`,
`README.md` (Configuration Reference table only).
- Remove from `Config`:
  - `ConsentAPIHost` (`consent_api_host`)
  - `ConsentKey` (`consent_key`)
  - `EnvConsentKey` (`CONSENT_KEY`) and its `applyEnv` branch
- Remove `Host` and `ConsentKey` from `consent.ClientConfig` and `Client`, the `httpReq.Host`
  override in `do()`, and the consent-key hash in `cacheKey()`. Until Step 3 the identifier
  search just sends no `x-visionstrust-consent-key` header.
- Add the new fields:
  - `CheckMode string` (`check_mode`, constants `CheckModeList = "list"` and
    `CheckModeCheck = "check"`, `applyDefaults` sets `list`)
  - `PrivacyNoticeID string` (`privacy_notice_id`)
  - `Purpose string` (`purpose`)
  - `RequireContract bool` (`require_contract`, default `false`, decision 2). Step 4 applies it.
- Add validation:
  - `check_mode` must be `list` or `check` after defaults.
  - `privacy_notice_id`, when set, must be a UUID. Add an exported `consent.IsUUID` (stdlib
    regexp with a named pattern constant, no new dependency) so Step 3 reuses it for
    `consentId`.
  - `check_mode=check` without `privacy_notice_id` is still valid, because the resolver may
    supply the notice id per claim.
- README table: delete the `consent_api_host` and `consent_key` rows, add the four new rows,
  and keep `config_doc_test.go` green.
- Tests: table-driven cases for each new validation rule and for `IsUUID`. Remove the tests for the removed
  fields and the env fallback, and update the `cacheKey` tests.
  - `internal/plugin/consent_test.go`: drop `ConsentKey` from the test `Config` literal.
  - `internal/integration/integration_test.go`: drop the `consent_key` config entries and the
    `x-visionstrust-consent-key == "itest-consent-key"` assertions. Step 5 adds the opposite
    assertion, that the header is absent.
  - `internal/consent/client_test.go`: drop `ConsentKey`/`Host` from every `ClientConfig`,
    the consent-key header assertions, `TestCheckConsent_EmptyConsentKeyOmitsHeader`, and
    the "consent key" `cacheKey` case.
- Acceptance: `make test lint license-check` pass, and no references to `consent_api_host`,
  `consent_key` or `CONSENT_KEY` remain under `internal/`.

### Step 2: Participant registry and provider identity on the dsc-consent-manager schema
Files: `internal/consent/client.go`, `internal/consent/client_test.go`,
`internal/integration/integration_test.go` (registry fake only).
- `ParticipantSelfDescriptionByDID`:
  - Call `GET {base}{prefix}/participants?identifier=<url-escaped DID>` and decode
    `ParticipantPage.content[]`.
  - Take the first entry whose `identifier` equals the DID and use its `selfDescriptionUri`.
  - Empty content, a matching entry with no SD URI, or a matching entry with `deregisteredAt`
    set returns `ErrParticipantNotRegistered` (always closed). The `identifier` filter returns
    participants "deregistered or not", and a retained record keeps its `selfDescriptionUri`,
    so without this check a departed consumer would reach the resolver and the consent check.
    The deny gets an explicit, logged reason and does not rest on the server refusing to
    deregister a participant with a GRANTED consent. Negative-cache it like "not found".
  - The rule applies on a cache miss only. A DID that was cached as registered keeps passing
    the registry gate until its positive entry expires (`participantSDCacheTTL`, 10 min).
    This bounded window is accepted, not closed with a shorter TTL: the consent check still
    runs on every request, uncached (decision 3), so the window only delays the explicit
    "deregistered" reason and does not skip the consent decision. Keep the TTL constant's
    GoDoc stating this window, and Step 6 documents it in the README.
  - Replace `participantListEntry`, `participantsResponse` and `decodeParticipants` with the
    new shape. Keep the positive and negative caches.
- `fetchProviderSD` and `meResponse`: decode `Participant{identifier, selfDescriptionUri}`.
  - `credentials` also returns the caller's own `identifier` (decision 2), cached with the
    token entry. The identifier is fetched from `/participants/me` even when `ProviderSD` or a
    static `ParticipantToken` is configured, so the static short-circuit only skips the token
    service, not `/me`. A configured `ProviderSD` still wins over the fetched SD URI.
  - An empty `identifier` in the `/participants/me` response is an error (no provider binding
    possible), mapped to `failAlwaysClosed` via `ErrConsentManagerRejected`.
- Add the error sentinels from decision 4: `ErrConsentManagerAuth` and
  `ErrConsentManagerRejected`.
  - Add the shared `statusError` helper from decision 4 (it wraps `unexpectedStatus`, so
    bodies stay out of errors) and use it for registry and `/participants/me` responses:
    401 after refresh → auth, 403 → auth with a "caller may be deregistered" reason, any
    other 4xx except 429 → rejected, 429/5xx → plain error.
  - In `internal/plugin/consent.go`, extend `failModeForError` so both are `failAlwaysClosed`,
    and add table cases in `consent_test.go`.
- Tests: a table for `statusError` (400, 401, 403, 404, 405, 422 → sentinel; 429, 500, 503 →
  plain error), table-driven registry cases (found, not found, missing SD, 401→refresh, 403,
  404 from a wrong prefix, 429, 5xx, malformed JSON, `deregisteredAt` set → not registered,
  and a DID cached as registered that the registry now reports deregistered: still allowed
  from cache before the positive TTL expires, `ErrParticipantNotRegistered` after it, using
  an in-package test that backdates the entry's `expiry` in `participantSDCache`), the `/participants/me` shape (including a missing `identifier`, and the
  `/me` call still made with static token and `ProviderSD`), and the `failModeForError` mapping. Update
  `participantRegistryHandler` in the integration fakes to the new page shape, and make the
  `/v1/participants/me` fakes in `internal/plugin/consent_test.go` and the integration tests
  return an `identifier`, since the static-config cases now call `/me` too.
- Acceptance: the existing plugin and integration tests still pass with the new registry shape.

### Step 3: Consent client — list and check modes
Files: `internal/consent/client.go`, `internal/consent/models.go`, `internal/consent/client_test.go`,
`internal/consent/reset.go`, `internal/plugin/consent.go` (`checkOwners` consumer only),
`internal/integration/integration_test.go` (consent-manager fake),
`internal/plugin/consent_test.go` (fakes only).
- Delete:
  - `identifierSearchPath`, `consentKeyHeader`, `resolveUserIdentifier` and the identifier cache
    (also remove it from `ResetCaches`)
  - `participantConsentsPathFmt`, `participantConsentsResponse`, `consentRecord`,
    `participantRef`, `grantedTo` with the `recipients[0]` logic, and `hasGrantedConsent`
- `models.go`:
  - Add a `Mode` type with `ModeList` and `ModeCheck` to `ConsentRequest`. `ModeList` is the
    zero value, so callers that don't set `Mode` (the plugin until Step 4) get list mode.
  - Add the fields `PrivacyNoticeID` and `ContractURI`. `Consumer` is now the consumer's
    participant identifier (DID). There is no `ConsumerSD` field (decision 2).
- `internal/plugin/consent.go`: in the same step, `checkOwners` takes `consumerDID` instead of
  `consumerSD` and sets `Consumer: consumerDID`. `evaluateWithResolver` passes it down, and
  `consumerSD` stays resolver-only (`parties.consumer`). This keeps the fakes honest: they
  return DIDs as `consumer`, never SD URLs.
  - Add `ConsentID` to `ConsentResponse` for audit.
  - Update the package and type GoDoc so it no longer mentions Prometheus-X/Visions.
- List mode (`listConsents`):
  - Call `GET {base}{prefix}/consents?userIdentifier=<owner>&page=<n>&size=<consentListPageSize>`,
    adding `&privacyNoticeId=` when it is known.
  - Page until a match is found or `totalPages` is reached, capped by `maxConsentListPages`.
    Hitting the cap without a match denies, with a reason.
  - Each entry goes through `matchConsent` (decision 2):
    - `consented == true` (defensive, the server already defaults to `status=GRANTED`)
    - `provider` equals the caller's own identifier from `credentials`
    - `consumer` equals `req.Consumer`
    - `contractUri` equals `req.ContractURI` when that is set
    - `privacyNoticeId` equals `req.PrivacyNoticeID` when that is set
    - `purposes[]` contains `req.Purpose` when that is set
  - Matching is verbatim and case-sensitive. A match returns allow with `ConsentID`.
    `req.DataResource` is not matched (it stays in the audit record only).
- Check mode (`checkValidity`):
  - Call `GET {base}{prefix}/consents/check?userIdentifier=&privacyNoticeId=[&purpose=]`.
  - `valid:false` denies with the server's `reason`.
  - `valid:true` always leads to `GET {base}{prefix}/consents/{consentId}?format=full`, and the
    returned `ConsentResponse` must pass the same `matchConsent` as list mode (decision 2).
    A `404` there, a failed match, or a missing or non-UUID `consentId` (`consent.IsUUID`)
    denies. The id is `url.PathEscape`d. This read is mandatory.
  - Never cached.
- `CheckConsent`:
  - Keep the guards for an empty `Subject` or `Consumer`.
  - In `ModeCheck`, an empty `PrivacyNoticeID` denies.
  - Keep the single token refresh and retry on 401.
  - Map statuses through `statusError` (decision 4). The only exception is the `404` on the
    consent read, which denies.
  - All paths and query keys are named constants, and query strings are built with `url.Values`.
- Update the `Client` GoDoc to describe the new flow briefly.
- Tests: parameterised tables for both modes, covering:
  - `matchConsent` itself: match, wrong provider (this participant is the consumer of
    another provider's consent), wrong consumer, consumer SD URL instead of DID (deny),
    wrong contract, wrong notice id (with and without `req.PrivacyNoticeID` set), wrong
    purpose, `consented:false`, and a non-matching `data[]` that still allows
  - pagination with a match on page 2, and the page cap
  - `valid:true` with a consumer match, provider mismatch, consumer mismatch, contract
    mismatch or notice-id mismatch on the consent read, `valid:false`, a missing `consentId`, a non-UUID `consentId` (no read is made),
    a 404 on the consent read, and a check that the read sends `format=full`
  - for both modes: 401→refresh→ok, 401 twice, 403, 400, 404 on the list/check endpoint
    (rejected, not deny), 429 (plain error), 500, timeout
  - a check that `Authorization: Bearer` is sent and no consent-key header is sent
- Minimal fake updates in the plugin and integration tests so the suite stays green. The fakes
  serve list mode (the zero `Mode`) and name the consumer by DID. The lifecycle scenarios come
  in Step 5.
- Acceptance: `make test lint` pass, and nothing under `internal/` references
  `identifier/search`, `consents/participants`, `x-visionstrust` or `recipients`.

### Step 4: Wire the modes into the response phase
Files: `internal/ownerresolver/client.go` (+ test), `internal/plugin/consent.go`,
`internal/plugin/consent_test.go`, `internal/metrics/metrics.go` (+ test),
`internal/audit/audit.go` (+ test) if a field is needed.
- `ownerresolver.Claim`: add the optional `ContractURI` (`contractUri`) and `PrivacyNoticeID`
  (`privacyNoticeId`) fields to the decoded response. The request envelope is unchanged.
  Record in the step PR the open points from decision 6 (field names and purpose format).
- `ownerClaim` and `distinctClaims`:
  - Carry `contractURI`, `privacyNoticeID` and the effective `purpose`
    (claim value, else `cfg.Purpose`).
  - Dedupe on owner + dataResource + contract + notice + effective purpose (after the
    `cfg.Purpose` fallback). Today's `pair{owner, resource}` key drops the purpose, so claims
    that differ only in purpose collapse into the first one. With purpose now a match
    criterion, that would release a response under deny_all when purpose A has a grant and
    purpose B does not.
  - Run `checkPurposeScoping` on the effective purpose.
  - Add `checkContractScoping` next to it (decision 2). A claim with no `contractUri` and no
    effective notice id denies with `failAlwaysClosed` when `require_contract` is set.
    Otherwise it calls a new `metrics.RecordContractUnconstrained()`
    (`consent_contract_unconstrained_total`) and logs `logging.WarnfEvery("contract-unconstrained", ...)`.
- Mode selection:
  - Add a helper `effectiveNoticeID(cfg, claim)`: the claim value, else `cfg.PrivacyNoticeID`.
    `Mode` comes from `cfg.CheckMode` alone (decision 1).
  - `check_mode=check` with no notice id means `failOutcome(failAlwaysClosed, ...)`.
- `checkOwners` (already passing `consumerDID` since Step 3): set `Mode`, `PrivacyNoticeID`,
  `ContractURI` and the effective `Purpose` on each `ConsentRequest`.
- Logging in `reduceOwnerResults`:
  - Auth and rejected sentinels log through `logging.ErrorfEvery("consent-auth", ... "config/auth error" ...)`.
  - Other errors log through `"consent-check"` and are marked retryable.
  - Per-owner denies log the sanitised reason at warn level, rate-limited.
- Audit: add the matched `ConsentID` to `checkedOwner` and the audit record, so a receipt can be
  fetched later by id. No receipt is fetched here (decision 2).
- Tests (table-driven, in `consent_test.go`):
  - mode selection (default→list, list with a claim or route notice id sends the
    `privacyNoticeId` filter, a notice id alone never switches to check, forced check,
    forced check without notice id → always-closed deny)
  - config purpose fallback with `require_purpose`
  - `distinctClaims`: same owner and resource with different purposes → two checks, and a
    grant for only one of them → 403 under deny_all; a claim with no purpose and one whose
    purpose equals `cfg.Purpose` → one check
  - contract scoping: unscoped claim with and without `require_contract` (deny vs. allow plus
    metric), scoped by claim `contractUri`, by claim notice id, and by route `privacy_notice_id`;
    `require_contract` still denies with `fail_open:true`
  - the failure mapping end to end through `ResponseFilter`: no match → 403; `valid:false` →
    403; 401/403/400/404-on-list → 403 even with `fail_open:true`; 429/5xx/timeout → 403, or
    passthrough with `fail_open:true`
- Acceptance: `make test-cover` passes, including the coverage floor.

### Step 5: Integration tests for the DSC consent IT scenario
Files: `internal/integration/integration_test.go`.
- Replace `newConsentManager` with a stateful httptest fake of the dsc-consent-manager. It
  serves `/v1/participants`, `/v1/participants/me`, `/v1/consents`, `/v1/consents/check` and
  `/v1/consents/{id}`, and holds a mutable consent set. Add helpers to grant and revoke a
  consent between plugin cycles.
- Parameterise over `check_mode` ∈ {`list`, `check`}. Run the lifecycle through
  `runPluginCycle` on one fake: **deny without consent → grant → allow → revoke → deny**.
- Keep or adapt the existing cases: custom deny response, fail-open on a 5xx, auth error
  closed even with fail_open, a consent granted to another consumer → deny in **both** modes
  (in check mode with a route-level `privacy_notice_id`), a consent where this participant is
  the consumer of another provider → deny in both modes, unknown owner → deny, multiple owners where one has no consent → deny.
- Assert that no request carries `x-visionstrust-consent-key` and that no `Host` override
  is sent.
- Acceptance: `go test -race ./internal/integration/...` passes. This is the in-repo stand-in
  for the external DSC IT (`k3s/consent-provider.yaml`).

### Step 6: Dev stack, documentation and context file
Files: `dev/mocks/*.json`, `docker-compose.yaml`, `README.md`, `AGENTS.md`.
- Dev mocks:
  - Delete `dev/mocks/identifier-search.json`.
  - Rewrite `consents.json` as the `GET /v1/consents` `ConsentPage` stub, and add
    `consents-check.json` (`ConsentValidity`) and `consent-by-id.json`.
  - Update `participants.json` and `participants-me.json` to the `ParticipantPage` /
    `Participant` shape (`identifier`, `selfDescriptionUri`).
- `docker-compose.yaml`: remove `CONSENT_KEY`, and fix the comment that says which stub flips
  the gate. Bring the stack up with `docker compose up` and smoke-test the curl examples in the
  README.
- `README.md`:
  - Replace "The two-call consent check" with a "Consent check (dsc-consent-manager)" section:
    list and check modes, mode selection, matching rules, the consumer verification in check
    mode, no caching.
  - Rewrite "Participant authentication": the token needs the `PARTICIPANT` role and the
    participant-identifier claim, the `/participants/me` and `/participants?identifier=`
    shapes, and a cache key without host or consent key.
  - State the registry cache windows: a deregistered consumer can still pass the registry
    gate for up to `participantSDCacheTTL` (10 min) after deregistration if it was cached,
    while the consent check itself is never cached.
  - Add a failure-mapping table (decision 4, including other 4xx → closed and 429 → policy).
  - Document contract scoping and `require_contract` next to `require_purpose`.
  - Recommend per-claim `contractUri` or `privacyNoticeId` from the resolver over a route-level
    `privacy_notice_id`. A contract's notice can be superseded (`/privacy-notices/by-contract`
    creates a new active notice), and old grants keep the old notice id. A fixed route value
    then silently denies every new grant while old grants keep passing, so it must be updated
    whenever the notice is superseded.
  - State that `check_mode=list` is the default and `check` costs an extra round trip per owner.
  - Update the route example and the "How It Works" bullets.
  - Add a migration note listing the removed options (`consent_api_host`, `consent_key`,
    `CONSENT_KEY`) and stating that this is a **major** release.
- `AGENTS.md`: drop the "Migration in progress" note and describe the final flow.
  **Deferred to plan mode:** step agents must not edit `AGENTS.md`, so the Step 6 PR leaves
  it unchanged and hands this item to a plan-mode agent through a `[plan-update]` comment.
- Acceptance: `make test lint license-check` pass, `docker compose config` validates, and
  nothing in the repo still mentions Visions-only concepts except the migration note. The
  work→main PR must carry the `major` label so the release workflow publishes the new image
  tag.

## Ticket closure (not an agent step)
The ticket's acceptance criterion is that the external DSC consent IT passes with the new
image tag. That run lives outside this repo, so no step above can satisfy it, and Step 5 is
only the in-repo stand-in. After the work→main PR is merged and the `major` release is
published, a maintainer bumps `k3s/consent-provider.yaml` in the DSC deployment to the new
tag and runs the DSC consent IT. Ticket #112 stays open until that run passes. A failure
there is filed as a fix on this ticket.
