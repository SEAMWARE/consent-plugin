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
  `ParticipantPage{content[Participant{identifier, selfDescriptionUri, ...}]}`.
  `GET /participants/me` returns a `Participant`. The field is now `selfDescriptionUri`
  (it was `selfDescriptionURL`), so the DID→SD mapping the resolver's `parties` rely on is
  **kept and adapted**, not deleted.
- All of these operations require a bearer token with role `PARTICIPANT` and the
  participant-identifier claim. The token still comes from the consent-facade
  (`token_service_url`, `token_audience`).

### Design decisions (for review)
1. **Mode selection.** Add `check_mode`, one of `list`, `check`, or unset. When unset,
   **check** is used if a privacy notice id is known for the claim (from the resolver claim
   or `privacy_notice_id`), and **list** otherwise. When `check_mode` is `check` and a claim
   has no notice id, the response always gets a closed deny.
2. **Consumer binding stays mandatory, and both modes share one matcher.**
   - `matchConsent(req, ConsentResponse)` accepts a record only when `consented == true`, its
     `consumer` equals the requesting consumer's DID (from `consumer_claim`), its
     `contractUri` equals the resolver's `contractUri` when that is set, and its `purposes[]`
     contains the effective purpose when one is set. The consumer's SD URL is never compared:
     `consumer` is always an identifier, so the SD URL is only passed to the resolver.
   - `dataResource` is **not** matched against `data[]`. `data[]` holds notice categories, not
     resource identifiers, so a verbatim match would deny every request that sets
     `dataResource`, and check mode could not apply it anyway.
   - List mode runs `matchConsent` on each `ConsentPage` entry.
   - Check mode: `valid:true` alone doesn't say which consumer the consent names, and
     `/consents/check` is only scoped to the caller being *a* party. The client therefore
     **always** reads `GET /consents/{consentId}` and runs `matchConsent` on it. This read is
     mandatory: without it, a route-level `privacy_notice_id` would let any consumer through
     on another consumer's grant. It also serves as the receipt lookup the ticket marks as
     optional.
3. **No caching of consent answers** in either mode, so "deny after revoke" takes effect
   immediately. The token and participant-SD caches stay.
4. **Failure mapping.**
   - `200` with no match, `valid:false`, or `404` on the consent read: **deny**, and the reason
     is logged.
   - `401` after one token refresh, `403`, or `400`: new sentinel `consent.ErrConsentManagerAuth`
     (401/403) or `consent.ErrConsentManagerRejected` (400). Both map to `failAlwaysClosed`
     and are logged as config/auth errors. A 403 also notes the caller may be deregistered.
   - `5xx`, transport error or timeout: a plain error, mapped to `failByPolicy` (`fail_open`
     governs) and logged as retryable.
5. **Purpose.** A claim's own `purpose` wins, and `purpose` in the config is the fallback.
   `require_purpose` checks the result of that fallback. Matching is verbatim, which is also
   how the `purpose` query parameter of `/consents/check` is applied.
6. **To confirm with the OwnerResolver owners** (recorded in the Step 4 PR): the claim field
   names `contractUri` and `privacyNoticeId`, and the `purpose` format. Notice purposes are
   full sentences, while `Claim.Purpose` is currently documented as "purpose (or contract)",
   so the resolver must emit the notice's purpose string for a purpose match to succeed.
7. **Release.** Config fields are removed, so the work→main PR needs the **`major`**
   semver label. The release workflow then publishes the new image tag.

## Steps

### Step 1: Config surface — drop Visions-only options, add check-mode options
Files: `internal/plugin/config.go`, `internal/plugin/config_test.go`, `internal/plugin/consent.go`
(`clientConfigFromCfg` only), `internal/consent/client.go`, `internal/consent/client_test.go`,
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
    `CheckModeCheck = "check"`, empty means auto)
  - `PrivacyNoticeID string` (`privacy_notice_id`)
  - `Purpose string` (`purpose`)
- Add validation:
  - `check_mode` must be empty, `list` or `check`.
  - `privacy_notice_id`, when set, must be a UUID. Use a stdlib check with a named pattern
    constant, not a new dependency.
  - `check_mode=check` without `privacy_notice_id` is still valid, because the resolver may
    supply the notice id per claim.
- README table: delete the `consent_api_host` and `consent_key` rows, add the three new rows,
  and keep `config_doc_test.go` green.
- Tests: table-driven cases for each new validation rule. Remove the tests for the removed
  fields and the env fallback, and update the `cacheKey` tests.
- Acceptance: `make test lint license-check` pass, and no references to `consent_api_host`,
  `consent_key` or `CONSENT_KEY` remain under `internal/`.

### Step 2: Participant registry and provider identity on the dsc-consent-manager schema
Files: `internal/consent/client.go`, `internal/consent/client_test.go`,
`internal/integration/integration_test.go` (registry fake only).
- `ParticipantSelfDescriptionByDID`:
  - Call `GET {base}{prefix}/participants?identifier=<url-escaped DID>` and decode
    `ParticipantPage.content[]`.
  - Take the first entry whose `identifier` equals the DID and use its `selfDescriptionUri`.
  - Empty content, or a matching entry with no SD URI, returns `ErrParticipantNotRegistered`.
  - Replace `participantListEntry`, `participantsResponse` and `decodeParticipants` with the
    new shape. Keep the positive and negative caches.
- `fetchProviderSD` and `meResponse`: decode `Participant{identifier, selfDescriptionUri}`.
- Add the error sentinels from decision 4: `ErrConsentManagerAuth` and
  `ErrConsentManagerRejected`.
  - Map registry and `/participants/me` responses to them: 401 after refresh → auth,
    403 → auth with a "caller may be deregistered" reason, 400 → rejected.
  - In `internal/plugin/consent.go`, extend `failModeForError` so both are `failAlwaysClosed`,
    and add table cases in `consent_test.go`.
- Tests: table-driven registry cases (found, not found, missing SD, 401→refresh, 403, 5xx,
  malformed JSON), the `/participants/me` shape, and the `failModeForError` mapping. Update
  `participantRegistryHandler` in the integration fakes to the new page shape.
- Acceptance: the existing plugin and integration tests still pass with the new registry shape.

### Step 3: Consent client — list and check modes
Files: `internal/consent/client.go`, `internal/consent/models.go`, `internal/consent/client_test.go`,
`internal/consent/reset.go`, `internal/integration/integration_test.go` (consent-manager fake),
`internal/plugin/consent_test.go` (fakes only).
- Delete:
  - `identifierSearchPath`, `consentKeyHeader`, `resolveUserIdentifier` and the identifier cache
    (also remove it from `ResetCaches`)
  - `participantConsentsPathFmt`, `participantConsentsResponse`, `consentRecord`,
    `participantRef`, `grantedTo` with the `recipients[0]` logic, and `hasGrantedConsent`
- `models.go`:
  - Add a `Mode` type with `ModeList` and `ModeCheck` to `ConsentRequest`.
  - Add the fields `PrivacyNoticeID` and `ContractURI`. `Consumer` is now the consumer's
    participant identifier (DID). There is no `ConsumerSD` field (decision 2).
  - Add `ConsentID` to `ConsentResponse` for audit.
  - Update the package and type GoDoc so it no longer mentions Prometheus-X/Visions.
- List mode (`listConsents`):
  - Call `GET {base}{prefix}/consents?userIdentifier=<owner>&page=<n>&size=<consentListPageSize>`,
    adding `&privacyNoticeId=` when it is known.
  - Page until a match is found or `totalPages` is reached, capped by `maxConsentListPages`.
    Hitting the cap without a match denies, with a reason.
  - Each entry goes through `matchConsent` (decision 2):
    - `consented == true` (defensive, the server already defaults to `status=GRANTED`)
    - `consumer` equals `req.Consumer`
    - `contractUri` equals `req.ContractURI` when that is set
    - `purposes[]` contains `req.Purpose` when that is set
  - Matching is verbatim and case-sensitive. A match returns allow with `ConsentID`.
    `req.DataResource` is not matched (it stays in the audit record only).
- Check mode (`checkValidity`):
  - Call `GET {base}{prefix}/consents/check?userIdentifier=&privacyNoticeId=[&purpose=]`.
  - `valid:false` denies with the server's `reason`.
  - `valid:true` always leads to `GET {base}{prefix}/consents/{consentId}`, and the returned
    `ConsentResponse` must pass the same `matchConsent` as list mode (decision 2). A `404`
    there, a failed match, or a missing `consentId` denies. This read is mandatory.
  - Never cached.
- `CheckConsent`:
  - Keep the guards for an empty `Subject` or `Consumer`.
  - In `ModeCheck`, an empty `PrivacyNoticeID` denies.
  - Keep the single token refresh and retry on 401.
  - Map statuses as in decision 4, using `unexpectedStatus` for 5xx so response bodies stay
    out of errors.
  - All paths and query keys are named constants, and query strings are built with `url.Values`.
- Update the `Client` GoDoc to describe the new flow briefly.
- Tests: parameterised tables for both modes, covering:
  - `matchConsent` itself: match, wrong consumer, consumer SD URL instead of DID (deny),
    wrong contract, wrong purpose, `consented:false`, and a non-matching `data[]` that still
    allows
  - pagination with a match on page 2, and the page cap
  - `valid:true` with a consumer match, consumer mismatch or contract mismatch on the consent
    read, `valid:false`, a missing `consentId`, and a 404 on the consent read
  - 401→refresh→ok, 401 twice, 403, 400, 500, timeout
  - a check that `Authorization: Bearer` is sent and no consent-key header is sent
- Minimal fake updates in the plugin and integration tests so the suite stays green. The
  lifecycle scenarios come in Step 5.
- Acceptance: `make test lint` pass, and nothing under `internal/` references
  `identifier/search`, `consents/participants`, `x-visionstrust` or `recipients`.

### Step 4: Wire the modes into the response phase
Files: `internal/ownerresolver/client.go` (+ test), `internal/plugin/consent.go`,
`internal/plugin/consent_test.go`, `internal/audit/audit.go` (+ test) if a field is needed.
- `ownerresolver.Claim`: add the optional `ContractURI` (`contractUri`) and `PrivacyNoticeID`
  (`privacyNoticeId`) fields to the decoded response. The request envelope is unchanged.
  Record in the step PR the open points from decision 6 (field names and purpose format).
- `ownerClaim` and `distinctClaims`:
  - Carry `contractURI`, `privacyNoticeID` and the effective `purpose`
    (claim value, else `cfg.Purpose`).
  - Dedupe on owner + dataResource + contract + notice.
  - Run `checkPurposeScoping` on the effective purpose.
- Mode selection:
  - Add a helper `modeFor(cfg, claim)` implementing decision 1, with an effective notice id
    of claim value, else `cfg.PrivacyNoticeID`.
  - `check_mode=check` with no notice id means `failOutcome(failAlwaysClosed, ...)`.
- `checkOwners`: build `ConsentRequest` with `Consumer` set to `consumerDID`. Pass
  `consumerDID` down from `evaluateWithResolver`. `consumerSD` stays resolver-only
  (`parties.consumer`).
- Logging in `reduceOwnerResults`:
  - Auth and rejected sentinels log through `logging.ErrorfEvery("consent-auth", ... "config/auth error" ...)`.
  - Other errors log through `"consent-check"` and are marked retryable.
  - Per-owner denies log the sanitised reason at warn level, rate-limited.
- Audit: add the matched `ConsentID` to `checkedOwner` and the audit record, so a receipt can be
  fetched later by id.
- Tests (table-driven, in `consent_test.go`):
  - mode selection (auto→list, auto→check via config, auto→check via claim, forced list,
    forced check without notice id → always-closed deny)
  - config purpose fallback with `require_purpose`
  - the failure mapping end to end through `ResponseFilter`: no match → 403; `valid:false` →
    403; 401/403 → 403 even with `fail_open:true`; 5xx/timeout → 403, or passthrough with
    `fail_open:true`
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
  (in check mode with a route-level `privacy_notice_id`), unknown owner →
  deny, multiple owners where one has no consent → deny.
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
  - Add a failure-mapping table.
  - Update the route example and the "How It Works" bullets.
  - Add a migration note listing the removed options (`consent_api_host`, `consent_key`,
    `CONSENT_KEY`) and stating that this is a **major** release.
- `AGENTS.md`: drop the "Migration in progress" note and describe the final flow.
- Acceptance: `make test lint license-check` pass, `docker compose config` validates, and
  nothing in the repo still mentions Visions-only concepts except the migration note. The
  work→main PR must carry the `major` label so the release workflow publishes the new image
  tag. Updating `k3s/consent-provider.yaml` in the DSC deployment to the new tag is a
  follow-up outside this repo.
