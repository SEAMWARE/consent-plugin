# consent-plugin

An Apache APISIX Go plugin that gates access to personal data on the **consent of the data subject**. It hooks into the APISIX request/response lifecycle via the [go-plugin-runner](https://github.com/apache/apisix-go-plugin-runner) and verifies consent against a [dsc-consent-manager](https://github.com/wistefan/dsc-consent-manager) ([API](https://github.com/wistefan/dsc-consent-manager/blob/main/api/openapi.yaml)) before letting a response reach the client.

## How It Works

The plugin is attached to a route in **both** external-plugin phases:

1. **Request phase** (`ext-plugin-pre-req` → `RequestFilter`): captures the request context — method, path, and the JWT claims decoded from the configured header — and stores it keyed by the Nginx `$request_id`.
2. **Response phase** (`ext-plugin-post-resp` → `ResponseFilter`): loads that context, asks the **OwnerResolver** who owns the data in the upstream response, and checks each resolved owner DID against the dsc-consent-manager (see [Consent check](#consent-check-dsc-consent-manager)):
   - **allow** (every resolved owner has a consent in force that names this provider, this consumer and, when the resolver scoped the claim, its contract, privacy notice and purpose) — the response passes through unchanged.
   - **deny** (any owner has no such consent, or the check could not be made) — the response is replaced with a configurable error status and body.

The decision is a coarse allow/deny and is **independent of the response body's shape**, so an empty or non-JSON personal-data response is still gated.

The payload is described to the resolver in one of three ways — `json` (parsed
and carried), `none` (there was no payload), and `opaque` (there was one but it
could not be parsed, sent with its declared content type and size). The last two
are deliberately distinct: an unreadable personal-data payload must not look to
the resolver like no payload at all.

> The `$request_id` correlation is required: `ext-plugin-pre-req` and `ext-plugin-post-resp` are separate RPCs to the runner and do **not** share the runner's per-call `ID()`.

### Ownership comes from the data, never from the requestor

`owner_resolver_url` is **required**. The access token's `sub` says who is
*asking*, not whose data is being *returned* — checking the caller's own consent
would let any subject holding a single granted consent read everyone else's
data. So the data owner is always derived from the response payload by the
OwnerResolver, and the token's claims are used only to name the **consuming
participant** for the contract lookup and to scope the consent match.

> **The plugin does not verify the JWT signature.** It decodes the claims and
> assumes an authentication plugin earlier in the route has already validated the
> token. Attaching `consent-filter` to a route with no authentication in front of
> it is a misconfiguration: the consumer identity would be attacker-supplied.

### Response buffering

`ext-plugin-post-resp` forces APISIX to **buffer the entire upstream response**
before the runner sees it (`ReadBody()` is a blocking extra-info RPC over the
unix socket). Gated routes therefore do not stream, and a large response is a
memory multiplier across APISIX and the runner. Keep gated routes to bounded
responses, and note that `response_phase_timeout`, `max_owners_per_response` and
`max_resolve_body_bytes` (below) bound how long the response is held, how many
owners are checked, and how large a payload is forwarded to the resolver.

Per-owner consent checks run concurrently (up to 8 in flight) and short-circuit
on the first denial, so latency is not the sum over owners.

## Consent check (dsc-consent-manager)

Every call goes to `{consent_api_url}{consent_api_prefix}` (e.g.
`http://consent-manager:8080/v1`) with `Authorization: Bearer <participant token>`
and nothing else: no consent key and no `Host` rewrite. Each resolved owner DID is
the `userIdentifier`. `check_mode` picks one of two lookups:

**`list` (the default)**, one call per owner:
```
GET {base}/consents?userIdentifier=<owner DID>[&privacyNoticeId=<id>]&page=0&size=50
→   { "content": [ { "id", "privacyNoticeId", "provider", "consumer", "consented",
                     "purposes": [...], "contractUri", ... } ], "totalPages": ... }
```
`privacyNoticeId` is sent whenever one is known. Pages are read until a record
matches, up to 20 pages. Reaching that limit without a match denies.

**`check`**, two calls per owner, so one extra round trip:
```
GET {base}/consents/check?userIdentifier=<owner DID>&privacyNoticeId=<id>[&purpose=<purpose>]
→   { "valid": true, "consentId": "<uuid>", ... }
GET {base}/consents/{consentId}?format=full
→   { "id", "provider", "consumer", "consented", ... }
```
`/consents/check` only says that *some* consent is in force. It does not say which
consumer that consent names. Without the read, a route-level `privacy_notice_id`
would release data to any consumer on another consumer's grant, so the plugin
**always** reads the consent and matches it like a list entry. `valid:false`, a
`consentId` that is not a UUID, or a `404` on the read (this participant is not a
party to it) deny. `/consents/check` requires a notice id, so in check mode a claim
without one is always denied, whatever `fail_open` says, and no call is made.

The dsc-consent-manager allows only one consent per subject and notice in force,
so both modes reach the same decision. `list` is cheaper and is the default.
`check` is never selected automatically.

### Matching

Both modes accept a consent record only when all of these hold. Every comparison
is verbatim and case-sensitive:

- `consented` is `true`;
- `provider` is **this** participant's own `identifier` from `/participants/me`.
  The consent endpoints also return consents in which this participant is the
  *consumer* of another provider's contract;
- `consumer` is the **requesting consumer's DID** (from `consumer_claim`). A
  consent granted to X is no authority for Y;
- `contractUri` equals the claim's `contractUri`, when set;
- `privacyNoticeId` equals the effective notice id, when set. That is the claim's
  `privacyNoticeId`, or else `privacy_notice_id`. It is compared on the client
  too, so the scoping does not rest only on the server's query filter;
- `purposes[]` contains the effective purpose, when set. That is the claim's
  `purpose`, or else `purpose`.

A claim's `dataResource` is **not** matched. The consent's `data[]` lists the
notice's personal-data *categories*, not resource identifiers.

Consent answers are **never cached** in either mode, so a revocation denies the
next request.

### Purpose and contract scoping

A claim without a purpose matches a consent for any purpose. A claim without a
`contractUri` or `privacyNoticeId` (on a route without `privacy_notice_id`)
matches any consent this owner gave this consumer under this provider, whatever
the contract. Both gaps are counted (`consent_purpose_unconstrained_total`,
`consent_contract_unconstrained_total`) and logged as rate-limited warnings.
`require_purpose` and `require_contract` turn each gap into a deny, which ignores
`fail_open`. Enable them once your OwnerResolver emits those fields.

Have the resolver emit a `contractUri` or `privacyNoticeId` **per claim**, rather
than fixing `privacy_notice_id` on the route. When a contract's notice is
superseded (`/privacy-notices/by-contract` creates a new active notice), grants
given since then carry the new notice id and older grants keep the old one. A fixed
route value then quietly denies every new grant while the old ones keep passing,
until someone updates it. Notice purposes are full sentences, so a resolver that
sets `purpose` must emit the notice's purpose string exactly.

### Failure mapping

| Consent-manager answer | Result |
|------------------------|--------|
| `200`, no matching record / `valid:false` / `404` on the consent read | **deny** (consent), reason logged |
| `401` after one token refresh, or `403` (caller may be deregistered) | `ErrConsentManagerAuth`: **always denied** |
| any other `4xx` except `429` (e.g. `400`, a `404` from a wrong `consent_api_prefix`, `405`, `422`) | `ErrConsentManagerRejected`: **always denied** |
| `429`, `5xx`, transport error, timeout | retryable outage: `fail_open` decides |

The same mapping applies to every endpoint: the registry, `/participants/me` and
both consent modes. "Always denied" means `fail_open` does not apply, because these
are misconfigurations or revoked access rather than outages. A dependency's
response body never reaches an error or audit reason. It is logged at debug level
only.

### Participant authentication

The plugin holds no participant credentials of its own. It asks the
participant-local OID4VP token service (the consent-facade's
`POST /internal/tokens`) for a short-lived token by **audience name**. The token
must carry the `PARTICIPANT` role and the participant-identifier claim, which every
operation above requires. The plugin then reads its own identity:

```
POST {token_service_url}   { "audience": "<token_audience>" }  →  { "access_token": ..., "expires_in": ... }
GET  {base}/participants/me   Authorization: Bearer <token>    →  { "identifier": "<DID>", "selfDescriptionUri": ... }
```

`identifier` is the provider every matched consent must name. It is always fetched,
even with a static `participant_token` and `provider_sd`. `selfDescriptionUri` (or
`provider_sd`, when set) is sent to the OwnerResolver as `parties.provider`. The
token is cached and refreshed on expiry or a `401`. The cache key covers the base
URL, prefix, audience, token-service URL, `provider_sd` and a hash of the static
token, so two routes fronting different participants against the same
consent-manager never share a token. A static `participant_token` and/or an
explicit `provider_sd` remain supported as overrides for tests and manual runs.

The consumer DID from the token is mapped to its self-description URI, which is
sent to the OwnerResolver as `parties.consumer`, through the participant registry:

```
GET {base}/participants?identifier=<consumer DID>
→   { "content": [ { "identifier": "<DID>", "selfDescriptionUri": ..., "deregisteredAt": ... } ] }
```

An unknown DID, a participant without a `selfDescriptionUri` or one with
`deregisteredAt` set is always denied (`ErrParticipantNotRegistered`). A mapping is
cached for **10 minutes**, and a negative answer for 30 seconds. So a consumer
deregistered while its mapping is cached still passes the *registry* gate for up
to 10 minutes. The consent check itself is never cached, so a revoked consent
still denies on the next request.

### Migrating from the Prometheus-X / Visions consent-manager

This is a **major** release. The plugin now speaks only the dsc-consent-manager
API. These options were removed:

- `consent_api_host` (the `Host` rewrite). The bearer token is the only
  authentication.
- `consent_key` and the `CONSENT_KEY` environment variable (the
  `x-visionstrust-consent-key` header and `/users/identifier/search`). Owners are
  checked by DID directly.

A route config that still sets a removed option loads, and the runner logs a warning
for each one. `check_mode`, `privacy_notice_id`, `purpose` and `require_contract`
are new.

## Configuration Reference

Configured via the APISIX route plugin JSON (identically on both `ext-plugin-pre-req` and `ext-plugin-post-resp`):

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `consent_api_url` | `string` | **Yes** | — | Base URL of the dsc-consent-manager (e.g. `http://consent-manager:8080`). `http`/`https` only. |
| `owner_resolver_url` | `string` | **Yes** | — | The OwnerResolver `/resolve` endpoint. The data owner is resolved from the response payload; without it the plugin cannot determine whose consent to check, so the route fails to load. `http`/`https` only. |
| `owner_resolver_timeout` | `int` | No | `2000` | Per-call timeout in ms for `/resolve`. Range 1–60000. |
| `service` | `string` | No | — | Logical dataset id sent to the OwnerResolver as `resource.service`, so it can select the rule for this route. |
| `response_phase_timeout` | `int` | No | `10000` | Budget in ms for the **entire** response phase — party lookups, `/resolve`, and every per-owner consent check together. APISIX holds the buffered response for this whole time, so it is bounded independently of the per-call timeouts. Range 1–120000. |
| `require_purpose` | `bool` | No | `false` | Deny when a resolved claim names no processing purpose. Purpose matching depends on the OwnerResolver populating an optional field, so a resolver that never sets it runs with purpose scoping silently disabled; turn this on once yours emits one. `consent_purpose_unconstrained_total` counts the checks it would deny. |
| `require_contract` | `bool` | No | `false` | Deny when a resolved claim names neither a `contractUri` nor a `privacyNoticeId` and the route sets no `privacy_notice_id`. Without it such a claim matches any consent the owner granted this consumer under this provider, whatever the contract; turn it on once your resolver emits one of the two. |
| `check_mode` | `string` | No | `list` | How consents are looked up: `list` (`GET /consents?userIdentifier=`, one call per owner) or `check` (`GET /consents/check`, then a read of the consent it names — one extra round trip). Both apply the same match. Any other value fails validation. |
| `privacy_notice_id` | `string` | No | — | Route-level privacy notice UUID consents are scoped to when a resolved claim names none. Must be a UUID; it is lowercased on load. In `check` mode a claim without any notice id is denied. |
| `purpose` | `string` | No | — | Processing purpose matched (verbatim) when a resolved claim names none. A claim's own purpose wins. |
| `max_resolve_body_bytes` | `int` | No | `1048576` | Maximum upstream body forwarded to the OwnerResolver. A larger body is denied rather than copied — the body is held whole, validated and marshalled again, so the peak footprint is ~3× its size per in-flight request on top of APISIX's own buffering. Range 1–104857600. |
| `max_owners_per_response` | `int` | No | `50` | Maximum distinct data owners checked for one response. A response resolving to more is denied rather than answered after an unbounded number of consent calls. Range 1–1000. |
| `consumer_claim` | `string` | No | `verifiableCredential.issuer` | Dotted claim path naming the **consuming participant**. Supports array indexing (`verifiableCredential[0].issuer`), and a bare segment landing on an array traverses its first element — a Verifiable Presentation routinely carries `verifiableCredential` as an array. Mapped to the consumer's self-description for the OwnerResolver, and matched against each consent's `consumer` — never used for ownership. |
| `consent_api_prefix` | `string` | No | `/v1` | API prefix prepended to endpoint paths (the dsc-consent-manager serves `/v1`). Must start with `/`; a trailing `/` is trimmed. |
| `consent_api_timeout` | `int` | No | `5000` | Per-call timeout in ms. Range 1–60000. |
| `token_service_url` | `string` | Yes* | — | The participant-local OID4VP token service (the consent-facade's `POST /internal/tokens`). Falls back to `CONSENT_TOKEN_SERVICE_URL`. `http`/`https` only. |
| `token_audience` | `string` | No | `consent-manager` | Audience **name** asked of the token service — its own configured target, not a URL. |
| `participant_token_ttl` | `int` | No | `3000` | Seconds a fetched token is cached. The token service's own `expires_in` wins when shorter. Range 1–86400. |
| `participant_token` | `string` | Yes* | — | *Static*, pre-obtained participant token. An override for tests and manual runs; prefer `token_service_url`, which refreshes automatically. |
| `provider_sd` | `string` | No | — | Provider self-description URL sent to the OwnerResolver as `parties.provider`. Derived from `/participants/me` when unset. The provider identifier consents are matched on always comes from `/participants/me`. |
| `jwt_header_name` | `string` | No | `Authorization` | Header carrying the JWT. |
| `jwt_claims_to_forward` | `[]string` | No | `[]` (all) | Claims to decode and keep. Empty decodes all. The root of `consumer_claim` is always added. |
| `deny_status_code` | `int` | No | `403` | Status returned on deny. Range 100–599. |
| `deny_response_body` | `string` | No | `{"error":"access denied by consent policy"}` | Body returned on deny. |
| `deny_response_content_type` | `string` | No | `application/json` | `Content-Type` for deny responses. |
| `fail_open` | `bool` | No | `false` | On a **dependency failure** (resolver or consent-manager down/erroring, unreadable body): `false` denies, `true` passes through. Enabling it is logged as a warning at parse time. It does **not** apply to structural failures — no correlation id, no request context, no participant credentials, or "consent required but no owner resolved" — which always deny. |
| `audit_enabled` | `bool` | No | `false` | Emit an access-decision audit event (OTLP/HTTP log) to a Collector for every decision. Async + best-effort; never affects the decision. |
| `audit_otlp_endpoint` | `string` | Yes† | — | Base OTLP/HTTP endpoint of the Collector (e.g. `http://otel-collector:4318`); `/v1/logs` is appended. Falls back to `CONSENT_AUDIT_OTLP_ENDPOINT`. |
| `audit_otlp_headers` | `object` | No | — | Extra HTTP headers sent on every audit export, for a Collector that requires authentication (e.g. `{"Authorization":"Bearer ..."}`). |
| `audit_service_name` | `string` | No | `consent-access-audit` | Resource `service.name` on audit records — the marker the Collector routes on to keep audit logs separate from traces. |

\* Provide **either** `token_service_url` (recommended) **or** a static
`participant_token`. This is enforced at parse time: a route with neither cannot
authenticate as the participant and so cannot complete a single consent check,
and is rejected rather than loaded.

† Required only when `audit_enabled` is `true`.

**Credentials via env.** `token_service_url` and `audit_otlp_endpoint` each
fall back to an environment variable (`CONSENT_TOKEN_SERVICE_URL`,
`CONSENT_AUDIT_OTLP_ENDPOINT`) when omitted from the route config; a value in
the config always wins. The plugin runner inherits these from the APISIX
container, which sources them from a Kubernetes Secret — so secrets need not be
stored as plaintext in the route config (etcd).

**Metrics.** Set the `CONSENT_METRICS_ADDRESS` environment variable on the
plugin runner (e.g. `:9091`) to expose Prometheus metrics on `/metrics`:
`consent_decisions_total{decision,fail_mode}` (a deny caused by an outage is
labelled apart from one caused by consent),
`consent_dependency_calls_total{dependency,outcome}`,
`consent_dependency_duration_seconds{dependency}`,
`consent_purpose_unconstrained_total`, `consent_contract_unconstrained_total`,
`consent_request_context_store_size`, `consent_request_contexts_evicted_total`
and `consent_audit_events_dropped_total`. Metrics are off unless the variable is
set — the runner is otherwise reached only over its unix socket, so opening a
TCP port is the deployment's decision.

**Access audit log.** With `audit_enabled`, the plugin emits one OTLP/HTTP **log record** per **checked data owner** (so the log answers whose consent was consulted and what each said, not merely whether the response was released; a request that failed before any owner was reached is recorded once as itself) to `audit_otlp_endpoint`, stamped with resource `service.name=<audit_service_name>` and attributes `event.domain=audit`, `consent.decision`, `consent.reason`, `enduser.id`, `http.request.method`, `url.path`, `http.request.id`, and on an allow `consent.id` (the matched consent, so its receipt can be fetched later with `GET /consents/{id}?format=receipt`). Emission is asynchronous, batched, and best-effort (a bounded queue drops rather than blocking the request path), so a slow/absent Collector never affects data access. The queue is flushed when the runner exits (it returns on `SIGTERM`/`SIGINT`), so a redeploy does not discard the last flush interval of decisions. Reasons are sanitised before export (control characters collapsed, length bounded) so an upstream error body cannot reach the audit sink verbatim. Mark-based routing lets the Collector send these to an append-only audit sink separate from traces.

## APISIX Route Configuration Example

```bash
# Both phases must carry the SAME configuration, so build it once.
PLUGIN_CONF='{"consent_api_url":"http://consent-manager:8080","consent_api_prefix":"/v1","check_mode":"list","require_purpose":true,"require_contract":true,"owner_resolver_url":"http://owner-resolver:8080/resolve","service":"personal-profiles","token_service_url":"http://consent-facade:8080/internal/tokens","token_audience":"consent-manager","fail_open":false}'

jq -n --arg conf "$PLUGIN_CONF" '{
  uri: "/*",
  host: "data-service.example.org",
  upstream: { type: "roundrobin", nodes: { "backend-service:8080": 1 } },
  plugins: {
    "ext-plugin-pre-req":   { conf: [ { name: "consent-filter", value: $conf } ] },
    "ext-plugin-post-resp": { conf: [ { name: "consent-filter", value: $conf } ] }
  }
}' | curl -X PUT http://127.0.0.1:9180/apisix/admin/routes/1 \
  -H "X-API-KEY: your-admin-api-key" \
  -H "Content-Type: application/json" \
  -d @-
```

`require_purpose` and `require_contract` assume a resolver that emits a purpose
and a `contractUri` or `privacyNoticeId` per claim. Both phases are required and must
carry the **same** configuration: `pre-req` captures the token context,
`post-resp` performs the check and blocks the response.

## Build and Deployment

### Prerequisites

- Go (see `go.mod` for the required version)
- Docker (for containerized builds)
- [golangci-lint](https://golangci-lint.run/) (for linting)

### Build / Test / Lint

```bash
make build         # build the go-runner binary
make docker-build  # build the Docker image
make test          # unit + integration tests
make test-cover    # tests with coverage
make lint          # golangci-lint
```

### Local Development with Docker Compose

```bash
docker compose up --build
```

The stack is self-contained — APISIX + etcd, the plugin runner, a mock
dsc-consent-manager / OwnerResolver / token service, an echo upstream, and an OTel
Collector for the audit log:

| Service | Description | Ports |
|---------|-------------|-------|
| `etcd` | APISIX configuration store | `2379` |
| `apisix` | APISIX gateway | `9080` (HTTP), `9180` (Admin API) |
| `plugin-runner` | consent-filter plugin runner | — (unix socket, shared volume) |
| `mock` | dsc-consent-manager + OwnerResolver + token service stubs (`dev/mocks/`) | `8081` |
| `upstream` | echo service standing in for the personal-data API | — |
| `otel-collector` | receives the access-decision audit log | `4318` |

The runner also serves Prometheus metrics on `9091` (`CONSENT_METRICS_ADDRESS` is
set for it in the compose file).

Then create the gated route:

```bash
PLUGIN_CONF='{"consent_api_url":"http://mock:8080","owner_resolver_url":"http://mock:8080/resolve","service":"dev-profiles","audit_enabled":true,"fail_open":false}'

jq -n --arg conf "$PLUGIN_CONF" '{
  uri: "/*",
  upstream: { type: "roundrobin", nodes: { "upstream:8080": 1 } },
  plugins: {
    "ext-plugin-pre-req":   { conf: [ { name: "consent-filter", value: $conf } ] },
    "ext-plugin-post-resp": { conf: [ { name: "consent-filter", value: $conf } ] }
  }
}' | curl -s -X PUT http://127.0.0.1:9180/apisix/admin/routes/1 \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1" -H "Content-Type: application/json" -d @-

# The token names the consumer the mock's consent was granted to, so this passes.
TOKEN_PAYLOAD=$(printf '{"verifiableCredential":{"issuer":"did:key:zDevConsumer"}}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
curl -i http://127.0.0.1:9080/profile -H "Authorization: Bearer e30.${TOKEN_PAYLOAD}.nosig"
```

`token_service_url` and `audit_otlp_endpoint` come from the runner's environment
(`CONSENT_TOKEN_SERVICE_URL`, `CONSENT_AUDIT_OTLP_ENDPOINT`) in the compose file.
Add `"check_mode":"check"` to the config to use `/consents/check` instead.

Set `consented` to `false` in `dev/mocks/consents.json` (or `valid` to `false` in
`consents-check.json` for check mode), or change the consent's `consumer`, and
restart the `mock` service to watch the same request be denied. A token naming any
other consumer is denied, because the registry stub knows only `did:key:zDevConsumer`.
The `otel-collector` logs show the audit record for each decision.

> The socket is shared through a **directory** (the `runner-socket` volume), not
> by bind-mounting the socket file: Docker creates a directory at a bind-mount
> path that does not exist yet, and the runner then cannot bind.

## Project Structure

```
consent-plugin/
├── main.go                        # Entry point — registers plugin, starts runner
├── Makefile / Dockerfile / docker-compose.yaml
├── internal/
│   ├── plugin/
│   │   ├── consent.go             # RequestFilter + ResponseFilter (the consent gate)
│   │   ├── config.go              # Configuration schema and validation
│   │   └── context.go             # Bounded request-context store keyed by $request_id
│   ├── consent/
│   │   ├── client.go              # dsc-consent-manager client (token, registry, list/check modes)
│   │   └── models.go              # Request/response models and Decision type
│   ├── ownerresolver/
│   │   └── client.go              # OwnerResolver /resolve client (who owns the data)
│   ├── audit/
│   │   └── audit.go               # OTLP/HTTP access-decision audit exporter
│   ├── jwt/
│   │   └── extractor.go           # JWT extraction and claim decoding
│   └── integration/
│       └── integration_test.go    # End-to-end integration tests
```

## CI & Releases

GitHub Actions run the quality gates on every PR and cut releases on merge to
`main`, following the [FIWARE/VCVerifier](https://github.com/FIWARE/VCVerifier)
structure. See [.github/workflows/README.md](.github/workflows/README.md) for the
full pipeline and [CONTRIBUTING.md](CONTRIBUTING.md) for the label-driven
versioning rules.

Each release publishes:

- a multi-arch (`linux/amd64,arm64`) image
  `quay.io/seamware/consent-plugin:<version>` (also `:latest`, `:<sha>`), and
- standalone `go-runner` binaries (`consent-plugin-linux-{amd64,arm64}`) on the
  GitHub Release.

### Using the release image in APISIX

The image is the primary artifact. In the APISIX deployment an init container
stages the runner binary out of the image into a shared `ext-plugin` volume, and
APISIX launches it as the external plugin runner:

```yaml
initContainers:
  - name: install-consent-plugin
    image: quay.io/seamware/consent-plugin:<version>
    command: ["cp", "/app/go-runner", "/ext-plugin/go-runner"]
    volumeMounts:
      - name: ext-plugin-bin
        mountPath: /ext-plugin
# ... APISIX then runs: exec /ext-plugin/go-runner
```

See the reference
[consent-provider.yaml](https://github.com/FIWARE/data-space-connector/blob/consent-management/k3s/consent-provider.yaml)
for the complete deployment (secret mounting, env, socket wiring).

Releasing requires the `QUAY_USERNAME` / `QUAY_PASSWORD` repository secrets.

## License

Apache-2.0 - see [LICENSE](LICENSE). Every Go source file carries the copyright header from
[`hack/license-header.txt`](hack/license-header.txt); `make license-check` verifies it and CI enforces
it on pull requests, on `main`, and as a gate on the pre-release and release.
