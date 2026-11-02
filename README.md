# consent-plugin

An Apache APISIX Go plugin that gates access to personal data on the **consent of the data subject**. It hooks into the APISIX request/response lifecycle via the [go-plugin-runner](https://github.com/apache/apisix-go-plugin-runner) and verifies consent against a [Prometheus-X / Visions consent-manager](https://github.com/Prometheus-X-association/consent-manager) before letting a response reach the client.

## How It Works

The plugin is attached to a route in **both** external-plugin phases:

1. **Request phase** (`ext-plugin-pre-req` → `RequestFilter`): captures the request context — method, path, and the JWT claims decoded from the configured header — and stores it keyed by the Nginx `$request_id`.
2. **Response phase** (`ext-plugin-post-resp` → `ResponseFilter`): loads that context, asks the **OwnerResolver** who owns the data in the upstream response, and runs a **two-call consent check** per resolved owner:
   - **allow** (every resolved owner has a granted consent for this consumer) — the response passes through unchanged.
   - **deny** (any owner has no such consent, or is unknown to the consent-manager) — the response is replaced with a configurable error status and body.

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

## The two-call consent check

The consent-manager has no single "is there consent?" endpoint, so a check is two calls (`{consent_api_url}{consent_api_prefix}` is the base, e.g. `http://consent-manager:3000/v1`):

**1. Resolve the owner to a user identifier** — authenticated with the consent key:
```
POST {base}/users/identifier/search
Header: x-visionstrust-consent-key: <consent_key>
Body:   { "selfDescription": "<provider_sd>", "email": "<owner DID>" }
→      { "userIdentifier": "<id>" }        (404 / empty ⇒ unknown owner ⇒ deny)
```

**2. List that user's consents** — authenticated with the participant JWT:
```
GET {base}/consents/participants/{userIdentifier}?receipt=true
Header: Authorization: Bearer <participant_token>
→      { "consents": [ { "status": "granted", "consumer": {...}, "purposes": [...], "data": [...] } ] }
```

Access is **allowed** only if a returned consent satisfies all of:

- `status == "granted"`;
- it was granted to the **consuming participant** identified from the token (a
  consent names one consumer; one granted to X is not authority for Y);
- it covers the **purpose**, when the resolver named one for the claim (set
  `require_purpose` to deny rather than proceed unscoped when it does not);
- it covers the **data resource**, when the resolver scoped the claim to one.

The owner DID is sent as the user `email` (the consent-manager's
DID-in-email convention).

### Participant authentication

Call 2 needs a **participant JWT**, and call 1 needs the **provider
self-description**. The plugin holds no participant credentials of its own: it
asks the participant-local OID4VP token service (the consent-facade's
`POST /internal/tokens`) for a short-lived token by **audience name**, then
derives the provider SD from `/participants/me`:

```
POST {token_service_url}   { "audience": "<token_audience>" }  →  { "access_token": ..., "expires_in": ... }
GET  {base}/participants/me   Authorization: Bearer <token>    →  { "selfDescriptionURL": ... }
```

The token is cached and refreshed on expiry or a 401. The cache is keyed on the
full credential identity (base URL, host, prefix, audience, token-service URL,
provider SD, and hashes of the static token and consent key), so two routes
fronting different participants against the same consent-manager never share a
token. A static `participant_token` and/or an explicit `provider_sd` remain
supported as overrides for tests and manual runs.

The consumer DID from the token is translated to a self-description URL via
`GET {base}/participants` (the consent-manager doubles as the participant
registry), cached for 10 minutes — and negatively for 30 seconds, so one
misconfigured DID does not re-fetch the registry on every request.

## Configuration Reference

Configured via the APISIX route plugin JSON (identically on both `ext-plugin-pre-req` and `ext-plugin-post-resp`):

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `consent_api_url` | `string` | **Yes** | — | Base URL of the consent-manager (e.g. `http://consent-manager:3000`). `http`/`https` only. |
| `owner_resolver_url` | `string` | **Yes** | — | The OwnerResolver `/resolve` endpoint. The data owner is resolved from the response payload; without it the plugin cannot determine whose consent to check, so the route fails to load. `http`/`https` only. |
| `owner_resolver_timeout` | `int` | No | `2000` | Per-call timeout in ms for `/resolve`. Range 1–60000. |
| `service` | `string` | No | — | Logical dataset id sent to the OwnerResolver as `resource.service`, so it can select the rule for this route. |
| `response_phase_timeout` | `int` | No | `10000` | Budget in ms for the **entire** response phase — party lookups, `/resolve`, and every per-owner consent check together. APISIX holds the buffered response for this whole time, so it is bounded independently of the per-call timeouts. Range 1–120000. |
| `require_purpose` | `bool` | No | `false` | Deny when a resolved claim names no processing purpose. Purpose matching depends on the OwnerResolver populating an optional field, so a resolver that never sets it runs with purpose scoping silently disabled; turn this on once yours emits one. `consent_purpose_unconstrained_total` counts the checks it would deny. |
| `require_contract` | `bool` | No | `false` | Deny when a resolved claim names neither a `contractUri` nor a `privacyNoticeId` and the route sets no `privacy_notice_id`. Without it such a claim matches any consent the owner granted this consumer under this provider, whatever the contract; turn it on once your resolver emits one of the two. |
| `check_mode` | `string` | No | `list` | How consents are looked up: `list` (`GET /consents?userIdentifier=`, one call per owner) or `check` (`GET /consents/check`, then a read of the consent it names — one extra round trip). Both apply the same match. Any other value fails validation. |
| `privacy_notice_id` | `string` | No | — | Route-level privacy notice UUID consents are scoped to when a resolved claim names none. Must be a UUID. In `check` mode a claim without any notice id is denied. |
| `purpose` | `string` | No | — | Processing purpose matched (verbatim) when a resolved claim names none. A claim's own purpose wins. |
| `max_resolve_body_bytes` | `int` | No | `1048576` | Maximum upstream body forwarded to the OwnerResolver. A larger body is denied rather than copied — the body is held whole, validated and marshalled again, so the peak footprint is ~3× its size per in-flight request on top of APISIX's own buffering. Range 1–104857600. |
| `max_owners_per_response` | `int` | No | `50` | Maximum distinct data owners checked for one response. A response resolving to more is denied rather than answered after an unbounded number of consent calls. Range 1–1000. |
| `consumer_claim` | `string` | No | `verifiableCredential.issuer` | Dotted claim path naming the **consuming participant**. Supports array indexing (`verifiableCredential[0].issuer`), and a bare segment landing on an array traverses its first element — a Verifiable Presentation routinely carries `verifiableCredential` as an array. Used for the contract lookup and to scope the consent match — never for ownership. |
| `consent_api_prefix` | `string` | No | `/v1` | API prefix prepended to endpoint paths (the consent-manager's `API_PREFIX`). Must start with `/`; a trailing `/` is trimmed. |
| `consent_api_timeout` | `int` | No | `5000` | Per-call timeout in ms. Range 1–60000. |
| `token_service_url` | `string` | Yes* | — | The participant-local OID4VP token service (the consent-facade's `POST /internal/tokens`). Falls back to `CONSENT_TOKEN_SERVICE_URL`. `http`/`https` only. |
| `token_audience` | `string` | No | `consent-manager` | Audience **name** asked of the token service — its own configured target, not a URL. |
| `participant_token_ttl` | `int` | No | `3000` | Seconds a fetched token is cached. The token service's own `expires_in` wins when shorter. Range 1–86400. |
| `participant_token` | `string` | Yes* | — | *Static*, pre-obtained participant token. An override for tests and manual runs; prefer `token_service_url`, which refreshes automatically. |
| `provider_sd` | `string` | No | — | Provider self-description URL for call 1. Derived from `/participants/me` when unset. |
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
`consent_request_context_store_size`, `consent_request_contexts_evicted_total`
and `consent_audit_events_dropped_total`. Metrics are off unless the variable is
set — the runner is otherwise reached only over its unix socket, so opening a
TCP port is the deployment's decision.

**Access audit log.** With `audit_enabled`, the plugin emits one OTLP/HTTP **log record** per **checked data owner** (so the log answers whose consent was consulted and what each said, not merely whether the response was released; a request that failed before any owner was reached is recorded once as itself) to `audit_otlp_endpoint`, stamped with resource `service.name=<audit_service_name>` and attributes `event.domain=audit`, `consent.decision`, `consent.reason`, `enduser.id`, `http.request.method`, `url.path`, `http.request.id`. Emission is asynchronous, batched, and best-effort (a bounded queue drops rather than blocking the request path), so a slow/absent Collector never affects data access. The queue is flushed when the runner exits (it returns on `SIGTERM`/`SIGINT`), so a redeploy does not discard the last flush interval of decisions. Reasons are sanitised before export (control characters collapsed, length bounded) so an upstream error body cannot reach the audit sink verbatim. Mark-based routing lets the Collector send these to an append-only audit sink separate from traces.

## APISIX Route Configuration Example

```bash
# Both phases must carry the SAME configuration, so build it once.
PLUGIN_CONF='{"consent_api_url":"http://consent-manager:3000","consent_api_prefix":"/v1","owner_resolver_url":"http://owner-resolver:8080/resolve","service":"personal-profiles","token_service_url":"http://consent-facade:8080/internal/tokens","token_audience":"consent-manager","fail_open":false}'

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

`consent_key` is omitted above because the facade injects it; set it (or
`CONSENT_KEY`) for a facade-less deployment. Both phases are required and must
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
consent-manager / OwnerResolver / token service, an echo upstream, and an OTel
Collector for the audit log:

| Service | Description | Ports |
|---------|-------------|-------|
| `etcd` | APISIX configuration store | `2379` |
| `apisix` | APISIX gateway | `9080` (HTTP), `9180` (Admin API) |
| `plugin-runner` | consent-filter plugin runner | — (unix socket, shared volume) |
| `mock` | consent-manager + OwnerResolver + token service stubs (`dev/mocks/`) | `8081` |
| `upstream` | echo service standing in for the personal-data API | — |
| `otel-collector` | receives the access-decision audit log | `4318` |

The runner also serves Prometheus metrics on `9091` (`CONSENT_METRICS_ADDRESS` is
set for it in the compose file).

Then create the gated route:

```bash
PLUGIN_CONF='{"consent_api_url":"http://mock:8080","owner_resolver_url":"http://mock:8080/resolve","token_service_url":"http://mock:8080/internal/tokens","consent_key":"dev-consent-key","service":"dev-profiles","fail_open":false}'

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

Change the `consumer` in `dev/mocks/consents.json` (or the `status` to
`revoked`) and restart the `mock` service to watch the same request be denied.
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
│   │   ├── client.go              # Two-call consent-manager client
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
