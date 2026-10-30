# consent-plugin

## Overview
An Apache APISIX Go plugin (go-plugin-runner, image `quay.io/seamware/consent-plugin`)
that releases a response only when every data owner in it has consented. The request
phase (`ext-plugin-pre-req`) captures the JWT claims, keyed by the Nginx `$request_id`.
The response phase (`ext-plugin-post-resp`) asks an external **OwnerResolver** who owns
the data, then checks each owner against the consent-manager. A failed check replaces
the response with a configurable deny.

> **Migration in progress (ticket #112):** the consent-manager is moving from
> Prometheus-X/Visions (two calls: `/users/identifier/search` + `/consents/participants/{id}`,
> consent key, Host rewrite) to **dsc-consent-manager** (`/v1/consents?userIdentifier=`
> list mode, `/v1/consents/check` check mode, bearer token only). Spec:
> https://github.com/wistefan/dsc-consent-manager/blob/main/api/openapi.yaml.
> Follow `IMPLEMENTATION_PLAN.md`, and update this file when a step changes what it describes.

Invariants:
- The owner always comes from the DATA, via the resolver, and never from the token's `sub`.
- The JWT is decoded but not verified. An auth plugin must run earlier on the route.
- The gate is coarse allow/deny and ignores the body's shape.

## Tech Stack
- Language: Go 1.26 (module `consent-plugin`)
- Framework: `github.com/apache/apisix-go-plugin-runner`
- Test: `testing` + `testify`, `net/http/httptest` fakes for every dependency
- Build: Makefile, Docker, golangci-lint (`.golangci.yml`); GitHub Actions in `.github/workflows`

## Project Structure
```
main.go                      # registers plugin, starts runner, optional metrics server
internal/plugin/             # consent.go (filters, checkOwners, failMode), config.go (Config, Validate, applyEnv),
                             # context.go (request-context store), config_doc_test.go (README<->Config guard)
internal/consent/            # client.go (token, participant registry, consent check), models.go, reset.go (test cache reset)
internal/ownerresolver/      # /resolve client (Claim{ownerId,dataResource,purpose}, Parties{consumer,provider})
internal/audit/              # async OTLP/HTTP audit log
internal/metrics/            # hand-rolled Prometheus exporter
internal/logging/            # Redact/Sanitize/*Every rate-limited logging (never log.Printf)
internal/jwt/                # claim decoding (no verification)
internal/integration/        # end-to-end filter tests against httptest consent-manager/resolver fakes
dev/mocks/*.json             # WireMock stubs for docker-compose (consent-manager, resolver, token service)
docker-compose.yaml, dev/    # local stack: etcd, APISIX, runner, WireMock, upstream, otel-collector
hack/                        # coverage-floor.sh, license-header.sh
```

## Build & Test
```bash
make build          # go build go-runner
make test           # go test -race ./...
make test-cover     # coverage with -coverpkg=./... + floor (hack/coverage-floor.sh)
make lint           # golangci-lint run ./...
make license-check  # Apache-2.0 header on every .go file (new files need it: make license-fix)
make docker-build
```

## Key Conventions
- Every exported identifier has GoDoc. Simple fields and constants get one line.
  Security-relevant decisions (fail modes, consumer scoping, caching) carry
  multi-paragraph *why* comments. Match the density around your edit and don't
  pad new code.
- Named constants for all literals (paths, TTLs, limits, header names); no magic numbers.
- Table-driven tests with `t.Run`; call `consent.ResetCaches()` between tests that touch caches.
- Errors are wrapped `fmt.Errorf("consent client: ...: %w", err)`. Sentinel errors
  (`ErrNoCredentials`, `ErrParticipantNotRegistered`) map to `failAlwaysClosed` in
  `failModeForError`. Every other dependency error is `failByPolicy`, so `fail_open` applies to it.
- A dependency's response body never goes into an error or an audit reason (`unexpectedStatus`
  logs it at debug level only).
- Config json tags are snake_case. Every new or removed field needs a matching README
  "Configuration Reference" row, or `config_doc_test.go` fails.
- Secrets can come from env (`applyEnv`: `CONSENT_TOKEN_SERVICE_URL`, `CONSENT_AUDIT_OTLP_ENDPOINT`;
  config wins).

## Important Files
- `internal/plugin/consent.go`: `evaluateWithResolver` (consumer DID → SD, provider SD,
  `/resolve`), `checkOwners` (concurrent per-owner checks, deny_all), `reduceOwnerResults`,
  `clientConfigFromCfg`, `failModeForError`, `recordAudit`.
- `internal/plugin/config.go`: `Config`, `applyDefaults`, `Validate`, `ParseConfig`.
  `owner_resolver_url` is required and `fail_open` defaults to false.
- `internal/consent/client.go`: `CheckConsent` (refreshes the token once on 401),
  `credentials` (token cache keyed by `cacheKey`), `ParticipantSelfDescriptionByDID`,
  `ProviderSelfDescription`, `endpoint`, `do`, `unexpectedStatus`.
- `internal/consent/models.go`: `ConsentRequest` and `ConsentResponse`, the plugin↔client contract.
- `README.md`: the configuration table is the contract. Release versions come from
  semver PR labels (see `CONTRIBUTING.md`).
