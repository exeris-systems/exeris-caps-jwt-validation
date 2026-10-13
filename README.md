# exeris-caps-jwt-validation

JWT admission as an Exeris capability. It provides `JwtAdmissionPolicy`, which verifies a compact JWS access token against the issuer's published keys, and the admission filter that runs that check on a Service Boundary request and records the verified caller in its `RequestContext`. It owns no transport.

Status: proof of concept, built against `exeris-kernel` 0.13.0-SNAPSHOT. The API is not stable and no artefact has been published.

## Where it sits

- **Layer:** Layer 3 — Gateway policy, in the Tier 2 capability map of [`high-level-architecture.md`](https://github.com/exeris-systems/exeris-docs/blob/main/high-level-architecture.md) §3.2.
- **Depends on:** `exeris-kernel-spi`, `exeris-sdk-composition-lifecycle` and `exeris-caps-service-boundary-core`, all at `provided` scope, so the jar carries no runtime dependency.
- **Provides** (`@Provides`): `JwtAdmissionPolicy` 2.0.0.
- **Requires** (`@Requires`, optional): `RequestFilterChain` `[1.1.0,2.0.0)` from `exeris-caps-service-boundary-core`. ADR-099 obligation 4 also names the gateway's `policy-chain` as an optional host; no published capability provides it yet, so that binding does not exist.
- **Wall (ADR-055):** `eu.exeris.caps.jwt.api` is the cross-cap surface; `eu.exeris.caps.jwt.internal` is private, and a sibling cap reaching into it fails the build. No Spring, servlet, Netty or reactive type may appear (ADR-006).

## Verification

`JwtAdmissionPolicy` checks a token in a fixed order, and each step runs only once the steps before it passed:

1. parse — three Base64URL segments; the header a JSON object with `alg` and no `crit`; duplicate JSON members are refused;
2. `kid` — required;
3. key — the issuer's key with that `kid`, from its JWKS;
4. algorithm — the header's `alg` must be the algorithm the key is bound to (Ed25519 → `EdDSA`, RSA ≥ 2048 bits → `RS256`) and an accepted one; `EdDSA` is accepted by default and `RS256` only when configured;
5. signature;
6. claims, read only after the signature — `iss`, `aud`, `exp` and `nbf` (both required), and `iat` not in the future, all with one clock skew of at most five minutes; `sub` is required.

No verification result is cached: every request verifies its token's signature. The JWKS is fetched with a connect and response timeout, reloaded when older than the refresh interval, and reloaded for an unknown `kid` at most once per minimum refresh interval. A failed reload keeps the previous keys.

## Service Boundary filter

`JwtServiceBoundaryBinding.of(chain, policy, anonymousRoutes)` builds the binding, and `new JwtValidationModule(binding)` attaches it at `initialize()`. The filter runs in the `AUTHENTICATION` phase. On a verified token it records a `JwtPrincipal` — subject, tenant, session id, roles and scopes, all UUID-typed where the kernel's `PrincipalContext` asks for it — through `AdmissionContext`, and the route handler reads it from `RequestContext.current().principal()`. That is the only source of the caller's identity a route may use. On any failure the filter answers `401` with `WWW-Authenticate: Bearer` and a fixed `application/problem+json` body that names nothing about the token. A route listed as anonymous admits a request without a token; a token that is present is verified on every route. A module with no binding refuses to initialise.

## Configuration

`JwtAdmissionPolicies.fromProperties(properties, inProcessJwks)` and `JwtServiceBoundaryBinding.anonymousRoutes(properties)` read:

| Key | Default | Meaning |
|---|---|---|
| `exeris.caps.jwt.issuer` | required | expected `iss` |
| `exeris.caps.jwt.audience` | required | expected member of `aud` |
| `exeris.caps.jwt.jwks-uri` | – | issuer JWKS; `https`, or `http` on loopback; without it the in-process JWKS supplier is used |
| `exeris.caps.jwt.algorithms` | `EdDSA` | accepted algorithms, `EdDSA` and optionally `RS256` |
| `exeris.caps.jwt.clock-skew-seconds` | `30` | skew on `exp`, `nbf`, `iat`; at most 300 |
| `exeris.caps.jwt.tenant-claim` | `tid` | claim carrying the tenant id: one string, absent when the token has no tenant (token-issuer `TokenIssueRequest.TENANT_CLAIM`) |
| `exeris.caps.jwt.jwks-timeout-millis` | `2000` | JWKS connect and response timeout |
| `exeris.caps.jwt.jwks-refresh-seconds` | `300` | JWKS age that triggers a reload |
| `exeris.caps.jwt.jwks-min-refresh-seconds` | `30` | minimum spacing of reloads, including unknown-`kid` reloads |
| `exeris.caps.jwt.anonymous-routes` | none | comma-separated `METHOD /path/{template}` routes that admit a request without a token |

## Build & test

Requires JDK 25 and Maven 3.9+.

```bash
mvn compile -Dexeris.codegen.skip=true   # pass 1 — the processor writes capability metadata
mvn verify                               # pass 2 — generate cap-manifest.json, validate the graph, scan the Wall
```

Both passes are needed after a `clean`: `exeris:generate` runs before `compile`, and `compile` is when the processor writes the metadata it reads. `src/main/generated/java/cap-manifest.json` is committed, so a clean `git status` after `mvn verify` shows the manifest matches the declaration.

The upstreams are not on Maven Central. `exeris-sdk` v0.10.0 and `exeris-tooling` v0.7.0 are built from source at those tags, `exeris-caps-service-boundary-core` is built from its `main` branch, and `exeris-kernel` 0.13.0-SNAPSHOT is resolved from GitHub Packages, which needs a token with `read:packages`. [`.github/workflows/build.yml`](.github/workflows/build.yml) is the exact sequence, and [`.github/maven-settings.xml`](.github/maven-settings.xml) the repository configuration it uses.

## Documentation

- [`AGENTS.md`](AGENTS.md) — the repository's operating contract and invariants.
- [Capability Author Guide](https://github.com/exeris-systems/exeris-docs/blob/main/cap-author-guide.md) — how a cap declares `@CapabilityModule`, `@Provides`, `@Requires` and `@CapabilityLifecycle`.
- [Capability licence registry](https://github.com/exeris-systems/exeris-docs/blob/main/cap-license-registry.md) — the licence value of every cap.

Where they disagree, the ADRs below and the HLA outrank this README.

## Governing ADRs

- [ADR-006](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-006-spring-free-kernel-boundary.md) — Spring-free kernel boundary.
- [ADR-023](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-023-capability-licensing-taxonomy.md) — capability licensing taxonomy.
- [ADR-024](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-024-capability-composition-model.md) — capability composition model.
- [ADR-053](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-053-sku-composition-manifest-format.md) — composition manifest format.
- [ADR-055](https://github.com/exeris-systems/exeris-tooling/blob/main/docs/adr/ADR-055-cap-tier-wall-guard.md) — cap-tier Wall guard.
- [ADR-088](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-088-cryptographic-license-manifest-and-offline-verification.md) — signed licence manifest.
- [ADR-089](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-089-capability-entitlement-enforcement-and-runtime-contract.md) — capability entitlement enforcement.
- [ADR-099](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-099-compose-identity-as-a-tier-3-platform-sku.md) — the Identity SKU, which lists this cap.

Registry: [`adr-index.md`](https://github.com/exeris-systems/exeris-docs/blob/main/adr-index.md).

## License

Exeris Commercial License 1.1 — see [`LICENSE`](LICENSE). `exeris-caps-jwt-validation` is a `commercial` capability under [ADR-023](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-023-capability-licensing-taxonomy.md): the source is available to read, build, test and evaluate, and production use requires a commercial licence.

The cap enforces that at boot. It registers a kernel `EntitlementRequirement` whose capability id is `exeris-caps-jwt-validation`, and in a production-class environment the kernel's contract gate refuses to start unless a signed licence manifest lists that id among its entitlements ([ADR-088](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-088-cryptographic-license-manifest-and-offline-verification.md), [ADR-089](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-089-capability-entitlement-enforcement-and-runtime-contract.md)).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Report a suspected vulnerability as described in [`SECURITY.md`](SECURITY.md), never in a public issue.
