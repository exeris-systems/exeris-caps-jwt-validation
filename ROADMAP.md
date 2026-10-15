---
title: "exeris-caps-jwt-validation — Roadmap"
type: roadmap
visibility: public
owning-repo: exeris-caps-jwt-validation
status: active
last-verified: 2026-10-15
---

# exeris-caps-jwt-validation — Roadmap

This file records what the proof of concept does not cover. Read it with the code: each item names the
path it concerns, and the pull request that closes an item removes it here. The README states what the
capability does today; this file states what it does not.

Milestones are versions, not dates. An item under "Before 0.1.0" blocks the first release and has a
tracking issue in the `0.1.0` milestone. An item under "Later" does not block it.

## Before 0.1.0

### Maximum staleness of the JWKS keys

Tracked in [#10](https://github.com/exeris-systems/exeris-caps-jwt-validation/issues/10).

A failed reload keeps the previous keys, and nothing bounds how long the keys may stay in force. While
the issuer's JWKS endpoint is down, a key the issuer has withdrawn keeps verifying tokens, so a "valid"
outcome can rest on a key set of unbounded age. The capability should refuse every key once the last
successful load is older than a configured maximum. The code is `JwksKeySet.find` and
`JwksKeySet.refresh` in `src/main/java/eu/exeris/caps/jwt/internal/JwksKeySet.java`.

### The verification decision reaches the network

Tracked in [#11](https://github.com/exeris-systems/exeris-caps-jwt-validation/issues/11).

`DefaultJwtAdmissionPolicy.validateToken` calls `JwksKeySet.find`, which fetches the JWKS on the request
thread on first use, on a stale document and on an unknown `kid`, and other callers wait on the refresh
lock for up to the fetch deadline. The README and rule S8 in `docs/repo-review-rules.md` say the
decision reads no network. Either the fetch moves off the request thread, or the documents state the
bounded synchronous fetch as the design and the lock wait is bounded. The code is
`src/main/java/eu/exeris/caps/jwt/internal/JwksKeySet.java` and
`src/main/java/eu/exeris/caps/jwt/internal/DefaultJwtAdmissionPolicy.java`.

## Later

### Gateway `policy-chain` binding

ADR-099 obligation 4 has the capability register in the gateway's `PolicyChain` when one is present.
`JwtValidationModule` declares only `RequestFilterChain` from `exeris-caps-service-boundary-core`, and
the only binding is `JwtServiceBoundaryBinding` in `src/main/java/eu/exeris/caps/jwt/api/`, so a gateway
composition cannot host the check. `exeris-caps-gateway-core` declares `PolicyChain` 0.1.0 on its main
branch; this item waits on that capability being published. The Identity SKU's composition carries
neither `gateway-core` nor `policy-chain`, so it does not need the binding.

### `TokenValidator` in the kernel

The capability provides `JwtAdmissionPolicy` and no kernel `TokenValidator`
(`eu.exeris.kernel.spi.security.identity`), so a kernel-direct HTTP edge verifies through the kernel's
own identity provider, not through this capability's ordered, algorithm-pinned check. In the kernel,
`CommunityOidcTokenValidator` pins RS256, so it cannot verify the EdDSA tokens Identity issues. This item
waits on the Community `TokenValidator` accepting EdDSA in `exeris-kernel`, and on a decision whether
this capability adapts its policy to that SPI or consumers keep going through the admission filter.

### Module construction without a binding

The reflective no-argument `JwtValidationModule()` binds no host, so `initialize()` refuses. A
composition has to construct the module with `JwtValidationModule(AdmissionHostBinding)`. This waits on a
composition runtime that can pass a binding, or a configuration reader that builds one from the
`exeris.caps.jwt.*` properties; the code is `src/main/java/eu/exeris/caps/jwt/JwtValidationModule.java`.

### The cause of a refused principal is not visible to the caller

`JwtPrincipal.from` yields a principal only when `sub`, the tenant claim and `sid` are canonical UUIDs.
A token that verifies but carries another identifier shape is answered with the same 401 and
`invalid_token` as a bad signature, and the cause is visible only in the token issuer's logs. A distinct
internal status or a log hook is an ergonomics decision that waits on the Identity SKU's identifier
rule; the code is `src/main/java/eu/exeris/caps/jwt/api/JwtPrincipal.java` and
`src/main/java/eu/exeris/caps/jwt/internal/JwtAdmissionFilter.java`.

### Release workflow and API baseline

No artefact is published: `.github/workflows/` holds the build and the guardrail gates and no release
job, and the capability builds against `exeris-kernel` 0.13.0-SNAPSHOT. The repository has no API golden
or accepted-changes register, because no released version exists to take a baseline from. A release
job and the first baseline wait on a released kernel 0.13.0 and on the 0.1.0 items above.
