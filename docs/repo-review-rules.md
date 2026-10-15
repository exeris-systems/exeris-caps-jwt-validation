---
title: "Review rules for exeris-caps-jwt-validation"
type: reference
visibility: public
owning-repo: exeris-caps-jwt-validation
status: active
last-verified: 2026-10-13
---

# Review rules for `exeris-caps-jwt-validation`

The `repo-routine` extension of `exeris-systems/.github`'s `docs-guardrails-review.md`, applied
**after** its parts and under its severity tags, output format and verdict schema. It adds checks
and raises severities; it lowers nothing and skips nothing. One review, one verdict, one publisher.
A finding cites a rule of this file as `repo-review-rules.md#S<n>`.

**The criteria are not authored here.** They are stated by this repository's `AGENTS.md`,
`README.md`, `CONTRIBUTING.md` and `SECURITY.md`, and by the build that enforces them. This file names the
questions a reviewer must reach for and the severity each answer carries; where a rule restates a
sentence of those documents, the document is the one to read and to change.

## What this repository is answerable for

`exeris-caps-jwt-validation` is a single-module Exeris capability: Layer 3 gateway policy, licence commercial (Exeris Commercial License 1.1), a proof of concept with
no published artefact. Other capabilities and the SKUs that compose them compile against its
`@Provides` services, so a contract broken here breaks a composition elsewhere while this build stays
green. The shared `code` part judges whether a change is correct. What it cannot know is which of this
capability's surfaces and invariants its own documents promise, and that is what follows.

## Step S — rules of this repository

S1. **The cap-tier Wall holds** (ADR-055, ADR-006; `AGENTS.md` §2). Only what the build's Wall check
    enforces is asserted here: the check is `CapTierWall` in `exeris-tooling`, run by
    `exeris:verify-capabilities` at `process-classes` over the compiled main classes, and it rejects
    a reference to `org.springframework.*`, `io.netty.*`, `reactor.*` or `jakarta.servlet.*`, to
    kernel internals (`eu.exeris.kernel.**.internal.**`), and to a sibling capability's `internal`
    package; the public (non-`internal`) packages of `exeris-kernel-spi`
    and `exeris-kernel-core` are the kernel this capability may name. In a diff: such
    an import in `src/main`; a dependency in `pom.xml` that brings one in; a rename of the package
    root `eu.exeris.caps.jwt` or an extra segment in it, because the guard derives the capability's
    name from the segment after `eu.exeris.caps.`; `eu.exeris.caps.jwt.internal` is private to this
    capability and `eu.exeris.caps.jwt.api` is the cross-cap surface, and an `internal` type in a
    public signature → `[HARD BLOCK]`. A Spring, servlet, Netty or reactor import in `src/test` is
    outside what the guard scans and is still forbidden by `AGENTS.md` → `[CONTRACT]`. A kernel
    driver dependency (`exeris-kernel-community` or an enterprise driver) outside `test` scope →
    `[HARD BLOCK]`: the driver is chosen by the SKU, never by a capability.

S2. **The committed manifest is regenerated, never edited.**
    `src/main/generated/java/cap-manifest.json` is written by `exeris:generate`, and a clean
    `git status` after `mvn verify` shows it matches the declaration. A diff that edits it by hand,
    touches the module class (`@CapabilityModule`, `@Provides`, `@Requires`) without carrying the
    regenerated manifest, carries a manifest change with no declaration change, or leaves a manifest
    that disagrees with the annotations (a `@Provides` version, a `@Requires` range or `optional`
    flag, an `initOrder`) → `[HARD BLOCK]`. A manifest whose `stamp.validated` is not `true` →
    `[HARD BLOCK]`.

S3. **Service contracts are `0.1.0` while the capability is unreleased**
    (`standards/capability-conventions.md` rule 9). While no artefact of this capability has been
    published, every `@Provides` declares `version = "0.1.0"` and every `@Requires` on an unreleased
    contract declares `[0.1.0,0.2.0)`; a declaration at `1.0.0` or higher, or a range that is not
    `[0.1.0,0.2.0)`, → `[CONTRACT]`. A pre-release breaking change does not bump the version: it
    keeps `0.1.0` and its Compatibility impact line is `breaking (ADR-099)` (accepted 2026-10-07),
    or `breaking (ADR-NNN)` of the accepted ADR that governs this capability. **An unreleased
    capability keeps no `accepted-api-changes.json`; the first released version starts it.** The
    reviewer therefore does not ask for that file, an entry in it, or a japicmp baseline on a
    pre-release pull request, and does not read the absence of a version bump as a finding. A pull
    request that publishes the first release is the one in which the register starts, and rule 24 of
    the shared routine then applies in full.

S4. **The entitlement registration stays, and its id is the artifactId.** This is a `commercial`
    capability (Exeris Commercial License 1.1, ADR-023), so
    `META-INF/services/eu.exeris.kernel.spi.contract.EntitlementRequirement` names an implementation
    whose capability id is `exeris-caps-jwt-validation`, the artifactId and without the groupId
    (ADR-088, ADR-089). The service file deleted, the id changed to anything else, the id no longer
    equal to the artifactId, or the registration made conditional → `[HARD BLOCK]`: in a
    production-class environment the kernel refuses to start without a licence that lists that id.
    The licence in `LICENSE`, the POM and the README moves together, and a change to one alone →
    `[CONTRACT]`.

S5. **No dependency creep.** The runtime classpath stays what the POM declares:
    `exeris-sdk-annotations` at `provided` (every Exeris annotation is `@Retention(SOURCE)`), the
    kernel SPI, and the sibling capabilities the README lists. A new `compile`-scope dependency, a
    logging implementation such as Logback or Log4j (use `System.Logger`, ADR-060), or a new sibling
    capability with no matching `@Requires` or README line → `[CONTRACT]`. Reading an Exeris
    annotation at runtime → `[HARD BLOCK]`.

S6. **The build baseline and the test contract hold** (`AGENTS.md` §2, `CONTRIBUTING.md`).
    `maven.compiler.release` stays 25 and no `--enable-preview` appears in any scope →
    `[HARD BLOCK]`. Tests use JUnit 5 and AssertJ only, with hand-written doubles and no mocking
    framework (ADR-058) → `[CONTRACT]`. A bug fix lands with the test that fails without it →
    `[CONTRACT]` when absent.

S7. **Verification names what ran.** CI runs `mvn verify` on JDK 25 and 26 on every head, so the
    pull request's Verification need not repeat it. A local run may be cited as
    `target/surefire-reports` at `<sha>`, and the reviewer accepts that as the evidence of what ran
    locally. A Verification that claims a pass without a command, report path or sha → `[STYLE]`.

S8. **The decision path is transport-free; the one outbound call is the issuer's JWKS.**
    `JwtAdmissionPolicy` takes a compact JWS and returns a `JwtValidationResult`, and the verification
    decision in `DefaultJwtAdmissionPolicy` reads no network or file: it works on
    the keys `JwksKeySet` holds. The capability may fetch the issuer's JWKS itself, through
    `HttpJwksFetcher` only, as an outbound HTTPS GET of the configured `jwks-uri` (HTTP only on a
    loopback host, no redirects). The whole fetch is bounded by one deadline that covers connecting,
    the headers and the body, and by a body size cap enforced while streaming. Refresh is
    single-flight in `JwksKeySet`, under a refresh interval and a minimum refetch interval that also
    limits reloads an unknown `kid` triggers, and a failed fetch keeps the previous keys. A JWKS may
    equally arrive as a string or a `Supplier<String>`. The only inbound HTTP binding is the Service
    Boundary admission filter (`JwtAdmissionFilter`, attached through `AdmissionHostBinding`).
    Findings:
    - a fetch with no deadline over the whole exchange, with no body size cap, over plain HTTP off
      loopback, following redirects, or run outside `HttpJwksFetcher` → `[HARD BLOCK]`;
    - a refresh that is not single-flight, or has no minimum refetch interval → `[HARD BLOCK]`;
    - any other outbound call, a fetch from the verification decision path, an inbound HTTP server or
      listener, or an HTTP-client or file-fetch call in `api` → `[HARD BLOCK]`.
    ADR-099 obligation 8 requires EdDSA verification against a JWKS document; it does not say who
    retrieves the document, and this rule judges code against the bounds above.

S9. **A rejected token is a `JwtValidationStatus`, not an exception.** A path that throws for a
    malformed, expired or badly signed token, or that collapses two statuses into one →
    `[CONTRACT]`.

S10. **The signature cache is bounded and keyed on the whole token.** The `JwtAdmissionPolicy`
    Javadoc names bounded signature caching, and the cache is keyed on the entire token so that a
    tampered payload cannot hit an entry. A cache with no bound, or one keyed on a part of the token
    such as the signature alone → `[HARD BLOCK]`.

S11. **Parsing stays allocation-conscious.** The Javadoc states zero-allocation parsing
    (`JsonHeaderScanner`, `JsonClaimsScanner`). An allocation added to that path, such as a
    general-purpose JSON tree, → `[CONTRACT]`; a new dependency to do it is also S5.

S12. **The algorithm set is the README's.** HMAC-SHA256 secret, Ed25519, RS256 or ES256 public key,
    or a JWKS. A new accepted algorithm with no README change → `[CONTRACT]`.

## Where this does not apply, and what it costs

The shared `code` and `pr` parts judge correctness, scope, the pull request's body and its commits, and the rules above are not a second copy of them. Whether a change to `internal` is correct is the `code` part's; what this file adds is the list of invariants this capability's own documents state, which a generic review cannot know to look for. Not to the pull request's body and commits, which the shared `pr` part judges, nor to comments
and Javadoc, which the shared `code-docs` part and the Javadoc gate judge.

The cost is that these rules are prose a reviewer applies, not a program. This repository hands the review no `repo-checks` output, so the Wall scan, the manifest comparison and the tests named above are evidence only through the build checks on the pull request, which the reviewer cannot read. A rule the reviewer could only check by running the build is reported as unchecked, not as passing. The README and `AGENTS.md` do not state the order in which a token is checked, nor that the algorithm is fixed before the signature is read, so no rule here asserts either. A change that reorders the checks is judged by the shared `code` part.
