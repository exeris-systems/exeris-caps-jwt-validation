# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

`exeris-caps-jwt-validation` is a single-module **capability** in the Exeris cap tier (Layer 3 — Gateway Policy,
ADR-024 / HLA §3.2). It publishes one service: `JwtAdmissionPolicy`. It provides zero-allocation JWT token
admission, zero-copy claims parsing, native cryptographic signature verification (HMAC-SHA256), and
bounded lock-free signature caching.

Two properties make it load-bearing:

1. **Zero-allocation hot path & native cryptography**: Token boundaries are scanned in-place without `String.split`,
   Base64URL decoding directly populates working buffers, and standard claims (`exp`, `sub`, `iss`, `tid`)
   are scanned directly from UTF-8 bytes without AST allocations. Repeated requests with the same valid token
   hit a bounded lock-free table (`LockFreeJwtCache`) resolving in `< 100 ns`.
2. **The jar carries zero runtime dependencies**: Every Exeris annotation is `@Retention(SOURCE)`, so
   `exeris-sdk-annotations` stays at `provided` scope and `exeris-processor` stays inside
   `annotationProcessorPaths`. Nothing survives to a consumer.

## Build & test

```bash
mvn compile -Dexeris.codegen.skip=true   # pass 1 — seed: the processor writes capability metadata
mvn verify                               # pass 2 — generate, validate the graph, scan the Wall
```

## Hard constraints

- **The cap-tier Wall (ADR-055), build-enforced**: `..jwt.api` is the entire cross-cap surface;
  `..jwt.internal` is private. Sibling caps cannot access internal classes.
- **Zero runtime dependencies**: No Jackson, no Gson, no Nimbus, no Spring, no Netty dependencies.
- **JDK 25 LTS, preview-clean**: `maven.compiler.release` is 25 preview-clean.
- **Fail-closed security**: Malformed, expired, premature, or invalid signature tokens are strictly rejected
  with terminal deny results (never fail-open).
- **Test contract (ADR-058)**: JUnit 5 + AssertJ only, no mocking frameworks.
