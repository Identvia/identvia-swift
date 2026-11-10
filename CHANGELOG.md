# Changelog

## 0.1.3 (2026-11-09)

- Public release for Swift Package Manager, installed from the `v0.1.3` git tag of `https://github.com/Identvia/identvia-swift`.
- README: badges, Xcode install steps and the `Identvia` repository URL. No code changes.

## 0.1.2 (2026-11-05)

- Examples: register the redirect on a **Native & desktop** portal client (public, PKCE; private-use schemes / App Links / loopback).

## 0.1.1 (2026-10-21)

- `sessionUpdates()` uses `AsyncStream.makeStream` with a non-optional `self` capture. It now compiles with Swift 5.10 (Sendable check) as well as 6.x.
- CI: the Linux matrix (5.10, 6.0) has fail-fast off. The Apple (iOS/macOS) job builds green. Tightened `.gitignore`.

## 0.1.0 — 2026-10-21

- First release.
- **IdentviaCore** (platform-neutral; builds and is tested on Linux):
  - `IdentviaClient` actor: authorization code flow with mandatory PKCE S256, `state`, `nonce` and the RFC 9207 `iss` check.
  - ID token validation: RS256/ES256 signature against the JWKS, plus `iss`, `aud`/`azp`, `exp`, `iat`, `nonce`, `at_hash` and `max_age`/`auth_time`. Rejects `none` and HS*. An unknown `kid` triggers a JWKS refetch, at most every 30 s.
  - Refresh-token rotation with single-flight refresh. A reused refresh token (`invalid_grant`) signs the user out locally (`.loginRequired`).
  - `userinfo()` with a `sub` check; `signOut(federated:)` revokes and does RP-initiated logout; `sessionUpdates()` AsyncStream.
  - `AuthorizationDetail.agentTask` (RFC 9396), which requires server 2026-10-21_5+ and throws `.unsupported` otherwise.
- **Identvia** (Apple):
  - `WebAuthenticationSessionPresenter` (ASWebAuthenticationSession; https callbacks on iOS 17.4+).
  - `KeychainTokenStore` (AfterFirstUnlockThisDeviceOnly, not synced).
  - SwiftUI `SignInWithIdentviaButton` and `IdentviaMark`.
