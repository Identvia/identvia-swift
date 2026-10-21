# Identvia for Swift

Sign in with [Identvia](https://identvia.com) on iOS 15+, macOS 12+ and visionOS. OpenID Connect with PKCE in `ASWebAuthenticationSession` (the system browser, with Safari's cookies and passkeys), Keychain storage, refresh-token rotation, `async`/`await`, and a SwiftUI button.

- **Public client.** Never ship a client secret in an app; this SDK has no secret option.
- **Pairwise `sub`.** Each app gets its own stable user ID. Key your users on `session.user.sub`.

## Install

Swift Package Manager:

```swift
.package(url: "https://github.com/identvia/identvia-swift", from: "0.1.0")
```

There are two products:

| Product | Use |
|---|---|
| `Identvia` | Apple apps: core + ASWebAuthenticationSession, Keychain, SwiftUI button. |
| `IdentviaCore` | Platform-neutral OIDC client. Also runs on Linux, with your own `AuthSessionPresenter`/`TokenStore`. |

## 1. Register

At <https://identvia.com/developers>, create a **public** (native) client and add one of these redirect URIs:

- `com.example.app:/oauth/identvia`: a reverse-domain custom scheme. Works on iOS 15+, and no Info.plist entry is needed.
- `https://app.example.com/oauth/identvia`: needs iOS 17.4 / macOS 14.4 and associated domains (`webcredentials:`/`applinks:`).

## 2. Quickstart

```swift
import Identvia

let identvia = try IdentviaClient(
    clientId: "oid_…",
    redirectURI: "com.example.app:/oauth/identvia"
)   // scopes: openid email profile offline_access

// On launch
let existing = try await identvia.currentSession()

// Sign in (SwiftUI)
SignInWithIdentviaButton(.continueWith, theme: .dark) {
    Task {
        do { let s = try await identvia.signIn(); print(s.user.sub) }
        catch IdentviaError.cancelled { }
    }
}

// Call your API. The access token is refreshed and rotated automatically.
var req = URLRequest(url: api)
req.setValue("Bearer \(try await identvia.accessToken())", forHTTPHeaderField: "Authorization")

// Sign out. federated: true also ends the Identvia browser session.
try await identvia.signOut()
```

More options:
- `signIn(prompt: "login", maxAge: 300, loginHint:, uiLocales:)`.
- `IdentviaClient(..., ephemeralSession: true)` for a private browser session.
- `for await s in await identvia.sessionUpdates() { … }`.

If `accessToken()` throws `IdentviaError.loginRequired`, the session ended (expired, revoked, or the refresh token was reused). Show sign-in again.

### Agent authorization: requires server 2026-10-21_5+

```swift
try await identvia.signIn(authorizationDetails: [.agentTask("Book a table for two on Friday", actions: ["book"])])
```

This throws `.unsupported` when the server doesn't advertise `authorization_details_types_supported`. Token exchange (RFC 8693) and CIBA need a client secret, so they live in server SDKs (`@identvia/js/server`, `Identvia.AspNetCore`), not in this package.

## Security

- **Sign-in:** PKCE S256, `state`, `nonce` and the RFC 9207 `iss` check on every sign-in. The callback must exactly match your redirect URI.
- **ID tokens:** verified with RS256/ES256 against the JWKS, plus `iss`, `aud`, `azp`, `exp`, `iat`, `nonce` and `at_hash`.
- **Storage:** Keychain with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, not synced. The refresh token is kept in its own item.
- **Browser:** always the system browser. There's no WKWebView code path.

## Linux / server-side Swift

`IdentviaCore` builds on Linux with swift-crypto. Supply an `AuthSessionPresenter` and a `TokenStore`.

## Tests

```sh
swift test                                                  # 35 tests, runs on macOS and Linux
IDENTVIA_LIVE_STATE=/tmp/live-state.json swift test --filter LiveTests   # against a real server
```

## Platform status (0.1.0)

| | Status |
|---|---|
| `IdentviaCore` | Tested on Linux (Swift 6.x, Swift 5 and 6 language modes), including against a real Identvia server. |
| `WebAuthenticationSessionPresenter`, `KeychainTokenStore`, `SignInWithIdentviaButton`, example app | Written against the Apple SDKs, but **not yet compiled or run on Apple platforms**. CI builds them on macOS. |

MIT © Identvia
