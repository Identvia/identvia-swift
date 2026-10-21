import Foundation

/// Every error the SDK throws.
public enum IdentviaError: Error, Equatable, Sendable, CustomStringConvertible {
    /// The SDK was set up wrongly (issuer, client ID, redirect URI).
    case configuration(String)
    /// The user closed the browser sheet.
    case cancelled
    /// The redirect didn't belong to this sign-in (state, iss or redirect mismatch). Possible CSRF or mix-up attack.
    case invalidState(String)
    /// Identvia returned an error to the redirect URI (for example `access_denied`).
    case authorization(error: String, description: String?)
    /// The token, userinfo or revocation endpoint returned an error.
    case token(error: String, description: String?, status: Int)
    /// An ID token or response failed validation.
    case validation(String)
    /// The network request failed or the response wasn't valid JSON.
    case network(String)
    /// The server doesn't support this feature yet (stage-5 features need server 2026-10-21_5+).
    case unsupported(String)
    /// The session ended (refresh token expired, revoked or reused). Sign in again.
    case loginRequired

    public var description: String {
        switch self {
        case .configuration(let m): return "Identvia configuration error: \(m)"
        case .cancelled: return "Sign-in was cancelled."
        case .invalidState(let m): return "Invalid authorization response: \(m)"
        case .authorization(let e, let d): return "Authorization failed: \(e)\(d.map { " (\($0))" } ?? "")"
        case .token(let e, let d, let s): return "Token request failed (\(s)): \(e)\(d.map { " (\($0))" } ?? "")"
        case .validation(let m): return "Validation failed: \(m)"
        case .network(let m): return "Network error: \(m)"
        case .unsupported(let m): return "Unsupported: \(m)"
        case .loginRequired: return "The session has ended; sign in again."
        }
    }
}
