import Foundation

let loopbackHosts: Set<String> = ["localhost", "127.0.0.1", "::1", "[::1]"]

public enum RedirectURI {
    /// Checks a native-app redirect URI (RFC 8252): a claimed `https` URL, an `http` loopback URL (desktop only),
    /// or a reverse-domain private-use scheme such as `com.example.app:/oauth/identvia`. No fragments.
    public static func validate(_ s: String) throws -> URL {
        guard let c = URLComponents(string: s), let scheme = c.scheme?.lowercased(), let url = c.url else {
            throw IdentviaError.configuration("redirectURI is not a valid URL: \(s)")
        }
        guard c.fragment == nil else { throw IdentviaError.configuration("redirectURI must not contain a fragment.") }
        if scheme == "https", let h = c.host, !h.isEmpty { return url }
        if scheme == "http", let h = c.host?.lowercased(), loopbackHosts.contains(h) { return url }
        let reverseDomain = scheme.range(of: #"^[a-z][a-z0-9+\-]*(\.[a-z0-9+\-]+)+$"#, options: .regularExpression) != nil
        if reverseDomain && scheme != "http" && scheme != "https" { return url }
        throw IdentviaError.configuration("redirectURI must be https://, http://localhost (desktop), or a reverse-domain scheme such as com.example.app:/callback (RFC 8252). Got \(s)")
    }

    /// True when `callback` was sent to `registered`: same scheme, host, port and path. Query is ignored.
    public static func matches(_ callback: URL, _ registered: URL) -> Bool {
        guard let a = URLComponents(url: callback, resolvingAgainstBaseURL: false),
              let b = URLComponents(url: registered, resolvingAgainstBaseURL: false) else { return false }
        func p(_ c: URLComponents) -> String { c.percentEncodedPath.isEmpty ? "/" : c.percentEncodedPath }
        return a.scheme?.lowercased() == b.scheme?.lowercased()
            && (a.host ?? "").lowercased() == (b.host ?? "").lowercased()
            && a.port == b.port
            && p(a) == p(b)
    }
}

func normalizeIssuer(_ s: String) throws -> String {
    var i = s.trimmingCharacters(in: .whitespaces)
    while i.hasSuffix("/") { i.removeLast() }
    guard let c = URLComponents(string: i), let scheme = c.scheme?.lowercased(), let host = c.host?.lowercased(),
          c.query == nil, c.fragment == nil,
          scheme == "https" || (scheme == "http" && loopbackHosts.contains(host)) else {
        throw IdentviaError.configuration("issuer must be an https:// URL without query or fragment.")
    }
    return i
}
