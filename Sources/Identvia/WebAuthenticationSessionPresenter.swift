#if canImport(AuthenticationServices)
import AuthenticationServices
import Foundation
#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

/// Presents sign-in with `ASWebAuthenticationSession`: a system browser sheet that shares Safari's cookies
/// (and passkeys), never an embedded web view. Set `ephemeral` to use a private session.
public final class WebAuthenticationSessionPresenter: NSObject, AuthSessionPresenter, ASWebAuthenticationPresentationContextProviding, @unchecked Sendable {
    /// Supply a window to present from; by default the key window is used.
    private let anchorProvider: (@MainActor () -> ASPresentationAnchor?)?
    private var session: ASWebAuthenticationSession?

    public init(anchor: (@MainActor () -> ASPresentationAnchor?)? = nil) {
        self.anchorProvider = anchor
        super.init()
    }

    public func authenticate(url: URL, redirectURI: URL, ephemeral: Bool) async throws -> URL {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<URL, Error>) in
            Task { @MainActor in
                do {
                    let s = try self.makeSession(url: url, redirectURI: redirectURI) { callback, error in
                        self.session = nil
                        if let callback { return cont.resume(returning: callback) }
                        if let e = error as? ASWebAuthenticationSessionError, e.code == .canceledLogin { return cont.resume(throwing: IdentviaError.cancelled) }
                        cont.resume(throwing: IdentviaError.network(error?.localizedDescription ?? "Web authentication failed."))
                    }
                    s.presentationContextProvider = self
                    s.prefersEphemeralWebBrowserSession = ephemeral
                    self.session = s
                    if !s.start() {
                        self.session = nil
                        cont.resume(throwing: IdentviaError.configuration("ASWebAuthenticationSession could not start."))
                    }
                } catch {
                    cont.resume(throwing: error)
                }
            }
        }
    }

    @MainActor
    private func makeSession(url: URL, redirectURI: URL, handler: @escaping ASWebAuthenticationSession.CompletionHandler) throws -> ASWebAuthenticationSession {
        let scheme = redirectURI.scheme?.lowercased() ?? ""
        if scheme == "https" {
            if #available(iOS 17.4, macOS 14.4, visionOS 1.1, *) {
                return ASWebAuthenticationSession(url: url, callback: .https(host: redirectURI.host ?? "", path: redirectURI.path.isEmpty ? "/" : redirectURI.path), completionHandler: handler)
            }
            throw IdentviaError.configuration("https redirect URIs need iOS 17.4 / macOS 14.4. Use a custom scheme such as com.example.app:/oauth/identvia on older versions.")
        }
        if scheme == "http" {
            throw IdentviaError.configuration("Loopback redirects aren't supported by ASWebAuthenticationSession; use a custom scheme.")
        }
        if #available(iOS 17.4, macOS 14.4, visionOS 1.1, *) {
            return ASWebAuthenticationSession(url: url, callback: .customScheme(scheme), completionHandler: handler)
        }
        return ASWebAuthenticationSession(url: url, callbackURLScheme: scheme, completionHandler: handler)
    }

    @MainActor
    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        if let a = anchorProvider?() { return a }
        #if canImport(UIKit)
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        return scenes.flatMap(\.windows).first(where: \.isKeyWindow) ?? scenes.first.map { UIWindow(windowScene: $0) } ?? ASPresentationAnchor()
        #else
        return NSApplication.shared.keyWindow ?? NSApplication.shared.windows.first ?? ASPresentationAnchor()
        #endif
    }
}
#endif
