// A minimal SwiftUI app. In Xcode: File ▸ New ▸ Project ▸ App ("IdentviaNotes", bundle ID com.example.identvianotes),
// add this package (File ▸ Add Package Dependencies… ▸ https://github.com/identvia/identvia-swift), and replace
// the generated App file with this one. Register com.example.identvianotes:/oauth/identvia as a redirect URI
// on a *public* Identvia client. No Info.plist URL type is needed: ASWebAuthenticationSession catches the callback.
import SwiftUI
import Identvia

@MainActor
final class Auth: ObservableObject {
    // Never put a client secret in an app.
    let client = try! IdentviaClient(clientId: "oid_your_client_id", redirectURI: "com.example.identvianotes:/oauth/identvia")
    @Published var session: IdentviaSession?
    @Published var busy = false
    @Published var error: String?

    func restore() async { session = try? await client.currentSession() }

    func run(_ f: @escaping () async throws -> Void) {
        busy = true; error = nil
        Task {
            defer { busy = false }
            do { try await f() }
            catch IdentviaError.cancelled {}
            catch { self.error = String(describing: error) }
        }
    }

    func signIn() { run { self.session = try await self.client.signIn() } }
    func signOut() { run { try await self.client.signOut(); self.session = nil } }
    func callAPI() {
        run {
            var r = URLRequest(url: URL(string: "https://api.example.com/notes")!)
            r.setValue("Bearer \(try await self.client.accessToken())", forHTTPHeaderField: "Authorization")
            _ = try await URLSession.shared.data(for: r)
        }
    }
}

@main
struct IdentviaNotesApp: App {
    @StateObject private var auth = Auth()
    var body: some Scene {
        WindowGroup {
            VStack(spacing: 16) {
                if let s = auth.session {
                    Text("Signed in as \(s.user.name ?? s.user.email ?? s.user.sub)")
                    Text("Pairwise sub: \(s.user.sub)").font(.caption).foregroundStyle(.secondary)
                    Button("Call API", action: auth.callAPI)
                    Button("Sign out", role: .destructive, action: auth.signOut)
                } else {
                    SignInWithIdentviaButton(.signIn, theme: .dark, isLoading: auth.busy, action: auth.signIn)
                }
                if let e = auth.error { Text(e).foregroundStyle(.red).font(.footnote) }
            }
            .padding()
            .task { await auth.restore() }
        }
    }
}
