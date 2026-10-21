import XCTest
import Foundation
@testable import IdentviaCore

/// Against a REAL Identvia (stage 4+): IDENTVIA_LIVE_STATE=/tmp/live-state.json swift test --filter LiveTests
/// The state file comes from tools/live/helper.php in the identvia-sdks checkout.
final class LiveTests: XCTestCase {
    struct HelperPresenter: AuthSessionPresenter {
        let state: String
        func authenticate(url: URL, redirectURI: URL, ephemeral: Bool) async throws -> URL {
            if url.path.hasSuffix("/oauth/logout") { return redirectURI }
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            p.arguments = ["php", URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../../tools/live/helper.php").path, "browse", state, url.absoluteString]
            let out = Pipe(); p.standardOutput = out
            try p.run(); p.waitUntilExit()
            let s = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            guard p.terminationStatus == 0, let u = URL(string: s) else { throw IdentviaError.network("helper failed") }
            return u
        }
    }

    func testSignInRefreshUserinfoSignOut() async throws {
        guard let path = ProcessInfo.processInfo.environment["IDENTVIA_LIVE_STATE"] else { throw XCTSkip("set IDENTVIA_LIVE_STATE") }
        let s = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: path))) as! [String: Any]
        let store = InMemoryTokenStore()
        let c = try IdentviaClient(issuer: s["base"] as! String, clientId: s["publicClientId"] as! String, redirectURI: s["publicRedirect"] as! String,
                                   presenter: HelperPresenter(state: path), store: store, refreshLeeway: 3600)
        let session = try await c.signIn()
        XCTAssertEqual(session.user.email, s["userEmail"] as? String)
        let rt1 = await store.values.first { $0.key.hasSuffix(".rt") }?.value
        _ = try await c.accessToken()
        let rt2 = await store.values.first { $0.key.hasSuffix(".rt") }?.value
        XCTAssertNotNil(rt2); XCTAssertNotEqual(rt1, rt2)
        let info = try await c.userinfo()
        XCTAssertEqual(info["sub"]?.stringValue, session.user.sub)
        try await c.signOut()
        let v = await store.values; XCTAssertTrue(v.isEmpty)
    }
}
