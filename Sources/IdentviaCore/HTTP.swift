import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Sends HTTP requests. Swap it out in tests or to add certificate pinning.
public protocol HTTPTransport: Sendable {
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

public struct URLSessionTransport: HTTPTransport, @unchecked Sendable {
    let session: URLSession
    public init(session: URLSession = .shared) { self.session = session }

    public func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        try await withCheckedThrowingContinuation { cont in
            session.dataTask(with: request) { data, response, error in
                if let error { return cont.resume(throwing: IdentviaError.network(error.localizedDescription)) }
                guard let http = response as? HTTPURLResponse else { return cont.resume(throwing: IdentviaError.network("No HTTP response")) }
                cont.resume(returning: (data ?? Data(), http))
            }.resume()
        }
    }
}
