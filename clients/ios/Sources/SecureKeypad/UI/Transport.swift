import Foundation

/// How the SDK talks to the integrator's endpoints. Replace to add authentication headers, pinning,
/// or a different HTTP stack. Bodies are already end-to-end encrypted; the transport only moves bytes.
public protocol SecureKeypadTransport {
    /// POSTs a JSON body and returns the response body. Must throw on non-2xx statuses.
    func post(url: URL, body: Data) async throws -> Data
}

/// Default `URLSession` transport (`application/json`, no caching, 15 s timeout).
public struct URLSessionTransport: SecureKeypadTransport {
    public var session: URLSession
    public var headers: [String: String]

    public init(session: URLSession = .shared, headers: [String: String] = [:]) {
        self.session = session
        self.headers = headers
    }

    public func post(url: URL, body: Data) async throws -> Data {
        var req = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 15)
        req.httpMethod = "POST"
        req.httpBody = body
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        return try await withCheckedThrowingContinuation { cont in
            let task = session.dataTask(with: req) { data, response, error in
                if let error = error {
                    cont.resume(throwing: SecureKeypadError.transport(error.localizedDescription))
                    return
                }
                if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
                    cont.resume(throwing: SecureKeypadError.httpStatus(http.statusCode))
                    return
                }
                cont.resume(returning: data ?? Data())
            }
            task.resume()
        }
    }
}
