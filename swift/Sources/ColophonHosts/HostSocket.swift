import Foundation
import os
import ColophonSession

/// What a socket reports. A socket calls these from one serial context, in the order things happened: `open` once,
/// then messages, then one end (`refused` or `closed`), and nothing after `HostSocket.close`.
public struct SocketHandlers: Sendable {
    public let open: @Sendable () -> Void
    /// One text message, exactly as received.
    public let message: @Sendable (String) -> Void
    /// The home refused the upgrade with this HTTP answer (only a runtime that can see the refused answer calls it).
    public let refused: @Sendable (HttpAnswer) -> Void
    /// The socket ended: the close code, or none when the transport failed or the socket never opened.
    public let closed: @Sendable (UInt32?) -> Void
    public init(open: @escaping @Sendable () -> Void, message: @escaping @Sendable (String) -> Void,
                refused: @escaping @Sendable (HttpAnswer) -> Void, closed: @escaping @Sendable (UInt32?) -> Void) {
        self.open = open; self.message = message; self.refused = refused; self.closed = closed
    }
}

/// An open (or opening) socket.
public protocol HostSocket: Sendable {
    func send(_ text: String)
    /// Closes with `code` (the runtime may substitute a code it allows). Reports nothing afterwards.
    func close(code: UInt32)
}

/// Opens a socket at `url` (which carries the ticket: never log it) and reports to `handlers`.
public typealias SocketFactory = @Sendable (_ url: String, _ handlers: SocketHandlers) throws -> any HostSocket

/// The `URLSessionWebSocketTask` behind `SocketFactory`.
///
/// What it reports: `open` from `didOpenWithProtocol`; every text message in order (binary messages are ignored: the
/// home sends only text); the close code from `didCloseWith` (1006, abnormal closure, which is never sent on the wire,
/// is reported as none). A refused upgrade is reported with `refused` and its status and headers: `URLSession` keeps the
/// HTTP response of a failed handshake on the task (`response`), but not its body, so the answer's body is empty (a
/// `403 refused:revoked` therefore reads as an unrecognised refusal, which the core backs off from within its ticket
/// budget; close 1008 still ends a live stream). A transport failure without a response is `closed(nil)`.
///
/// `close(code:)` sends the code given (`URLSessionWebSocketTask.CloseCode` is an open enumeration). Only `wss` is
/// opened, and `ws` to a loopback address when `allowingLoopback` is set (tests).
public struct URLSessionSocketFactory: Sendable {
    public let allowingLoopback: Bool
    public let maximumMessageSize: Int
    public init(allowingLoopback: Bool = false, maximumMessageSize: Int = 1 << 20) {
        self.allowingLoopback = allowingLoopback; self.maximumMessageSize = maximumMessageSize
    }
    public var factory: SocketFactory {
        let allowing = allowingLoopback, size = maximumMessageSize
        return { url, handlers in
            guard let parsed = URL(string: url), let scheme = parsed.scheme?.lowercased() else { throw HostError.insecureSocket }
            let loopback = ["127.0.0.1", "::1", "localhost"].contains(parsed.host ?? "")
            guard scheme == "wss" || (scheme == "ws" && allowing && loopback) else { throw HostError.insecureSocket }
            return URLSessionSocket(url: parsed, handlers: handlers, maximumMessageSize: size)
        }
    }
}

final class URLSessionSocket: NSObject, HostSocket, URLSessionWebSocketDelegate, Sendable {
    private let handlers: SocketHandlers
    /// Whether the socket reported its end or was closed by its owner: nothing is reported after either.
    private let ended = OSAllocatedUnfairLock(initialState: false)
    private let parts = OSAllocatedUnfairLock<(session: URLSession, task: URLSessionWebSocketTask)?>(initialState: nil)

    init(url: URL, handlers: SocketHandlers, maximumMessageSize: Int) {
        self.handlers = handlers
        super.init()
        let queue = OperationQueue()
        queue.maxConcurrentOperationCount = 1
        queue.name = "org.luff.colophon.stream-socket"
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieAcceptPolicy = .never
        configuration.urlCache = nil
        // The session holds its delegate until it is invalidated (at the end, below).
        let session = URLSession(configuration: configuration, delegate: self, delegateQueue: queue)
        let task = session.webSocketTask(with: url)
        task.maximumMessageSize = maximumMessageSize
        parts.withLock { $0 = (session, task) }
        task.resume()
        receive(task)
    }

    private var isEnded: Bool { ended.withLock { $0 } }
    /// Marks the end; true for the first caller only.
    private func end() -> Bool { ended.withLock { e in if e { return false }; e = true; return true } }

    private func receive(_ task: URLSessionWebSocketTask) {
        task.receive { [weak self] result in
            guard let self, !self.isEnded else { return }
            switch result {
            case .success(.string(let text)): self.handlers.message(text); self.receive(task)
            case .success: self.receive(task)
            // The failure is reported by the delegate's close or completion.
            case .failure: break
            }
        }
    }

    func send(_ text: String) {
        guard !isEnded, let task = parts.withLock({ $0?.task }) else { return }
        task.send(.string(text)) { _ in }
    }

    func close(code: UInt32) {
        ended.withLock { $0 = true }
        guard let (session, task) = parts.withLock({ p -> (URLSession, URLSessionWebSocketTask)? in let v = p; p = nil; return v }) else { return }
        let closeCode = URLSessionWebSocketTask.CloseCode(rawValue: Int(code)) ?? .normalClosure
        task.cancel(with: closeCode, reason: nil)
        session.finishTasksAndInvalidate()
    }

    private func finish(_ report: () -> Void) {
        guard end() else { return }
        report()
        if let (session, _) = parts.withLock({ p -> (URLSession, URLSessionWebSocketTask)? in let v = p; p = nil; return v }) {
            session.finishTasksAndInvalidate()
        }
    }

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didOpenWithProtocol protocol: String?) {
        guard !isEnded else { return }
        handlers.open()
    }
    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didCloseWith closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) {
        let code = UInt32(clamping: closeCode.rawValue)
        finish { handlers.closed(code == 1006 || code == 0 ? nil : code) }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: (any Error)?) {
        // A failed handshake leaves the HTTP response on the task: the refused answer, without its body.
        if let response = task.response as? HTTPURLResponse, response.statusCode != 101 {
            let headers = response.allHeaderFields.compactMap { name, value -> Header? in
                guard let name = name as? String else { return nil }
                return Header(name: name.lowercased(), value: String(describing: value))
            }
            let answer = HttpAnswer(status: UInt32(clamping: response.statusCode), headers: Array(headers.prefix(256)), body: Data())
            finish { handlers.refused(answer) }
            return
        }
        let code = (task as? URLSessionWebSocketTask)?.closeCode.rawValue ?? 0
        finish { handlers.closed(code == 0 || code == 1006 ? nil : UInt32(clamping: code)) }
    }
}
