@testable import Citadel
import NIO
import NIOConcurrencyHelpers
import NIOSSH
import XCTest

// MARK: - Remote half-closure of an SFTP channel (Duomote fork)

/// The SFTP pipeline enables remote half-closure (`SSHChannelDataUnwrapper.handlerAdded`), so a
/// server's `SSH_MSG_CHANNEL_EOF` without `SSH_MSG_CHANNEL_CLOSE` leaves the channel ACTIVE. NIOSSH
/// turns that EOF into `ChannelEvent.inputClosed` at the head of the child pipeline
/// (`SSHChildChannel` fires it from the pipeline's head). These rows deliver exactly that event at
/// exactly that place, through the real handlers of a real client, so every handler between the
/// head and `SFTPClientInboundHandler` is the production one.
extension EndToEndTests {

    /// A server delegate whose `realPath` answers only when the test lets it — that is what keeps a
    /// request IN FLIGHT at the moment the EOF arrives.
    final class GatedSFTP: SFTPDelegate, @unchecked /* for testing */ Sendable {
        let gate = NIOLockedValueBox<CheckedContinuation<Void, Never>?>(nil)
        let parked = NIOLockedValueBox<Bool>(false)
        let blockNext = NIOLockedValueBox<Bool>(false)

        func realPath(for canonicalUrl: String, context: SSHContext) async throws -> [SFTPPathComponent] {
            if blockNext.withLockedValue({ $0 }) {
                await withCheckedContinuation { continuation in
                    gate.withLockedValue { $0 = continuation }
                    parked.withLockedValue { $0 = true }
                }
            }
            return [SFTPPathComponent(filename: canonicalUrl, longname: canonicalUrl, attributes: .none)]
        }

        func release() {
            gate.withLockedValue { $0?.resume(); $0 = nil }
        }
    }

    func testRemoteHalfClosureFailsTheRequestInFlightAndEveryLaterOneWhileTheChannelStaysActive() async throws {
        try await runTest(
            perform: { server, client in
                let delegate = GatedSFTP()
                server.enableSFTP(withDelegate: delegate)
                let sftp = try await client.openSFTP()

                // Positive control: a healthy client answers, and reports no half-closure.
                _ = try await sftp.getRealPath(atPath: "/healthy")
                XCTAssertTrue(sftp.isActive)
                XCTAssertFalse(sftp.isRemoteHalfClosed, "a healthy client must not report a half-closure")

                // One request held by the server, so it is in flight when the EOF arrives.
                delegate.blockNext.withLockedValue { $0 = true }
                let inFlight = Task { try await sftp.getRealPath(atPath: "/held") }
                for _ in 0..<500 where !delegate.parked.withLockedValue({ $0 }) {
                    try await Task.sleep(for: .milliseconds(10))
                }
                XCTAssertTrue(delegate.parked.withLockedValue { $0 }, "the server never received the held request")

                // The server's EOF, at the place NIOSSH delivers it.
                try await sftp.channel.eventLoop.submit {
                    sftp.channel.pipeline.fireUserInboundEventTriggered(ChannelEvent.inputClosed)
                }.get()

                // The request in flight fails (it would otherwise wait for ever — the server holds
                // it). The 10 s budget is a WATCHDOG against "never fails", not a timing bound: on
                // expiry the server is released so the row ends red instead of hanging the suite.
                let outcome = await Self.firstOutcome(of: inFlight, watchdog: .seconds(10))
                switch outcome {
                case .failed(SFTPError.connectionClosed):
                    break
                case .failed(let error):
                    XCTFail("the request in flight failed with \(error), not SFTPError.connectionClosed")
                case .answered:
                    XCTFail("the request in flight was answered although the server never replied")
                case .stillWaiting:
                    XCTFail("the request in flight is still waiting after the server's EOF — the half-closure was not reported")
                    // After the EOF the decoder drops every later byte, so releasing the server
                    // would not answer it either; only the channel's close fails it.
                    try? await sftp.close()
                }

                // The channel is still active — that is exactly why `isActive` alone cannot tell.
                XCTAssertTrue(sftp.isActive, "half-closure must not close the channel; the server still owns it")
                XCTAssertTrue(sftp.isRemoteHalfClosed, "the half-closure was not reported")

                // A new request is refused at once instead of being sent into a channel nobody answers.
                delegate.blockNext.withLockedValue { $0 = false }
                let after = Task { try await sftp.getRealPath(atPath: "/after") }
                switch await Self.firstOutcome(of: after, watchdog: .seconds(10)) {
                case .failed(SFTPError.connectionClosed):
                    break
                case .failed(let error):
                    XCTFail("a request after the server's EOF failed with \(error), not SFTPError.connectionClosed")
                case .answered:
                    XCTFail("a request after the server's EOF was answered")
                case .stillWaiting:
                    XCTFail("a request after the server's EOF was sent and waits for an answer that cannot come")
                }

                delegate.release()
                try? await sftp.close()
            },
            matchingError: { _ in false },
            expectsFailure: false
        )
    }

    enum InFlightOutcome: @unchecked Sendable { case answered, failed(Error), stillWaiting }

    /// The request's outcome, or `.stillWaiting` once `watchdog` elapsed — whichever comes FIRST.
    ///
    /// Deliberately NOT a task group: a group waits for every child before it returns, and awaiting a
    /// `Task`'s result does not react to cancellation, so a request that never completes would hang
    /// the group — the very failure this helper exists to report. Two unstructured tasks race to
    /// resume one continuation instead; the loser's resume is dropped.
    static func firstOutcome(of request: Task<String, Error>, watchdog: Duration) async -> InFlightOutcome {
        let resumed = NIOLockedValueBox(false)
        return await withCheckedContinuation { (continuation: CheckedContinuation<InFlightOutcome, Never>) in
            @Sendable func finish(_ outcome: InFlightOutcome) {
                let first = resumed.withLockedValue { done -> Bool in
                    defer { done = true }
                    return !done
                }
                if first { continuation.resume(returning: outcome) }
            }
            Task {
                switch await request.result {
                case .success: finish(.answered)
                case .failure(let error): finish(.failed(error))
                }
            }
            Task {
                try? await Task.sleep(for: watchdog)
                finish(.stillWaiting)
            }
        }
    }

    /// The other direction: an unrelated user event is NOT a half-closure.
    func testAnotherInboundEventDoesNotMarkTheClientHalfClosed() async throws {
        try await runTest(
            perform: { server, client in
                server.enableSFTP(withDelegate: GatedSFTP())
                let sftp = try await client.openSFTP()
                try await sftp.channel.eventLoop.submit {
                    sftp.channel.pipeline.fireUserInboundEventTriggered(ChannelEvent.outputClosed)
                }.get()
                XCTAssertFalse(sftp.isRemoteHalfClosed, "outputClosed was mistaken for the server's EOF")
                _ = try await sftp.getRealPath(atPath: "/still-fine")
                try await sftp.close()
            },
            matchingError: { _ in false },
            expectsFailure: false
        )
    }
}
