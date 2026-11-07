@testable import Citadel
import NIO
import NIOConcurrencyHelpers
@preconcurrency import NIOSSH
import XCTest
import Foundation

@available(macOS 15.0, *)
final class WithExecTests: XCTestCase {

    // MARK: - Helpers

    private struct TestTimeout: Error {}

    private func runTest(
        timeout: Duration = .seconds(5),
        perform: @escaping (SSHServer, SSHClient) async throws -> Void
    ) async throws {
        let authDelegate = AuthDelegate(supportedAuthenticationMethods: .password) { request, promise in
            switch request.request {
            case .password(.init(password: "test")) where request.username == "citadel":
                promise.succeed(.success)
            default:
                promise.succeed(.failure)
            }
        }
        let server = try await SSHServer.host(
            host: "localhost",
            port: 0,
            hostKeys: [NIOSSHPrivateKey(p521Key: .init())],
            authenticationDelegate: authDelegate
        )

        let port = try XCTUnwrap(server.channel.localAddress?.port)

        let client = try await SSHClient.connect(
            host: "localhost",
            port: port,
            authenticationMethod: .passwordBased(username: "citadel", password: "test"),
            hostKeyValidator: .acceptAnything(),
            reconnect: .never
        )

        defer {
            Task { try? await server.close() }
        }

        do {
            try await withThrowingTaskGroup(of: Void.self) { group in
                group.addTask {
                    try await perform(server, client)
                }
                group.addTask {
                    try await Task.sleep(for: timeout)
                    throw TestTimeout()
                }
                // First to finish wins; cancel the other
                try await group.next()
                group.cancelAll()
            }
        } catch is TestTimeout {
            XCTFail("Test timed out after \(timeout)")
        } catch let error as ChannelError where error == .alreadyClosed {
            // Server-initiated channel close can race with client close in withExec
        }

        do {
            try await client.close()
        } catch let error as ChannelError where error == .alreadyClosed {
            // Already cleaned up
        }
    }

    // MARK: - Dropping an executeCommandStream closes its channel (Duomote fork)

    /// A recorded server-side command that runs until the channel goes away.
    ///
    /// `ExecHandler.channelInactive` calls ``ExecCommandContext/terminate()``, so `didTerminate`
    /// is a direct reading of "the client closed the exec channel" — the protocol event, not a
    /// proxy for it.
    private final class NeverEndingExec: ExecDelegate, @unchecked Sendable {
        final class Ctx: ExecCommandContext {
            let onTerminate: @Sendable () -> Void
            init(onTerminate: @escaping @Sendable () -> Void) { self.onTerminate = onTerminate }
            func terminate() async throws { onTerminate() }
        }

        // `NIOLockedValueBox`, not `NSLock`: `start` is async and `terminate` runs on the
        // server's event loop, and NSLock's `lock()` is unavailable from an async context
        // (an error in Swift 6 mode).
        private let _didTerminate = NIOLockedValueBox<Bool>(false)
        private let _didStart = NIOLockedValueBox<Bool>(false)

        var didTerminate: Bool { _didTerminate.withLockedValue { $0 } }
        var didStart: Bool { _didStart.withLockedValue { $0 } }

        func setEnvironmentValue(_ value: String, forKey key: String) async throws {}

        func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
            _didStart.withLockedValue { $0 = true }
            // Nothing is written and `succeed` is never called: the command is still running, the
            // way `sleep 60` is. Only a channel close can end it.
            let flag = _didTerminate
            return Ctx { flag.withLockedValue { $0 = true } }
        }
    }

    /// Dropping the stream from ``SSHClient/executeCommandStream(_:environment:inShell:)`` must
    /// end the command's server-side context.
    ///
    /// **"Ends the command" is true of THIS server and must not be read as true of every one.**
    /// `ExecHandler.channelInactive` calls ``ExecCommandContext/terminate()``, so against
    /// Citadel's own server the channel close alone is enough. Against OpenSSH it is NOT:
    /// measured on loopback against OpenSSH 10.3p1, a cancelled `sleep 300` was still alive 30 s
    /// after the close, which is why the cancellation path also sends a `signal` request — see
    /// the row below. This row owns the channel-close half; that one owns the signal.
    ///
    /// Upstream built that stream with `makeStream()` and registered no `onTermination`, and the
    /// public entry point keeps only `.output` — it discards the `Channel` that
    /// `_executeCommandStream` hands back. So a consumer that walked away, or whose task was
    /// cancelled, sent NOTHING: the remote command ran to its own end while the caller believed
    /// it had given the channel back. A caller that budgets its concurrent channels then
    /// understates what is open on the host by one per abandoned exec.
    func testDroppingTheCommandStreamTerminatesTheServerSideCommandContext() async throws {
        try await runTest(timeout: .seconds(20)) { server, client in
            let exec = NeverEndingExec()
            server.enableExec(withDelegate: exec)

            // Scoped so the stream is released at the end of the block — this IS the "consumer
            // walks away" case, with no cancellation involved.
            do {
                let stream = try await client.executeCommandStream("sleep-forever")
                var iterator = stream.makeAsyncIterator()

                // Wait for the STATE "the server started the command". Until then there is nothing
                // to terminate and the row would pass without measuring anything.
                var started = false
                for _ in 0..<2_000 where !started {
                    if exec.didStart { started = true; break }
                    try await Task.sleep(for: .milliseconds(10))
                }
                XCTAssertTrue(started, "the server never started the command — nothing was measured")
                XCTAssertFalse(exec.didTerminate,
                               "the command was terminated before this row dropped the stream, so "
                               + "a later termination would prove nothing")
                _ = iterator  // keeps the iterator alive until the scope ends
            }

            var terminated = false
            for _ in 0..<2_000 where !terminated {
                if exec.didTerminate { terminated = true; break }
                try await Task.sleep(for: .milliseconds(10))
            }
            XCTAssertTrue(terminated,
                          "the exec channel was never closed, so the command is still running on "
                          + "the host although its stream is gone")
        }
    }

    /// The shape that actually bites — a CANCELLED consumer.
    ///
    /// **What this row fences is the channel close, NOT the signal, and that limit is stated
    /// rather than implied.** `ExecHandler` does not act on `SignalRequest` — its
    /// `userInboundEventTriggered` has no arm for it and the `default` arm only forwards the
    /// event — so this server cannot observe the signal at all, and nothing here inserts a
    /// handler that could. What it asserts is that the cancellation reaches
    /// ``ExecCommandContext/terminate()``, which `ExecHandler.channelInactive` calls, i.e. that
    /// the channel was really closed. Red (by timeout) without the change.
    ///
    /// That `ExecHandler` ignores the request is also why sending it is safe: an unhandled channel
    /// request whose `wantReply` is `false` costs the server nothing.
    ///
    /// **The signal itself is only observable against a real `sshd`**, and the consumer's own live
    /// suite is where it is fenced — against OpenSSH 10.3p1 the close alone left a cancelled
    /// `sleep 300` alive for 30 s, and with the signal the command and the child of its `sh -c`
    /// wrapper were gone on the first poll.
    func testCancellingTheConsumerSignalsTheRemoteProcessAndThenClosesTheChannel() async throws {
        try await runTest(timeout: .seconds(20)) { server, client in
            let exec = NeverEndingExec()
            server.enableExec(withDelegate: exec)

            let consumer = Task {
                let stream = try await client.executeCommandStream("sleep-forever")
                for try await _ in stream {}
            }

            var started = false
            for _ in 0..<2_000 where !started {
                if exec.didStart { started = true; break }
                try await Task.sleep(for: .milliseconds(10))
            }
            XCTAssertTrue(started, "the server never started the command — nothing was measured")
            XCTAssertFalse(exec.didTerminate, "terminated before the cancellation")

            consumer.cancel()
            _ = try? await consumer.value

            var terminated = false
            for _ in 0..<2_000 where !terminated {
                if exec.didTerminate { terminated = true; break }
                try await Task.sleep(for: .milliseconds(10))
            }
            XCTAssertTrue(terminated,
                          "a cancelled consumer left the command running on the host: the slot its "
                          + "caller gave back no longer describes the host")
        }
    }

    // MARK: - Tests

    /// Server writes known data to stdout; client receives it tagged as `.stdout`.
    func testWithExecReceivesStdout() async throws {
        final class Exec: ExecDelegate, @unchecked Sendable {
            struct Ctx: ExecCommandContext {
                func terminate() async throws {}
            }
            func setEnvironmentValue(_ value: String, forKey key: String) async throws {}
            func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
                DispatchQueue.global().async {
                    let handle = outputHandler.stdoutPipe.fileHandleForWriting
                    handle.write(Data("hello stdout".utf8))
                    try? handle.close()
                    // Let NIO drain the pipe before succeed triggers pipeChannel.close
                    Thread.sleep(forTimeInterval: 0.3)
                    outputHandler.succeed(exitCode: 0)
                }
                return Ctx()
            }
        }

        try await runTest { server, client in
            let execDelegate = Exec()
            server.enableExec(withDelegate: execDelegate)

            try await client.withExec("test") { inbound, _ in
                var collected = ByteBuffer()
                for try await chunk in inbound {
                    switch chunk {
                    case .stdout(let buf):
                        collected.writeImmutableBuffer(buf)
                    case .stderr:
                        XCTFail("Expected only stdout data")
                    }
                }
                XCTAssertEqual(String(buffer: collected), "hello stdout")
            }
        }
    }

    /// Client writes data via outbound and server writes back a response on stdout.
    /// Verifies both directions of the exec channel work in a single session.
    func testWithExecBidirectionalIO() async throws {
        final class Exec: ExecDelegate, @unchecked Sendable {
            struct Ctx: ExecCommandContext {
                func terminate() async throws {}
            }
            var receivedCommand: String?
            func setEnvironmentValue(_ value: String, forKey key: String) async throws {}
            func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
                receivedCommand = command
                DispatchQueue.global().async {
                    // Write a response on stdout (independent of stdin)
                    let output = outputHandler.stdoutPipe.fileHandleForWriting
                    output.write(Data("response from server".utf8))
                    try? output.close()
                    // Let NIO drain the pipe before succeed triggers pipeChannel.close
                    Thread.sleep(forTimeInterval: 0.3)
                    outputHandler.succeed(exitCode: 0)
                }
                return Ctx()
            }
        }

        try await runTest { server, client in
            let execDelegate = Exec()
            server.enableExec(withDelegate: execDelegate)

            try await client.withExec("my-command") { inbound, outbound in
                // Client writes to stdin (verifies write doesn't crash)
                try await outbound.write(ByteBuffer(string: "request from client"))

                // Client reads stdout response
                var collected = ByteBuffer()
                for try await chunk in inbound {
                    if case .stdout(let buf) = chunk {
                        collected.writeImmutableBuffer(buf)
                    }
                }
                XCTAssertEqual(String(buffer: collected), "response from server")
            }

            // Verify the command was forwarded correctly
            XCTAssertEqual(execDelegate.receivedCommand, "my-command")
        }
    }

    /// Binary data (all 256 byte values) is sent from server to client without mangling.
    func testWithExecBinaryData() async throws {
        let binaryPayload = Data(0...255)

        final class BinaryExec: ExecDelegate, @unchecked Sendable {
            let payload: Data
            struct Ctx: ExecCommandContext {
                func terminate() async throws {}
            }
            init(payload: Data) { self.payload = payload }
            func setEnvironmentValue(_ value: String, forKey key: String) async throws {}
            func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
                let payload = self.payload
                DispatchQueue.global().async {
                    let output = outputHandler.stdoutPipe.fileHandleForWriting
                    output.write(payload)
                    try? output.close()
                    // Let NIO drain the pipe before succeed triggers pipeChannel.close
                    Thread.sleep(forTimeInterval: 0.3)
                    outputHandler.succeed(exitCode: 0)
                }
                return Ctx()
            }
        }

        try await runTest { server, client in
            let execDelegate = BinaryExec(payload: binaryPayload)
            server.enableExec(withDelegate: execDelegate)

            try await client.withExec("cat") { inbound, _ in
                var collected = ByteBuffer()
                for try await chunk in inbound {
                    if case .stdout(let buf) = chunk {
                        collected.writeImmutableBuffer(buf)
                    }
                }
                XCTAssertEqual(collected.readableBytes, 256)
                XCTAssertEqual(collected.readBytes(length: 256), Array(binaryPayload))
            }
        }
    }

    /// Server writes to stderr pipe; client receives data tagged as `.stderr`.
    func testWithExecReceivesStderr() async throws {
        final class Exec: ExecDelegate, @unchecked Sendable {
            struct Ctx: ExecCommandContext {
                func terminate() async throws {}
            }
            func setEnvironmentValue(_ value: String, forKey key: String) async throws {}
            func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
                DispatchQueue.global().async {
                    let handle = outputHandler.stderrPipe.fileHandleForWriting
                    handle.write(Data("error output".utf8))
                    try? handle.close()
                    try? outputHandler.stdoutPipe.fileHandleForWriting.close()
                    // Let the readabilityHandler fire and flush before closing
                    Thread.sleep(forTimeInterval: 0.3)
                    outputHandler.succeed(exitCode: 0)
                }
                return Ctx()
            }
        }

        try await runTest { server, client in
            let execDelegate = Exec()
            server.enableExec(withDelegate: execDelegate)

            try await client.withExec("test") { inbound, _ in
                var collected = ByteBuffer()
                for try await chunk in inbound {
                    switch chunk {
                    case .stderr(let buf):
                        collected.writeImmutableBuffer(buf)
                    case .stdout:
                        break
                    }
                }
                XCTAssertEqual(String(buffer: collected), "error output")
            }
        }
    }

    /// When the `perform` closure throws, the error propagates and the channel closes.
    func testWithExecClosesChannelOnError() async throws {
        struct TestError: Error, Equatable {}

        final class Exec: ExecDelegate, @unchecked Sendable {
            struct Ctx: ExecCommandContext {
                func terminate() async throws {}
            }
            func setEnvironmentValue(_ value: String, forKey key: String) async throws {}
            func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
                DispatchQueue.global().async {
                    try? outputHandler.stdoutPipe.fileHandleForWriting.close()
                    outputHandler.succeed(exitCode: 0)
                }
                return Ctx()
            }
        }

        try await runTest { server, client in
            let execDelegate = Exec()
            server.enableExec(withDelegate: execDelegate)

            do {
                try await client.withExec("test") { _, _ in
                    throw TestError()
                }
                XCTFail("Expected error to propagate")
            } catch is TestError {
                // Expected
            }
        }
    }

    // MARK: - ExecHandler infrastructure tests
    // These use public APIs other than withExec to show the fixes are
    // necessary at the server handler level, not specific to one client API.

    /// Stderr-only output is delivered via executeCommand.
    /// Exercises the writeAndFlush fix: without it, stderr data sits in the
    /// channel's write buffer and never reaches the client because nothing
    /// triggers a flush.
    func testExecuteCommandReceivesStderrOnly() async throws {
        final class StderrOnly: ExecDelegate, @unchecked Sendable {
            struct Ctx: ExecCommandContext {
                func terminate() async throws {}
            }
            func setEnvironmentValue(_ value: String, forKey key: String) async throws {}
            func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
                DispatchQueue.global().async {
                    let handle = outputHandler.stderrPipe.fileHandleForWriting
                    handle.write(Data("only on stderr".utf8))
                    try? handle.close()
                    // No stdout at all — close it immediately
                    try? outputHandler.stdoutPipe.fileHandleForWriting.close()
                    Thread.sleep(forTimeInterval: 0.3)
                    outputHandler.succeed(exitCode: 0)
                }
                return Ctx()
            }
        }

        try await runTest { server, client in
            let execDelegate = StderrOnly()
            server.enableExec(withDelegate: execDelegate)

            let result = try await client.executeCommand("test", mergeStreams: true)
            XCTAssertEqual(String(buffer: result), "only on stderr")
        }
    }

    /// Stderr arrives on the dedicated stderr stream of executeCommandPair.
    /// Same underlying fix: without writeAndFlush the data never flushes.
    func testExecuteCommandPairReceivesStderr() async throws {
        final class StderrExec: ExecDelegate, @unchecked Sendable {
            struct Ctx: ExecCommandContext {
                func terminate() async throws {}
            }
            func setEnvironmentValue(_ value: String, forKey key: String) async throws {}
            func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
                DispatchQueue.global().async {
                    outputHandler.stderrPipe.fileHandleForWriting.write(Data("err".utf8))
                    try? outputHandler.stderrPipe.fileHandleForWriting.close()
                    outputHandler.stdoutPipe.fileHandleForWriting.write(Data("out".utf8))
                    try? outputHandler.stdoutPipe.fileHandleForWriting.close()
                    Thread.sleep(forTimeInterval: 0.3)
                    outputHandler.succeed(exitCode: 0)
                }
                return Ctx()
            }
        }

        try await runTest { server, client in
            let execDelegate = StderrExec()
            server.enableExec(withDelegate: execDelegate)

            let streams = try await client.executeCommandPair("test")

            var stdoutBuf = ByteBuffer()
            for try await chunk in streams.stdout {
                stdoutBuf.writeImmutableBuffer(chunk)
            }

            var stderrBuf = ByteBuffer()
            for try await chunk in streams.stderr {
                stderrBuf.writeImmutableBuffer(chunk)
            }

            XCTAssertEqual(String(buffer: stdoutBuf), "out")
            XCTAssertEqual(String(buffer: stderrBuf), "err")
        }
    }

    /// Stdin data written to the exec channel reaches the server process's pipe.
    /// Exercises the SSHOutboundChannelDataUnwrapper fix in ExecHandler:
    /// without it, SSHChannelData from the SSH channel can't be written to
    /// the pipe channel (which expects ByteBuffer), so stdin never arrives.
    func testExecStdinReachesServer() async throws {
        final class StdinCapture: ExecDelegate, @unchecked Sendable {
            private let lock = NSLock()
            private var _stdinReceived: Data?
            var stdinReceived: Data? { lock.withLock { _stdinReceived } }
            struct Ctx: ExecCommandContext {
                func terminate() async throws {}
            }
            func setEnvironmentValue(_ value: String, forKey key: String) async throws {}
            func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
                let input = outputHandler.stdinPipe.fileHandleForReading
                input.readabilityHandler = { [weak self] handle in
                    let data = handle.availableData
                    if !data.isEmpty {
                        self?.lock.withLock { self?._stdinReceived = data }
                    }
                    handle.readabilityHandler = nil
                }
                DispatchQueue.global().async {
                    let output = outputHandler.stdoutPipe.fileHandleForWriting
                    output.write(Data("ack".utf8))
                    try? output.close()
                    Thread.sleep(forTimeInterval: 0.3)
                    outputHandler.succeed(exitCode: 0)
                }
                return Ctx()
            }
        }

        try await runTest { server, client in
            let execDelegate = StdinCapture()
            server.enableExec(withDelegate: execDelegate)

            try await client.withExec("echo") { inbound, outbound in
                try await outbound.write(ByteBuffer(string: "hello from stdin"))
                for try await _ in inbound {}
            }

            XCTAssertEqual(
                execDelegate.stdinReceived.flatMap { String(data: $0, encoding: .utf8) },
                "hello from stdin"
            )
        }
    }

    // MARK: - withExec-specific tests

    /// Environment variables are forwarded to the server delegate.
    func testWithExecEnvironmentVariables() async throws {
        final class Exec: ExecDelegate, @unchecked Sendable {
            struct Ctx: ExecCommandContext {
                func terminate() async throws {}
            }
            var receivedEnv: [String: String] = [:]
            func setEnvironmentValue(_ value: String, forKey key: String) async throws {
                receivedEnv[key] = value
            }
            func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
                DispatchQueue.global().async {
                    try? outputHandler.stdoutPipe.fileHandleForWriting.close()
                    outputHandler.succeed(exitCode: 0)
                }
                return Ctx()
            }
        }

        try await runTest { server, client in
            let execDelegate = Exec()
            server.enableExec(withDelegate: execDelegate)

            try await client.withExec(
                "test",
                environment: [
                    .init(wantReply: true, name: "FOO", value: "bar"),
                    .init(wantReply: true, name: "BAZ", value: "qux"),
                ]
            ) { inbound, _ in
                for try await _ in inbound {}
            }

            XCTAssertEqual(execDelegate.receivedEnv["FOO"], "bar")
            XCTAssertEqual(execDelegate.receivedEnv["BAZ"], "qux")
        }
    }

    /// `withPTYExec` sends `EnvironmentRequest`, `PseudoTerminalRequest`, and `ExecRequest` in order
    /// (never `ShellRequest`), forwards `WindowChangeRequest`, delivers stdout, and returns cleanly
    /// without throwing `ChannelError.alreadyClosed` when the remote command exits first.
    func testWithPTYExecExecutesCommandOnPTYChannelWithoutInvokingInteractiveShell() async throws {
        struct UncheckedOutputBox: @unchecked Sendable {
            let handler: ExecOutputHandler
        }

        final class ExecSpy: ExecDelegate, @unchecked Sendable {
            struct Ctx: ExecCommandContext {
                func terminate() async throws {}
            }
            let receivedCommand = NIOLockedValueBox<String?>(nil)
            let receivedEnv = NIOLockedValueBox<[String: String]>([:])

            func setEnvironmentValue(_ value: String, forKey key: String) async throws {
                receivedEnv.withLockedValue { $0[key] = value }
            }

            func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
                receivedCommand.withLockedValue { $0 = command }
                let box = UncheckedOutputBox(handler: outputHandler)
                DispatchQueue.global().async {
                    let output = box.handler.stdoutPipe.fileHandleForWriting
                    output.write(Data("pty-exec-ok".utf8))
                    try? output.close()
                    Thread.sleep(forTimeInterval: 0.3)
                    box.handler.succeed(exitCode: 0)
                }
                return Ctx()
            }
        }

        final class ForbiddenShellSpy: ShellDelegate, @unchecked Sendable {
            let wasInvoked = NIOLockedValueBox<Bool>(false)
            func startShell(
                inbound: AsyncStream<ShellClientEvent>,
                outbound: ShellOutboundWriter,
                context: SSHShellContext
            ) async throws {
                wasInvoked.withLockedValue { $0 = true }
            }
        }

        try await runTest { server, client in
            let execSpy = ExecSpy()
            let shellSpy = ForbiddenShellSpy()
            server.enableExec(withDelegate: execSpy)
            server.enableShell(withDelegate: shellSpy)

            let ptyRequest = SSHChannelRequestEvent.PseudoTerminalRequest(
                wantReply: true,
                term: "xterm-256color",
                terminalCharacterWidth: 80,
                terminalRowHeight: 24,
                terminalPixelWidth: 0,
                terminalPixelHeight: 0,
                terminalModes: .init([:])
            )
            let expectedCommand = "/bin/sh -c 'tmux attach -t =work'"
            let capturedHandler = NIOLockedValueBox<ExecCommandHandler?>(nil)
            let didReturnCleanly = NIOLockedValueBox<Bool>(false)

            do {
                try await client.withPTYExec(
                    ptyRequest,
                    command: expectedCommand,
                    environment: [.init(wantReply: true, name: "LC_CTYPE", value: "UTF-8")]
                ) { inbound, outbound in
                    let handler = try await outbound.channel.pipeline.handler(type: ExecCommandHandler.self).get()
                    capturedHandler.withLockedValue { $0 = handler }
                    try await outbound.changeSize(cols: 100, rows: 32, pixelWidth: 640, pixelHeight: 384)

                    var collected = ByteBuffer()
                    for try await chunk in inbound {
                        if case .stdout(let buf) = chunk {
                            collected.writeImmutableBuffer(buf)
                        }
                    }
                    XCTAssertEqual(String(buffer: collected), "pty-exec-ok")
                    XCTAssertEqual(
                        handler.recordedOutboundRequests.withLockedValue { $0 },
                        [
                            .environment(name: "LC_CTYPE", value: "UTF-8"),
                            .pty(term: "xterm-256color", cols: 80, rows: 24),
                            .exec(command: expectedCommand, wantReply: true),
                            .windowChange(cols: 100, rows: 32, pixelWidth: 640, pixelHeight: 384),
                        ]
                    )
                    XCTAssertEqual(execSpy.receivedCommand.withLockedValue { $0 }, expectedCommand)
                    XCTAssertFalse(
                        shellSpy.wasInvoked.withLockedValue { $0 },
                        "withPTYExec must send ExecRequest, never ShellRequest"
                    )
                }
                didReturnCleanly.withLockedValue { $0 = true }
            } catch {
                XCTFail("withPTYExec must return cleanly after normal server-side exit, but threw: \(error)")
            }

            XCTAssertTrue(
                didReturnCleanly.withLockedValue { $0 },
                "withPTYExec must complete normally without throwing ChannelError.alreadyClosed"
            )
            let recorded = capturedHandler.withLockedValue { $0 }?.recordedOutboundRequests.withLockedValue { $0 }
            XCTAssertEqual(
                recorded,
                [
                    .environment(name: "LC_CTYPE", value: "UTF-8"),
                    .pty(term: "xterm-256color", cols: 80, rows: 24),
                    .exec(command: expectedCommand, wantReply: true),
                    .windowChange(cols: 100, rows: 32, pixelWidth: 640, pixelHeight: 384),
                ]
            )
            XCTAssertEqual(execSpy.receivedCommand.withLockedValue { $0 }, expectedCommand)
            XCTAssertEqual(execSpy.receivedEnv.withLockedValue { $0["LC_CTYPE"] }, "UTF-8")
            XCTAssertFalse(
                shellSpy.wasInvoked.withLockedValue { $0 },
                "withPTYExec must send ExecRequest, never ShellRequest"
            )
        }
    }

    /// When the remote command exits with a non-zero status and the server closes the channel,
    /// `withPTYExec` propagates `SSHClient.CommandFailed(exitCode:)` rather than masking it with
    /// `ChannelError.alreadyClosed`.
    func testWithPTYExecPropagatesNonZeroExitCodeWithoutMaskingAsAlreadyClosed() async throws {
        struct UncheckedOutputBox: @unchecked Sendable {
            let handler: ExecOutputHandler
        }

        final class FailingExecSpy: ExecDelegate, @unchecked Sendable {
            struct Ctx: ExecCommandContext {
                func terminate() async throws {}
            }
            func setEnvironmentValue(_ value: String, forKey key: String) async throws {}
            func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
                let box = UncheckedOutputBox(handler: outputHandler)
                DispatchQueue.global().async {
                    try? box.handler.stdoutPipe.fileHandleForWriting.close()
                    Thread.sleep(forTimeInterval: 0.1)
                    box.handler.succeed(exitCode: 7)
                }
                return Ctx()
            }
        }

        try await runTest { server, client in
            server.enableExec(withDelegate: FailingExecSpy())

            let ptyRequest = SSHChannelRequestEvent.PseudoTerminalRequest(
                wantReply: true,
                term: "xterm-256color",
                terminalCharacterWidth: 80,
                terminalRowHeight: 24,
                terminalPixelWidth: 0,
                terminalPixelHeight: 0,
                terminalModes: .init([:])
            )

            var caughtError: Error?
            do {
                try await client.withPTYExec(ptyRequest, command: "exit 7") { inbound, _ in
                    for try await _ in inbound {}
                }
            } catch {
                caughtError = error
            }

            guard let commandFailed = caughtError as? SSHClient.CommandFailed else {
                XCTFail("Expected SSHClient.CommandFailed(exitCode: 7), got: \(String(describing: caughtError))")
                return
            }
            XCTAssertEqual(commandFailed.exitCode, 7)
        }
    }
}
