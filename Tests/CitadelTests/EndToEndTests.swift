@testable import Citadel
import Crypto
import NIO
import NIOSSH
import XCTest

final class AuthDelegate: NIOSSHServerUserAuthenticationDelegate {
    var supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods
    var handle: @Sendable (NIOSSHUserAuthenticationRequest, EventLoopPromise<NIOSSHUserAuthenticationOutcome>) -> Void

    init(
        supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods,
        handle: @Sendable @escaping (NIOSSHUserAuthenticationRequest, EventLoopPromise<NIOSSHUserAuthenticationOutcome>) -> Void
    ) {
        self.supportedAuthenticationMethods = supportedAuthenticationMethods
        self.handle = handle
    }

    func requestReceived(request: NIOSSHUserAuthenticationRequest, responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>) {
        handle(request, responsePromise)
    }
}

final class EndToEndTests: XCTestCase {
    func runTest<ExpectedError: Error & Equatable>(
        credentials: SSHAuthenticationMethod,
        hostKeyValidator: SSHHostKeyValidator,
        expectedError: ExpectedError
    ) async throws {
        try await runTest(
            credentials: credentials,
            hostKeyValidator: hostKeyValidator,
            perform: { _, _ in
                XCTFail("Should never get here")
            },
            matchingError: { error in
                guard let error = error as? ExpectedError else {
                    return false
                }

                return error == expectedError
            },
            expectsFailure: true
        )
    }

    func runTest(
        credentials: SSHAuthenticationMethod = .passwordBased(username: "citadel", password: "test"),
        hostKey: NIOSSHPrivateKey = .init(p521Key: .init()),
        hostKeyValidator: SSHHostKeyValidator = .acceptAnything(),
        perform: (SSHServer, SSHClient) async throws -> Void,
        matchingError matchError: (Error) -> Bool,
        expectsFailure: Bool
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
            port: 2222,
            hostKeys: [
                hostKey
            ],
            authenticationDelegate: authDelegate
        )

        do {
            let client = try await SSHClient.connect(
                host: "localhost",
                port: 2222,
                authenticationMethod: credentials,
                hostKeyValidator: hostKeyValidator,
                reconnect: .never
            )

            if expectsFailure {
                XCTFail("Client was not supposed to connect successfully")
            } else {
                try await perform(server, client)
            }

            try await client.close()
        } catch {
            guard matchError(error) else {
                try await server.close()
                throw error
            }
        }

        try await server.close()
    }

    func testServerRejectsPassword() async throws {
        try await runTest(
            credentials: .passwordBased(
                username: "citadel",
                password: "wrong"
            ),
            hostKeyValidator: .acceptAnything(),
            expectedError: SSHClientError.allAuthenticationOptionsFailed
        )
    }

    func testServerRejectsUsername() async throws {
        try await runTest(
            credentials: .passwordBased(
                username: "citadel2",
                password: "test"
            ),
            hostKeyValidator: .acceptAnything(),
            expectedError: SSHClientError.allAuthenticationOptionsFailed
        )
    }

    func testClientRejectsHostKey() async throws {
        try await runTest(
            credentials: .passwordBased(
                username: "citadel",
                password: "test"
            ),
            hostKeyValidator: .trustedKeys([]),
            expectedError: InvalidHostKey()
        )
    }

    func testClientConnectsSuccessfully() async throws {
        try await runTest(
            perform: { _, _ in },
            matchingError: { _ in  false },
            expectsFailure: false
        )
    }

    func testClientRejectsWrongHostKey() async throws {
        let hostKey = NIOSSHPrivateKey(p521Key: .init())
        try await runTest(
            hostKey: hostKey,
            hostKeyValidator: .trustedKeys([
                hostKey.publicKey
            ]),
            perform: { _, _ in },
            matchingError: { _ in  false },
            expectsFailure: false
        )
    }

    func testJump() async throws {
         guard
             let host = ProcessInfo.processInfo.environment["SSH_HOST"],
             let _port = ProcessInfo.processInfo.environment["SSH_PORT"],
             let port = Int(_port),
             let username = ProcessInfo.processInfo.environment["SSH_USERNAME"],
             let password = ProcessInfo.processInfo.environment["SSH_PASSWORD"]
         else {
             throw XCTSkip()
         }

        let settings = SSHClientSettings(
            host: host,
            port: port,
            authenticationMethod: { .passwordBased(username: username, password: password) },
            hostKeyValidator: .acceptAnything()
        )

        let client = try await SSHClient.connect(to: settings)
        try await Task.sleep(for: .seconds(1))
        // Jump to the same server, from a different host
        let client2 = try await client.jump(to: settings)
        let output = try await client2.executeCommand("ls /")
        XCTAssertFalse(String(buffer: output).isEmpty)
        try await client2.close()
        try await client.close()
    }

    func testSimpleSFTP() async throws {
        final class SFTP: SFTPDelegate, @unchecked /* for testing */ Sendable {
            var didCreateDirectory = false
            func createDirectory(_ filePath: String, withAttributes: SFTPFileAttributes, context: SSHContext) async throws -> SFTPStatusCode {
                XCTAssertEqual(context.username, "citadel")
                XCTAssertEqual(filePath, "/test/citadel/sftp")
                didCreateDirectory = true
                return .ok
            }
        }

        try await runTest(
            perform: { server, client in
                let sftpServer = SFTP()
                server.enableSFTP(withDelegate: sftpServer)
                let sftp = try await client.openSFTP()
                try await sftp.createDirectory(atPath: "/test/citadel/sftp")
                XCTAssertTrue(sftpServer.didCreateDirectory)
            },
            matchingError: { _ in false },
            expectsFailure: false
        )
    }

    // MARK: - listDirectory releases its directory handle (Duomote fork)

    /// `listDirectory` must send `SSH_FXP_CLOSE` for the handle `opendir` gave it.
    ///
    /// Upstream never did. The leak is invisible to the client — the listing is correct and the
    /// call returns — and it only shows up on the SERVER, which keeps a directory handle (and its
    /// file descriptor) allocated until CLOSE arrives. So this fence observes the server's side:
    /// `SFTPServerInboundHandler` drops its `directories[id]` entry when it handles CLOSE, and
    /// nothing else retains the handle the delegate returned, so the handle object is deallocated
    /// exactly when the close was really sent. A weak reference is therefore a direct reading of
    /// "the server freed it", not a proxy for it.
    func testListDirectorySendsCloseSoTheServerReleasesTheDirectoryHandle() async throws {
        final class Listing: SFTPDirectoryHandle {
            func listFiles(context: SSHContext) async throws -> [SFTPFileListing] {
                [SFTPFileListing(path: [SFTPPathComponent(
                    filename: "one.txt", longname: "one.txt", attributes: .none)])]
            }
        }

        final class SFTP: SFTPDelegate, @unchecked /* for testing */ Sendable {
            /// The handle the server still holds. WEAK on purpose: this is the measurement.
            weak var lastHandle: Listing?
            /// The positive control, and it cannot be `lastHandle != nil` — that reference is
            /// expected to go away, so reading it as "did the server open a directory" makes the
            /// row red exactly when the fix works. Measured: the first version of this test did
            /// that and failed with "the server never opened a directory" on a correct close.
            var openDirectoryCalls = 0

            func realPath(for canonicalUrl: String, context: SSHContext) async throws -> [SFTPPathComponent] {
                [SFTPPathComponent(filename: canonicalUrl, longname: canonicalUrl, attributes: .none)]
            }

            func openDirectory(atPath path: String, context: SSHContext) async throws -> SFTPDirectoryHandle {
                let handle = Listing()
                lastHandle = handle
                openDirectoryCalls += 1
                return handle
            }
        }

        try await runTest(
            perform: { server, client in
                let sftpServer = SFTP()
                server.enableSFTP(withDelegate: sftpServer)
                let sftp = try await client.openSFTP()

                let names = try await sftp.listDirectory(atPath: "/test/citadel/dir")
                XCTAssertEqual(names.flatMap(\.components).map(\.filename), ["one.txt"],
                               "the listing itself must be unchanged by the close")
                XCTAssertEqual(sftpServer.openDirectoryCalls, 1,
                               "the server opened \(sftpServer.openDirectoryCalls) directories "
                               + "instead of exactly one, so this row measured something else")

                // A STATE wait, not a timing bound: the server clears its entry before it writes
                // the status, but the final release happens on its event loop, so the object can
                // outlive the client's `await` by a hop. The budget is a watchdog that turns "the
                // close was never sent" into a red test instead of a hung one.
                var released = false
                for _ in 0..<500 where !released {
                    if sftpServer.lastHandle == nil { released = true; break }
                    try await Task.sleep(for: .milliseconds(10))
                }
                XCTAssertTrue(released,
                              "the server still holds the directory handle, so listDirectory sent "
                              + "no SSH_FXP_CLOSE — one descriptor leaked for the life of the session")

                try await sftp.close()
            },
            matchingError: { _ in false },
            expectsFailure: false
        )
    }

    /// `closeHandle` CAN fail, which is what makes the `try?` on `listDirectory`'s failing path
    /// load-bearing rather than defensive noise.
    ///
    /// This row exists because the obvious test — "kill the channel mid-listing and check which
    /// error comes out" — is **unable to discriminate** the defect it would be written for. The
    /// listing's own error there is `SFTPError.connectionClosed` (`SFTPResponses.close()` fails
    /// every outstanding promise with it) while a close that was allowed to throw answers
    /// `ChannelError.alreadyClosed` — but `alreadyClosed` is ALSO the honest answer when the
    /// channel dies between two READDIRs rather than during one, and nothing in the harness can
    /// decide which of the two happened. Measured: with `try?` replaced by `try await`, that row
    /// stayed GREEN. So it was deleted rather than kept as a passing row that proves nothing.
    ///
    /// What is left is the half that IS decidable: on a dead channel the close fails, so a bare
    /// `try await` in the `catch` would replace the listing's cause with the close's.
    func testClosingADirectoryHandleFailsOnADeadChannelWhichIsWhyTheFailingPathSwallowsIt() async throws {
        final class SFTP: SFTPDelegate, @unchecked /* for testing */ Sendable {
            func realPath(for canonicalUrl: String, context: SSHContext) async throws -> [SFTPPathComponent] {
                [SFTPPathComponent(filename: canonicalUrl, longname: canonicalUrl, attributes: .none)]
            }
        }

        try await runTest(
            perform: { server, client in
                server.enableSFTP(withDelegate: SFTP())
                let sftp = try await client.openSFTP()

                // A healthy channel first — the positive control, so a row that could never send
                // anything cannot pass by being equally unable to send the close.
                XCTAssertTrue(sftp.isActive, "the SFTP channel did not open")
                _ = try await sftp.getRealPath(atPath: "/test/citadel")

                try await sftp.close()
                XCTAssertFalse(sftp.isActive, "the channel is supposed to be gone now")

                do {
                    // The handle value is irrelevant: the write never reaches a server.
                    try await sftp.closeHandle(ByteBuffer(integer: UInt32(0), endianness: .big))
                    XCTFail("closing a handle on a dead channel succeeded, so the `try?` on "
                            + "listDirectory's failing path guards nothing and could be dropped")
                } catch {
                    // Exactly the error `try?` swallows so the listing's own cause survives.
                }
            },
            matchingError: { _ in false },
            expectsFailure: false
        )
    }

    func testSetAttributes() async throws {
        final class SFTP: SFTPDelegate, @unchecked /* for testing */ Sendable {
            var fileAttributes: SFTPFileAttributes?
            var path: String?
            func fileAttributes(atPath path: String, context: SSHContext) async throws -> SFTPFileAttributes {
                return fileAttributes!
            }

            func setFileAttributes(to attributes: SFTPFileAttributes, atPath path: String, context: SSHContext) async throws -> SFTPStatusCode {
                fileAttributes = attributes
                self.path = path
                return .ok
            }
        }

        try await runTest(
            perform: { server, client in
                let sftpServer = SFTP()
                server.enableSFTP(withDelegate: sftpServer)
                let sftp = try await client.openSFTP()
                let attributes = SFTPFileAttributes(size: 100, accessModificationTime: SFTPFileAttributes.AccessModificationTime(accessTime: Date(timeIntervalSince1970: 1000), modificationTime: Date(timeIntervalSince1970: 2000)))
                try await sftp.setAttributes(at: "/test/citadel/sftp", to: attributes)
                XCTAssertEqual(sftpServer.fileAttributes, attributes)
                XCTAssertEqual(sftpServer.path, "/test/citadel/sftp")
            },
            matchingError: { _ in false },
            expectsFailure: false
        )
    }

    func testExecExitCode() async throws {
        final class Exec: ExecDelegate, @unchecked /* for testing */ Sendable {
            struct CommandContext: ExecCommandContext {
                func terminate() async throws {
                    // Always fine
                }
            }

            var ranCommand = false
            func setEnvironmentValue(_ value: String, forKey key: String) async throws {}
            func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
                XCTAssertEqual(command, "ls")
                defer { ranCommand = true }

                if !ranCommand {
                    // First command always fails
                    outputHandler.succeed(exitCode: 1)
                } else {
                    // Successive commmands succeed
                    outputHandler.succeed(exitCode: 0)
                }

                return CommandContext()
            }
        }

        try await runTest(
            perform: { server, client in
                let execServer = Exec()
                server.enableExec(withDelegate: execServer)

                do {
                    _ = try await client.executeCommand("ls")
                    XCTFail("Shouldn't succeed on the first attempt")
                } catch let error as SSHClient.CommandFailed where error.exitCode == 1 {}

                XCTAssertTrue(execServer.ranCommand)

                _ = try await client.executeCommand("ls")
            },
            matchingError: { _ in false },
            expectsFailure: false
        )
    }
}

extension SFTPDelegate {
    func fileAttributes(atPath path: String, context: Citadel.SSHContext) async throws -> Citadel.SFTPFileAttributes {
        throw ShouldNotGetHere()
    }

    func openFile(_ filePath: String, withAttributes: Citadel.SFTPFileAttributes, flags: Citadel.SFTPOpenFileFlags, context: Citadel.SSHContext) async throws -> Citadel.SFTPFileHandle {
        throw ShouldNotGetHere()
    }

    func removeFile(_ filePath: String, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
        throw ShouldNotGetHere()
    }

    func createDirectory(_ filePath: String, withAttributes: Citadel.SFTPFileAttributes, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
        throw ShouldNotGetHere()
    }

    func removeDirectory(_ filePath: String, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
        throw ShouldNotGetHere()
    }

    func realPath(for canonicalUrl: String, context: Citadel.SSHContext) async throws -> [Citadel.SFTPPathComponent] {
        throw ShouldNotGetHere()
    }

    func openDirectory(atPath path: String, context: Citadel.SSHContext) async throws -> Citadel.SFTPDirectoryHandle {
        throw ShouldNotGetHere()
    }

    func setFileAttributes(to attributes: Citadel.SFTPFileAttributes, atPath path: String, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
        throw ShouldNotGetHere()
    }

    func addSymlink(linkPath: String, targetPath: String, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
        throw ShouldNotGetHere()
    }

    func readSymlink(atPath path: String, context: Citadel.SSHContext) async throws -> [Citadel.SFTPPathComponent] {
        throw ShouldNotGetHere()
    }

    func rename(oldPath: String, newPath: String, flags: UInt32, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
        throw ShouldNotGetHere()
    }
}

struct ShouldNotGetHere: Error {
    init() {
        XCTFail("Should not get here")
    }
}
