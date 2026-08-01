import Darwin
import Foundation
import Phase2Transport

@main
struct Phase2TransportProbeMain {
  static let logger = ConsoleClosedCodeLogger()

  static func main() async {
    do {
      try await run(arguments: Array(CommandLine.arguments.dropFirst()))
      logger.record(.probeCompleted)
    } catch let error as KeychainIdentityError where error.isMissingEntitlement {
      logger.record(.keychainUnavailable)
      exit(EX_NOPERM)
    } catch {
      logger.record(.probeFailed)
      exit(EXIT_FAILURE)
    }
  }

  private static func run(arguments: [String]) async throws {
    guard let command = arguments.first else { throw ProbeError.invalidArguments }
    switch command {
    case "keychain-create":
      guard arguments.count == 3 else { throw ProbeError.invalidArguments }
      try keychainCreate(runID: arguments[1], proofPath: arguments[2])
    case "keychain-retrieve":
      guard arguments.count == 3 else { throw ProbeError.invalidArguments }
      try keychainRetrieve(runID: arguments[1], proofPath: arguments[2])
    case "keychain-mismatch":
      guard arguments.count == 3 else { throw ProbeError.invalidArguments }
      try keychainMismatch(runID: arguments[1], proofPath: arguments[2])
    case "keychain-cleanup":
      guard arguments.count == 3 else { throw ProbeError.invalidArguments }
      try keychainCleanup(runID: arguments[1], proofPath: arguments[2])
    case "certificate-probe":
      guard arguments.count == 1 else { throw ProbeError.invalidArguments }
      try certificateProbe()
    case "interface-inventory":
      guard arguments.count == 1 else { throw ProbeError.invalidArguments }
      let count = try InterfaceDiscovery.eligibleBindings(policy: InterfacePolicy()).count
      logger.record(count > 0 ? .interfaceEligible : .interfaceDenied, count: count)
    case "transport-loopback":
      guard arguments.count == 1 else { throw ProbeError.invalidArguments }
      try await transportProbe(useLoopback: true, publishBonjour: false)
    case "transport-lan":
      guard arguments.count == 1 else { throw ProbeError.invalidArguments }
      try await transportProbe(useLoopback: false, publishBonjour: true)
    default:
      throw ProbeError.invalidArguments
    }
  }

  private static func keychainCreate(runID: String, proofPath: String) throws {
    try ProbeKeychainNamespaceInventory.cleanupAll(primaryRunID: runID)
    do {
      let store = KeychainIdentityStore(namespace: try SpikeKeychainNamespace(runID: runID))
      let host = try store.create(role: .host)
      let tls = try store.create(role: .tls)
      try host.assertPrivateKeyIsNonExportable()
      try tls.assertPrivateKeyIsNonExportable()
      var proof = host.spkiSHA256
      proof.append(tls.spkiSHA256)
      try writePrivateFile(proof, path: proofPath)
    } catch {
      do {
        try ProbeKeychainNamespaceInventory.cleanupAll(primaryRunID: runID)
      } catch {
        throw error
      }
      throw error
    }
  }

  private static func keychainRetrieve(runID: String, proofPath: String) throws {
    let proof = try Data(contentsOf: URL(fileURLWithPath: proofPath))
    guard proof.count == 64 else { throw ProbeError.proofMismatch }
    let store = KeychainIdentityStore(namespace: try SpikeKeychainNamespace(runID: runID))
    let host = try store.load(role: .host, expectedSPKISHA256: Data(proof.prefix(32)))
    let tls = try store.load(role: .tls, expectedSPKISHA256: Data(proof.suffix(32)))
    let message = Data("content-neutral-process-proof".utf8)
    guard host.verify(signature: try host.sign(message), message: message),
      tls.verify(signature: try tls.sign(message), message: message)
    else {
      throw ProbeError.signatureMismatch
    }
  }

  private static func keychainMismatch(runID: String, proofPath: String) throws {
    var proof = try Data(contentsOf: URL(fileURLWithPath: proofPath))
    guard proof.count == 64 else { throw ProbeError.proofMismatch }
    proof[0] ^= 0x01
    let store = KeychainIdentityStore(namespace: try SpikeKeychainNamespace(runID: runID))
    do {
      _ = try store.load(role: .host, expectedSPKISHA256: Data(proof.prefix(32)))
      throw ProbeError.failOpen
    } catch KeychainIdentityError.keyMismatch {
      return
    }
  }

  private static func keychainCleanup(runID: String, proofPath: String) throws {
    try ProbeKeychainNamespaceInventory.cleanupAll(primaryRunID: runID)
    let fileURL = URL(fileURLWithPath: proofPath)
    if FileManager.default.fileExists(atPath: fileURL.path) {
      try FileManager.default.removeItem(at: fileURL)
    }
  }

  private static func certificateProbe() throws {
    let primaryRunID = ProbeKeychainNamespaceInventory.certificateRunIDs[0]
    try ProbeKeychainNamespaceInventory.cleanupAll(primaryRunID: primaryRunID)
    var primaryError: Error?
    do {
      let hostStore = KeychainIdentityStore(
        namespace: try SpikeKeychainNamespace(runID: "cert-host-probe")
      )
      let tlsStore = KeychainIdentityStore(
        namespace: try SpikeKeychainNamespace(runID: "cert-tls-probe")
      )
      let nextTLSStore = KeychainIdentityStore(
        namespace: try SpikeKeychainNamespace(runID: "cert-next-probe")
      )
      let host = try hostStore.create(role: .host)
      let tls = try tlsStore.create(role: .tls)
      let nextTLS = try nextTLSStore.create(role: .tls)
      let now = Date()
      let first = try ContentNeutralCertificateFactory.makeSelfSigned(
        identity: tls,
        notValidBefore: now.addingTimeInterval(-60),
        notValidAfter: now.addingTimeInterval(3_600)
      )
      let renewal = try ContentNeutralCertificateFactory.makeSelfSigned(
        identity: tls,
        notValidBefore: now,
        notValidAfter: now.addingTimeInterval(7_200)
      )
      let nextCertificate = try ContentNeutralCertificateFactory.makeSelfSigned(
        identity: nextTLS,
        notValidBefore: now,
        notValidAfter: now.addingTimeInterval(7_200)
      )
      guard P256SPKI.matches(first.spkiDER, renewal.spkiDER),
        !P256SPKI.matches(first.spkiDER, nextCertificate.spkiDER)
      else {
        throw ProbeError.proofMismatch
      }

      let timestamp = Int64(now.timeIntervalSince1970 * 1_000)
      let statement = try HostSignedRotationStatement(
        generation: 2,
        notBeforeMilliseconds: timestamp - 1_000,
        notAfterMilliseconds: timestamp + 60_000,
        previousSPKISHA256: first.spkiSHA256,
        nextSPKISHA256: nextCertificate.spkiSHA256
      )
      let signed = try statement.signed(by: host)
      try signed.verify(
        hostIdentity: host,
        previousGeneration: 1,
        nowMilliseconds: timestamp,
        expectedCurrentSPKISHA256: first.spkiSHA256,
        presentedNextSPKISHA256: nextCertificate.spkiSHA256
      )
    } catch {
      primaryError = error
    }

    do {
      try ProbeKeychainNamespaceInventory.cleanupAll(primaryRunID: primaryRunID)
    } catch {
      throw error
    }
    if let primaryError {
      throw primaryError
    }
  }

  private static func transportProbe(useLoopback: Bool, publishBonjour: Bool) async throws {
    let policy = InterfacePolicy(allowLoopbackForTests: useLoopback)
    let binding =
      useLoopback
      ? try InterfaceBinding.testOnlyLoopback()
      : try InterfaceDiscovery.firstEligibleBinding(policy: policy)

    let identity = try TestOnlyEphemeralIdentityFactory.make()
    let now = Date()
    let certificate = try ContentNeutralCertificateFactory.makeSelfSigned(
      identity: identity,
      notValidBefore: now.addingTimeInterval(-60),
      notValidAfter: now.addingTimeInterval(3_600)
    )
    let server = NIOTSTLSWebSocketServer(connectionLimit: 2)
    let endpoint = try await server.start(
      binding: binding,
      policy: policy,
      certificate: certificate
    )
    do {
      logger.record(.listenerReady)
      if publishBonjour {
        try await server.publishBonjour()
      }
      let host = endpoint.host.contains(":") ? "[\(endpoint.host)]" : endpoint.host
      guard let url = URL(string: "wss://\(host):\(endpoint.port)\(HardenedWebSocketPolicy.path)")
      else {
        throw ProbeError.invalidURL
      }
      let message = Data([0x50, 0x32])
      let response = try await PinnedWebSocketClient(
        expectedSPKISHA256: endpoint.spkiSHA256
      ).exchange(url: url, message: message)
      guard response == message else { throw ProbeError.proofMismatch }
      try await server.stop()
      let snapshot = await server.snapshot()
      guard snapshot.phase == .terminated, snapshot.activeChildren == 0, snapshot.groupShutdown
      else {
        throw ProbeError.teardownIncomplete
      }
      logger.record(.listenerStopped)
    } catch {
      try? await server.stop()
      throw error
    }
  }

  private static func writePrivateFile(_ data: Data, path: String) throws {
    let url = URL(fileURLWithPath: path)
    try FileManager.default.createDirectory(
      at: url.deletingLastPathComponent(),
      withIntermediateDirectories: true
    )
    guard
      FileManager.default.createFile(
        atPath: url.path,
        contents: data,
        attributes: [.posixPermissions: 0o600]
      )
    else {
      throw ProbeError.fileWriteFailed
    }
  }
}

private enum ProbeError: Error {
  case failOpen
  case fileWriteFailed
  case invalidArguments
  case invalidURL
  case proofMismatch
  case signatureMismatch
  case teardownIncomplete
}

extension KeychainIdentityError {
  fileprivate var isMissingEntitlement: Bool {
    switch self {
    case .claimCreation(let status), .keyCreation(let status), .keyLookup(let status):
      return status == errSecMissingEntitlement
    case .cleanupFailures(let statuses), .rollbackFailures(let statuses):
      return statuses.contains(errSecMissingEntitlement)
    case .duplicate, .incompleteCreation, .invalidNamespace, .keyMissing, .keyMismatch,
      .keyMultiplicity, .privateKeyExported, .publicKeyUnavailable, .signatureFailed:
      return false
    }
  }
}
