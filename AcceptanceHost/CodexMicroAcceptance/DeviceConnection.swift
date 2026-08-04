import CompanionCrypto
import CompanionProtocol
import Foundation
import Security

/// Signs session statements with the phone's Enclave key.
///
/// The same key and the same operation as pairing, behind a different seam.
/// Both protocols want canonical bytes in and 64 raw `r||s` bytes out, and the
/// conversion from the Enclave's DER output is shared rather than duplicated —
/// getting it wrong twice in two places is exactly how a signature that
/// verifies half the time gets shipped.
struct EnclaveSessionSigner: SessionStatementSigner, @unchecked Sendable {
  let key: SecKey

  func signSessionStatement(_ canonicalBytes: Data) throws -> Data {
    try EnclaveTranscriptSigner(key: key).signPairingTranscript(canonicalBytes)
  }
}

/// Connects the phone to its paired Mac and keeps the device surface fed.
///
/// This is the piece that turns a drawn pad into a working one. Before it, the
/// keys rendered correctly from state that never arrived and their handlers
/// were empty: the surface resolved availability against capabilities it was
/// never told, so every control showed as unavailable and pressing one did
/// nothing.
///
/// **One connection, one reader.** The session's frame codecs carry
/// exactly-next counters, so two readers would race to open frames and the
/// loser would see a counter violation and tear down a healthy session. The
/// read loop lives here and everything else — commands included — goes through
/// it, which is why `send` hands its result back rather than reading a reply
/// itself.
@MainActor
public final class DeviceConnection: ObservableObject {
  public enum Status: Equatable, Sendable {
    case notPaired
    case connecting
    case connected
    case failed(String)
  }

  @Published public private(set) var status: Status = .notPaired
  @Published public private(set) var threads: [ObservedThreadState] = []
  @Published public private(set) var capabilities: Set<DeviceCapability> = []
  @Published public private(set) var reasoningEfforts: [String] = []
  @Published public private(set) var lastUpdate: Date?
  /// The most recent command result, for the surface to report.
  @Published public private(set) var lastOutcome: CommandOutcome?

  private var session: SessionClient?
  private var readTask: Task<Void, Never>?
  private var cursor: ReplayCursorEnvelope?
  private let subscriptionID = UUID()
  /// Command results are handed to whoever is waiting on that command ID.
  private var waiters: [UUID: CheckedContinuation<SecureCommandResult, Never>] = [:]

  public init() {}

  /// Connection progress on standard error.
  ///
  /// The Mac reports its startup the same way, and for the same reason: a
  /// phone that will not connect is undiagnosable from the screen, which says
  /// only "not connected". Every code here is a closed vocabulary — no
  /// address, no key, no identifier.
  private func report(_ code: String, _ detail: String = "") {
    let line = detail.isEmpty ? "device: \(code)" : "device: \(code) — \(detail)"
    FileHandle.standardError.write(Data((line + "\n").utf8))
  }

  // MARK: - Lifecycle

  /// Connects, authenticates, and subscribes.
  public func connect() async {
    guard readTask == nil else { return }
    let stored = try? PairedHostStore.load()
    guard let host = stored ?? nil else {
      report("connect.notPaired")
      status = .notPaired
      return
    }
    report("connect.paired", "hostID known")
    guard let key = try? DeviceIdentity.load() ?? DeviceIdentity.create(),
      let publicKey = try? DeviceIdentity.publicKeyX963(key),
      let identity = try? SessionDeviceIdentity(
        deviceID: DeviceInstallation.deviceID(),
        publicKeyX963: publicKey,
        signer: EnclaveSessionSigner(key: key))
    else {
      report("connect.identityUnavailable")
      status = .failed("identityUnavailable")
      return
    }

    status = .connecting
    // Discover where the Mac is now. The stored origin records where it was,
    // and the listener binds an ephemeral port, so that address is stale after
    // any restart — which is why a paired phone connected exactly once. The
    // pins make browsing safe: a wrong answer fails at TLS.
    var target = host
    let found = await BridgeDiscovery.find()
    report("connect.discovery", found == nil ? "not found" : "found")
    if let found {
      target = PairedHost(
        hostID: host.hostID,
        hostPublicKeyX963: host.hostPublicKeyX963,
        tlsSPKIFingerprint: host.tlsSPKIFingerprint,
        endpointOrigin: "wss://\(found.host):\(found.port)"
      )
    }
    let session = SessionClient(host: target, identity: identity)
    do {
      try await session.authenticate()
    } catch {
      report("connect.authFailed", Self.describe(error))
      status = .failed(Self.describe(error))
      return
    }
    report("connect.authenticated")
    self.session = session
    status = .connected

    // Resume from the stored cursor so a reconnect continues rather than
    // replaying from the beginning; the Mac decides whether that cursor is
    // still serviceable and forces a snapshot when it is not.
    let subscribe = SecureObservationSubscribe(
      subscriptionID: subscriptionID, resumeCursor: cursor)
    do {
      try await session.send(
        kind: .observationSubscribe, payload: try JSONEncoder().encode(subscribe))
    } catch {
      report("connect.subscribeFailed")
      status = .failed("subscribeFailed")
      return
    }
    report("connect.subscribed")
    readTask = Task { [weak self] in await self?.readLoop(session) }
  }

  public func disconnect() async {
    readTask?.cancel()
    readTask = nil
    await session?.close()
    session = nil
    // Waiters must be released or a command awaits forever after a teardown.
    failAllWaiters()
    status = .notPaired
    threads = []
    capabilities = []
    reasoningEfforts = []
  }

  // MARK: - Reading

  /// The single reader. Deliveries update the surface; command results are
  /// routed to whoever is waiting for them.
  private func readLoop(_ session: SessionClient) async {
    while !Task.isCancelled {
      let envelope: ListenerApplicationEnvelopeWire
      do {
        envelope = try await session.receive()
      } catch {
        status = .failed(Self.describe(error))
        failAllWaiters()
        return
      }
      switch envelope.kind {
      case .observationDelivery:
        apply(delivery: envelope.payload)
      case .commandResult:
        route(result: envelope.payload)
      case .closeNotice:
        status = .failed("closedByHost")
        failAllWaiters()
        return
      case .observationSubscribe, .observationAcknowledge, .commandRequest:
        // Device-originated kinds cannot arrive from the host; SessionClient
        // already refuses them, so reaching here would be a contradiction.
        continue
      }
    }
  }

  private func apply(delivery payload: Data) {
    guard let delivery = try? JSONDecoder().decode(SecureObservationDelivery.self, from: payload),
      delivery.subscriptionID == subscriptionID
    else {
      return
    }
    switch delivery.kind {
    case .snapshot:
      guard
        let snapshot = try? JSONDecoder().decode(
          SecureObservationSnapshot.self, from: delivery.payload)
      else { return }
      threads = snapshot.threads
      capabilities = snapshot.capabilities
      reasoningEfforts = snapshot.reasoningEfforts
    case .event:
      guard
        let batch = try? JSONDecoder().decode(
          SecureObservationEventBatch.self, from: delivery.payload)
      else { return }
      apply(events: batch)
    }
    cursor = delivery.cursor
    lastUpdate = Date()
    acknowledge(delivery.cursor)
  }

  /// Applies an event batch to the held thread list.
  ///
  /// The Mac sends changes, not a new world, so a batch that mentions a thread
  /// replaces that thread and leaves the rest alone. A thread the batch does
  /// not mention is unchanged rather than removed — removing it would treat
  /// "nothing happened here" as "this is gone".
  private func apply(events batch: SecureObservationEventBatch) {
    var byID = Dictionary(threads.map { ($0.threadID, $0) }, uniquingKeysWith: { _, last in last })
    for event in batch.events {
      // An event without state means the Mac knew something changed but not
      // what to. Dropping the thread would blank a key that is still there;
      // keeping the old state would claim something now known to be wrong. So
      // the thread stays and its detail is cleared, which the surface renders
      // as bound-but-unknown — the honest reading of "it moved, we were not
      // told where".
      if let thread = event.thread {
        byID[event.threadID] = thread
      } else if let previous = byID[event.threadID] {
        byID[event.threadID] =
          (try? ObservedThreadState(
            threadID: previous.threadID,
            projectID: previous.projectID,
            status: .unknown,
            activeTurnID: nil,
            lastTurnID: nil,
            lastTurnStatus: nil
          )) ?? previous
      }
    }
    threads = byID.values.sorted { $0.threadID < $1.threadID }
  }

  private func acknowledge(_ cursor: ReplayCursorEnvelope) {
    guard let session else { return }
    Task {
      let acknowledgement = SecureObservationAcknowledgement(
        subscriptionID: subscriptionID, cursor: cursor)
      try? await session.send(
        kind: .observationAcknowledge,
        payload: try JSONEncoder().encode(acknowledgement))
    }
  }

  // MARK: - Commands

  /// Sends a command and waits for its result.
  ///
  /// The reply is delivered by the read loop rather than read here, because
  /// two readers on one counter-bearing stream would race and the loser would
  /// tear down a healthy session.
  @discardableResult
  public func send(_ body: ClientCommandBody, commandID: UUID = UUID()) async -> CommandOutcome {
    guard let session, status == .connected else {
      lastOutcome = .notSent
      return .notSent
    }
    guard let command = try? ClientCommand(commandID: commandID, issuedAt: Date(), body: body),
      let payload = try? JSONEncoder().encode(command)
    else {
      lastOutcome = .notSent
      return .notSent
    }

    do {
      try await session.send(kind: .commandRequest, payload: payload)
    } catch {
      lastOutcome = .notSent
      return .notSent
    }

    let result = await withCheckedContinuation { continuation in
      waiters[commandID] = continuation
    }
    let outcome = CommandOutcome.from(result)
    lastOutcome = outcome
    return outcome
  }

  private func route(result payload: Data) {
    guard let result = try? JSONDecoder().decode(SecureCommandResult.self, from: payload),
      let waiter = waiters.removeValue(forKey: result.commandID)
    else {
      return
    }
    waiter.resume(returning: result)
  }

  /// Releases every waiting command as unknown.
  ///
  /// Unknown rather than failed: the command reached the Mac, and whether it
  /// ran is genuinely not knowable from here. Reporting failure would invite a
  /// retry that executes twice.
  private func failAllWaiters() {
    let pending = waiters
    waiters = [:]
    for (commandID, continuation) in pending {
      let unknown = try? SecureCommandResult(
        commandID: commandID, outcome: .outcomeUnknown, denialReason: nil)
      if let unknown { continuation.resume(returning: unknown) }
    }
  }

  static func describe(_ error: any Error) -> String {
    guard let failure = error as? SessionClient.Failure else { return "unknown" }
    switch failure {
    case .notPaired: return "notPaired"
    case .connectionFailed: return "connectionFailed"
    case .authenticationFailed: return "authenticationFailed"
    case .sessionClosed(let reason): return reason.rawValue
    case .malformedReply: return "malformedReply"
    case .notAuthenticated: return "notAuthenticated"
    }
  }
}
