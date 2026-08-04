import CodexAppServer
import CompanionCrypto
import CompanionProtocol
import Foundation
import MacBridgeCore
import MacBridgeServer

/// News up the production graph for the running app.
///
/// `BridgeNetworkAssembly` says what is connected to what; this says where the
/// real state lives — the Data Protection Keychain for grants, the Secure
/// Enclave for identities — and hands back the two objects the menu drives.
///
/// It is separate from the assembly because the assembly must stay
/// constructible from deterministic doubles in tests. This file is the only
/// one that names production storage, so it is also the only one that cannot
/// run in a unit test, and keeping that boundary sharp is what lets everything
/// else be tested.
public struct BridgeLiveComposition: Sendable {
  /// The LAN control the menu toggles.
  public let lanController: BridgeLANController
  /// The pairing session lifecycle the pairing window drives.
  public let pairing: BridgePairingService
  /// The pairing screen's state.
  public let pairingModel: BridgePairingModel
  /// Kept so the caller can read authority state for diagnostics.
  public let authority: DeviceGrantAuthority
  /// The assembly, so an acceptance run can probe each startup prerequisite
  /// individually. `BridgeLANFailure.startupDenied` is the right vocabulary
  /// for a menu but useless for diagnosis: it collapses five independent
  /// refusals — interface, Codex, policy, authority, identity — into one word.
  public let assembly: BridgeNetworkAssembly

  /// Builds everything, or throws so the menu can show the bridge as
  /// unavailable rather than offering a control that cannot work.
  ///
  /// **Identities are loaded, not created, when one already exists.** The
  /// store refuses to replace an identity it cannot find but was told to
  /// expect, so a wiped Keychain surfaces as a failure here instead of as a
  /// silently re-keyed bridge every paired phone would then reject.
  private init(
    workspaceRootsForRefresh: BridgeWorkspaceRootResolver,
    hostPublicKeyX963: Data,
    attribution: ThreadProjectTable,
    runtime: CodexRuntimeSupervisor?,
    codexAssembly: CodexBridgeAssembly?,
    registryForGrants: BridgeProjectRegistry,
    pumpForRetention: BridgeObservationPump?,
    assemblyForDiagnostics: BridgeNetworkAssembly,
    lanController: BridgeLANController,
    pairing: BridgePairingService,
    pairingModel: BridgePairingModel,
    authority: DeviceGrantAuthority
  ) {
    self.workspaceRoots = workspaceRootsForRefresh
    self.hostPublicKeyX963 = hostPublicKeyX963
    self.attribution = attribution
    self.runtime = runtime
    self.codexAssembly = codexAssembly
    self.registry = registryForGrants
    self.pump = pumpForRetention
    self.assembly = assemblyForDiagnostics
    self.lanController = lanController
    self.pairing = pairing
    self.pairingModel = pairingModel
    self.authority = authority
  }

  /// The pump feeding the broker, retained so it keeps running.
  public let pump: BridgeObservationPump?
  /// The projects a device may be granted. Threads resolve to these.
  public let registry: BridgeProjectRegistry
  /// The gateway's view of writable roots, refreshed when projects change.
  public let workspaceRoots: BridgeWorkspaceRootResolver
  /// The host's signing key, as a device holds it after pairing. Exposed so an
  /// in-process device can authenticate a session exactly as a phone does.
  public let hostPublicKeyX963: Data
  /// Which project a thread belongs to. The gateway scopes every command
  /// through this, so an unattributed thread is refused.
  public let attribution: ThreadProjectTable
  /// The Codex runtime the gateway dispatches to, when there is one.
  public let runtime: CodexRuntimeSupervisor?
  /// The Codex assembly, so a thread the bridge opens can be taken into the
  /// store that feeds every device snapshot.
  public let codexAssembly: CodexBridgeAssembly?

  @MainActor
  public static func make(
    codexProbe: BridgeCodexSupportProbe,
    assembly codex: CodexBridgeAssembly? = nil
  ) throws -> BridgeLiveComposition {
    // Resetting an identity is gated on "no grants exist". The live gate is
    // administration work that does not exist yet, so the safe answer is no:
    // an identity is never destroyed by this path.
    let makeIdentityStore: @Sendable () -> BridgeIdentityStore = {
      BridgeIdentityStore(backend: SecureEnclaveIdentityBackend(), resetPolicy: { false })
    }
    let hostIdentity = try makeIdentityStore().loadOrCreate(role: .host).identity
    let hostSigner = try EnclaveHostStatementSigner(identity: hostIdentity)

    // The store refuses to create its own item, so a first install must
    // provision one before the authority is constructed. Without this a fresh
    // bridge can never start: the grant-authority probe refuses, LAN stays
    // off, and pairing — the only thing that creates a grant — is unreachable.
    let grantStore = DataProtectionKeychainGrantStore()
    try BridgeAuthorityProvisioning.ensureProvisioned(store: grantStore)
    let authority = DeviceGrantAuthority(storage: grantStore)
    let pairingCoordinator = try PairingCoordinator(
      hostID: BridgeHostIdentifier.stable(),
      hostPublicKeyX963: hostSigner.hostPublicKeyX963,
      signer: hostSigner
    )
    // **The TLS identity, not the host identity.** These are two different
    // Enclave keys, and the session transcript binds the fingerprint of the
    // certificate the listener actually serves — which is the TLS one, and
    // which is what the device pinned at pairing and re-derives on every
    // connect. Binding the host key here made the two sides compute different
    // transcripts from the same handshake, so a correctly paired phone with a
    // valid grant was refused with a bare `authenticationFailed` every time.
    // Pairing was unaffected, which is exactly why this survived: the failure
    // appeared only at the step after the one being tested.
    let tlsIdentity = try makeIdentityStore().loadOrCreate(role: .tls).identity
    let sessions = try SessionCoordinator(
      hostID: BridgeHostIdentifier.stable(),
      hostTLSSPKIFingerprint: tlsIdentity.spkiFingerprint,
      authority: GrantAuthoritySessionAuthority(authority: authority),
      signer: hostSigner,
      store: InMemoryAuthenticatedSessionStore()
    )

    let attribution = ThreadProjectTable()
    let registry = BridgeProjectRegistry()
    let roots = BridgeWorkspaceRootResolver(projects: [])
    // The snapshot source is the live assembly when there is one. Without it
    // a device connects, subscribes, and is told about nothing — which is
    // precisely how the keys stayed dark: the surface was correct and the
    // feed behind it was a stub.
    let snapshots: any ObservationSnapshotProviding =
      codex.map(CodexAssemblySnapshotSource.init) ?? EmptyBridgeSnapshotSource()
    let broker = DeviceObservationBroker(
      scopes: authority,
      snapshots: snapshots,
      attribution: attribution,
      journalEpoch: try SystemJournalEpochMint().mintJournalEpoch()
    )

    let pairingModel = BridgePairingModel()
    let pairingObserver = BridgePairingObserver(
      model: pairingModel, recorder: PairingGrantRecorder(authority: authority))
    let assembly = BridgeNetworkAssembly(
      authority: authority,
      sessions: sessions,
      pairing: pairingCoordinator,
      broker: broker,
      gateway: NetworkCommandGateway(
        authority: authority,
        attribution: attribution,
        ledger: InMemoryCommandLedger(),
        sessions: SessionCoordinatorVerifier(coordinator: sessions),
        // The live supervisor, not a stub. It already owns compatibility,
        // restart, and degradation, so a command is refused while Codex is
        // unhealthy by the same logic that refuses one on the Mac. With the
        // stub in place every state-changing command was denied
        // runtimeUnavailable before it went anywhere.
        runtime: codex?.runtime ?? NeverReadyRuntime(),
        responder: codex?.runtime ?? UnavailableCodexResponder(),
        turnStarter: codex?.runtime ?? UnavailableTurnStarter(),
        // New chat and approvals stay closed here. Both are opt-in by design
        // and neither default is a mistake: `startThread` honours the Step
        // 2.12 deferral's terms, and approvals stay shut until the Mac has a
        // reviewed way to surface them. Supplying either is a deliberate act,
        // which is exactly what those gates exist to require.
        threadStarter: DeniedThreadStarter(),
        approvals: nil,
        turnSteerer: codex?.runtime ?? UnavailableTurnSteerer(),
        // Without this the gateway resolves every project to no writable
        // roots, so a workspace-write turn silently becomes read-only —
        // present-and-degraded rather than refused, which is the shape the
        // invariants exist to avoid.
        workspaceRoots: roots,
        readCursors: try DeviceReadCursorStore(
          storage: FileBackedReadCursorStorage(),
          scopes: authority,
          attribution: attribution
        )
      ),
      tls: BridgeSecureEnclaveTLSProvider(makeStore: makeIdentityStore),
      codexProbe: codexProbe,
      pairingObserver: pairingObserver
    )

    // Replays the journal and tells the broker which threads moved, resolving
    // attribution first because the broker reads it synchronously and an
    // unattributed thread is invisible.
    let pump = codex.map { live in
      BridgeObservationPump(
        broker: broker,
        attribution: BridgeThreadAttributionResolver(
          registry: registry,
          table: attribution,
          readThread: { threadID in
            // The assembly reads the thread from the running app-server; the
            // resolver turns thread["cwd"] into a project the Mac allowlisted.
            try await live.runtime.readThread(threadID: threadID)
          }
        ),
        replay: { cursor in try await live.replay(after: cursor) }
      )
    }

    return BridgeLiveComposition(
      workspaceRootsForRefresh: roots,
      hostPublicKeyX963: hostSigner.hostPublicKeyX963,
      attribution: attribution,
      runtime: codex?.runtime,
      codexAssembly: codex,
      registryForGrants: registry,
      pumpForRetention: pump,
      assemblyForDiagnostics: assembly,
      lanController: assembly.makeLANController(),
      pairing: BridgePairingService(
        coordinator: pairingCoordinator, model: pairingModel, observer: pairingObserver),
      pairingModel: pairingModel,
      authority: authority
    )
  }
}

/// The host's stable, non-secret identifier.
///
/// It is derived once and stored in preferences rather than regenerated,
/// because a phone binds its session to this value: a host that changed
/// identifiers on every launch would invalidate every pairing. It carries no
/// information about the machine — it is a random UUID, not a serial number or
/// a hardware identifier.
enum BridgeHostIdentifier {
  private static let key = "com.codexmicro.bridge.host-id"

  static func stable() -> UUID {
    if let stored = UserDefaults.standard.string(forKey: key),
      let id = UUID(uuidString: stored)
    {
      return id
    }
    let id = UUID()
    UserDefaults.standard.set(id.uuidString, forKey: key)
    return id
  }
}

/// Serves the device-facing snapshot from the live assembly.
///
/// The broker filters this per device; nothing here decides what anyone may
/// see, it only supplies the unfiltered truth for the projection to cut down.
struct CodexAssemblySnapshotSource: ObservationSnapshotProviding {
  let assembly: CodexBridgeAssembly

  func currentObservationSnapshot() async -> CompanionStateSnapshot {
    await assembly.snapshot()
  }
}

/// Observation has no snapshot source until the pump is attached.
///
/// An empty snapshot is the honest answer for a bridge that is reachable but
/// not yet observing: a device sees nothing rather than seeing stale state.
struct EmptyBridgeSnapshotSource: ObservationSnapshotProviding {
  func currentObservationSnapshot() async -> CompanionStateSnapshot {
    CompanionStateSnapshot(generatedAt: Date(), latestSequence: 0, threads: [])
  }
}

/// Commands are refused until the Codex runtime is attached to the gateway.
///
/// These are deliberately refusing rather than absent: the gateway's contract
/// is that an unavailable runtime denies, and a device asking for a command
/// gets a closed refusal instead of a hang.
struct NeverReadyRuntime: NetworkRuntimeReadiness {
  func isReadyForStateChange() async -> Bool { false }
}

struct UnavailableCodexResponder: CodexApprovalResponding {
  func respondToServerRequest(id: Int64, result: JSONValue) async throws {
    throw CodexRuntimeRequestError.notReady
  }
  func interruptTurn(threadID: String, turnID: String) async throws {
    throw CodexRuntimeRequestError.notReady
  }
}

struct UnavailableTurnStarter: CodexTurnStarting {
  func startTurn(threadID: String, prompt: String, policy: PhoneTurnPolicy) async throws -> String {
    throw CodexRuntimeRequestError.notReady
  }
}

struct UnavailableTurnSteerer: CodexTurnSteering {
  func steerTurn(threadID: String, turnID: String, prompt: String) async throws {
    throw CodexRuntimeRequestError.notReady
  }
}
