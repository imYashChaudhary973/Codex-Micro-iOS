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
    assemblyForDiagnostics: BridgeNetworkAssembly,
    lanController: BridgeLANController,
    pairing: BridgePairingService,
    pairingModel: BridgePairingModel,
    authority: DeviceGrantAuthority
  ) {
    self.assembly = assemblyForDiagnostics
    self.lanController = lanController
    self.pairing = pairing
    self.pairingModel = pairingModel
    self.authority = authority
  }

  @MainActor
  public static func make(codexProbe: BridgeCodexSupportProbe) throws -> BridgeLiveComposition {
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
    let sessions = try SessionCoordinator(
      hostID: BridgeHostIdentifier.stable(),
      hostTLSSPKIFingerprint: hostIdentity.spkiFingerprint,
      authority: GrantAuthoritySessionAuthority(authority: authority),
      signer: hostSigner,
      store: InMemoryAuthenticatedSessionStore()
    )

    let attribution = ThreadProjectTable()
    let broker = DeviceObservationBroker(
      scopes: authority,
      snapshots: EmptyBridgeSnapshotSource(),
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
        runtime: NeverReadyRuntime(),
        responder: UnavailableCodexResponder(),
        turnStarter: UnavailableTurnStarter(),
        // New chat and approvals stay closed here. Both are opt-in by design
        // and neither default is a mistake: `startThread` honours the Step
        // 2.12 deferral's terms, and approvals stay shut until the Mac has a
        // reviewed way to surface them. Supplying either is a deliberate act,
        // which is exactly what those gates exist to require.
        threadStarter: DeniedThreadStarter(),
        approvals: nil,
        turnSteerer: UnavailableTurnSteerer(),
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

    return BridgeLiveComposition(
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
