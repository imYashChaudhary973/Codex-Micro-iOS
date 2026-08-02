import CompanionProtocol
import CryptoKit
import Foundation

/// Everything the host produces from one accepted claim.
public struct PairingClaimAcceptance: Equatable, Sendable {
  /// The signed reply to send to the device.
  public let response: SecurePairingResponse
  /// The canonical transcript both endpoints sign.
  public let transcript: PairingTranscript
  /// The transcript-bound phrase the Mac user must confirm locally.
  public let verificationPhrase: SecureShortAuthenticationString
}

extension PairingClaimAcceptance: CustomStringConvertible, CustomDebugStringConvertible,
  CustomReflectable
{
  /// Redacted: the acceptance carries the transcript, which binds the
  /// single-use bootstrap secret.
  public var description: String { "PairingClaimAcceptance(redacted)" }
  public var debugDescription: String { description }
  public var customMirror: Mirror { Mirror(self, children: []) }
}

/// Host-side, transport-independent pairing state machine (plan Step 2.5).
///
/// The coordinator owns pairing choreography and nothing else: it holds no
/// socket, no Keychain, no grant store, and no Codex access. Its seams —
/// wall clock, monotonic clock, CSPRNG, and ephemeral session store — are
/// injected, and the long-term host signature comes from a
/// ``PairingTranscriptSigner`` so the Secure Enclave identity in
/// `MacBridgeServer` is never imported here.
///
/// Security-relevant ordering, fixed by plan §2 invariant 7:
///
/// 1. The bootstrap secret is exactly 256 CSPRNG bits and is compared in
///    constant time.
/// 2. The atomic `available → claimed` transition happens **before** any
///    transcript or signature processing, and both the comparison and the
///    commit run inside one ``PairingSessionStore/withRecord(_:_:)`` critical
///    section. Atomicity therefore holds at the store, so several
///    coordinators sharing one store — one per connection in the listener —
///    still produce exactly one winner.
/// 3. A completed claim consumes the secret regardless of the eventual
///    outcome; reuse, losing concurrent claimants, expiry, cancellation, and
///    exhausted attempt budgets are each rejected with a distinct closed
///    reason.
/// 4. Pairing completes only after **both** local confirmations. Any failure
///    produces a closed reason and no ``PairedDeviceProposal``; this type
///    never stores a grant.
/// 5. Expiry is enforced on a monotonic clock, so no wall-clock adjustment
///    can extend a session's usable life.
public actor PairingCoordinator {
  private let hostID: UUID
  private let hostPublicKeyX963: Data
  private let hostIdentityFingerprint: Data
  private let signer: any PairingTranscriptSigner
  private let store: any PairingSessionStore
  private let random: any PairingRandomSource
  private let clock: @Sendable () -> UInt64
  private let monotonicClock: @Sendable () -> UInt64

  /// - Parameters:
  ///   - hostID: Opaque, non-secret host identifier.
  ///   - hostPublicKeyX963: The long-term host identity public key, 65 bytes.
  ///   - signer: Seam producing host signatures over transcript bytes.
  ///   - store: Ephemeral, memory-only pairing-session store.
  ///   - random: CSPRNG seam.
  ///   - clock: Wall-clock epoch-seconds seam. Display only: it sets the
  ///     `expiresAt` the QR shows and the pairing instant in the proposal.
  ///   - monotonicClock: Monotonic-seconds seam that enforces expiry.
  public init(
    hostID: UUID,
    hostPublicKeyX963: Data,
    signer: any PairingTranscriptSigner,
    store: any PairingSessionStore = InMemoryPairingSessionStore(),
    random: any PairingRandomSource = SystemPairingRandomSource(),
    clock: @escaping @Sendable () -> UInt64 = {
      UInt64(max(0, Date().timeIntervalSince1970.rounded(.down)))
    },
    monotonicClock: @escaping @Sendable () -> UInt64 = PairingMonotonicClock.system
  ) throws {
    _ = try SecureP256KeyEncoding.signingPublicKey(fromX963: hostPublicKeyX963)
    self.hostID = hostID
    self.hostPublicKeyX963 = hostPublicKeyX963
    self.hostIdentityFingerprint = try SPKIFingerprint.fingerprint(
      x963PublicKey: hostPublicKeyX963)
    self.signer = signer
    self.store = store
    self.random = random
    self.clock = clock
    self.monotonicClock = monotonicClock
  }

  // MARK: - Session creation

  /// Creates one pairing session and returns its QR payload.
  ///
  /// The pairing session ID, the bootstrap secret, and the host nonce all
  /// come from the injected CSPRNG — 128, 256, and 256 bits respectively —
  /// and the session expires exactly
  /// ``PairingPolicy/sessionLifetimeSeconds`` after creation on the
  /// monotonic clock.
  public func createSession(
    endpointOrigin: PairingEndpointOrigin,
    selection: SecureProtocolSelection,
    tlsSPKIFingerprint: Data
  ) throws -> PairingQRPayload {
    sweepExpired()
    guard (try? SecureProtocolNegotiation.accept(selection)) != nil else {
      throw PairingClosedReason.selectionRejected
    }
    try requireExactCryptoByteCount(
      tlsSPKIFingerprint, SPKIFingerprint.byteCount, field: "tlsSPKIFingerprint")
    let pairingSessionID = UUID(canonicalBytes: try entropy(16))
    let secret = try entropy(PairingPolicy.bootstrapSecretByteCount)
    let hostNonce = try entropy(PairingPolicy.nonceByteCount)
    let createdAt = clock()
    let (expiresAt, wallOverflow) = createdAt.addingReportingOverflow(
      PairingPolicy.sessionLifetimeSeconds)
    let (monotonicExpiry, monotonicOverflow) = monotonicClock().addingReportingOverflow(
      PairingPolicy.sessionLifetimeSeconds)
    guard !wallOverflow, !monotonicOverflow else { throw PairingClosedReason.sessionExpired }

    store.insert(
      PairingSessionRecord(
        pairingSessionID: pairingSessionID,
        endpointOrigin: endpointOrigin,
        selection: selection,
        tlsSPKIFingerprint: tlsSPKIFingerprint,
        createdAtEpochSeconds: createdAt,
        expiresAtEpochSeconds: expiresAt,
        expiresAtMonotonicSeconds: monotonicExpiry,
        bootstrapSecret: secret,
        hostNonce: hostNonce
      )
    )
    return try PairingQRPayload(
      selection: selection,
      hostID: hostID,
      endpointOrigin: endpointOrigin,
      hostIdentityFingerprint: hostIdentityFingerprint,
      tlsSPKIFingerprint: tlsSPKIFingerprint,
      pairingSessionID: pairingSessionID,
      bootstrapSecret: secret,
      expiresAtEpochSeconds: expiresAt
    )
  }

  /// Clears secret material from every expired session and removes records
  /// that also passed ``PairingPolicy/expiredRecordRetentionSeconds``.
  ///
  /// Every public operation sweeps first, so ordinary traffic bounds
  /// accumulation. The Step 2.13 Mac assembly must additionally call this on
  /// a timer: an abandoned session that no later operation touches otherwise
  /// keeps its material until the next call.
  @discardableResult
  public func sweepExpired() -> Int {
    store.sweep(
      atMonotonicSeconds: monotonicClock(),
      retentionSeconds: PairingPolicy.expiredRecordRetentionSeconds
    )
  }

  /// The session's current lifecycle, with monotonic expiry applied lazily.
  public func lifecycle(of pairingSessionID: UUID) -> PairingSessionState? {
    sweepExpired()
    guard let record = store.record(for: pairingSessionID) else { return nil }
    switch record.state {
    case .available, .claimed:
      return isExpired(record) ? .destroyed(.sessionExpired) : record.state
    case .consumed, .destroyed:
      return record.state
    }
  }

  /// Destroys a session on explicit Mac-user cancellation. Idempotent.
  public func cancel(pairingSessionID: UUID) {
    sweepExpired()
    _ = store.withRecord(pairingSessionID) { record in
      record.terminate(.destroyed(.sessionCancelled))
    }
  }

  // MARK: - Claim

  /// Performs the atomic claim and, only afterwards, the transcript work.
  ///
  /// The secret is compared in constant time and the session is claimed in
  /// one store-level critical section, before the request's mode, endpoint
  /// origin, selection, or public key is examined and before any signature is
  /// produced, so every post-claim failure still spends the single-use
  /// secret.
  public func claim(request: SecurePairingRequest) throws -> PairingClaimAcceptance {
    sweepExpired()
    let now = monotonicClock()
    var failure: PairingClosedReason?
    var claimed: PairingSessionRecord?

    let existing = store.withRecord(request.pairingSessionID) { record in
      switch record.state {
      case .available:
        break
      case .claimed:
        failure = .sessionAlreadyClaimed
        return
      case .consumed:
        failure = .secretAlreadyConsumed
        return
      case .destroyed(let reason):
        failure = reason
        return
      }
      guard now < record.expiresAtMonotonicSeconds else {
        record.terminate(.destroyed(.sessionExpired))
        failure = .sessionExpired
        return
      }
      guard constantTimeEquals(request.bootstrapSecret, record.bootstrapSecret) else {
        record.failedClaimAttempts += 1
        if record.failedClaimAttempts >= PairingPolicy.maxFailedClaimAttempts {
          record.terminate(.destroyed(.attemptLimitExceeded))
          failure = .attemptLimitExceeded
        } else {
          failure = .bootstrapSecretMismatch
        }
        return
      }
      // Committed inside the store's critical section: from here the secret
      // is spent, whatever happens next.
      record.state = .claimed
      claimed = record
    }

    guard existing != nil else { throw PairingClosedReason.unknownPairingSession }
    if let failure { throw failure }
    guard let record = claimed else { throw PairingClosedReason.malformedRequest }

    do {
      let transcript = try buildTranscript(request: request, record: record)
      let signature = try hostSignature(over: transcript)
      let response = try SecurePairingResponse(
        pairingSessionID: record.pairingSessionID,
        hostID: hostID,
        hostNonce: record.hostNonce,
        hostPublicKey: hostPublicKeyX963,
        selection: record.selection,
        transcriptSignature: signature
      )
      var bindFailure: PairingClosedReason?
      _ = store.withRecord(record.pairingSessionID) { stored in
        guard case .claimed = stored.state, !isExpired(stored, at: now) else {
          bindFailure = Self.terminalReason(stored.state) ?? .sessionExpired
          return
        }
        stored.transcript = transcript
      }
      if let bindFailure { throw bindFailure }
      return PairingClaimAcceptance(
        response: response,
        transcript: transcript,
        verificationPhrase: SecureShortAuthenticationString.derive(from: transcript)
      )
    } catch {
      consume(record.pairingSessionID)
      throw Self.closedReason(error)
    }
  }

  // MARK: - Dual confirmation

  /// Records the Mac user's local confirmation of the verification phrase.
  ///
  /// A mismatched phrase fails closed and consumes the attempt; a matching
  /// phrase completes pairing only if the device already confirmed. The
  /// result is not discardable: a `completed` outcome carries the only
  /// ``PairedDeviceProposal`` and the transcript is cleared immediately
  /// afterwards.
  public func confirmVerificationPhrase(
    pairingSessionID: UUID,
    phrase: SecureShortAuthenticationString
  ) throws -> PairingProgress {
    try confirm(pairingSessionID) { record in
      guard let transcript = record.transcript else {
        return .sessionNotClaimed
      }
      guard phrase == SecureShortAuthenticationString.derive(from: transcript) else {
        return .verificationPhraseMismatch
      }
      record.hostConfirmed = true
      return nil
    }
  }

  /// Verifies the device's transcript signature and records the device's own
  /// local confirmation, which the confirmation message signals.
  ///
  /// Pairing completes only if the Mac user already confirmed the phrase. The
  /// result is not discardable for the same reason as above.
  public func submitDeviceConfirmation(
    _ confirmation: SecurePairingConfirmation
  ) throws -> PairingProgress {
    try confirm(confirmation.pairingSessionID) { record in
      guard let transcript = record.transcript else {
        return .sessionNotClaimed
      }
      guard
        let devicePublicKey = try? SecureP256KeyEncoding.signingPublicKey(
          fromX963: transcript.devicePublicKey)
      else {
        return .deviceKeyInvalid
      }
      guard
        SecureTranscriptSignature.isValid(
          confirmation.transcriptSignature,
          for: transcript.canonicalEncoding(),
          publicKey: devicePublicKey
        )
      else {
        return .deviceSignatureInvalid
      }
      if let existing = record.deviceID, existing != confirmation.deviceID {
        return .deviceIdentityMismatch
      }
      record.deviceID = confirmation.deviceID
      record.deviceConfirmed = true
      return nil
    }
  }

  // MARK: - Internals

  /// Runs one confirmation step entirely inside the store's critical section
  /// so concurrent confirmations cannot clobber each other's writes.
  ///
  /// `step` returns a closed reason to reject, or `nil` to accept; on
  /// rejection the attempt is consumed inside the same section.
  private func confirm(
    _ pairingSessionID: UUID,
    _ step: (inout PairingSessionRecord) -> PairingClosedReason?
  ) throws -> PairingProgress {
    sweepExpired()
    let now = monotonicClock()
    let pairedAt = clock()
    var failure: PairingClosedReason?
    var progress = PairingProgress.awaitingConfirmation

    let existing = store.withRecord(pairingSessionID) { record in
      switch record.state {
      case .available:
        failure = .sessionNotClaimed
        return
      case .claimed:
        break
      case .consumed:
        failure = .secretAlreadyConsumed
        return
      case .destroyed(let reason):
        failure = reason
        return
      }
      guard !isExpired(record, at: now) else {
        record.terminate(.destroyed(.sessionExpired))
        failure = .sessionExpired
        return
      }
      if let reason = step(&record) {
        record.terminate(.consumed)
        failure = reason
        return
      }
      guard record.hostConfirmed, record.deviceConfirmed, let deviceID = record.deviceID,
        let transcript = record.transcript
      else {
        return
      }
      progress = .completed(
        PairedDeviceProposal(
          pairingSessionID: record.pairingSessionID,
          deviceID: deviceID,
          devicePublicKeyX963: transcript.devicePublicKey,
          initialGrant: .initial,
          pairedAtEpochSeconds: pairedAt
        )
      )
      record.terminate(.consumed)
    }

    guard existing != nil else { throw PairingClosedReason.unknownPairingSession }
    if let failure { throw failure }
    return progress
  }

  private func entropy(_ count: Int) throws -> Data {
    guard let bytes = try? random.randomBytes(count: count), bytes.count == count else {
      throw PairingClosedReason.entropyUnavailable
    }
    return bytes
  }

  private func isExpired(_ record: PairingSessionRecord) -> Bool {
    isExpired(record, at: monotonicClock())
  }

  private nonisolated func isExpired(
    _ record: PairingSessionRecord,
    at monotonicNow: UInt64
  ) -> Bool {
    monotonicNow >= record.expiresAtMonotonicSeconds
  }

  private func buildTranscript(
    request: SecurePairingRequest,
    record: PairingSessionRecord
  ) throws -> PairingTranscript {
    guard request.mode == .directLAN else {
      throw PairingClosedReason.modeUnsupported
    }
    guard let origin = try? PairingEndpointOrigin(request.endpointOrigin),
      origin == record.endpointOrigin
    else {
      throw PairingClosedReason.endpointOriginMismatch
    }
    guard request.selection == record.selection,
      (try? SecureProtocolNegotiation.accept(request.selection)) != nil
    else {
      throw PairingClosedReason.selectionRejected
    }
    guard (try? SecureP256KeyEncoding.signingPublicKey(fromX963: request.devicePublicKey)) != nil
    else {
      throw PairingClosedReason.deviceKeyInvalid
    }
    return try PairingTranscript(
      pairingSessionID: record.pairingSessionID,
      mode: request.mode,
      endpointOrigin: record.endpointOrigin.normalized,
      selection: record.selection,
      bootstrapSecret: record.bootstrapSecret,
      deviceNonce: request.deviceNonce,
      devicePublicKey: request.devicePublicKey,
      hostID: hostID,
      hostNonce: record.hostNonce,
      hostPublicKey: hostPublicKeyX963,
      hostTLSSPKIFingerprint: record.tlsSPKIFingerprint
    )
  }

  private func hostSignature(over transcript: PairingTranscript) throws -> Data {
    guard let signature = try? signer.signPairingTranscript(transcript.canonicalEncoding()),
      signature.count == SecureTranscriptSignature.byteCount
    else {
      throw PairingClosedReason.hostSignatureUnavailable
    }
    return signature
  }

  /// Spends the attempt without revealing why it ended: every post-claim
  /// failure and every success lands in the same `consumed` state.
  private func consume(_ pairingSessionID: UUID) {
    _ = store.withRecord(pairingSessionID) { record in
      guard case .claimed = record.state else { return }
      record.terminate(.consumed)
    }
  }

  private static func terminalReason(_ state: PairingSessionState) -> PairingClosedReason? {
    switch state {
    case .available: return .sessionNotClaimed
    case .claimed: return nil
    case .consumed: return .secretAlreadyConsumed
    case .destroyed(let reason): return reason
    }
  }

  private static func closedReason(_ error: any Error) -> PairingClosedReason {
    (error as? PairingClosedReason) ?? .malformedRequest
  }
}
