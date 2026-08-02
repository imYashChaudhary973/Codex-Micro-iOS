import CompanionCrypto
import CompanionProtocol
import Foundation

extension PairingFixtures {

  /// Builds a coordinator. `monotonicClock` defaults to the same instance as
  /// the wall clock, so ordinary tests model time simply passing; tests that
  /// need the two to diverge pass a separate monotonic clock.
  static func coordinator(
    clock: TestPairingClock,
    monotonicClock: TestPairingClock? = nil,
    random: ScriptedRandomSource? = nil,
    signer: (any PairingTranscriptSigner)? = nil,
    store: (any PairingSessionStore)? = nil
  ) throws -> PairingCoordinator {
    try PairingCoordinator(
      hostID: CryptoFixtures.hostID,
      hostPublicKeyX963: CryptoFixtures.hostPublicKeyX963,
      signer: signer ?? TestTranscriptSigner(privateKey: CryptoFixtures.hostSigningKey),
      store: store ?? InMemoryPairingSessionStore(),
      random: random ?? hostRandom(),
      clock: clock.closure,
      monotonicClock: (monotonicClock ?? clock).closure
    )
  }

  static func deviceEndpoint(
    clock: TestPairingClock,
    random: ScriptedRandomSource? = nil,
    signer: (any PairingTranscriptSigner)? = nil,
    deviceID: UUID = PairingFixtures.deviceID
  ) throws -> PairingDeviceEndpoint {
    PairingDeviceEndpoint(
      identity: try PairingDeviceIdentity(
        deviceID: deviceID,
        publicKeyX963: CryptoFixtures.devicePublicKeyX963,
        signer: signer ?? TestTranscriptSigner(privateKey: CryptoFixtures.deviceSigningKey)
      ),
      random: random ?? deviceRandom(),
      clock: clock.closure
    )
  }
}
