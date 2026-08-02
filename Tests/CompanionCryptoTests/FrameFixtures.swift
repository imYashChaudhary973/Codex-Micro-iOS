import CompanionCrypto
import Foundation

extension CryptoFixtures {
  static func frameKeys() throws -> SecureDirectionalFrameKeys {
    try SecureSessionKeySchedule.frameKeys(
      inputKeyMaterial: keyScheduleIKM,
      sessionTranscriptHash: sessionTranscript().canonicalHash(),
      selection: selection()
    )
  }

  static let framePlaintext0 = Data("codex-micro frame vector 0".utf8)
  static let framePlaintext1 = Data("codex-micro frame vector 1".utf8)
}
