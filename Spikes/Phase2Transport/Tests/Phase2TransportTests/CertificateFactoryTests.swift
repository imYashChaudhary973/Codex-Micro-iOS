import Foundation
import Security
import Testing
import X509

@testable import Phase2Transport

@Suite(.serialized)
struct CertificateFactoryTests {
  @Test
  func secKeyCertificateBuildsSecIdentityAndRenewalPreservesSPKI() throws {
    let identity = try TestOnlyEphemeralIdentityFactory.make()
    let start = Date(timeIntervalSince1970: 1_800_000_000)
    let first = try ContentNeutralCertificateFactory.makeSelfSigned(
      identity: identity,
      notValidBefore: start,
      notValidAfter: start.addingTimeInterval(3_600)
    )
    let renewed = try ContentNeutralCertificateFactory.makeSelfSigned(
      identity: identity,
      notValidBefore: start.addingTimeInterval(1_800),
      notValidAfter: start.addingTimeInterval(7_200)
    )

    #expect(P256SPKI.matches(first.spkiDER, identity.spkiDER))
    #expect(P256SPKI.matches(first.spkiDER, renewed.spkiDER))
    #expect(
      SecCertificateCopyData(first.secCertificate) != SecCertificateCopyData(renewed.secCertificate)
    )

    var copiedKey: SecKey?
    #expect(SecIdentityCopyPrivateKey(first.secIdentity, &copiedKey) == errSecSuccess)
    #expect(copiedKey != nil)
    if let copiedKey {
      var error: Unmanaged<CFError>?
      #expect(SecKeyCopyExternalRepresentation(copiedKey, &error) == nil)
      _ = error?.takeRetainedValue()
    }
  }

  @Test
  func certificateFactoryRejectsHostRole() throws {
    let host = try TestOnlyEphemeralIdentityFactory.make(role: .host)
    let start = Date(timeIntervalSince1970: 1_800_000_000)
    #expect(throws: CertificateFactoryError.incorrectIdentityRole) {
      _ = try ContentNeutralCertificateFactory.makeSelfSigned(
        identity: host,
        notValidBefore: start,
        notValidAfter: start.addingTimeInterval(3_600)
      )
    }
  }

  @Test
  func newKeyChangesSPKI() throws {
    let first = try TestOnlyEphemeralIdentityFactory.make()
    let second = try TestOnlyEphemeralIdentityFactory.make()
    #expect(!P256SPKI.matches(first.spkiDER, second.spkiDER))
  }
}
