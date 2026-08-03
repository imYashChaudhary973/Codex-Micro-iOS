import CompanionCrypto
import CryptoKit
import Foundation
import NIOCore
import Network
import Security
import X509

@testable import MacBridgeServer

enum EphemeralTLSIdentity {
  static func make() throws -> (identity: ListenerServingIdentity, spkiFingerprint: Data) {
    let attributes: [CFString: Any] = [
      kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits: 256,
      kSecAttrIsPermanent: false,
    ]
    var error: Unmanaged<CFError>?
    guard let secKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
      throw BridgeCertificateError.assemblyFailed
    }
    let signer = try Certificate.PrivateKey(secKey)
    let name = try DistinguishedName {
      CommonName(BridgeCertificateProfile.subjectCommonName)
    }
    let extensions = try Certificate.Extensions {
      Critical(BasicConstraints.notCertificateAuthority)
      Critical(KeyUsage(digitalSignature: true))
      try ExtendedKeyUsage([.serverAuth])
      SubjectAlternativeNames([
        .dnsName(BridgeCertificateProfile.subjectAlternativeDNSName)
      ])
    }
    let now = Date()
    let certificate = try Certificate(
      version: .v3,
      serialNumber: Certificate.SerialNumber(),
      publicKey: signer.publicKey,
      notValidBefore: now.addingTimeInterval(-60),
      notValidAfter: now.addingTimeInterval(3_600),
      issuer: name,
      subject: name,
      signatureAlgorithm: .ecdsaWithSHA256,
      extensions: extensions,
      issuerPrivateKey: signer
    )
    let secCertificate = try SecCertificate.makeWithCertificate(certificate)
    guard let secIdentity = SecIdentityCreate(nil, secCertificate, secKey) else {
      throw BridgeCertificateError.assemblyFailed
    }
    let point = Data(certificate.publicKey.subjectPublicKeyInfoBytes)
    let spkiDER = try SPKIFingerprint.subjectPublicKeyInfoDER(x963PublicKey: point)
    let fingerprint = Data(SHA256.hash(data: spkiDER))
    return (
      ListenerServingIdentity.testOnlyAssembled(
        secIdentity: secIdentity,
        spkiFingerprint: fingerprint
      ),
      fingerprint
    )
  }
}

/// Injectable prerequisite failure marker.
struct StubTLSIdentityProvider: ListenerTLSIdentityProviding {
  let identity: ListenerServingIdentity?

  func servingIdentity() async throws -> ListenerServingIdentity {
    guard let identity else { throw StubPrerequisiteFailure() }
    return identity
  }
}

struct StubGrantAuthorityProbe: ListenerGrantAuthorityProbing {
  var available = true

  func assertGrantAuthorityAvailable() async throws {
    guard available else { throw StubPrerequisiteFailure() }
  }
}

struct StubPolicyProbe: ListenerPolicyProbing {
  var available = true

  func assertPolicyAvailable() async throws {
    guard available else { throw StubPrerequisiteFailure() }
  }
}

struct StubCodexProbe: ListenerCodexSupportProbing {
  var supported = true

  func assertCodexSupported() async throws {
    guard supported else { throw StubPrerequisiteFailure() }
  }
}

/// Live-interface resolver double. It always answers `nil`, which the
/// test-only loopback binding tolerates and a production-kind binding must
/// treat as fail-closed.
struct NilLiveInterfaceResolver: ListenerLiveInterfaceResolving {
  func resolveLiveInterface(bsdName: String) async -> NWInterface? { nil }
}

/// Deterministic handshake seam. It records what crossed the gate and
/// replays a scripted outcome, so the transport's allowlist and ceilings are
/// tested without any real grant, journal, or Codex state.
extension ListenerPrerequisites {
  /// A prerequisite set where every probe passes.
  static func allPassing(identity: ListenerServingIdentity) -> ListenerPrerequisites {
    ListenerPrerequisites(
      identity: StubTLSIdentityProvider(identity: identity),
      grantAuthority: StubGrantAuthorityProbe(),
      policy: StubPolicyProbe(),
      codex: StubCodexProbe(),
      liveInterface: NilLiveInterfaceResolver()
    )
  }
}

/// Builds a well-formed upgrade request head; individual tests mutate one
/// field at a time so a rejection is attributable to exactly that field.
