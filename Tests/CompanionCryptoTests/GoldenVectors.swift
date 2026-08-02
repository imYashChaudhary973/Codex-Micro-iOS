/// Byte-exact golden vectors for the deterministic CompanionCrypto
/// primitives, produced from the fixed `CryptoFixtures` inputs. Any change to
/// a canonical layout, domain separator, HKDF label, nonce construction, or
/// SAS derivation breaks these fixtures and requires a new reviewed vector
/// set (and a new context version).
enum GoldenVectors {
  static let pairingEncodingHex =
    "010021636f6465782d6d6963726f2f70616972696e672d7472616e7363726970742f7631001011111111"
    + "111111111111111111111111000a6469726563742d6c616e00177773733a2f2f3139322e3136382e342e"
    + "32303a38343433000100010003000f6f6273657276652d73796e632d763100157468726561642d726561"
    + "642d637572736f722d763100117475726e2d696e746572727570742d76310020b5b5b5b5b5b5b5b5b5b5"
    + "b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b50020d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1"
    + "d1d1d1d1d1d1d1d1d1d1d1d1d1d10041041f140146bfb1b251f84f4ddbe0d4cdcfd77afd984a9520e357"
    + "94021f8312bb9eec995a08b1fa7704df3dcc0b50a9665263fb7711f95f9f8a449c5096e47c892b001022"
    + "2222222222222222222222222222220020e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2"
    + "e2e2e2e2e2e2e2004104515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f"
    + "4536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f93540020480b0dcd0b0547fb"
    + "175a4acb7ee567f5e44f362ce272623bd3ec910c939c22f9"

  static let pairingHashHex =
    "e9f634710acadddb41eb2f3ef41d869abaa02ec0141b710cd6af625aa707aa3e"

  static let sessionEncodingHex =
    "010021636f6465782d6d6963726f2f73657373696f6e2d7472616e7363726970742f7631001044444444"
    + "444444444444444444444444001033333333333333333333333333333333000100010003000f6f627365"
    + "7276652d73796e632d763100157468726561642d726561642d637572736f722d763100117475726e2d69"
    + "6e746572727570742d7631004104261efbd3550cf068ef013ed7366ba32f5d6fe557b4b2abce8ade58cb"
    + "a168a55e1788a0b29a56a6abec4084c0c96bd3dcbca6b507f35dbea9e985708479d8bdc90020c4c4c4c4"
    + "c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4004104bd5714b9c20400411f1e51"
    + "dbff63647f05d1d70b55fc200c6cad10c2f4614dc1e5048562f731f54573c04224d973a916a59f526a82"
    + "68076fc1cfa92a5f143f190020f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7"
    + "f7f7f7000000000000000700000000000000030000000000000001"

  static let sessionHashHex =
    "2a11c4bd769624ac51b6e18a323f2b8dcd85c274a6c0f54033d5fc859c1cb6d1"

  /// Byte-exact canonical pairing QR payload (ADR §12 allowlist) built from
  /// the fixed pairing fixtures. Any added, removed, or reordered field
  /// breaks this vector.
  static let pairingQRPayloadHex =
    "010019636f6465782d6d6963726f2f70616972696e672d71722f7631000100010003000f6f627365"
    + "7276652d73796e632d763100157468726561642d726561642d637572736f722d763100117475726e"
    + "2d696e746572727570742d763100102222222222222222222222222222222200177773733a2f2f31"
    + "39322e3136382e342e32303a383434330020f1d59449b727165de732bf283338122b99628a615918"
    + "fedc67d878fffcf47da70020480b0dcd0b0547fb175a4acb7ee567f5e44f362ce272623bd3ec910c"
    + "939c22f90010111111111111111111111111111111110020b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5"
    + "b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b500000000688bebac"

  static let rotationEncodingHex =
    "010021636f6465782d6d6963726f2f726f746174696f6e2d73746174656d656e742f7631000000000000"
    + "00030020480b0dcd0b0547fb175a4acb7ee567f5e44f362ce272623bd3ec910c939c22f900202294b52f"
    + "439bad155ee900c926c0ba853d3af73172e1eb10a430d83d654dac8e00000000688bea8000000000688d"
    + "3c00"

  /// One recorded host signature over the golden pairing encoding. ECDSA
  /// signing is randomized, so this pins verification, not signing.
  static let hostPairingSignatureHex =
    "30be5e589fa7c8f54b0c9166cbd2ddbe7edb1651ae133402c88ed4f354507e7e36a39d7f9043b4dc7b06"
    + "e3180011eb155eff4899eb05f584ca17d98b55034621"

  /// One recorded host signature over the golden rotation encoding.
  static let hostRotationSignatureHex =
    "13f0bed8f40b47b346abb65331610d2488720cee49fdb0a7e543af24a8a99fc14205769c5c048695712c"
    + "ab924b35a95d65e84232e75aa5bf7f5fd4a2bebbad31"

  /// HKDF-SHA256 directional keys from the fixed IKM, the golden session
  /// transcript hash as salt, and the exact negotiated tuple labels.
  static let clientToServerKeyHex =
    "85c21bd6481f3f90dc4cd00853942bf1fa80ec2fe4511b8022eff5d344800811"
  static let serverToClientKeyHex =
    "9a9a47ceda9d2caab80a553609706a21e939b259334254380c77045b91a234ce"

  /// ECDH shared secret between the fixed client and server ephemerals.
  static let sharedSecretHex =
    "4a418b195ee7fed6e737803ab53cb8750b71c09335a70b030c70921b221664b7"

  /// SPKI fingerprint of the fixed device key. Cross-checked externally: the
  /// same DER parses as a valid EC public key and its SHA-256 matches.
  static let deviceSPKIFingerprintHex =
    "68a0f2d46bcfd04bfcdb78c90597aec21bd20f88093756b1eca5036b460bbe73"

  static let sasIndices: [UInt16] = [1810, 125, 1393, 2037, 1338, 1258]
  static let sasDisplay = "1810-0125-1393-2037-1338-1258"

  /// Sealed client-to-server frames for counters 0 and 1 under the golden
  /// client-to-server key and fixed connection ID.
  static let frame0Hex =
    "01633273315555555555555555555555555555555500000000000000000000001a216596de6204506d9d"
    + "6f917a6fe5335f2ee0fab82b86596b78635516035f792bdbefd6f2c706c7057b17"
  static let frame1Hex =
    "01633273315555555555555555555555555555555500000000000000010000001a4887a4a7b699624868"
    + "ce5fbba5736fe022f8e06beeb2e376e5d26203585e7061f7c3b6957a47e537ba03"
}
