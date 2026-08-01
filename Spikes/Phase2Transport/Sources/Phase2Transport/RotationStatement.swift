import Foundation

public enum RotationStatementError: Error, Equatable {
  case currentSPKIMismatch
  case incorrectIdentityRole
  case invalidHashLength
  case invalidValidity
  case nextSPKIMismatch
  case rollback
  case sameKey
  case signatureInvalid
}

public struct HostSignedRotationStatement: Equatable, Sendable {
  public static let formatVersion: UInt8 = 1

  public let generation: UInt64
  public let notBeforeMilliseconds: Int64
  public let notAfterMilliseconds: Int64
  public let previousSPKISHA256: Data
  public let nextSPKISHA256: Data

  public init(
    generation: UInt64,
    notBeforeMilliseconds: Int64,
    notAfterMilliseconds: Int64,
    previousSPKISHA256: Data,
    nextSPKISHA256: Data
  ) throws {
    guard previousSPKISHA256.count == 32, nextSPKISHA256.count == 32 else {
      throw RotationStatementError.invalidHashLength
    }
    guard notBeforeMilliseconds < notAfterMilliseconds else {
      throw RotationStatementError.invalidValidity
    }
    guard !P256SPKI.matches(previousSPKISHA256, nextSPKISHA256) else {
      throw RotationStatementError.sameKey
    }
    self.generation = generation
    self.notBeforeMilliseconds = notBeforeMilliseconds
    self.notAfterMilliseconds = notAfterMilliseconds
    self.previousSPKISHA256 = previousSPKISHA256
    self.nextSPKISHA256 = nextSPKISHA256
  }

  public var canonicalData: Data {
    var data = Data("P2RT".utf8)
    data.append(Self.formatVersion)
    data.appendBigEndian(generation)
    data.appendBigEndian(UInt64(bitPattern: notBeforeMilliseconds))
    data.appendBigEndian(UInt64(bitPattern: notAfterMilliseconds))
    data.appendBigEndian(UInt16(previousSPKISHA256.count))
    data.append(previousSPKISHA256)
    data.appendBigEndian(UInt16(nextSPKISHA256.count))
    data.append(nextSPKISHA256)
    return data
  }

  public func validate(previousGeneration: UInt64, nowMilliseconds: Int64) throws {
    guard generation > previousGeneration else { throw RotationStatementError.rollback }
    guard nowMilliseconds >= notBeforeMilliseconds, nowMilliseconds <= notAfterMilliseconds else {
      throw RotationStatementError.invalidValidity
    }
  }

  public func signed(by hostIdentity: KeychainIdentity) throws -> SignedRotationStatement {
    guard hostIdentity.role == .host else {
      throw RotationStatementError.incorrectIdentityRole
    }
    return SignedRotationStatement(
      statement: self,
      signature: try hostIdentity.sign(canonicalData)
    )
  }
}

public struct SignedRotationStatement: Equatable, Sendable {
  public let statement: HostSignedRotationStatement
  public let signature: Data

  public init(statement: HostSignedRotationStatement, signature: Data) {
    self.statement = statement
    self.signature = signature
  }

  public func verify(
    hostIdentity: KeychainIdentity,
    previousGeneration: UInt64,
    nowMilliseconds: Int64,
    expectedCurrentSPKISHA256: Data,
    presentedNextSPKISHA256: Data
  ) throws {
    guard hostIdentity.role == .host else {
      throw RotationStatementError.incorrectIdentityRole
    }
    guard expectedCurrentSPKISHA256.count == 32, presentedNextSPKISHA256.count == 32 else {
      throw RotationStatementError.invalidHashLength
    }
    guard P256SPKI.matches(statement.previousSPKISHA256, expectedCurrentSPKISHA256) else {
      throw RotationStatementError.currentSPKIMismatch
    }
    guard P256SPKI.matches(statement.nextSPKISHA256, presentedNextSPKISHA256) else {
      throw RotationStatementError.nextSPKIMismatch
    }
    try statement.validate(previousGeneration: previousGeneration, nowMilliseconds: nowMilliseconds)
    guard hostIdentity.verify(signature: signature, message: statement.canonicalData) else {
      throw RotationStatementError.signatureInvalid
    }
  }
}

extension Data {
  fileprivate mutating func appendBigEndian<T: FixedWidthInteger>(_ value: T) {
    var bigEndian = value.bigEndian
    Swift.withUnsafeBytes(of: &bigEndian) { append(contentsOf: $0) }
  }
}
