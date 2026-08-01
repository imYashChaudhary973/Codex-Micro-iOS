import CompanionProtocol
import CryptoKit
import Darwin
import Foundation
import SQLite3
import Security

public enum PersistentCommandLedgerError: Error, Equatable, Sendable {
  case databaseUnavailable
  case unsupportedSchemaVersion
  case invalidRecord
  case encryptionFailed
}

public enum LedgerKeyStoreError: Error, Equatable, Sendable {
  case invalidConfiguration
  case keychainFailure
  case invalidStoredKey
  case randomGenerationFailed
}

public struct KeychainLedgerKeyProvider: Sendable {
  private let service: String
  private let account: String

  public init(
    service: String = "com.codexmicro.command-ledger",
    account: String = "database-key-v1"
  ) throws {
    guard !service.isEmpty, !account.isEmpty else {
      throw LedgerKeyStoreError.invalidConfiguration
    }
    self.service = service
    self.account = account
  }

  public func loadOrCreateKey() throws -> SymmetricKey {
    if let existing = try readKey() { return SymmetricKey(data: existing) }

    var bytes = Data(count: 32)
    let randomStatus = bytes.withUnsafeMutableBytes { buffer in
      SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
    }
    guard randomStatus == errSecSuccess else {
      throw LedgerKeyStoreError.randomGenerationFailed
    }

    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
      kSecValueData as String: bytes,
    ]
    let status = SecItemAdd(query as CFDictionary, nil)
    if status == errSecDuplicateItem, let existing = try readKey() {
      return SymmetricKey(data: existing)
    }
    guard status == errSecSuccess else { throw LedgerKeyStoreError.keychainFailure }
    return SymmetricKey(data: bytes)
  }

  private func readKey() throws -> Data? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecReturnData as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound { return nil }
    guard status == errSecSuccess, let data = result as? Data else {
      throw LedgerKeyStoreError.keychainFailure
    }
    guard data.count == 32 else { throw LedgerKeyStoreError.invalidStoredKey }
    return data
  }
}

public actor PersistentCommandLedger {
  private var records: [UUID: CommandLedgerRecord]
  private let storage: EncryptedLedgerStorage

  public init(
    databaseURL: URL,
    key: SymmetricKey,
    recoveryDate: Date = Date()
  ) throws {
    let storage = try EncryptedLedgerStorage(databaseURL: databaseURL, key: key)
    var records = try storage.loadAll()
    for commandID in Array(records.keys) {
      guard var record = records[commandID], !record.state.isTerminal else { continue }
      record.markOutcomeUnknown(at: recoveryDate)
      try storage.save(record)
      records[commandID] = record
    }
    self.storage = storage
    self.records = records
  }

  public static func keychainBacked(
    databaseURL: URL,
    keyService: String = "com.codexmicro.command-ledger",
    keyAccount: String = "database-key-v1",
    recoveryDate: Date = Date()
  ) throws -> PersistentCommandLedger {
    let provider = try KeychainLedgerKeyProvider(
      service: keyService,
      account: keyAccount
    )
    return try PersistentCommandLedger(
      databaseURL: databaseURL,
      key: provider.loadOrCreateKey(),
      recoveryDate: recoveryDate
    )
  }

  public func register(
    deviceID: UUID,
    command: ClientCommand,
    at date: Date = Date()
  ) throws -> CommandRegistration {
    let digest = try CommandFingerprint.digest(command)
    if let existing = records[command.commandID] {
      guard existing.deviceID == deviceID, existing.requestDigest == digest else {
        throw CommandLedgerError.commandIDCollision
      }
      return .replay(existing)
    }

    let record = CommandLedgerRecord(
      commandID: command.commandID,
      deviceID: deviceID,
      commandKind: command.body.kind,
      requestDigest: digest,
      state: .submitting,
      createdAt: date,
      updatedAt: date
    )
    try storage.save(record)
    records[command.commandID] = record
    return .accepted(record)
  }

  public func markSubmitted(
    commandID: UUID,
    threadID: String? = nil,
    turnID: String? = nil,
    requestID: String? = nil,
    at date: Date = Date()
  ) throws {
    guard var record = records[commandID] else { throw CommandLedgerError.missingCommand }
    guard record.state == .submitting else { throw CommandLedgerError.invalidTransition }
    record.markSubmitted(
      threadID: threadID,
      turnID: turnID,
      requestID: requestID,
      at: date
    )
    try storage.save(record)
    records[commandID] = record
  }

  public func finish(
    commandID: UUID,
    state: CommandLifecycleState,
    resultCode: CommandResultCode,
    at date: Date = Date()
  ) throws {
    guard [.succeeded, .failed, .declined].contains(state) else {
      throw CommandLedgerError.invalidTerminalState
    }
    guard var record = records[commandID] else { throw CommandLedgerError.missingCommand }
    guard record.state == .submitting || record.state == .submitted else {
      throw CommandLedgerError.invalidTransition
    }
    record.finish(state: state, resultCode: resultCode, at: date)
    try storage.save(record)
    records[commandID] = record
  }

  public func markInFlightOutcomesUnknown(at date: Date = Date()) throws {
    for commandID in Array(records.keys) {
      guard var record = records[commandID], !record.state.isTerminal else { continue }
      record.markOutcomeUnknown(at: date)
      try storage.save(record)
      records[commandID] = record
    }
  }

  public func markOutcomeUnknown(
    commandID: UUID,
    resultCode: CommandResultCode = .bridgeRestartedBeforeOutcome,
    at date: Date = Date()
  ) throws {
    guard var record = records[commandID] else { throw CommandLedgerError.missingCommand }
    guard !record.state.isTerminal else { throw CommandLedgerError.invalidTransition }
    record.markOutcomeUnknown(resultCode: resultCode, at: date)
    try storage.save(record)
    records[commandID] = record
  }

  public func record(commandID: UUID) -> CommandLedgerRecord? {
    records[commandID]
  }

  public func purgeTerminalRecords(olderThan date: Date) throws {
    let expiredIDs = records.values.filter {
      $0.state.isTerminal && $0.updatedAt < date
    }.map(\.commandID)
    for commandID in expiredIDs {
      try storage.delete(commandID: commandID)
      records.removeValue(forKey: commandID)
    }
  }
}

extension PersistentCommandLedger: CommandLedgering {}

private final class EncryptedLedgerStorage: @unchecked Sendable {
  private static let schemaVersion: Int32 = 1
  private static let maximumRecordSize = 1_048_576
  private let databaseURL: URL
  private let key: SymmetricKey
  private var database: OpaquePointer?

  init(databaseURL: URL, key: SymmetricKey) throws {
    self.databaseURL = databaseURL
    self.key = key

    let parent = databaseURL.deletingLastPathComponent()
    try FileManager.default.createDirectory(
      at: parent,
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700]
    )

    var opened: OpaquePointer?
    let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
    guard sqlite3_open_v2(databaseURL.path, &opened, flags, nil) == SQLITE_OK,
      let opened
    else {
      if let opened { sqlite3_close(opened) }
      throw PersistentCommandLedgerError.databaseUnavailable
    }
    database = opened

    do {
      sqlite3_busy_timeout(opened, 2_000)
      try execute("PRAGMA journal_mode=DELETE")
      try execute("PRAGMA secure_delete=ON")
      let version = try userVersion()
      guard version == 0 || version == Self.schemaVersion else {
        throw PersistentCommandLedgerError.unsupportedSchemaVersion
      }
      if version == 0 {
        try execute(
          """
          CREATE TABLE ledger_records (
            command_id TEXT PRIMARY KEY NOT NULL,
            sealed_record BLOB NOT NULL,
            updated_at REAL NOT NULL
          )
          """
        )
        try execute("PRAGMA user_version=\(Self.schemaVersion)")
      }
      guard chmod(databaseURL.path, S_IRUSR | S_IWUSR) == 0 else {
        throw PersistentCommandLedgerError.databaseUnavailable
      }
      var values = URLResourceValues()
      values.isExcludedFromBackup = true
      var mutableURL = databaseURL
      try mutableURL.setResourceValues(values)
    } catch {
      sqlite3_close(opened)
      database = nil
      throw error
    }
  }

  deinit {
    if let database { sqlite3_close(database) }
  }

  func loadAll() throws -> [UUID: CommandLedgerRecord] {
    let statement = try prepare(
      "SELECT command_id, sealed_record FROM ledger_records ORDER BY command_id"
    )
    defer { sqlite3_finalize(statement) }

    var records: [UUID: CommandLedgerRecord] = [:]
    while sqlite3_step(statement) == SQLITE_ROW {
      guard let idBytes = sqlite3_column_text(statement, 0) else {
        throw PersistentCommandLedgerError.invalidRecord
      }
      let commandIDString = String(cString: idBytes)
      let byteCount = Int(sqlite3_column_bytes(statement, 1))
      guard byteCount > 0, byteCount <= Self.maximumRecordSize,
        let bytes = sqlite3_column_blob(statement, 1)
      else {
        throw PersistentCommandLedgerError.invalidRecord
      }
      let sealedData = Data(bytes: bytes, count: byteCount)
      let record = try open(sealedData, commandID: commandIDString)
      guard record.commandID.uuidString.lowercased() == commandIDString,
        records[record.commandID] == nil
      else {
        throw PersistentCommandLedgerError.invalidRecord
      }
      records[record.commandID] = record
    }
    guard sqlite3_errcode(database) == SQLITE_OK || sqlite3_errcode(database) == SQLITE_DONE else {
      throw PersistentCommandLedgerError.databaseUnavailable
    }
    return records
  }

  func save(_ record: CommandLedgerRecord) throws {
    let commandID = record.commandID.uuidString.lowercased()
    let sealedData = try seal(record, commandID: commandID)
    let statement = try prepare(
      """
      INSERT INTO ledger_records(command_id, sealed_record, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(command_id) DO UPDATE SET
        sealed_record = excluded.sealed_record,
        updated_at = excluded.updated_at
      """
    )
    defer { sqlite3_finalize(statement) }
    try bind(commandID, at: 1, to: statement)
    try bind(sealedData, at: 2, to: statement)
    guard sqlite3_bind_double(statement, 3, record.updatedAt.timeIntervalSince1970) == SQLITE_OK,
      sqlite3_step(statement) == SQLITE_DONE
    else {
      throw PersistentCommandLedgerError.databaseUnavailable
    }
  }

  func delete(commandID: UUID) throws {
    let statement = try prepare("DELETE FROM ledger_records WHERE command_id = ?")
    defer { sqlite3_finalize(statement) }
    try bind(commandID.uuidString.lowercased(), at: 1, to: statement)
    guard sqlite3_step(statement) == SQLITE_DONE else {
      throw PersistentCommandLedgerError.databaseUnavailable
    }
  }

  private func seal(_ record: CommandLedgerRecord, commandID: String) throws -> Data {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .millisecondsSince1970
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    do {
      let plaintext = try encoder.encode(record)
      let sealed = try AES.GCM.seal(
        plaintext,
        using: key,
        authenticating: Data(commandID.utf8)
      )
      guard let combined = sealed.combined else {
        throw PersistentCommandLedgerError.encryptionFailed
      }
      return combined
    } catch let error as PersistentCommandLedgerError {
      throw error
    } catch {
      throw PersistentCommandLedgerError.encryptionFailed
    }
  }

  private func open(_ data: Data, commandID: String) throws -> CommandLedgerRecord {
    do {
      let box = try AES.GCM.SealedBox(combined: data)
      let plaintext = try AES.GCM.open(
        box,
        using: key,
        authenticating: Data(commandID.utf8)
      )
      let decoder = JSONDecoder()
      decoder.dateDecodingStrategy = .millisecondsSince1970
      return try decoder.decode(CommandLedgerRecord.self, from: plaintext)
    } catch {
      throw PersistentCommandLedgerError.invalidRecord
    }
  }

  private func execute(_ sql: String) throws {
    guard sqlite3_exec(database, sql, nil, nil, nil) == SQLITE_OK else {
      throw PersistentCommandLedgerError.databaseUnavailable
    }
  }

  private func userVersion() throws -> Int32 {
    let statement = try prepare("PRAGMA user_version")
    defer { sqlite3_finalize(statement) }
    guard sqlite3_step(statement) == SQLITE_ROW else {
      throw PersistentCommandLedgerError.databaseUnavailable
    }
    return sqlite3_column_int(statement, 0)
  }

  private func prepare(_ sql: String) throws -> OpaquePointer {
    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(database, sql, -1, &statement, nil) == SQLITE_OK,
      let statement
    else {
      throw PersistentCommandLedgerError.databaseUnavailable
    }
    return statement
  }

  private func bind(_ value: String, at index: Int32, to statement: OpaquePointer) throws {
    guard sqlite3_bind_text(statement, index, value, -1, sqliteTransient) == SQLITE_OK else {
      throw PersistentCommandLedgerError.databaseUnavailable
    }
  }

  private func bind(_ value: Data, at index: Int32, to statement: OpaquePointer) throws {
    let result = value.withUnsafeBytes { buffer in
      sqlite3_bind_blob(statement, index, buffer.baseAddress, Int32(buffer.count), sqliteTransient)
    }
    guard result == SQLITE_OK else { throw PersistentCommandLedgerError.databaseUnavailable }
  }
}

private let sqliteTransient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
