import CodexAppServer
import CryptoKit
import Foundation

public struct CodexCompatibilityManifest: Equatable, Sendable {
  public let codexVersion: String
  public let schemaDigest: String

  public init(codexVersion: String, schemaDigest: String) {
    self.codexVersion = codexVersion
    self.schemaDigest = schemaDigest
  }
}

public struct CodexCompatibilityReport: Equatable, Sendable {
  public let codexVersion: String
  public let schemaDigest: String

  public init(codexVersion: String, schemaDigest: String) {
    self.codexVersion = codexVersion
    self.schemaDigest = schemaDigest
  }
}

public enum CodexCompatibilityDecision: Equatable, Sendable {
  case supported
  case unsupportedVersion
  case schemaMismatch
}

public struct CodexCompatibilityPolicy: Sendable {
  public static let phase1 = CodexCompatibilityPolicy(
    supportedManifests: [
      CodexCompatibilityManifest(
        codexVersion: "0.146.0",
        schemaDigest: "e4298390ccd84fd0458c9eec49588c3041571c0eea19c301693f4e9bc5ada973"
      )
    ]
  )

  public let supportedManifests: [CodexCompatibilityManifest]

  public init(supportedManifests: [CodexCompatibilityManifest]) {
    self.supportedManifests = supportedManifests
  }

  public func evaluate(_ report: CodexCompatibilityReport) -> CodexCompatibilityDecision {
    let versionMatches = supportedManifests.filter {
      $0.codexVersion == report.codexVersion
    }
    guard !versionMatches.isEmpty else { return .unsupportedVersion }
    guard versionMatches.contains(where: { $0.schemaDigest == report.schemaDigest }) else {
      return .schemaMismatch
    }
    return .supported
  }
}

public enum CodexCompatibilityProbeError: Error, Equatable, Sendable {
  case commandFailed
  case invalidVersionOutput
  case invalidSchemaBundle
  case schemaBundleTooLarge
  case unsupportedPlatform
}

public protocol CodexCompatibilityProbing: Sendable {
  func probe() async throws -> CodexCompatibilityReport
}

public struct SystemCodexCompatibilityProbe: CodexCompatibilityProbing {
  private let codexExecutableURL: URL

  public init(codexExecutableURL: URL) {
    self.codexExecutableURL = codexExecutableURL
  }

  public func probe() async throws -> CodexCompatibilityReport {
    #if os(macOS)
      let versionOutput = try ProcessRunner.run(
        executableURL: codexExecutableURL,
        arguments: ["--version"]
      )
      let version = try Self.parseVersion(versionOutput)

      let schemaDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent("codex-micro-schema-\(UUID().uuidString)", isDirectory: true)
      try FileManager.default.createDirectory(
        at: schemaDirectory,
        withIntermediateDirectories: false
      )
      defer { try? FileManager.default.removeItem(at: schemaDirectory) }

      _ = try ProcessRunner.run(
        executableURL: codexExecutableURL,
        arguments: [
          "app-server", "generate-json-schema", "--out", schemaDirectory.path,
        ]
      )
      let digest = try CodexSchemaDigest.digest(directory: schemaDirectory)
      return CodexCompatibilityReport(codexVersion: version, schemaDigest: digest)
    #else
      throw CodexCompatibilityProbeError.unsupportedPlatform
    #endif
  }

  static func parseVersion(_ output: String) throws -> String {
    let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
    let prefix = "codex-cli "
    guard trimmed.hasPrefix(prefix) else {
      throw CodexCompatibilityProbeError.invalidVersionOutput
    }

    let version = String(trimmed.dropFirst(prefix.count))
    let allowed = CharacterSet(
      charactersIn: "0123456789.-+abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
    guard !version.isEmpty, version.rangeOfCharacter(from: allowed.inverted) == nil else {
      throw CodexCompatibilityProbeError.invalidVersionOutput
    }
    return version
  }
}

public enum CodexExecutableLocator {
  public static func locate() throws -> URL {
    #if os(macOS)
      let output = try ProcessRunner.run(
        executableURL: URL(fileURLWithPath: "/usr/bin/which"),
        arguments: ["codex"]
      )
      let path = output.trimmingCharacters(in: .whitespacesAndNewlines)
      guard path.hasPrefix("/"), !path.contains("\n") else {
        throw CodexCompatibilityProbeError.commandFailed
      }
      let url = URL(fileURLWithPath: path).resolvingSymlinksInPath()
      let values = try url.resourceValues(forKeys: [.isRegularFileKey])
      guard values.isRegularFile == true, FileManager.default.isExecutableFile(atPath: url.path)
      else {
        throw CodexCompatibilityProbeError.commandFailed
      }
      return url
    #else
      throw CodexCompatibilityProbeError.unsupportedPlatform
    #endif
  }
}

public enum CodexSchemaDigest {
  private static let maximumFileCount = 4_096
  private static let maximumFileSize = 16 * 1_024 * 1_024
  private static let maximumBundleSize = 128 * 1_024 * 1_024

  public static func digest(directory: URL) throws -> String {
    let fileManager = FileManager.default
    let keys: Set<URLResourceKey> = [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey]
    let relativePaths = try fileManager.subpathsOfDirectory(atPath: directory.path)
    guard relativePaths.count <= maximumFileCount * 2 else {
      throw CodexCompatibilityProbeError.schemaBundleTooLarge
    }
    guard !relativePaths.contains(where: { $0.hasPrefix(".") }) else {
      throw CodexCompatibilityProbeError.invalidSchemaBundle
    }

    var files: [(path: String, url: URL, size: Int)] = []
    var totalSize = 0
    for relativePath in relativePaths {
      let components = relativePath.split(separator: "/", omittingEmptySubsequences: false)
      guard !components.isEmpty, !components.contains(".."), !components.contains("") else {
        throw CodexCompatibilityProbeError.invalidSchemaBundle
      }
      let fileURL = directory.appendingPathComponent(relativePath)
      let values = try fileURL.resourceValues(forKeys: keys)
      if values.isSymbolicLink == true {
        throw CodexCompatibilityProbeError.invalidSchemaBundle
      }
      guard values.isRegularFile == true else { continue }
      guard fileURL.pathExtension == "json", let size = values.fileSize else {
        throw CodexCompatibilityProbeError.invalidSchemaBundle
      }
      guard size <= maximumFileSize else {
        throw CodexCompatibilityProbeError.schemaBundleTooLarge
      }

      totalSize += size
      guard totalSize <= maximumBundleSize else {
        throw CodexCompatibilityProbeError.schemaBundleTooLarge
      }
      guard !relativePath.isEmpty, !relativePath.hasPrefix("../") else {
        throw CodexCompatibilityProbeError.invalidSchemaBundle
      }
      files.append((relativePath, fileURL, size))
      guard files.count <= maximumFileCount else {
        throw CodexCompatibilityProbeError.schemaBundleTooLarge
      }
    }
    guard !files.isEmpty else {
      throw CodexCompatibilityProbeError.invalidSchemaBundle
    }

    var bundleHasher = SHA256()
    for file in files.sorted(by: { $0.path < $1.path }) {
      let data = try Data(contentsOf: file.url, options: [.mappedIfSafe])
      let canonicalData = try canonicalize(data)

      update(&bundleHasher, with: Data(file.path.utf8))
      update(&bundleHasher, with: canonicalData)
    }
    return hex(bundleHasher.finalize())
  }

  static func canonicalize(_ data: Data) throws -> Data {
    let json = try JSONDecoder().decode(JSONValue.self, from: data)
    return try CanonicalJSON.data(for: json)
  }

  private static func update(_ hasher: inout SHA256, with data: Data) {
    var length = UInt64(data.count).bigEndian
    withUnsafeBytes(of: &length) { hasher.update(bufferPointer: $0) }
    hasher.update(data: data)
  }

  private static func hex(_ digest: SHA256.Digest) -> String {
    digest.map { String(format: "%02x", $0) }.joined()
  }
}

#if os(macOS)
  private enum ProcessRunner {
    static func run(executableURL: URL, arguments: [String]) throws -> String {
      let process = Process()
      let standardOutput = Pipe()
      process.executableURL = executableURL
      process.arguments = arguments
      process.standardOutput = standardOutput
      process.standardError = FileHandle.nullDevice

      do {
        try process.run()
      } catch {
        throw CodexCompatibilityProbeError.commandFailed
      }
      let output = standardOutput.fileHandleForReading.readDataToEndOfFile()
      process.waitUntilExit()
      guard process.terminationReason == .exit, process.terminationStatus == 0 else {
        throw CodexCompatibilityProbeError.commandFailed
      }
      return String(decoding: output, as: UTF8.self)
    }
  }
#endif
