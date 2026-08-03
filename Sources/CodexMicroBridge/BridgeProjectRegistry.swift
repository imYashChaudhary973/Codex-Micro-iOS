import CodexAppServer
import CompanionProtocol
import CryptoKit
import Foundation
import MacBridgeCore

/// One project the Mac user allowlisted, as the bridge stores it.
///
/// The device only ever sees ``projectID``, which is a digest of the
/// canonical root path rather than the path itself. That is what lets a grant
/// name a project without the phone learning where it lives on disk: the
/// identifier is stable across restarts, is the same for the same directory,
/// and reveals nothing about it.
public struct BridgeProject: Equatable, Sendable {
  /// The opaque identifier grants and wire payloads carry.
  public let projectID: String
  /// The canonical absolute root. Never leaves the Mac.
  public let rootPath: String

  /// Derives a project from a filesystem root.
  ///
  /// The path is canonicalized first — symlinks resolved, trailing slashes
  /// removed — so the same directory reached two ways is one project rather
  /// than two, and so containment checks below compare like with like.
  public init?(rootPath: String) {
    guard let canonical = BridgeProject.canonicalize(rootPath) else { return nil }
    self.rootPath = canonical
    self.projectID = BridgeProject.identifier(forCanonicalPath: canonical)
  }

  /// The opaque identifier for a canonical path: the first 32 hex characters
  /// of its SHA-256, under a versioned domain separator so a future scheme
  /// cannot collide with this one.
  static func identifier(forCanonicalPath path: String) -> String {
    var bytes = Data("codex-micro/project-id/v1\u{0}".utf8)
    bytes.append(Data(path.utf8))
    return SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined().prefix(32)
      .lowercased()
  }

  /// Canonicalizes an absolute path, or returns `nil` when it is not usable.
  static func canonicalize(_ path: String) -> String? {
    guard path.hasPrefix("/") else { return nil }
    let standardized = URL(fileURLWithPath: path).standardizedFileURL.resolvingSymlinksInPath()
    let canonical = standardized.path
    guard canonical.hasPrefix("/"), !canonical.isEmpty else { return nil }
    guard canonical.utf8.count <= GrantAuthorityLimits.maxProjectIDBytes * 8 else { return nil }
    return canonical == "/"
      ? canonical : String(canonical.reversed().drop(while: { $0 == "/" }).reversed())
  }

  /// Whether `path` is inside this project.
  ///
  /// Compared on path boundaries, so `/Users/me/app2` is **not** inside
  /// `/Users/me/app`. A prefix test alone would have silently widened a
  /// project's scope to a sibling directory.
  func contains(canonicalPath path: String) -> Bool {
    if path == rootPath { return true }
    let boundary = rootPath == "/" ? "/" : rootPath + "/"
    return path.hasPrefix(boundary)
  }
}

/// The Mac user's allowlist of projects.
///
/// Nothing is implicit: a directory becomes a project only because the user
/// registered it. A thread whose working directory is inside no registered
/// project is unattributable, and an unattributable thread is visible to no
/// device (Step 2.8's fail-closed rule).
public actor BridgeProjectRegistry {
  /// Maximum projects, matching the grant authority's own per-device bound so
  /// a grant can name every project the Mac knows.
  public static let maximumProjects = GrantAuthorityLimits.maxProjectCount

  private var projects: [String: BridgeProject] = [:]

  public init(rootPaths: [String] = []) {
    for path in rootPaths {
      guard let project = BridgeProject(rootPath: path),
        projects.count < Self.maximumProjects
      else { continue }
      projects[project.projectID] = project
    }
  }

  /// Registers a root the user selected. Registering the same directory twice
  /// is idempotent because the identifier is derived from the canonical path.
  @discardableResult
  public func register(rootPath: String) -> BridgeProject? {
    guard let project = BridgeProject(rootPath: rootPath) else { return nil }
    if projects[project.projectID] == nil, projects.count >= Self.maximumProjects {
      return nil
    }
    projects[project.projectID] = project
    return project
  }

  /// Removes a project. Existing grants naming it keep the identifier, and
  /// the thread attribution for it stops resolving, so its threads become
  /// invisible rather than reassigned.
  public func remove(projectID: String) {
    projects.removeValue(forKey: projectID)
  }

  /// Every registered project, ordered by identifier.
  public func allProjects() -> [BridgeProject] {
    projects.values.sorted { $0.projectID < $1.projectID }
  }

  /// The project a filesystem path belongs to, or `nil`.
  ///
  /// The **most specific** match wins, so a project nested inside another
  /// attributes its own threads rather than its parent's.
  public func project(containingPath path: String) -> BridgeProject? {
    guard let canonical = BridgeProject.canonicalize(path) else { return nil }
    return projects.values
      .filter { $0.contains(canonicalPath: canonical) }
      .max { $0.rootPath.utf8.count < $1.rootPath.utf8.count }
  }

  /// The registered project with an identifier, or `nil`.
  public func project(id projectID: String) -> BridgeProject? {
    projects[projectID]
  }
}

/// Supplies workspace-write roots from the registry.
///
/// A project's only writable root is its own canonical directory: the phone
/// cannot name a path, and the bridge never widens one beyond the project the
/// grant already allows. An unregistered project has no roots, so a turn for
/// it resolves down to read-only (Step 2.10's rule).
public struct BridgeWorkspaceRootResolver: WorkspaceRootResolving {
  private let roots: [String: [String]]

  /// Snapshots the registry. Taken at listener start so a root cannot change
  /// underneath a turn that already resolved its policy.
  public init(projects: [BridgeProject]) {
    roots = Dictionary(
      projects.map { ($0.projectID, [$0.rootPath]) },
      uniquingKeysWith: { first, _ in first }
    )
  }

  public func writableRoots(forProjectID projectID: String) -> [String] {
    roots[projectID] ?? []
  }
}

/// Reads a thread's working directory and attributes it to a registered
/// project.
///
/// `ThreadProjectAttributing` is synchronous by contract because the
/// observation path consults it inside a lock, while reading a thread is an
/// app-server round trip. So this resolves asynchronously and writes into the
/// existing fail-closed ``ThreadProjectTable``: a thread the bridge has not
/// resolved yet, or cannot resolve, is simply absent from the table and
/// therefore invisible to every device.
public actor BridgeThreadAttributionResolver {
  /// Reads one thread's authoritative object.
  public typealias ThreadReader = @Sendable (String) async throws -> JSONValue

  private let registry: BridgeProjectRegistry
  private let table: ThreadProjectTable
  private let readThread: ThreadReader
  private var resolved: Set<String> = []

  public init(
    registry: BridgeProjectRegistry,
    table: ThreadProjectTable,
    readThread: @escaping ThreadReader
  ) {
    self.registry = registry
    self.table = table
    self.readThread = readThread
  }

  /// Resolves a thread if it has not been resolved already.
  ///
  /// Returns the project it was attributed to, or `nil` when the thread has
  /// no working directory, its directory is outside every registered project,
  /// or the read failed. Every one of those leaves the thread unattributed.
  @discardableResult
  public func resolve(threadID: String) async -> BridgeProject? {
    if resolved.contains(threadID), let existing = table.projectID(forThreadID: threadID) {
      return await registry.project(id: existing)
    }
    guard let thread = try? await readThread(threadID),
      let cwd = thread["cwd"].string,
      let project = await registry.project(containingPath: cwd)
    else {
      return nil
    }
    guard table.attribute(threadID: threadID, projectID: project.projectID) else {
      return nil
    }
    resolved.insert(threadID)
    return project
  }

  /// Forgets a thread's attribution, so a later change re-resolves it.
  public func forget(threadID: String) {
    resolved.remove(threadID)
    table.forget(threadID: threadID)
  }

  /// Drops every attribution. Called when the project allowlist changes, so
  /// no thread keeps a project the user just removed.
  public func forgetAll() {
    for threadID in resolved {
      table.forget(threadID: threadID)
    }
    resolved.removeAll()
  }
}
