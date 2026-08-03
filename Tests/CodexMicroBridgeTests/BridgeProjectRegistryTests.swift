import CodexAppServer
import CompanionProtocol
import Foundation
import MacBridgeCore
import XCTest

@testable import CodexMicroBridge

/// Project resolution: the gap that made every filtering rule in Steps 2.8
/// and 2.10 provable only against injected tables.
///
/// `thread["cwd"]` is real — the merged Phase 0 spike reads it from a live
/// app-server — so a thread can be attributed to a project the Mac user
/// allowlisted, and the device only ever learns an opaque identifier.
final class BridgeProjectRegistryTests: XCTestCase {

  // MARK: - Opaque identifiers

  func testTheIdentifierRevealsNothingAboutThePath() throws {
    let project = try XCTUnwrap(BridgeProject(rootPath: "/Users/example/secret-project"))

    XCTAssertFalse(project.projectID.contains("secret"))
    XCTAssertFalse(project.projectID.contains("Users"))
    XCTAssertFalse(project.projectID.contains("/"))
    XCTAssertEqual(project.projectID.count, 32)
    XCTAssertTrue(project.projectID.allSatisfy { $0.isHexDigit && !$0.isUppercase })
  }

  func testTheIdentifierIsStableForTheSameDirectory() throws {
    let first = try XCTUnwrap(BridgeProject(rootPath: "/Users/example/app"))
    let second = try XCTUnwrap(BridgeProject(rootPath: "/Users/example/app/"))
    let third = try XCTUnwrap(BridgeProject(rootPath: "/Users/example/./app"))

    XCTAssertEqual(first.projectID, second.projectID)
    XCTAssertEqual(first.projectID, third.projectID)
    XCTAssertEqual(first.rootPath, "/Users/example/app")
  }

  func testDifferentDirectoriesGetDifferentIdentifiers() throws {
    let first = try XCTUnwrap(BridgeProject(rootPath: "/Users/example/app"))
    let second = try XCTUnwrap(BridgeProject(rootPath: "/Users/example/app2"))

    XCTAssertNotEqual(first.projectID, second.projectID)
  }

  func testARelativePathIsNotAProject() {
    for path in ["relative/path", "", "~/app"] {
      XCTAssertNil(BridgeProject(rootPath: path), path)
    }
  }

  func testTheIdentifierFitsTheGrantAuthorityBound() throws {
    let project = try XCTUnwrap(
      BridgeProject(rootPath: "/Users/example/" + String(repeating: "d", count: 200)))

    XCTAssertLessThanOrEqual(
      project.projectID.utf8.count, GrantAuthorityLimits.maxProjectIDBytes)
    XCTAssertLessThanOrEqual(
      project.projectID.utf8.count, SecureObservationLimits.maxProjectIDBytes)
  }

  // MARK: - Containment is on path boundaries

  /// A prefix test alone would silently widen a project's scope to a sibling
  /// directory, which is a disclosure bug, not a cosmetic one.
  func testASiblingDirectoryIsNotInsideAProject() throws {
    let project = try XCTUnwrap(BridgeProject(rootPath: "/Users/example/app"))

    XCTAssertTrue(project.contains(canonicalPath: "/Users/example/app"))
    XCTAssertTrue(project.contains(canonicalPath: "/Users/example/app/src/main.swift"))
    XCTAssertFalse(project.contains(canonicalPath: "/Users/example/app2"))
    XCTAssertFalse(project.contains(canonicalPath: "/Users/example/appendix"))
    XCTAssertFalse(project.contains(canonicalPath: "/Users/example"))
  }

  // MARK: - The registry

  func testRegisteringTheSameDirectoryTwiceIsIdempotent() async throws {
    let registry = BridgeProjectRegistry()

    let first = await registry.register(rootPath: "/Users/example/app")
    let second = await registry.register(rootPath: "/Users/example/app/")

    XCTAssertEqual(first?.projectID, second?.projectID)
    let all = await registry.allProjects()
    XCTAssertEqual(all.count, 1)
  }

  func testAnUnregisteredPathHasNoProject() async {
    let registry = BridgeProjectRegistry(rootPaths: ["/Users/example/app"])

    let project = await registry.project(containingPath: "/Users/example/other/file.swift")

    XCTAssertNil(project)
  }

  /// A project nested inside another must attribute its own threads rather
  /// than its parent's, or a device scoped to the outer project would see the
  /// inner one's activity.
  func testTheMostSpecificProjectWins() async throws {
    let registry = BridgeProjectRegistry(rootPaths: [
      "/Users/example/mono", "/Users/example/mono/packages/inner",
    ])

    let outer = await registry.project(containingPath: "/Users/example/mono/README.md")
    let inner = await registry.project(
      containingPath: "/Users/example/mono/packages/inner/Sources/x.swift")

    XCTAssertEqual(outer?.rootPath, "/Users/example/mono")
    XCTAssertEqual(inner?.rootPath, "/Users/example/mono/packages/inner")
  }

  func testTheProjectCountIsBounded() async {
    let registry = BridgeProjectRegistry()
    for index in 0..<BridgeProjectRegistry.maximumProjects {
      _ = await registry.register(rootPath: "/Users/example/p\(index)")
    }

    let overflow = await registry.register(rootPath: "/Users/example/one-too-many")

    XCTAssertNil(overflow)
    let all = await registry.allProjects()
    XCTAssertEqual(all.count, BridgeProjectRegistry.maximumProjects)
  }

  func testRemovingAProjectStopsItResolving() async throws {
    let registry = BridgeProjectRegistry(rootPaths: ["/Users/example/app"])
    let project = try await unwrapAsync(
      await registry.project(containingPath: "/Users/example/app"))

    await registry.remove(projectID: project.projectID)

    let after = await registry.project(containingPath: "/Users/example/app")
    XCTAssertNil(after)
  }

  // MARK: - Writable roots

  func testAProjectsOnlyWritableRootIsItsOwnDirectory() async throws {
    let registry = BridgeProjectRegistry(rootPaths: ["/Users/example/app"])
    let projects = await registry.allProjects()
    let resolver = BridgeWorkspaceRootResolver(projects: projects)
    let project = try XCTUnwrap(projects.first)

    XCTAssertEqual(
      resolver.writableRoots(forProjectID: project.projectID),
      [
        "/Users/example/app"
      ])
  }

  func testAnUnregisteredProjectHasNoWritableRoots() {
    let resolver = BridgeWorkspaceRootResolver(projects: [])

    XCTAssertEqual(resolver.writableRoots(forProjectID: "unknown"), [])
  }

  // MARK: - Thread attribution

  func testAThreadInsideAProjectIsAttributed() async throws {
    let world = await AttributionWorld(cwd: "/Users/example/app/sub")

    let project = await world.resolver.resolve(threadID: "thread-a")

    XCTAssertEqual(project?.rootPath, "/Users/example/app")
    XCTAssertEqual(world.table.projectID(forThreadID: "thread-a"), project?.projectID)
  }

  func testAThreadOutsideEveryProjectStaysUnattributed() async throws {
    let world = await AttributionWorld(cwd: "/Users/example/elsewhere")

    let project = await world.resolver.resolve(threadID: "thread-a")

    XCTAssertNil(project)
    XCTAssertNil(world.table.projectID(forThreadID: "thread-a"))
  }

  func testAThreadWithNoWorkingDirectoryStaysUnattributed() async throws {
    let world = await AttributionWorld(cwd: nil)

    let project = await world.resolver.resolve(threadID: "thread-a")

    XCTAssertNil(project)
    XCTAssertNil(world.table.projectID(forThreadID: "thread-a"))
  }

  func testAFailedReadLeavesTheThreadUnattributed() async throws {
    let world = await AttributionWorld(cwd: "/Users/example/app", readFails: true)

    let project = await world.resolver.resolve(threadID: "thread-a")

    XCTAssertNil(project)
    XCTAssertNil(world.table.projectID(forThreadID: "thread-a"))
  }

  func testResolvingTwiceReadsTheThreadOnce() async throws {
    let world = await AttributionWorld(cwd: "/Users/example/app")

    _ = await world.resolver.resolve(threadID: "thread-a")
    _ = await world.resolver.resolve(threadID: "thread-a")

    let reads = await world.reader.readCount
    XCTAssertEqual(reads, 1)
  }

  func testForgettingAThreadMakesItInvisibleAgain() async throws {
    let world = await AttributionWorld(cwd: "/Users/example/app")
    _ = await world.resolver.resolve(threadID: "thread-a")

    await world.resolver.forget(threadID: "thread-a")

    XCTAssertNil(world.table.projectID(forThreadID: "thread-a"))
  }

  /// Removing a project must not leave its threads attributed to it.
  func testForgettingEverythingClearsTheTable() async throws {
    let world = await AttributionWorld(cwd: "/Users/example/app")
    _ = await world.resolver.resolve(threadID: "thread-a")

    await world.resolver.forgetAll()

    XCTAssertNil(world.table.projectID(forThreadID: "thread-a"))
  }

  // MARK: - Fixtures

  private struct AttributionWorld {
    let registry = BridgeProjectRegistry(rootPaths: ["/Users/example/app"])
    let table = ThreadProjectTable()
    let reader: RecordingThreadReader
    let resolver: BridgeThreadAttributionResolver

    init(cwd: String?, readFails: Bool = false) async {
      reader = RecordingThreadReader(cwd: cwd, fails: readFails)
      let reader = self.reader
      resolver = BridgeThreadAttributionResolver(
        registry: registry,
        table: table,
        readThread: { threadID in try await reader.read(threadID: threadID) }
      )
    }
  }
}

/// Deterministic thread reader that counts reads.
actor RecordingThreadReader {
  private(set) var readCount = 0
  private let cwd: String?
  private let fails: Bool

  init(cwd: String?, fails: Bool) {
    self.cwd = cwd
    self.fails = fails
  }

  func read(threadID: String) async throws -> JSONValue {
    readCount += 1
    if fails { throw CodexRuntimeRequestError.notReady }
    var fields: [String: JSONValue] = [
      "id": .string(threadID),
      "status": .object(["type": .string("idle")]),
    ]
    if let cwd { fields["cwd"] = .string(cwd) }
    return .object(fields)
  }
}
