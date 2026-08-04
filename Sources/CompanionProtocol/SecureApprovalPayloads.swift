import Foundation

/// Bounds on the approval surface.
public enum SecureApprovalLimits {
  /// Most pending approvals a device is told about at once. Beyond this the
  /// oldest are omitted rather than the payload growing without limit.
  public static let maxPendingCount = 16
  /// Longest summary the Mac may attach. Short enough to be read on a key's
  /// worth of screen, and short enough that it cannot become a channel for
  /// exporting a file.
  public static let maxSummaryBytes = 240
  public static let maxRequestIDBytes = 128
}

/// One approval a device may be shown.
///
/// **Content is excluded by default and disclosed only if the Mac chooses.**
/// This is the hardest trade in the product and it is worth stating in full.
///
/// An approval the user cannot evaluate is worse than no approval at all: it
/// trains them to press accept because pressing accept is the only way to make
/// the prompt go away. That argues for sending the command line, the patch,
/// the paths.
///
/// But approval content *is* workspace content — the very thing Phase 2's
/// observation surface deliberately never carries. A phone that renders a diff
/// has become a workspace viewer through a side door, on a device that may be
/// on a different network, in a pocket, or lost.
///
/// So the payload always carries what the decision *is* — its kind, the
/// decisions available, and the digest binding it — and carries a summary only
/// when the Mac has opted in. The default is absent. A device that receives no
/// summary must say so rather than implying it has seen the request, which is
/// what makes "approve blind" a visible choice instead of an accident.
public struct SecureApprovalRequest: Codable, Equatable, Sendable {
  public let requestID: String
  public let threadID: String
  /// The project this approval belongs to. Present so the same scoping that
  /// governs observation governs approvals, using the same field.
  public let projectID: String
  public let kind: CompanionApprovalKind
  public let availableDecisions: [CompanionApprovalDecision]
  /// Binds a decision to the request it was made about.
  ///
  /// The device echoes this when resolving. A Mac whose pending request no
  /// longer matches refuses, so an approval cannot be applied to a request
  /// that changed after it was displayed — which is the whole mechanism by
  /// which "it is impossible to approve something the screen did not show"
  /// is enforced rather than merely intended.
  public let requestDigest: String
  public let expiresAtEpochSeconds: UInt64
  /// A short, Mac-chosen description. Absent unless the Mac opts in.
  public let summary: String?

  public init(
    requestID: String,
    threadID: String,
    projectID: String,
    kind: CompanionApprovalKind,
    availableDecisions: [CompanionApprovalDecision],
    requestDigest: String,
    expiresAtEpochSeconds: UInt64,
    summary: String? = nil
  ) throws {
    try requireBoundedText(
      requestID, maxUTF8: SecureApprovalLimits.maxRequestIDBytes, field: "requestID")
    try requireBoundedText(
      threadID, maxUTF8: SecureObservationLimits.maxThreadIDBytes, field: "threadID")
    try requireBoundedText(
      projectID, maxUTF8: SecureObservationLimits.maxProjectIDBytes, field: "projectID")
    guard !availableDecisions.isEmpty else {
      // An approval with no available decision is not a decision. Showing one
      // would present a control that cannot do anything.
      throw SecureWireValidationError.invalidField(name: "availableDecisions")
    }
    guard Set(availableDecisions).count == availableDecisions.count else {
      throw SecureWireValidationError.invalidField(name: "availableDecisions")
    }
    guard !requestDigest.isEmpty else {
      throw SecureWireValidationError.invalidField(name: "requestDigest")
    }
    if let summary {
      try requireBoundedText(
        summary, maxUTF8: SecureApprovalLimits.maxSummaryBytes, field: "summary")
    }
    self.requestID = requestID
    self.threadID = threadID
    self.projectID = projectID
    self.kind = kind
    self.availableDecisions = availableDecisions
    self.requestDigest = requestDigest
    self.expiresAtEpochSeconds = expiresAtEpochSeconds
    self.summary = summary
  }

  public init(from decoder: Decoder) throws {
    let container = try strictContainer(from: decoder, keyedBy: CodingKeys.self)
    try self.init(
      requestID: container.decode(String.self, forKey: .requestID),
      threadID: container.decode(String.self, forKey: .threadID),
      projectID: container.decode(String.self, forKey: .projectID),
      kind: container.decode(CompanionApprovalKind.self, forKey: .kind),
      availableDecisions: container.decode(
        [CompanionApprovalDecision].self, forKey: .availableDecisions),
      requestDigest: container.decode(String.self, forKey: .requestDigest),
      expiresAtEpochSeconds: container.decode(UInt64.self, forKey: .expiresAtEpochSeconds),
      summary: try container.decodeIfPresent(String.self, forKey: .summary)
    )
  }

  /// Whether the device has been told what it would be approving.
  public var disclosesContent: Bool { summary?.isEmpty == false }

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case requestID
    case threadID
    case projectID
    case kind
    case availableDecisions
    case requestDigest
    case expiresAtEpochSeconds
    case summary
  }
}

/// The approvals a device may currently see.
///
/// Delivered separately from the observation snapshot rather than folded into
/// it. Observation is a continuous feed a device consumes passively; an
/// approval is a claim on the user's attention with an expiry. Merging them
/// would mean either sending approvals at the snapshot's cadence, which is too
/// slow, or sending snapshots at the approval's, which is wasteful — and would
/// couple a security-relevant surface to a performance one.
public struct SecureApprovalBatch: Codable, Equatable, Sendable {
  public let generatedAtEpochSeconds: UInt64
  public let pending: [SecureApprovalRequest]

  public init(generatedAtEpochSeconds: UInt64, pending: [SecureApprovalRequest]) throws {
    guard pending.count <= SecureApprovalLimits.maxPendingCount else {
      throw SecureWireValidationError.invalidField(name: "pending")
    }
    let identifiers = Set(pending.map(\.requestID))
    guard identifiers.count == pending.count else {
      throw SecureWireValidationError.invalidField(name: "pending")
    }
    self.generatedAtEpochSeconds = generatedAtEpochSeconds
    self.pending = pending
  }

  public init(from decoder: Decoder) throws {
    let container = try strictContainer(from: decoder, keyedBy: CodingKeys.self)
    try self.init(
      generatedAtEpochSeconds: container.decode(
        UInt64.self, forKey: .generatedAtEpochSeconds),
      pending: container.decode([SecureApprovalRequest].self, forKey: .pending)
    )
  }

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case generatedAtEpochSeconds
    case pending
  }
}
