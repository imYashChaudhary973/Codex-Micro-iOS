import CompanionProtocol
import Foundation

public enum MobileActionProfile: String, Codable, CaseIterable, Sendable {
  case observe
  case respond
  case runReadOnly
  case runWorkspace

  public static func mostRestrictive(_ profiles: [MobileActionProfile]) -> MobileActionProfile {
    profiles.min(by: { $0.rank < $1.rank }) ?? .observe
  }

  fileprivate var permitsAgentWork: Bool {
    self == .runReadOnly || self == .runWorkspace
  }

  private var rank: Int {
    switch self {
    case .observe: 0
    case .respond: 1
    case .runReadOnly: 2
    case .runWorkspace: 3
    }
  }
}

public struct DeviceGrant: Equatable, Sendable {
  public let deviceID: UUID
  public let capabilities: Set<DeviceCapability>
  public let permittedProjectIDs: Set<String>
  public let actionProfile: MobileActionProfile
  public let isRevoked: Bool

  public init(
    deviceID: UUID,
    capabilities: Set<DeviceCapability>,
    permittedProjectIDs: Set<String>,
    actionProfile: MobileActionProfile,
    isRevoked: Bool = false
  ) {
    self.deviceID = deviceID
    self.capabilities = capabilities
    self.permittedProjectIDs = permittedProjectIDs
    self.actionProfile = actionProfile
    self.isRevoked = isRevoked
  }
}

public enum CommandAuthorization: Equatable, Sendable {
  case allowed(effectiveProfile: MobileActionProfile)
  case denied(CommandDenialReason)
}

public enum CommandDenialReason: String, Equatable, Sendable {
  case revokedDevice
  case missingCapability
  case projectNotAllowed
  case missingProjectContext
  case actionProfileTooRestrictive
  case staleCommand
}

public enum CapabilityPolicy {
  public static func authorize(
    command: ClientCommand,
    grant: DeviceGrant,
    resolvedProjectID: String?,
    hostProfile: MobileActionProfile,
    now: Date = Date()
  ) -> CommandAuthorization {
    guard !grant.isRevoked else { return .denied(.revokedDevice) }
    guard command.issuedAt >= now.addingTimeInterval(-60),
      command.issuedAt <= now.addingTimeInterval(30)
    else {
      return .denied(.staleCommand)
    }

    let required = requiredCapabilities(for: command.body)
    guard required.isSubset(of: grant.capabilities) else {
      return .denied(.missingCapability)
    }

    let projectID: String?
    switch command.body {
    case .startThread(let commandProjectID, _, _):
      projectID = commandProjectID
    default:
      projectID = resolvedProjectID
    }
    guard let projectID else { return .denied(.missingProjectContext) }
    guard grant.permittedProjectIDs.contains(projectID) else {
      return .denied(.projectNotAllowed)
    }

    let effectiveProfile = MobileActionProfile.mostRestrictive([
      grant.actionProfile,
      hostProfile,
    ])
    if startsOrSteersAgent(command.body), !effectiveProfile.permitsAgentWork {
      return .denied(.actionProfileTooRestrictive)
    }
    return .allowed(effectiveProfile: effectiveProfile)
  }

  private static func requiredCapabilities(
    for command: ClientCommandBody
  ) -> Set<DeviceCapability> {
    switch command {
    case .selectThread, .markThreadRead:
      [.view]
    case .startThread:
      [.view, .runAgent, .startThread]
    case .sendPrompt, .steerTurn:
      [.runAgent]
    case .interruptTurn:
      [.interrupt]
    case .resolveApproval:
      [.approve]
    }
  }

  private static func startsOrSteersAgent(_ command: ClientCommandBody) -> Bool {
    switch command {
    case .startThread, .sendPrompt, .steerTurn:
      true
    case .selectThread, .interruptTurn, .resolveApproval, .markThreadRead:
      false
    }
  }
}
