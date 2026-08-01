import Foundation

public enum ListenerLifecycleError: Error, Equatable {
  case alreadyRunning
  case generationOverflow
  case prerequisiteMissing
  case staleAuthentication
}

public struct ListenerPrerequisites: Equatable, Sendable {
  public let hostIdentityAvailable: Bool
  public let tlsIdentityAvailable: Bool
  public let interfaceEligible: Bool
  public let policyAvailable: Bool

  public init(
    hostIdentityAvailable: Bool,
    tlsIdentityAvailable: Bool,
    interfaceEligible: Bool,
    policyAvailable: Bool
  ) {
    self.hostIdentityAvailable = hostIdentityAvailable
    self.tlsIdentityAvailable = tlsIdentityAvailable
    self.interfaceEligible = interfaceEligible
    self.policyAvailable = policyAvailable
  }

  fileprivate var allSatisfied: Bool {
    hostIdentityAvailable && tlsIdentityAvailable && interfaceEligible && policyAvailable
  }
}

public struct AuthenticationGeneration: Equatable, Sendable {
  fileprivate let value: UInt64
}

public struct ListenerLifecycleState: Sendable {
  public enum State: Equatable, Sendable {
    case stopped
    case ready(generation: UInt64)
  }

  public private(set) var state: State = .stopped
  private var nextGeneration: UInt64 = 1

  public init(startingGeneration: UInt64 = 1) {
    self.nextGeneration = startingGeneration
  }

  public mutating func start(prerequisites: ListenerPrerequisites) throws -> UInt64 {
    guard case .stopped = state else { throw ListenerLifecycleError.alreadyRunning }
    guard prerequisites.allSatisfied else { throw ListenerLifecycleError.prerequisiteMissing }
    guard nextGeneration < UInt64.max else {
      throw ListenerLifecycleError.generationOverflow
    }
    let generation = nextGeneration
    nextGeneration += 1
    state = .ready(generation: generation)
    return generation
  }

  public func authenticationGeneration() throws -> AuthenticationGeneration {
    guard case .ready(let generation) = state else {
      throw ListenerLifecycleError.staleAuthentication
    }
    return AuthenticationGeneration(value: generation)
  }

  public func validate(_ authentication: AuthenticationGeneration) throws {
    guard case .ready(let generation) = state, authentication.value == generation else {
      throw ListenerLifecycleError.staleAuthentication
    }
  }

  public mutating func stop() {
    state = .stopped
  }
}
