import Foundation
import Network
import Testing

@testable import Phase2Transport

@Suite(.serialized)
struct CorePolicyTests {
  @Test
  func interfacePolicyAllowsOnlyExplicitDirectLANKinds() {
    let production = InterfacePolicy()
    let test = InterfacePolicy(allowLoopbackForTests: true)
    func descriptor(_ kind: NetworkInterfaceKind, pointToPoint: Bool = false)
      -> NetworkInterfaceDescriptor
    {
      NetworkInterfaceDescriptor(
        identifier: "sentinel",
        kind: kind,
        isUp: true,
        isRunning: true,
        isPointToPoint: pointToPoint
      )
    }

    #expect(production.allows(descriptor(.wifi)))
    #expect(production.allows(descriptor(.ethernet)))
    #expect(!production.allows(descriptor(.loopback)))
    #expect(test.allows(descriptor(.loopback)))
    for kind in [
      NetworkInterfaceKind.vpn, .tunnel, .cellular, .peerToPeer, .other, .wildcard,
    ] {
      #expect(!production.allows(descriptor(kind)))
    }
    #expect(!production.allows(descriptor(.wifi, pointToPoint: true)))
  }

  @Test
  func validatedBindingRejectsNonlocalAndNonnumericAddresses() throws {
    let wifi = NetworkInterfaceDescriptor(
      identifier: "sentinel",
      kind: .wifi,
      isUp: true,
      isRunning: true,
      isPointToPoint: false
    )
    let policy = InterfacePolicy()
    for address in [
      "0.0.0.0", "::", "example.invalid", "224.0.0.1", "ff02::1", "169.254.1.1",
      "fe80::1", "198.51.100.10",
    ] {
      #expect(throws: (any Error).self) {
        _ = try InterfaceBinding.validated(
          interface: wifi,
          numericAddress: address,
          policy: policy
        )
      }
    }
    _ = try InterfaceBinding.validated(
      interface: wifi,
      numericAddress: "192.168.10.20",
      policy: policy
    )
    _ = try InterfaceBinding.validated(
      interface: wifi,
      numericAddress: "fd00::20",
      policy: policy
    )
    #expect(throws: InterfaceBindingError.interfaceDenied) {
      _ = try InterfaceBinding.validated(
        interface: NetworkInterfaceDescriptor(
          identifier: "loopback",
          kind: .loopback,
          isUp: true,
          isRunning: true,
          isPointToPoint: false
        ),
        numericAddress: "127.0.0.1",
        policy: policy
      )
    }
    _ = try InterfaceBinding.testOnlyLoopback()
  }

  @Test
  func lifecycleRestartRequiresReauthentication() throws {
    var lifecycle = ListenerLifecycleState()
    let ready = readyPrerequisites()
    _ = try lifecycle.start(prerequisites: ready)
    let priorAuthentication = try lifecycle.authenticationGeneration()
    try lifecycle.validate(priorAuthentication)
    lifecycle.stop()
    #expect(throws: ListenerLifecycleError.staleAuthentication) {
      try lifecycle.validate(priorAuthentication)
    }
    _ = try lifecycle.start(prerequisites: ready)
    #expect(throws: ListenerLifecycleError.staleAuthentication) {
      try lifecycle.validate(priorAuthentication)
    }
  }

  @Test
  func lifecycleGenerationFailsClosedBeforeOverflow() {
    var lifecycle = ListenerLifecycleState(startingGeneration: UInt64.max)
    #expect(throws: ListenerLifecycleError.generationOverflow) {
      try lifecycle.start(prerequisites: readyPrerequisites())
    }
    #expect(lifecycle.state == .stopped)
    #expect(throws: ListenerLifecycleError.staleAuthentication) {
      _ = try lifecycle.authenticationGeneration()
    }
    #expect(throws: ListenerLifecycleError.generationOverflow) {
      try lifecycle.start(prerequisites: readyPrerequisites())
    }
  }

  @Test
  func lifecycleFailsClosedForEveryMissingPrerequisite() {
    let cases = [
      ListenerPrerequisites(
        hostIdentityAvailable: false,
        tlsIdentityAvailable: true,
        interfaceEligible: true,
        policyAvailable: true
      ),
      ListenerPrerequisites(
        hostIdentityAvailable: true,
        tlsIdentityAvailable: false,
        interfaceEligible: true,
        policyAvailable: true
      ),
      ListenerPrerequisites(
        hostIdentityAvailable: true,
        tlsIdentityAvailable: true,
        interfaceEligible: false,
        policyAvailable: true
      ),
      ListenerPrerequisites(
        hostIdentityAvailable: true,
        tlsIdentityAvailable: true,
        interfaceEligible: true,
        policyAvailable: false
      ),
    ]
    for prerequisites in cases {
      var lifecycle = ListenerLifecycleState()
      #expect(throws: ListenerLifecycleError.prerequisiteMissing) {
        try lifecycle.start(prerequisites: prerequisites)
      }
    }
  }

  @Test
  func transportLifecycleIsOneShotAndSerializesStopTransitions() throws {
    var machine = TransportLifecycleStateMachine()
    try machine.beginStart()
    #expect(throws: NetworkTransportError.alreadyStarted) {
      try machine.beginStart()
    }
    let startStopNeedsInflightCleanup = machine.requestStop()
    #expect(!startStopNeedsInflightCleanup)
    let startCompleted = machine.completeStart()
    #expect(!startCompleted)
    machine.terminate()
    #expect(machine.phase == .terminated)
    #expect(throws: NetworkTransportError.terminated) {
      try machine.beginStart()
    }

    var publishing = TransportLifecycleStateMachine()
    try publishing.beginStart()
    let publishingStarted = publishing.completeStart()
    #expect(publishingStarted)
    try publishing.beginPublish()
    let publishStopNeedsInflightCleanup = publishing.requestStop()
    #expect(!publishStopNeedsInflightCleanup)
    let publishCompleted = publishing.completePublish()
    #expect(!publishCompleted)
    publishing.terminate()
    #expect(publishing.phase == .terminated)
  }

  @Test
  func bonjourStateMachineCancelsLosingTimeoutAndHandlesRemoval() throws {
    var success = BonjourRegistrationStateMachine()
    try success.begin()
    let added = success.receive(.added)
    #expect(added == .published)
    #expect(success.state == .published)
    let losingTimeout = success.receive(.timedOut)
    #expect(losingTimeout == .none)
    #expect(success.state == .published)
    let removed = success.receive(.removed)
    #expect(removed == .unexpectedRemoval)
    #expect(success.state == .stopped)

    var timeout = BonjourRegistrationStateMachine()
    try timeout.begin()
    let timeoutWinner = timeout.receive(.timedOut)
    #expect(timeoutWinner == .removeService(.publicationTimedOut))
    let lateAdd = timeout.receive(.added)
    #expect(lateAdd == .none)

    var stopped = BonjourRegistrationStateMachine()
    try stopped.begin()
    let stopWinner = stopped.receive(.stopped)
    #expect(stopWinner == .removeService(.publicationStopped))
  }

  @Test
  func bonjourDescriptorIsContentNeutralAndClosed() {
    let service = ContentNeutralBonjourService.make()
    #expect(service.name == ContentNeutralBonjourService.name)
    #expect(service.type == ContentNeutralBonjourService.type)
    #expect(service.domain == ContentNeutralBonjourService.domain)
    #expect(service.noAutoRename)
    #expect(service.txtRecordObject?.dictionary == ["mode": "spike", "v": "1"])
  }

  @Test
  func loggerAcceptsOnlyClosedCodesAndCounts() {
    let logger = InMemoryClosedCodeLogger()
    logger.record(.policyRejected, count: 2)
    logger.record(.probeFailed, count: -1)
    #expect(logger.events == [ClosedLogEvent(code: .policyRejected, count: 2)])
    #expect(SpikeLogCode.interfaceEligible.rawValue == "interface_eligible")
  }

  private func readyPrerequisites() -> ListenerPrerequisites {
    ListenerPrerequisites(
      hostIdentityAvailable: true,
      tlsIdentityAvailable: true,
      interfaceEligible: true,
      policyAvailable: true
    )
  }
}
