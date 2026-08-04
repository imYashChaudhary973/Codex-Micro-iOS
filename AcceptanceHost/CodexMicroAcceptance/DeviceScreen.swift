import CompanionProtocol
import SwiftUI

/// Hosts the device surface, driven by a real connection.
///
/// Every control here now reaches the Mac. Before this the screen rendered
/// correctly from state that never arrived and its handlers were empty
/// closures: the pad looked right, resolved availability against capabilities
/// it was never told, and did nothing when pressed.
struct DeviceScreen: View {
  @StateObject private var connection = DeviceConnection()
  @StateObject private var talk = PushToTalkRecogniser()

  @State private var bindings: AgentKeyBindings = .empty
  @State private var selectedSlot: Int?
  @State private var requestedEffort: String?
  @State private var layout: KeyLayout = .default
  @State private var promptTarget: PromptTarget?
  @State private var showingRemap = false

  /// What a prompt sheet is for, so steer and send share one presenter.
  private struct PromptTarget: Identifiable {
    let threadID: String
    let turnID: String?
    var id: String { threadID + (turnID ?? "") }
    var isSteer: Bool { turnID != nil }
  }

  var body: some View {
    DeviceView(
      surface: surface,
      capabilities: connection.capabilities,
      dial: dialState,
      onSelect: { slot in
        selectedSlot = surface.selectedSlot == slot ? nil : slot
      },
      onCommand: perform,
      onDial: { delta in
        if let next = dialState.stepped(by: delta) { requestedEffort = next }
      },
      onWorkflow: run,
      approvals: approvalKeys,
      onApproval: resolve,
      talkState: talk.state,
      onTalkDown: { talk.start() },
      onTalkUp: {
        talk.stop()
        if let transcript = talk.transcript, let threadID = surface.selectedKey?.threadID {
          // A dictated prompt is an ordinary prompt. Nothing downstream can
          // tell it was spoken, which is the point.
          Task {
            await connection.send(
              .sendPrompt(threadID: threadID, prompt: transcript, attachmentIDs: []))
          }
        }
        talk.reset()
      },
      statusLine: statusLine,
      onRemap: { showingRemap = true }
    )
    .onAppear {
      bindings = AgentKeyBindingStore.load()
      layout = KeyLayoutStore.load()
    }
    .task {
      await talk.prepare()
      await connection.connect()
    }
    .onChange(of: connection.threads) { _, incoming in
      // Fill empty keys as threads appear. Established bindings never move.
      let filled = bindings.filling(from: incoming)
      if filled != bindings {
        bindings = filled
        AgentKeyBindingStore.save(filled)
      }
    }
    .sheet(item: $promptTarget) { target in
      PromptSheet(
        agentLabel: String(target.threadID.suffix(6)),
        isSteer: target.isSteer,
        onSend: { text in
          let body: ClientCommandBody =
            target.isSteer
            ? .steerTurn(threadID: target.threadID, turnID: target.turnID ?? "", prompt: text)
            : .sendPrompt(threadID: target.threadID, prompt: text, attachmentIDs: [])
          promptTarget = nil
          Task { await connection.send(body) }
        },
        onCancel: { promptTarget = nil }
      )
    }
    .sheet(isPresented: $showingRemap) {
      RemapSheet(
        capabilities: connection.capabilities,
        layout: $layout,
        onDone: {
          KeyLayoutStore.save(layout)
          showingRemap = false
        }
      )
    }
  }

  // MARK: - Derived state

  private var surface: DeviceSurfaceState {
    DeviceSurfaceProjection().project(
      bindings: bindings.slots,
      threads: connection.threads,
      lastUpdate: connection.lastUpdate,
      now: Date(),
      isConnected: connection.status == .connected,
      selectedSlot: selectedSlot
    )
  }

  private var dialState: ReasoningDialState {
    ReasoningDialState.resolve(
      positions: connection.reasoningEfforts,
      requested: requestedEffort,
      surface: surface,
      capabilities: connection.capabilities
    )
  }

  private var approvalKeys: ApprovalKeyState {
    ApprovalKeyState.resolve(
      pending: [], surface: surface, capabilities: connection.capabilities)
  }

  /// One line describing the connection and the last command, so a press
  /// always produces visible feedback even when the Mac refuses.
  private var statusLine: String {
    if let outcome = connection.lastOutcome { return outcome.message }
    switch connection.status {
    case .notPaired: return "Not paired"
    case .connecting: return "Connecting…"
    case .connected: return "Connected"
    case .failed(let reason): return "Disconnected: \(reason)"
    }
  }

  // MARK: - Actions

  private func perform(_ key: CommandKey) {
    switch key {
    case .previousAgent: moveSelection(by: -1)
    case .nextAgent: moveSelection(by: 1)
    case .stop:
      guard let thread = surface.selectedKey?.threadID,
        let turn = activeTurnID(for: thread)
      else { return }
      Task { await connection.send(.interruptTurn(threadID: thread, turnID: turn)) }
    case .markRead:
      guard let thread = surface.selectedKey?.threadID else { return }
      Task { await connection.send(.markThreadRead(threadID: thread, throughSequence: 0)) }
    case .steer:
      guard let thread = surface.selectedKey?.threadID,
        let turn = activeTurnID(for: thread)
      else { return }
      promptTarget = PromptTarget(threadID: thread, turnID: turn)
    }
  }

  private func run(_ workflow: JoystickWorkflow) {
    guard let thread = surface.selectedKey?.threadID else { return }
    Task {
      await connection.send(
        .sendPrompt(threadID: thread, prompt: workflow.prompt, attachmentIDs: []))
    }
  }

  private func resolve(_ decision: CompanionApprovalDecision) {
    guard let body = approvalKeys.command(for: decision) else { return }
    Task { await connection.send(body) }
  }

  /// The turn a thread is currently running, which stop and steer both need.
  private func activeTurnID(for threadID: String) -> String? {
    connection.threads.first { $0.threadID == threadID }?.activeTurnID
  }

  private func moveSelection(by step: Int) {
    let bound = surface.agentKeys.filter(\.isBound).map(\.slot)
    guard !bound.isEmpty else { return }
    guard let current = surface.selectedSlot, let index = bound.firstIndex(of: current) else {
      selectedSlot = bound.first
      return
    }
    selectedSlot = bound[(index + step + bound.count) % bound.count]
  }
}
