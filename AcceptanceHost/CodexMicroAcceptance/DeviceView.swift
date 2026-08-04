import CompanionProtocol
import SwiftUI

/// The Codex Micro surface.
///
/// Laid out like the hardware — six agent keys above a row of command keys,
/// with the dial and joystick below — so muscle memory transfers from the
/// device. The keys are large and widely spaced because they are meant to be
/// hit with a thumb without looking, which is the property that makes the
/// physical pad worth $230 and the reason a denser layout would be a worse
/// replica even though it fits more on screen.
struct DeviceView: View {
  let surface: DeviceSurfaceState
  let capabilities: Set<DeviceCapability>
  let dial: ReasoningDialState
  let onSelect: (Int) -> Void
  let onCommand: (CommandKey) -> Void
  let onDial: (Int) -> Void
  let onWorkflow: (JoystickWorkflow) -> Void
  let approvals: ApprovalKeyState
  let onApproval: (CompanionApprovalDecision) -> Void

  var body: some View {
    VStack(spacing: 28) {
      connectionBanner
      agentKeys
      Divider().overlay(Color.white.opacity(0.08))
      approvalBanner
      commandKeys
      controls
      Spacer(minLength: 0)
    }
    .padding(24)
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .background(Color.black.opacity(0.96))
    .preferredColorScheme(.dark)
  }

  // MARK: - Connection

  /// The hardware has no way to say "the cable is out" except by going dark,
  /// which is unambiguous when you can see the cable and useless on a phone.
  /// This says it in words, and only when something is wrong.
  @ViewBuilder
  private var connectionBanner: some View {
    if !surface.isConnected {
      label("Not connected", systemImage: "bolt.horizontal.circle", tint: .orange)
    } else if surface.agentKeys.contains(where: { $0.freshness == .stale }) {
      label("Status may be out of date", systemImage: "clock.badge.exclamationmark", tint: .yellow)
    }
  }

  private func label(_ text: String, systemImage: String, tint: Color) -> some View {
    Label(text, systemImage: systemImage)
      .font(.footnote.weight(.medium))
      .foregroundStyle(tint)
      .frame(maxWidth: .infinity, alignment: .leading)
  }

  // MARK: - Agent keys

  private var agentKeys: some View {
    let columns = Array(repeating: GridItem(.flexible(), spacing: 14), count: 3)
    return LazyVGrid(columns: columns, spacing: 14) {
      ForEach(surface.agentKeys, id: \.slot) { key in
        AgentKeyView(key: key, isSelected: key.slot == surface.selectedSlot)
          .onTapGesture { onSelect(key.slot) }
      }
    }
  }

  // MARK: - Approvals

  /// The pending approval, shown **above** the keys that would answer it.
  ///
  /// The layout is the guarantee: the request and the buttons are one block,
  /// so a decision cannot be made from a screen that is not also showing what
  /// is being decided. When the Mac has not disclosed the content, the banner
  /// says so in the same place — approving blind stays possible and stops
  /// being accidental.
  @ViewBuilder
  private var approvalBanner: some View {
    if let request = approvals.presented {
      VStack(alignment: .leading, spacing: 8) {
        Label(
          "\(request.kind.rawValue.capitalized) approval waiting",
          systemImage: "exclamationmark.shield"
        )
        .font(.footnote.weight(.semibold))
        .foregroundStyle(.orange)

        if let summary = request.summary, !summary.isEmpty {
          Text(summary)
            .font(.caption)
            .foregroundStyle(.white.opacity(0.85))
            .fixedSize(horizontal: false, vertical: true)
        } else {
          Text("The request is not shown on this device. Review it on the Mac before approving.")
            .font(.caption)
            .foregroundStyle(.yellow.opacity(0.9))
            .fixedSize(horizontal: false, vertical: true)
        }

        HStack(spacing: 10) {
          ForEach(request.availableDecisions, id: \.rawValue) { decision in
            Button {
              onApproval(decision)
            } label: {
              Text(Self.title(for: decision))
                .font(.caption.weight(.semibold))
                .frame(maxWidth: .infinity)
                .frame(height: 40)
                .background(
                  RoundedRectangle(cornerRadius: 8)
                    .fill(Self.tint(for: decision).opacity(0.22))
                )
                .foregroundStyle(Self.tint(for: decision))
            }
            .buttonStyle(.plain)
          }
        }
      }
      .padding(12)
      .background(RoundedRectangle(cornerRadius: 12).fill(Color.white.opacity(0.05)))
    }
  }

  static func title(for decision: CompanionApprovalDecision) -> String {
    switch decision {
    case .approveOnce: return "Approve once"
    case .decline: return "Decline"
    case .cancel: return "Cancel turn"
    }
  }

  static func tint(for decision: CompanionApprovalDecision) -> Color {
    switch decision {
    case .approveOnce: return .green
    case .decline: return .orange
    case .cancel: return .red
    }
  }

  // MARK: - Command keys

  /// Each key shows whether it can be pressed *before* it is pressed, and
  /// says why not when it cannot. Availability comes from the same resolver
  /// the action path uses, so the label and the behaviour cannot disagree.
  private var commandKeys: some View {
    HStack(spacing: 10) {
      commandKey(.previousAgent, "chevron.left", "Prev")
      commandKey(.nextAgent, "chevron.right", "Next")
      commandKey(.stop, "stop.fill", "Stop")
      commandKey(.steer, "arrow.triangle.turn.up.right.diamond", "Steer")
      commandKey(.markRead, "envelope.open", "Read")
    }
  }

  private func commandKey(
    _ key: CommandKey, _ symbol: String, _ title: String
  ) -> some View {
    let availability = key.availability(in: surface, capabilities: capabilities)
    return Button {
      onCommand(key)
    } label: {
      VStack(spacing: 5) {
        Image(systemName: symbol).font(.body)
        Text(title).font(.caption2)
      }
      .frame(maxWidth: .infinity)
      .frame(height: 58)
      .background(
        RoundedRectangle(cornerRadius: 10)
          .fill(Color.white.opacity(availability.isAvailable ? 0.10 : 0.04))
      )
      .overlay(
        RoundedRectangle(cornerRadius: 10)
          .stroke(Color.white.opacity(availability.isAvailable ? 0.22 : 0.07), lineWidth: 1)
      )
      .foregroundStyle(.white.opacity(availability.isAvailable ? 0.92 : 0.24))
    }
    .buttonStyle(.plain)
    .disabled(!availability.isAvailable)
    .accessibilityLabel(Self.describe(key: title, availability: availability))
  }

  /// The reason is spoken, not just implied by dimming — a screen reader gets
  /// nothing from opacity.
  static func describe(key: String, availability: CommandKeyAvailability) -> String {
    switch availability {
    case .available: return key
    case .notPermitted: return "\(key), not permitted for this device"
    case .noSelection: return "\(key), select an agent first"
    case .noRunningTurn: return "\(key), that agent is not running"
    case .notLive: return "\(key), not connected"
    }
  }

  // MARK: - Dial and joystick

  private var controls: some View {
    HStack(spacing: 32) {
      dialControl
      joystick
    }
    .foregroundStyle(.white.opacity(0.22))
  }

  /// The dial reads out its position **and when that position applies**. The
  /// timing line is not a footnote: a control whose effect is deferred and
  /// does not say so reads as broken.
  private var dialControl: some View {
    VStack(spacing: 8) {
      ZStack {
        Circle()
          .stroke(
            Color.white.opacity(dial.isAvailable ? 0.22 : 0.08),
            lineWidth: 10
          )
          .frame(width: 92, height: 92)
        VStack(spacing: 2) {
          Text(dial.selected ?? "—")
            .font(.callout.weight(.semibold))
            .lineLimit(1)
            .minimumScaleFactor(0.6)
          Text("effort").font(.caption2).opacity(0.6)
        }
      }
      .overlay(alignment: .top) {
        stepButton(-1, "chevron.up").offset(y: -14)
      }
      .overlay(alignment: .bottom) {
        stepButton(1, "chevron.down").offset(y: 14)
      }
      Text(dial.isAvailable ? dial.timingDescription : Self.describe(dial.unavailability))
        .font(.caption2)
        .multilineTextAlignment(.center)
        .foregroundStyle(.white.opacity(0.35))
    }
    .frame(maxWidth: .infinity)
    .foregroundStyle(.white.opacity(dial.isAvailable ? 0.9 : 0.25))
  }

  private func stepButton(_ delta: Int, _ symbol: String) -> some View {
    Button {
      onDial(delta)
    } label: {
      Image(systemName: symbol).font(.caption)
    }
    .buttonStyle(.plain)
    // At the end of travel the button is dead, because a real dial stops.
    .disabled(!dial.isAvailable || dial.stepped(by: delta) == nil)
    .opacity(dial.stepped(by: delta) == nil ? 0.2 : 1)
  }

  static func describe(_ reason: ReasoningDialState.Unavailability?) -> String {
    switch reason {
    case .noPositionsOffered: return "No levels offered"
    case .notPermitted: return "Not permitted"
    case .noSelection: return "Select an agent"
    case .notLive: return "Not connected"
    case nil: return ""
    }
  }

  /// A four-way pad. Each direction sends a scoped prompt to the selected
  /// agent, which is the same thing typing it would do and spends the same
  /// capability.
  private var joystick: some View {
    let availability = JoystickWorkflow.availability(
      in: surface, capabilities: capabilities)
    return VStack(spacing: 8) {
      ZStack {
        RoundedRectangle(cornerRadius: 20)
          .stroke(
            Color.white.opacity(availability.isAvailable ? 0.22 : 0.08), lineWidth: 10
          )
          .frame(width: 92, height: 92)
        ForEach(JoystickWorkflow.allCases, id: \.rawValue) { workflow in
          workflowButton(workflow, enabled: availability.isAvailable)
        }
      }
      Text(availability.isAvailable ? "Workflows" : DeviceView.describe(availability))
        .font(.caption2)
        .foregroundStyle(.white.opacity(0.35))
    }
    .frame(maxWidth: .infinity)
    .foregroundStyle(.white.opacity(availability.isAvailable ? 0.9 : 0.25))
  }

  private func workflowButton(_ workflow: JoystickWorkflow, enabled: Bool) -> some View {
    let offset: CGSize
    switch workflow.direction {
    case .up: offset = CGSize(width: 0, height: -30)
    case .right: offset = CGSize(width: 32, height: 0)
    case .down: offset = CGSize(width: 0, height: 30)
    case .left: offset = CGSize(width: -32, height: 0)
    }
    return Button {
      onWorkflow(workflow)
    } label: {
      Text(workflow.title)
        .font(.system(size: 9, weight: .semibold))
        .lineLimit(1)
        .minimumScaleFactor(0.6)
        .frame(width: 52)
    }
    .buttonStyle(.plain)
    .disabled(!enabled)
    .offset(offset)
    .accessibilityLabel("\(workflow.title) workflow")
  }

  static func describe(_ availability: CommandKeyAvailability) -> String {
    switch availability {
    case .available: return ""
    case .notPermitted: return "Not permitted"
    case .noSelection: return "Select an agent"
    case .noRunningTurn: return "Not running"
    case .notLive: return "Not connected"
    }
  }
}

/// One frosted, back-lit agent key.
///
/// The hardware communicates by colour before any text is read, so colour
/// carries the activity and everything else is secondary. Freshness is shown
/// by **dimming and a dashed border** rather than by a different hue: a stale
/// running agent is still a running agent, and recolouring it would replace
/// one wrong reading with another.
struct AgentKeyView: View {
  let key: AgentKeyState
  let isSelected: Bool

  var body: some View {
    ZStack {
      RoundedRectangle(cornerRadius: 14)
        .fill(fill)
        .overlay(border)
        .shadow(color: glow, radius: key.freshness == .live ? 14 : 0)
      VStack(spacing: 6) {
        Image(systemName: symbol).font(.title2)
        Text(caption)
          .font(.caption2.weight(.medium))
          .lineLimit(1)
          .minimumScaleFactor(0.7)
      }
      .foregroundStyle(.white.opacity(key.isBound ? 0.95 : 0.28))
      .padding(6)
    }
    .frame(height: 84)
    .opacity(key.freshness == .stale ? 0.55 : 1)
    .accessibilityElement(children: .ignore)
    .accessibilityLabel(accessibilityText)
  }

  /// Colour is the whole signal. `unknown` is deliberately grey rather than
  /// any status colour, because "we do not know" must not be mistakable for a
  /// state at a glance.
  private var tint: Color {
    switch key.activity {
    case .working: return .cyan
    case .waiting: return .orange
    case .finished: return .green
    case .failed: return .red
    case .unknown: return .gray
    }
  }

  private var fill: Color {
    guard key.isBound, key.freshness != .disconnected else { return .white.opacity(0.04) }
    return tint.opacity(0.22)
  }

  private var glow: Color {
    guard key.isBound, key.freshness == .live, key.activity != .unknown else { return .clear }
    return tint.opacity(0.5)
  }

  @ViewBuilder
  private var border: some View {
    let shape = RoundedRectangle(cornerRadius: 14)
    if isSelected {
      shape.stroke(Color.white.opacity(0.85), lineWidth: 2)
    } else if key.freshness == .stale {
      shape.stroke(
        tint.opacity(0.5), style: StrokeStyle(lineWidth: 1.5, dash: [4, 3]))
    } else {
      shape.stroke(Color.white.opacity(0.1), lineWidth: 1)
    }
  }

  private var symbol: String {
    guard key.isBound else { return "circle.dotted" }
    switch key.activity {
    case .working: return "waveform"
    case .waiting: return "hand.raised.fill"
    case .finished: return "checkmark"
    case .failed: return "exclamationmark.triangle.fill"
    case .unknown: return "questionmark"
    }
  }

  private var caption: String {
    guard let threadID = key.threadID else { return "Empty" }
    // The slot shows the tail of the identifier: enough to tell six apart,
    // short enough to read at a glance, and it is opaque either way.
    return String(threadID.suffix(6))
  }

  /// VoiceOver gets the full reading, including staleness, because the visual
  /// cue for it is dimming — which conveys nothing to a screen reader.
  private var accessibilityText: String {
    guard key.isBound else { return "Agent key \(key.slot + 1), empty" }
    let state: String
    switch key.freshness {
    case .live: state = key.activity.rawValue
    case .stale: state = "\(key.activity.rawValue), possibly out of date"
    case .disconnected: state = "disconnected"
    }
    return "Agent key \(key.slot + 1), \(state)"
  }
}
