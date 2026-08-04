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
  let onSelect: (Int) -> Void
  let onCommand: (CommandKey) -> Void

  var body: some View {
    VStack(spacing: 28) {
      connectionBanner
      agentKeys
      Divider().overlay(Color.white.opacity(0.08))
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
      dial
      joystick
    }
    .foregroundStyle(.white.opacity(0.22))
  }

  private var dial: some View {
    VStack(spacing: 8) {
      Circle()
        .stroke(Color.white.opacity(0.12), lineWidth: 10)
        .frame(width: 92, height: 92)
        .overlay(Image(systemName: "dial.medium").font(.title2))
      Text("Reasoning").font(.caption2)
    }
    .frame(maxWidth: .infinity)
  }

  private var joystick: some View {
    VStack(spacing: 8) {
      RoundedRectangle(cornerRadius: 20)
        .stroke(Color.white.opacity(0.12), lineWidth: 10)
        .frame(width: 92, height: 92)
        .overlay(Image(systemName: "dpad").font(.title2))
      Text("Workflows").font(.caption2)
    }
    .frame(maxWidth: .infinity)
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
