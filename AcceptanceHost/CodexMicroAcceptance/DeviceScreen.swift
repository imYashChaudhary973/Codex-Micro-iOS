import CompanionProtocol
import SwiftUI

/// Hosts the device surface.
///
/// **The feed is not connected yet.** Step 3.1 lands the surface and its state
/// rules; Step 3.2 binds slots to threads and Step 3.1b brings up the
/// authenticated session that supplies live observation. Until then the
/// surface renders honestly from whatever it has been told, which is nothing —
/// so every key is dark and the banner says the device is not connected.
///
/// That is the correct appearance for this state rather than a placeholder.
/// The alternative, showing invented agents to demonstrate the layout, would
/// violate the one invariant the surface exists to keep.
struct DeviceScreen: View {
  @State private var surface: DeviceSurfaceState = .disconnected
  @State private var bindings: AgentKeyBindings = .empty
  @State private var threads: [ObservedThreadState] = []
  @State private var lastUpdate: Date?
  @State private var isConnected = false
  @State private var selectedSlot: Int?
  @State private var capabilities: Set<DeviceCapability> = []

  var body: some View {
    DeviceView(
      surface: surface,
      capabilities: capabilities,
      onSelect: { slot in
        selectedSlot = surface.selectedSlot == slot ? nil : slot
        reproject()
      },
      onCommand: perform
    )
    .onAppear {
      bindings = AgentKeyBindingStore.load()
      reproject()
    }
  }

  /// Applies a new authorized view: fill empty keys, keep every established
  /// one, persist, and re-derive.
  func apply(
    threads incoming: [ObservedThreadState],
    capabilities granted: Set<DeviceCapability>,
    at instant: Date
  ) {
    threads = incoming
    capabilities = granted
    lastUpdate = instant
    let filled = bindings.filling(from: incoming)
    if filled != bindings {
      bindings = filled
      AgentKeyBindingStore.save(filled)
    }
    reproject()
  }

  /// Runs a command key.
  ///
  /// Navigation is local. The acting keys are wired in the next step; the
  /// availability resolver already governs whether they are reachable, so
  /// adding the command call does not change what is pressable.
  private func perform(_ key: CommandKey) {
    switch key {
    case .previousAgent: moveSelection(by: -1)
    case .nextAgent: moveSelection(by: 1)
    case .stop, .steer, .markRead: break
    }
  }

  /// Moves to the next bound key, skipping empty slots so navigation never
  /// lands somewhere nothing can be done.
  private func moveSelection(by step: Int) {
    let bound = surface.agentKeys.filter(\.isBound).map(\.slot)
    guard !bound.isEmpty else { return }
    guard let current = surface.selectedSlot, let index = bound.firstIndex(of: current) else {
      selectedSlot = bound.first
      reproject()
      return
    }
    let next = (index + step + bound.count) % bound.count
    selectedSlot = bound[next]
    reproject()
  }

  /// Re-derives the surface from whatever is currently known.
  private func reproject() {
    surface = DeviceSurfaceProjection().project(
      bindings: bindings.slots,
      threads: threads,
      lastUpdate: lastUpdate,
      now: Date(),
      isConnected: isConnected,
      selectedSlot: selectedSlot
    )
  }
}
