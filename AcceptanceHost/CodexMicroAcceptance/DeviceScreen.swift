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

  var body: some View {
    DeviceView(surface: surface) { slot in
      selectedSlot = surface.selectedSlot == slot ? nil : slot
      reproject()
    }
    .onAppear {
      bindings = AgentKeyBindingStore.load()
      reproject()
    }
  }

  /// Applies a new authorized view: fill empty keys, keep every established
  /// one, persist, and re-derive.
  func apply(threads incoming: [ObservedThreadState], at instant: Date) {
    threads = incoming
    lastUpdate = instant
    let filled = bindings.filling(from: incoming)
    if filled != bindings {
      bindings = filled
      AgentKeyBindingStore.save(filled)
    }
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
