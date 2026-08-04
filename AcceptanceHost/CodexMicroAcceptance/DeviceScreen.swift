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
  @State private var selectedSlot: Int?

  var body: some View {
    DeviceView(surface: surface) { slot in
      selectedSlot = surface.selectedSlot == slot ? nil : slot
      reproject()
    }
  }

  /// Re-derives the surface. Once the session client exists this runs on every
  /// observation batch; for now it only reflects selection.
  private func reproject() {
    surface = DeviceSurfaceProjection().project(
      bindings: [],
      threads: [],
      lastUpdate: nil,
      now: Date(),
      isConnected: false,
      selectedSlot: selectedSlot
    )
  }
}
