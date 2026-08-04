import CompanionProtocol
import SwiftUI

/// Reassigns the six command-key positions.
///
/// Actions the device may not perform are shown and labelled rather than
/// hidden. Hiding them would make the grant invisible: a user would wonder why
/// "Approve" is missing and have no way to learn that their device was never
/// granted it. Shown-and-marked, the pad explains itself.
struct RemapSheet: View {
  let capabilities: Set<DeviceCapability>
  @Binding var layout: KeyLayout
  let onDone: () -> Void

  var body: some View {
    NavigationStack {
      List {
        ForEach(0..<KeyLayout.positionCount, id: \.self) { position in
          Section("Key \(position + 1)") {
            ForEach(KeyAction.allCases, id: \.rawValue) { action in
              row(action, at: position)
            }
          }
        }
      }
      .navigationTitle("Remap keys")
      .navigationBarTitleDisplayMode(.inline)
      .toolbar {
        ToolbarItem(placement: .confirmationAction) { Button("Done", action: onDone) }
        ToolbarItem(placement: .cancellationAction) {
          Button("Reset") { layout = .default }
        }
      }
    }
  }

  private func row(_ action: KeyAction, at position: Int) -> some View {
    let permitted =
      action.requiredCapability.map { capabilities.contains($0) } ?? true
    return Button {
      layout = layout.assigning(action, to: position)
    } label: {
      HStack {
        Text(action == .none ? "Empty" : action.title)
        if !permitted {
          Text("not permitted")
            .font(.caption2)
            .foregroundStyle(.secondary)
        }
        Spacer()
        if layout.action(at: position) == action {
          Image(systemName: "checkmark").foregroundStyle(.tint)
        }
      }
    }
    .foregroundStyle(permitted ? .primary : .secondary)
  }
}
