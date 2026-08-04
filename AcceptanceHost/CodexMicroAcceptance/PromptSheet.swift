import CompanionProtocol
import SwiftUI

/// Prompt entry for the selected agent.
///
/// This is the one place the replica departs from the hardware on purpose.
/// The macropad has push-to-talk and a key that opens the desktop app; it has
/// no way to type, because a thirteen-key pad is the wrong instrument for
/// prose. Inventing a hardware metaphor for a text field would help nobody, so
/// this is a plain iOS sheet.
///
/// What it does keep from the device is the target: the prompt goes to the
/// **selected agent key**, never to "the current conversation" as the Mac
/// understands it. The phone's selection is the phone's, and a prompt landing
/// somewhere else because the desktop focus moved would be the same class of
/// surprise as a key that rebinds itself.
struct PromptSheet: View {
  let agentLabel: String
  let isSteer: Bool
  let onSend: (String) -> Void
  let onCancel: () -> Void

  @State private var text = ""
  @FocusState private var focused: Bool

  var body: some View {
    NavigationStack {
      VStack(alignment: .leading, spacing: 12) {
        Text(isSteer ? "Steer \(agentLabel)" : "Send to \(agentLabel)")
          .font(.headline)
        if isSteer {
          Text(
            "This changes what the running turn is doing. It keeps the sandbox and approval settings it started with."
          )
          .font(.caption)
          .foregroundStyle(.secondary)
        }
        TextEditor(text: $text)
          .focused($focused)
          .font(.body)
          .frame(minHeight: 160)
          .overlay(
            RoundedRectangle(cornerRadius: 8)
              .stroke(Color.secondary.opacity(0.3), lineWidth: 1)
          )
        Spacer()
      }
      .padding()
      .navigationBarTitleDisplayMode(.inline)
      .toolbar {
        ToolbarItem(placement: .cancellationAction) {
          Button("Cancel", action: onCancel)
        }
        ToolbarItem(placement: .confirmationAction) {
          Button("Send") { onSend(trimmed) }
            .disabled(trimmed.isEmpty)
        }
      }
      .onAppear { focused = true }
    }
  }

  /// Whitespace-only input is not a prompt. Sending it would spend a command
  /// and a turn to say nothing.
  private var trimmed: String {
    text.trimmingCharacters(in: .whitespacesAndNewlines)
  }
}
