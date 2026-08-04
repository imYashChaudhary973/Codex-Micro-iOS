import AppKit
import SwiftUI

/// The Mac's pairing window: show the QR, then show the phrase to compare.
///
/// It is a window rather than a menu item because both steps need the user to
/// look at something for several seconds while holding a phone, and a menu
/// that dismisses on the first click outside it is the wrong container for
/// that.
///
/// **The QR is shown only while a session is live.** The payload carries the
/// single-use bootstrap secret, so leaving it on screen after pairing
/// completes or fails would leave a spent — or worse, unspent — secret
/// visible to anyone who walks past.
struct BridgePairingView: View {
  @ObservedObject var model: BridgePairingModel
  let onBegin: () -> Void
  let onConfirm: () -> Void
  let onCancel: () -> Void

  var body: some View {
    VStack(spacing: 16) {
      switch model.state {
      case .idle:
        idle
      case .awaitingScan(let text, let expiresAt):
        scan(text: text, expiresAt: expiresAt)
      case .awaitingPhrase:
        phrase
      case .awaitingDevice:
        waiting
      case .paired(let deviceID):
        paired(deviceID)
      case .alreadyPaired:
        alreadyPaired
      case .failed(let reason):
        failed(reason)
      }
    }
    .padding(24)
    .frame(width: 380)
  }

  private var idle: some View {
    VStack(spacing: 12) {
      Text("Pair a device").font(.headline)
      Text("LAN access must be on before a device can pair.")
        .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
      Button("Show pairing code", action: onBegin)
    }
  }

  private func scan(text: String, expiresAt: UInt64) -> some View {
    VStack(spacing: 12) {
      Text("Scan with your iPhone").font(.headline)
      if let image = BridgePairingQR.image(for: text) {
        Image(decorative: image, scale: 1)
          .interpolation(.none)
          .resizable()
          .frame(width: 260, height: 260)
      } else {
        Text("Could not render the code").foregroundStyle(.red)
      }
      Text("This code carries a single-use secret and expires shortly.")
        .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
      Button("Cancel", action: onCancel)
    }
  }

  private var phrase: some View {
    VStack(spacing: 12) {
      Text("Do these words match your iPhone?").font(.headline)
      // Two rows of three. The words are the security boundary against a
      // machine-in-the-middle, so they are the largest thing on screen.
      let words = model.pendingWords
      VStack(spacing: 6) {
        ForEach(Array(stride(from: 0, to: words.count, by: 3)), id: \.self) { start in
          HStack(spacing: 14) {
            ForEach(words[start..<min(start + 3, words.count)], id: \.self) { word in
              Text(word).font(.system(.title2, design: .monospaced)).bold()
            }
          }
        }
      }
      .padding(.vertical, 8)
      Text("Confirm only if every word matches, in order.")
        .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
      HStack {
        Button("They do not match", action: onCancel)
        Button("They match", action: onConfirm).keyboardShortcut(.defaultAction)
      }
    }
  }

  private var waiting: some View {
    VStack(spacing: 12) {
      ProgressView()
      Text("Waiting for the iPhone to confirm").font(.headline)
      Button("Cancel", action: onCancel)
    }
  }

  private func paired(_ deviceID: UUID) -> some View {
    VStack(spacing: 12) {
      Image(systemName: "checkmark.circle").font(.largeTitle).foregroundStyle(.green)
      Text("Paired").font(.headline)
      // A freshly paired device can see nothing until a project is granted;
      // saying so here prevents the "it paired but shows nothing" report.
      Text("This device can observe nothing yet. Grant it a project to give it a view.")
        .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
      Button("Done", action: onCancel)
    }
  }

  private var alreadyPaired: some View {
    VStack(spacing: 12) {
      Image(systemName: "checkmark.circle").font(.largeTitle).foregroundStyle(.secondary)
      Text("Already paired").font(.headline)
      Text(
        "This device already has a grant, which was kept. Remove it first if you "
          + "want to pair it again from scratch."
      )
      .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
      Button("Done", action: onCancel)
    }
  }

  private func failed(_ reason: String) -> some View {
    VStack(spacing: 12) {
      Image(systemName: "xmark.octagon").font(.largeTitle).foregroundStyle(.red)
      Text("Pairing failed").font(.headline)
      Text(reason).font(.caption).foregroundStyle(.secondary)
      Button("Close", action: onCancel)
    }
  }
}
