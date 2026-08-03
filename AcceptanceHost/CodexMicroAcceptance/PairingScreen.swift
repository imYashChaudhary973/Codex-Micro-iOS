import SwiftUI

/// The phone's pairing screen: scan, compare, confirm.
///
/// The comparison step is the one that matters. It is the only defence against
/// something on the same Wi-Fi answering instead of the Mac, so the words are
/// the largest thing on screen and the affirmative button is not the default —
/// a user tapping through should not confirm a pairing by reflex.
struct PairingScreen: View {
  @ObservedObject var model: PhonePairingModel
  let flow: PhonePairingFlow

  var body: some View {
    NavigationStack {
      Group {
        switch model.state {
        case .idle:
          idle
        case .scanning:
          QRScannerView { text in
            Task { await flow.begin(scannedText: text) }
          }
          .ignoresSafeArea()
        case .comparing(let words):
          comparing(words)
        case .awaitingMac:
          awaitingMac
        case .paired:
          paired
        case .failed(let reason):
          failed(reason)
        }
      }
      .navigationTitle("Pair with Mac")
      .navigationBarTitleDisplayMode(.inline)
    }
  }

  private var idle: some View {
    VStack(spacing: 16) {
      Image(systemName: "qrcode.viewfinder").font(.system(size: 64))
      Text("Scan the code shown on your Mac").font(.headline)
      Text("Turn on LAN access in the Codex Micro menu first.")
        .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
      Button("Scan") { model.set(.scanning) }.buttonStyle(.borderedProminent)
    }
    .padding()
  }

  private func comparing(_ words: [String]) -> some View {
    VStack(spacing: 20) {
      Text("Do these match your Mac?").font(.headline)
      VStack(spacing: 8) {
        ForEach(Array(stride(from: 0, to: words.count, by: 3)), id: \.self) { start in
          HStack(spacing: 12) {
            ForEach(words[start..<min(start + 3, words.count)], id: \.self) { word in
              Text(word).font(.system(.title3, design: .monospaced)).bold()
            }
          }
        }
      }
      Text(
        "Every word must match, in order. If they do not, something else on this network answered."
      )
      .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
      VStack(spacing: 10) {
        Button("They match") { Task { await flow.confirmMatch() } }
          .buttonStyle(.borderedProminent)
        Button("They do not match", role: .destructive) { Task { await flow.cancel() } }
      }
    }
    .padding()
  }

  private var awaitingMac: some View {
    VStack(spacing: 16) {
      ProgressView()
      Text("Confirm on your Mac to finish").font(.headline)
      Button("Done") { Task { await flow.cancel() } }
    }
    .padding()
  }

  private var paired: some View {
    VStack(spacing: 16) {
      Image(systemName: "checkmark.circle").font(.system(size: 56)).foregroundStyle(.green)
      Text("Paired").font(.headline)
      Button("Done") { Task { await flow.cancel() } }
    }
    .padding()
  }

  private func failed(_ reason: String) -> some View {
    VStack(spacing: 16) {
      Image(systemName: "xmark.octagon").font(.system(size: 56)).foregroundStyle(.red)
      Text("Pairing failed").font(.headline)
      Text(reason).font(.caption).foregroundStyle(.secondary)
      if reason == "pinMismatch" {
        Text("The server did not present the key the code named. Do not retry on this network.")
          .font(.caption).foregroundStyle(.red).multilineTextAlignment(.center)
      }
      Button("Start over") { Task { await flow.cancel() } }
    }
    .padding()
  }
}
