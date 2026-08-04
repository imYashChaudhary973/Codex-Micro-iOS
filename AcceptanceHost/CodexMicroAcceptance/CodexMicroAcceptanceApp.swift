import SwiftUI

/// The minimal signed iOS acceptance host (plan Step 2.14).
///
/// **This is not the Phase 3 companion app.** It exists to do three things and
/// nothing else: prove that `CompanionProtocol` and `CompanionCrypto` compile
/// and link into a development-signed iOS app, carry the local-network
/// entitlement keys a real pairing needs, and present the acceptance matrix so
/// a physical run is driven from a checklist rather than from memory.
///
/// It implements no protocol of its own and makes no authorization decision.
/// Plan §3 fixes that boundary: the acceptance host supplies iOS Keychain and
/// network adapters to `CompanionCrypto` and contains no independent protocol
/// or authorization implementation. It becomes the technical foundation for
/// Phase 3; it is not yet that app.
@main
struct CodexMicroAcceptanceApp: App {
  @StateObject private var pairing = PhonePairingModel()

  var body: some Scene {
    WindowGroup {
      TabView {
        DeviceScreen()
          .tabItem { Label("Device", systemImage: "square.grid.3x2.fill") }
        PairingScreen(model: pairing, flow: PhonePairingFlow(model: pairing))
          .tabItem { Label("Pair", systemImage: "qrcode") }
        AcceptanceView()
          .tabItem { Label("Matrix", systemImage: "checklist") }
      }
      .task {
        // An acceptance run supplies the pairing code at launch so the run is
        // reproducible and its output readable. Absent the variable this does
        // nothing and the camera is the only path.
        if let code = PhoneAcceptanceRun.suppliedCode {
          await PhoneAcceptanceRun.run(code: code, model: pairing)
        }
      }
    }
  }
}
