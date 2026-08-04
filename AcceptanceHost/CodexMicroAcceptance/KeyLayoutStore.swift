import CompanionProtocol
import Foundation

/// Persists the command-row layout.
///
/// A layout is a preference: it names actions the device may or may not be
/// permitted to perform, and permission is decided from the grant every time
/// the key is drawn. Storing it cannot grant anything, which is why it sits in
/// `UserDefaults` next to the agent-key bindings rather than in the Keychain
/// with the pinning material.
public enum KeyLayoutStore {
  private static let key = "com.codexmicro.acceptance.key-layout"

  public static func load(from defaults: UserDefaults = .standard) -> KeyLayout {
    guard let data = defaults.data(forKey: key),
      let layout = try? JSONDecoder().decode(KeyLayout.self, from: data)
    else {
      return .default
    }
    return layout
  }

  public static func save(_ layout: KeyLayout, to defaults: UserDefaults = .standard) {
    guard let data = try? JSONEncoder().encode(layout) else { return }
    defaults.set(data, forKey: key)
  }
}
