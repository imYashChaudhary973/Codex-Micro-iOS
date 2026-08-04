import CompanionProtocol
import Foundation

/// Persists which thread each agent key is bound to.
///
/// Bindings survive relaunch and reconnect, because a key that forgets its
/// agent when the app is backgrounded is a key you cannot build muscle memory
/// around — and muscle memory is the entire reason the layout is fixed.
///
/// `UserDefaults` is correct here, unlike for the paired host. A binding is a
/// preference: it names a thread the device is already authorized to see, and
/// learning it tells an attacker nothing they could not learn from the
/// observation feed itself. The pinning material next door is in the Keychain
/// precisely because that distinction is real.
public enum AgentKeyBindingStore {
  private static let key = "com.codexmicro.acceptance.agent-key-bindings"

  public static func load(from defaults: UserDefaults = .standard) -> AgentKeyBindings {
    guard let data = defaults.data(forKey: key),
      let bindings = try? JSONDecoder().decode(AgentKeyBindings.self, from: data)
    else {
      // Undecodable stored bindings reset to empty rather than throwing. The
      // worst case is that six keys need reassigning, and refusing to start
      // over a corrupt preference would be a far worse trade.
      return .empty
    }
    return bindings
  }

  public static func save(
    _ bindings: AgentKeyBindings,
    to defaults: UserDefaults = .standard
  ) {
    guard let data = try? JSONEncoder().encode(bindings) else { return }
    defaults.set(data, forKey: key)
  }
}
