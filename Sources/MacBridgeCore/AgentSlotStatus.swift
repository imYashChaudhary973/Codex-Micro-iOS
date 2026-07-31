public enum AgentSlotStatus: String, Codable, Equatable, Sendable {
  case unassigned
  case inputRequired
  case thinking
  case error
  case completeUnread
  case idle

  public static func derive(
    isAssigned: Bool,
    hasPendingInput: Bool,
    hasActiveTurn: Bool,
    hasUnreadFailure: Bool,
    hasUnreadCompletion: Bool
  ) -> AgentSlotStatus {
    guard isAssigned else { return .unassigned }
    if hasPendingInput { return .inputRequired }
    if hasActiveTurn { return .thinking }
    if hasUnreadFailure { return .error }
    if hasUnreadCompletion { return .completeUnread }
    return .idle
  }
}
