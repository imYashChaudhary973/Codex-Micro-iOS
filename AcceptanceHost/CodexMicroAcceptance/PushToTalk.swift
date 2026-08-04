import AVFoundation
import Foundation
import Speech

/// Push-to-talk: hold, speak, release, and a prompt string comes out.
///
/// **Recognition is forced on-device and audio never leaves the phone.**
/// Phase 3 invariant 5 requires only that voice is text by the time it reaches
/// the protocol, which would be satisfied by sending audio to Apple's servers
/// and putting the transcript on the wire. That is not good enough here: the
/// prompts a user dictates to a coding agent describe their own codebase, and
/// routing them through a third party to save a few points of accuracy is a
/// disclosure the user did not ask for and would not see.
///
/// `requiresOnDeviceRecognition` is therefore set, and a recogniser that
/// cannot honour it fails rather than silently falling back — which is exactly
/// what the framework does by default, and is the failure mode worth guarding.
///
/// The command path cannot tell the difference between this and typing. That
/// is deliberate: a dictated prompt gets no special handling, spends the same
/// capability, and is governed by the same policy.
@MainActor
public final class PushToTalkRecogniser: ObservableObject {
  public enum State: Equatable, Sendable {
    case idle
    case unavailable(Reason)
    case listening(partial: String)
    case finished(String)
  }

  public enum Reason: String, Equatable, Sendable {
    case permissionDenied
    case onDeviceUnavailable
    case recogniserUnavailable
    case audioUnavailable
  }

  @Published public private(set) var state: State = .idle

  private let recogniser = SFSpeechRecognizer(locale: Locale.current)
  /// The audio engine is not main-actor state and must not be treated as
  /// such: `installTap` invokes its block on a real-time audio thread, and a
  /// closure that inherits main-actor isolation from this class makes Swift's
  /// executor check trap there. `nonisolated(unsafe)` says what is true — the
  /// engine is used from the audio thread by design — and the tap is
  /// installed by a `nonisolated` helper so the closure never captures actor
  /// context at all.
  private nonisolated(unsafe) let engine = AVAudioEngine()
  private var request: SFSpeechAudioBufferRecognitionRequest?
  private var task: SFSpeechRecognitionTask?

  public init() {}

  /// Asks for permission and reports whether dictation can work at all.
  ///
  /// On-device availability is checked here rather than at first use, so the
  /// key can show itself as unavailable instead of failing under a thumb.
  public func prepare() async {
    guard let recogniser, recogniser.isAvailable else {
      state = .unavailable(.recogniserUnavailable)
      return
    }
    guard recogniser.supportsOnDeviceRecognition else {
      // No silent fallback to server recognition: the whole point is that the
      // audio does not leave.
      state = .unavailable(.onDeviceUnavailable)
      return
    }
    guard await Self.requestSpeechAuthorization() == .authorized else {
      state = .unavailable(.permissionDenied)
      return
    }
    let microphone = await Self.requestMicrophoneAccess()
    state = microphone ? .idle : .unavailable(.permissionDenied)
  }

  /// Asks TCC for speech authorization, off the main actor.
  ///
  /// **This must not be `@MainActor`.** `SFSpeechRecognizer.requestAuthorization`
  /// invokes its callback on TCC's own XPC reply queue. Resuming a
  /// continuation from there while the enclosing function is main-actor
  /// isolated makes Swift's executor check fail the dispatch queue assertion,
  /// which is a `SIGTRAP` — the app crashed on launch because `prepare()` runs
  /// from `.task` and never got past this call.
  ///
  /// Isolating the bridge to `nonisolated` lets the callback resume on
  /// whatever queue TCC chose, and the `await` at the call site hops back to
  /// the main actor afterwards.
  private nonisolated static func requestSpeechAuthorization() async
    -> SFSpeechRecognizerAuthorizationStatus
  {
    await withCheckedContinuation { continuation in
      SFSpeechRecognizer.requestAuthorization { continuation.resume(returning: $0) }
    }
  }

  /// Microphone access, off the main actor for the same reason.
  private nonisolated static func requestMicrophoneAccess() async -> Bool {
    await AVAudioApplication.requestRecordPermission()
  }

  /// Begins listening. Called on key-down.
  public func start() {
    guard case .idle = state, let recogniser, recogniser.supportsOnDeviceRecognition else {
      return
    }
    let request = SFSpeechAudioBufferRecognitionRequest()
    request.shouldReportPartialResults = true
    request.requiresOnDeviceRecognition = true
    self.request = request

    do {
      try Self.startCapturing(engine: engine, into: request)
    } catch {
      state = .unavailable(.audioUnavailable)
      return
    }

    state = .listening(partial: "")
    task = recogniser.recognitionTask(with: request) { [weak self] result, error in
      Task { @MainActor in
        guard let self else { return }
        if let result {
          let text = result.bestTranscription.formattedString
          if result.isFinal {
            self.state = .finished(text)
          } else if case .listening = self.state {
            self.state = .listening(partial: text)
          }
        }
        if error != nil, case .listening(let partial) = self.state {
          // A recogniser error after speech is not a reason to discard what
          // was heard; the user can see it and decide.
          self.state = partial.isEmpty ? .idle : .finished(partial)
        }
      }
    }
  }

  /// Configures the session and installs the tap, off the main actor.
  ///
  /// The tap block runs on a real-time audio thread. Declaring it `@Sendable`
  /// inside a `nonisolated` function is what stops it inheriting main-actor
  /// isolation from the enclosing class — which is what crashed the app the
  /// moment the talk key was held.
  ///
  /// `SFSpeechAudioBufferRecognitionRequest.append` is safe to call from that
  /// thread; the isolation, not the API, was the problem.
  private nonisolated static func startCapturing(
    engine: AVAudioEngine,
    into request: SFSpeechAudioBufferRecognitionRequest
  ) throws {
    let session = AVAudioSession.sharedInstance()
    try session.setCategory(.record, mode: .measurement, options: .duckOthers)
    try session.setActive(true, options: .notifyOthersOnDeactivation)
    let input = engine.inputNode
    let format = input.outputFormat(forBus: 0)
    // A zero-channel format means no usable input route. Installing a tap on
    // one throws deep inside AVFAudio; refusing here keeps the failure in the
    // closed vocabulary.
    guard format.channelCount > 0 else { throw Failure.noInputRoute }
    input.installTap(onBus: 0, bufferSize: 1_024, format: format) {
      @Sendable buffer, _ in
      request.append(buffer)
    }
    engine.prepare()
    try engine.start()
  }

  private enum Failure: Error { case noInputRoute }

  /// Stops listening and settles on a transcript. Called on key-up.
  public func stop() {
    Self.stopCapturing(engine: engine)
    request?.endAudio()
    task?.finish()
    if case .listening(let partial) = state {
      state = partial.isEmpty ? .idle : .finished(partial)
    }
  }

  /// Tears the capture down, off the main actor for the same reason.
  private nonisolated static func stopCapturing(engine: AVAudioEngine) {
    engine.inputNode.removeTap(onBus: 0)
    engine.stop()
    try? AVAudioSession.sharedInstance().setActive(
      false, options: .notifyOthersOnDeactivation)
  }

  /// Clears a finished transcript once it has been used or discarded.
  public func reset() {
    if case .unavailable = state { return }
    state = .idle
  }

  /// The transcript, trimmed, or `nil` when there is nothing usable.
  ///
  /// Whitespace-only dictation is not a prompt; sending it would spend a
  /// command and a turn to say nothing.
  public var transcript: String? {
    guard case .finished(let text) = state else { return nil }
    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
    return trimmed.isEmpty ? nil : trimmed
  }
}
