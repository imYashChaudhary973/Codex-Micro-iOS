import AVFoundation
import SwiftUI
import UIKit

/// A camera preview that reports the first QR code it sees.
///
/// **It fires once.** The pairing payload carries a single-use bootstrap
/// secret, and a scanner that kept firing would start a second pairing attempt
/// against a secret the first one already consumed — which the coordinator
/// correctly refuses, but which reaches the user as a confusing failure rather
/// than as nothing at all.
struct QRScannerView: UIViewControllerRepresentable {
  let onScan: @Sendable (String) -> Void

  func makeCoordinator() -> Coordinator { Coordinator(onScan: onScan) }

  func makeUIViewController(context: Context) -> ScannerController {
    let controller = ScannerController()
    controller.delegate = context.coordinator
    return controller
  }

  func updateUIViewController(_ controller: ScannerController, context: Context) {}

  final class Coordinator: NSObject, AVCaptureMetadataOutputObjectsDelegate {
    private let onScan: @Sendable (String) -> Void
    private var hasFired = false

    init(onScan: @escaping @Sendable (String) -> Void) {
      self.onScan = onScan
    }

    func metadataOutput(
      _ output: AVCaptureMetadataOutput,
      didOutput objects: [AVMetadataObject],
      from connection: AVCaptureConnection
    ) {
      guard !hasFired,
        let object = objects.first as? AVMetadataMachineReadableCodeObject,
        object.type == .qr,
        let value = object.stringValue
      else {
        return
      }
      hasFired = true
      // The delegate queue is `.main` (set below), so this callback already
      // runs on the main actor; asserting that is cheaper and more honest
      // than hopping to a queue we are already on.
      let deliver = onScan
      MainActor.assumeIsolated { deliver(value) }
    }
  }
}

/// Hosts the capture session.
final class ScannerController: UIViewController {
  weak var delegate: AVCaptureMetadataOutputObjectsDelegate?
  /// `AVCaptureSession` is not `Sendable`, and start/stop must not run on the
  /// main thread because both block. It is confined to this serial queue
  /// instead, which is the ownership the SDK actually expects.
  private nonisolated(unsafe) let session = AVCaptureSession()
  private let sessionQueue = DispatchQueue(label: "com.codexmicro.acceptance.capture")
  private var preview: AVCaptureVideoPreviewLayer?

  override func viewDidLoad() {
    super.viewDidLoad()
    view.backgroundColor = .black
    configure()
  }

  override func viewWillAppear(_ animated: Bool) {
    super.viewWillAppear(animated)
    guard !session.isRunning else { return }
    // Starting blocks; keeping it off the main thread is what stops the first
    // frame from stalling the presentation animation.
    sessionQueue.async { [session] in session.startRunning() }
  }

  override func viewWillDisappear(_ animated: Bool) {
    super.viewWillDisappear(animated)
    // Stop as soon as the view goes away. A camera left running behind a
    // dismissed screen is both a battery cost and a privacy surprise.
    if session.isRunning {
      sessionQueue.async { [session] in session.stopRunning() }
    }
  }

  override func viewDidLayoutSubviews() {
    super.viewDidLayoutSubviews()
    preview?.frame = view.bounds
  }

  private func configure() {
    guard let device = AVCaptureDevice.default(for: .video),
      let input = try? AVCaptureDeviceInput(device: device),
      session.canAddInput(input)
    else {
      return
    }
    session.addInput(input)

    let output = AVCaptureMetadataOutput()
    guard session.canAddOutput(output) else { return }
    session.addOutput(output)
    output.setMetadataObjectsDelegate(delegate, queue: .main)
    // QR only. Restricting the types means a barcode on a nearby object cannot
    // produce a spurious callback the flow would then have to reject.
    output.metadataObjectTypes = [.qr]

    let preview = AVCaptureVideoPreviewLayer(session: session)
    preview.videoGravity = .resizeAspectFill
    preview.frame = view.bounds
    view.layer.addSublayer(preview)
    self.preview = preview
  }
}
