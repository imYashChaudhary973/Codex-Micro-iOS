import SwiftUI

/// Drives the acceptance matrix on the device.
///
/// The screen is deliberately plain. Its job is to make three states
/// impossible to confuse at a gate: a precondition that holds, one that does
/// not, and a case that has no offline precondition at all. Colour alone would
/// not do that, so each row states which it is in words.
struct AcceptanceView: View {
  @State private var readiness: [String: AcceptanceReadiness] = [:]
  @State private var expanded: Set<String> = []

  var body: some View {
    NavigationStack {
      List {
        Section {
          summary
        }
        ForEach(AcceptanceCase.matrix) { item in
          Section {
            row(for: item)
          }
        }
        Section {
          Text(
            "Readiness is not a pass. It reports only whether this device is in "
              + "a position for the physical run to mean anything. Every gate above "
              + "requires a real Mac, a real iPhone, and real Wi-Fi."
          )
          .font(.footnote)
          .foregroundStyle(.secondary)
        }
      }
      .navigationTitle("Phase 2 Acceptance")
      .toolbar {
        Button("Check") { runPreconditions() }
      }
    }
    .onAppear(perform: runPreconditions)
  }

  private var summary: some View {
    let results = AcceptanceGate.allCases.map { readiness[$0.rawValue] ?? .physicalOnly }
    let blocked = results.filter(\.isBlocking).count
    let checkable = results.filter { if case .satisfied = $0 { return true } else { return false } }
      .count
    return VStack(alignment: .leading, spacing: 4) {
      Text("\(AcceptanceCase.matrix.count) gates").font(.headline)
      Text("\(checkable) preconditions satisfied, \(blocked) blocking")
        .font(.subheadline)
        .foregroundStyle(blocked > 0 ? .red : .secondary)
      Text("Physical results are recorded outside this app, against a frozen main SHA.")
        .font(.caption)
        .foregroundStyle(.secondary)
    }
  }

  @ViewBuilder
  private func row(for item: AcceptanceCase) -> some View {
    let state = readiness[item.gate.rawValue] ?? .physicalOnly
    VStack(alignment: .leading, spacing: 6) {
      Text(item.title).font(.headline)
      Text(item.proves).font(.caption).foregroundStyle(.secondary)
      readinessLabel(state)
      Button(expanded.contains(item.id) ? "Hide procedure" : "Show procedure") {
        if expanded.contains(item.id) {
          expanded.remove(item.id)
        } else {
          expanded.insert(item.id)
        }
      }
      .font(.caption)
      if expanded.contains(item.id) {
        ForEach(Array(item.procedure.enumerated()), id: \.offset) { index, step in
          Text("\(index + 1). \(step)").font(.caption).foregroundStyle(.secondary)
        }
      }
    }
    .padding(.vertical, 2)
  }

  @ViewBuilder
  private func readinessLabel(_ state: AcceptanceReadiness) -> some View {
    switch state {
    case .satisfied(let detail):
      Label("Precondition holds — \(detail)", systemImage: "checkmark.circle")
        .font(.caption).foregroundStyle(.green)
    case .physicalOnly:
      Label("No offline precondition — physical only", systemImage: "iphone.gen3")
        .font(.caption).foregroundStyle(.secondary)
    case .unsatisfied(let reason):
      Label("Blocked — \(reason)", systemImage: "xmark.octagon")
        .font(.caption).foregroundStyle(.red)
    }
  }

  private func runPreconditions() {
    var next: [String: AcceptanceReadiness] = [:]
    for gate in AcceptanceGate.allCases {
      next[gate.rawValue] = AcceptancePreconditions.readiness(for: gate)
    }
    readiness = next
    AcceptancePreconditions.emit(next)
  }
}
