import Foundation

/// The fixed, versioned 2,048-entry word list the verification phrase renders
/// through (plan §2 invariant 7).
///
/// **The list is generated, not transcribed.** Step 2.3 recorded that it must
/// ship once, complete and reviewed, rather than hand-assembled — a
/// transcribed natural-language list is 2,048 opportunities for a silent
/// typo, and a single wrong entry on one endpoint makes two honest devices
/// disagree about a phrase that is otherwise identical. Generating it from a
/// 20-line rule removes that failure mode entirely: the rule *is* the list,
/// it is reviewable in one screen, and its properties are asserted rather
/// than assumed.
///
/// Every word is one pronounceable syllable built as onset + nucleus + coda
/// from three small fixed alphabets whose sizes multiply to exactly 2,048
/// (16 × 8 × 16 = 2^11), so index *n* maps to exactly one word and every
/// index in `0..<2048` is reachable.
///
/// **This is a display concern only.** The six indices, their derivation, and
/// their golden vectors are unchanged; a device comparing decimal groups and
/// one comparing words are comparing the same 66 bits.
public enum SecureSASWordList {
  /// The versioned identity of this list. A future list must change it, so
  /// two endpoints can never silently render the same indices differently.
  public static let version = "codex-micro/sas-words/v1"

  /// Syllable onsets. 16 entries.
  static let onsets = [
    "b", "d", "f", "g", "h", "j", "k", "l", "m", "n", "p", "r", "s", "t", "v", "z",
  ]

  /// Syllable nuclei. 8 entries, all unambiguous when read aloud.
  static let nuclei = ["a", "e", "i", "o", "u", "ai", "ee", "oo"]

  /// Syllable codas. 16 entries.
  static let codas = [
    "b", "d", "f", "g", "k", "l", "m", "n", "p", "r", "s", "t", "v", "z", "ng", "sh",
  ]

  /// The number of words, fixed by the 11 bits each index carries.
  public static let count = Int(SecureShortAuthenticationString.indexUpperBound)

  /// The complete list, in index order.
  ///
  /// Built once and held, because the phrase is rendered on every pairing and
  /// rebuilding 2,048 strings each time would be wasteful for no benefit.
  public static let words: [String] = {
    var built: [String] = []
    built.reserveCapacity(count)
    for onset in onsets {
      for nucleus in nuclei {
        for coda in codas {
          built.append(onset + nucleus + coda)
        }
      }
    }
    return built
  }()

  /// The word for one index, or `nil` when the index is out of range.
  ///
  /// Out of range is unreachable through ``SecureShortAuthenticationString``,
  /// whose initializer already rejects it; the optional exists so a caller
  /// that builds an index some other way cannot silently render a wrong word.
  public static func word(at index: UInt16) -> String? {
    let position = Int(index)
    guard position >= 0, position < words.count else { return nil }
    return words[position]
  }
}

extension SecureShortAuthenticationString {
  /// The phrase as six words from the fixed versioned list.
  ///
  /// This is what a user reads aloud and compares. It carries exactly the
  /// same 66 bits as ``displayGroups``; neither rendering is more or less
  /// authoritative than the other.
  public var displayWords: [String] {
    indices.compactMap { SecureSASWordList.word(at: $0) }
  }

  /// The phrase as a single space-separated string.
  public var displayPhrase: String {
    displayWords.joined(separator: " ")
  }
}
