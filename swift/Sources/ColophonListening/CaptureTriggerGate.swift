import Foundation

/// Admission for a semantic Next command while an app owns active playback. The command is
/// available on headphones, car controls and keyboards; it does not identify the device.
public struct CaptureTriggerGate: Sendable {
  private var last: (episode: String, seconds: Double, date: Date)?

  public init() {}

  public mutating func accept(modeEnabled: Bool, isPlaying: Bool, episode: String?, seconds: Double,
    now: Date = .now) -> Bool
  {
    guard modeEnabled, isPlaying, let episode, !episode.isEmpty,
      seconds.isFinite, seconds >= 0 else { return false }
    if let last, last.episode == episode, now.timeIntervalSince(last.date) >= 0,
      now.timeIntervalSince(last.date) < 1, abs(last.seconds - seconds) < 1
    { return false }
    last = (episode, seconds, now)
    return true
  }
}
