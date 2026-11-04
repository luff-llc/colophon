import ColophonListening
import Foundation
import Testing

@Suite struct CaptureTriggerGateTests {
  @Test func requiresOptInAndActiveEpisode() {
    var gate = CaptureTriggerGate()
    let now = Date(timeIntervalSince1970: 100)
    let disabled = gate.accept(modeEnabled: false, isPlaying: true, episode: "e", seconds: 12, now: now)
    let paused = gate.accept(modeEnabled: true, isPlaying: false, episode: "e", seconds: 12, now: now)
    let missing = gate.accept(modeEnabled: true, isPlaying: true, episode: nil, seconds: 12, now: now)
    let invalid = gate.accept(modeEnabled: true, isPlaying: true, episode: "e", seconds: .nan, now: now)
    let admitted = gate.accept(modeEnabled: true, isPlaying: true, episode: "e", seconds: 12, now: now)
    #expect(!disabled)
    #expect(!paused)
    #expect(!missing)
    #expect(!invalid)
    #expect(admitted)
  }

  @Test func suppressesDuplicateAtSameMomentOnly() {
    var gate = CaptureTriggerGate()
    let now = Date(timeIntervalSince1970: 100)
    let first = gate.accept(modeEnabled: true, isPlaying: true, episode: "e", seconds: 12, now: now)
    let duplicate = gate.accept(modeEnabled: true, isPlaying: true, episode: "e", seconds: 12.2,
      now: now.addingTimeInterval(0.4))
    let laterMoment = gate.accept(modeEnabled: true, isPlaying: true, episode: "e", seconds: 14,
      now: now.addingTimeInterval(0.5))
    let otherEpisode = gate.accept(modeEnabled: true, isPlaying: true, episode: "f", seconds: 14,
      now: now.addingTimeInterval(0.6))
    let laterTime = gate.accept(modeEnabled: true, isPlaying: true, episode: "f", seconds: 14,
      now: now.addingTimeInterval(1.7))
    #expect(first)
    #expect(!duplicate)
    #expect(laterMoment)
    #expect(otherEpisode)
    #expect(laterTime)
  }
}
