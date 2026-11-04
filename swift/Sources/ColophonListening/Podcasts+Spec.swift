import ColophonCore
import ColophonReplica
import Foundation

public extension Podcasts {
  // Transcript preparation, scoped questions and retained answers use typed services with
  // source/role/replay validation. Do not expose them as raw generic MCP mutation tools.
  // Their additive kinds remain advertised by `kinds` and are projected by those services.
  static var operations: [OperationSpec] {
    [
      OperationSpec(Kind.follow, "Follow a show by its feed.", [
        FieldSpec("show", .string, required: true, "Show ID: Podcasts.showID(feed:)."),
        FieldSpec("feed", .string, required: true, "The RSS feed address."),
        FieldSpec("title", .string, required: true, "The show's title."),
      ]),
      OperationSpec(Kind.unfollow, "Stop following a show.", [FieldSpec("show", .string, required: true, "The show.")]),
      OperationSpec(Kind.showSettings, "Set a show's playback preferences.", [
        FieldSpec("show", .string, required: true, "The show."),
        FieldSpec("speed", .number, "Playback rate, e.g. 1.25."),
        FieldSpec("skipIntro", .number, "Seconds to skip at the start."),
        FieldSpec("skipOutro", .number, "Seconds to skip at the end."),
      ]),
      OperationSpec(Kind.preferenceBatch, "Atomically set bounded playback or listening preferences.", [
        FieldSpec("commandID", .string, required: true, "Signer-scoped idempotency ID."),
        FieldSpec("commandDigest", .string, required: true, "Canonical digest of changes and expected revisions."),
        FieldSpec("changes", .object, required: true, "Exact preference keys mapped to string values."),
        FieldSpec("expected", .object, required: true, "The observed revision or null for every changed key."),
      ]),
      OperationSpec(Kind.setState, "Mark an episode played, or not.", [
        FieldSpec("episode", .string, required: true, "Episode ID: Podcasts.episodeID(feed:guid:)."),
        FieldSpec("show", .string, required: true, "The show."),
        FieldSpec("consumption", .string, required: true, "Listening state.", values: ["notStarted", "inProgress",
          "doneEnough", "completed", "abandoned"]),
        FieldSpec("expect", .string, "The state revision you last saw."),
      ]),
      OperationSpec(Kind.position, "Record a playback position.", [
        FieldSpec("episode", .string, required: true, "The episode."),
        FieldSpec("show", .string, required: true, "The show."),
        FieldSpec("seconds", .number, required: true, "Position in seconds."),
        FieldSpec("duration", .number, "Episode length in seconds."),
        FieldSpec("deliberate", .boolean, required: true, "True for a seek the person chose."),
        FieldSpec("expect", .string, "The position revision playback started from."),
      ]),
      OperationSpec(Kind.queue, "Replace the Up Next queue.", [
        FieldSpec("episodes", .strings, required: true, "Episode IDs in order."),
      ]),
      // Deliberately omit Kind.legacyBridgeImport from generic adapters. Only the typed,
      // archive-verified local import flow may offer this command; the fold also checks role.
      // Optional transcriptAnchor objects pass through the v1 adapter unchanged; clients
      // validate their exact range against the saved blob before describing them as verified.
      OperationSpec(ContentKind.addNote, "Add a note about an episode or a pinned transcript passage.", [
        FieldSpec("note", .string, required: true, "A new unique ID."),
        FieldSpec("episode", .string, required: true, "The episode."),
        FieldSpec("show", .string, required: true, "The show."),
        FieldSpec("seconds", .number, "Where in the episode, in seconds."),
        FieldSpec("text", .string, required: true, "The note."),
        FieldSpec("quote", .string, "The words from the transcript it refers to."),
        FieldSpec("origin", .string, "Who wrote it. Agents write ai.", values: ["person", "ai"]),
      ]),
      OperationSpec(ContentKind.editNote, "Edit an episode note.", [
        FieldSpec("note", .string, required: true, "The note."),
        FieldSpec("text", .string, required: true, "New text."),
        FieldSpec("expect", .string, "The revision you last saw; a stale one keeps both versions."),
      ]),
      OperationSpec(ContentKind.resolveNote, "Resolve competing edits to an episode note.", [
        FieldSpec("note", .string, required: true, "The note."),
        FieldSpec("text", .string, required: true, "The version to keep."),
        FieldSpec("expect", .string, "The revision last seen."),
      ]),
      OperationSpec(ContentKind.deleteNote, "Delete an episode note.", [FieldSpec("note", .string, required: true, "The note.")]),
      OperationSpec(ContentKind.segments, "Record ad or other segments for one audio file.", [
        FieldSpec("episode", .string, required: true, "The episode."),
        FieldSpec("show", .string, required: true, "The show."),
        FieldSpec("audio", .string, required: true, "Lowercase hex SHA-256 of the audio file the times refer to."),
        FieldSpec("source", .string, required: true, "Who found them. Agents write detected.", values: ["detected", "person"]),
        FieldSpec("detector", .string, "The engine that detected them."),
        FieldSpec("segments", .objects, required: true,
          "The segments, each {\"start\": seconds, \"end\": seconds, \"kind\": \"sponsor\"}."),
      ]),
    ] + playlistSpecs + chapterSpecs
  }

  static var queries: [QuerySpec] {
    [
      QuerySpec("transcript", "Read an episode's transcript, if one is in the library.", [
        FieldSpec("episode", .string, required: true, "The episode."),
      ]) { replica, arguments in
        let listening = try replica.state(of: Podcasts.self)
        guard let episode = arguments["episode"]?.string,
          let document = try replica.transcript(of: episode, in: listening),
          let record = listening.transcripts[episode]
        else { return .object(["available": .bool(false)]) }
        var result: [String: JSONValue] = ["available": .bool(true), "source": .string(record.source),
          "language": JSONValue(record.language), "text": .string(document.text), "timed": .bool(record.timed)]
        // Timed: sentences with their times, so an agent can cite and link to moments.
        if let words = document.words, !words.isEmpty {
          result["segments"] = .array(Podcasts.segments(of: words).map {
            .object(["start": .number($0.start), "end": .number($0.end), "text": .string($0.text)])
          })
        }
        return .object(result)
      },
      QuerySpec("moment", "What was being said at a moment of an episode: the words around it, its chapter and nearby notes.", [
        FieldSpec("episode", .string, required: true, "The episode."),
        FieldSpec("seconds", .number, required: true, "The moment, in seconds."),
        FieldSpec("window", .number, "Seconds of transcript before the moment; 30 if omitted."),
      ]) { replica, arguments in
        let listening = try replica.state(of: Podcasts.self)
        guard let episode = arguments["episode"]?.string, let seconds = arguments["seconds"]?.double else {
          return .object(["available": .bool(false)])
        }
        let window = min(max(arguments["window"]?.double ?? 30, 5), 300)
        var result: [String: JSONValue] = ["episode": .string(episode), "seconds": .number(seconds)]
        if let document = try? replica.transcript(of: episode, in: listening), let words = document.words, !words.isEmpty {
          let around = words.filter { $0.end >= seconds - window && $0.start <= seconds + 10 }
          result["said"] = .string(around.map(\.text).joined(separator: " "))
          result["from"] = around.first.map { .number($0.start) } ?? .null
          result["to"] = around.last.map { .number($0.end) } ?? .null
        } else {
          result["said"] = .null
          result["transcript"] = .string(listening.transcripts[episode] == nil ? "none" : "untimed")
        }
        if let set = listening.chapters[episode]?.values.first,
          let chapter = set.entries.last(where: { $0.start <= seconds })
        {
          result["chapter"] = .object(["title": .string(chapter.title), "start": .number(chapter.start)])
        }
        result["notes"] = .array(listening.notes(for: episode).filter { abs(($0.seconds ?? -1_000) - seconds) <= 60 }.map {
          .object(["note": .string($0.id), "seconds": JSONValue($0.seconds), "text": .string($0.text),
            "quote": JSONValue($0.quote), "authorLabel": .string($0.author)])
        })
        return .object(result)
      },
      QuerySpec("chapters", "Chapters recorded for an episode (made from its transcript or by the person), per recording.", [
        FieldSpec("episode", .string, required: true, "The episode."),
      ]) { replica, arguments in
        let listening = try replica.state(of: Podcasts.self)
        let sets = arguments["episode"]?.string.flatMap { listening.chapters[$0] } ?? [:]
        return .object(["recordings": .array(sets.values.map { set in
          .object(["audio": .string(set.audio), "source": .string(set.source), "origin": JSONValue(set.origin),
            "chapters": .array(set.entries.map { .object(["start": .number($0.start), "title": .string($0.title)]) })])
        })])
      },
      QuerySpec("search_transcripts", "Find where episodes in the library talk about something.", [
        FieldSpec("query", .string, required: true, "Words to look for."),
      ]) { replica, arguments in
        let listening = try replica.state(of: Podcasts.self)
        let query = arguments["query"]?.string ?? ""
        var matches: [JSONValue] = []
        for episode in listening.transcripts.keys.sorted() {
          guard let document = try? replica.transcript(of: episode, in: listening) else { continue }
          if let words = document.words, !words.isEmpty {
            let lowered = words.map { $0.text.lowercased() }
            let terms = query.lowercased().split(separator: " ").map(String.init)
            guard let first = terms.first else { continue }
            for index in lowered.indices where lowered[index].contains(first) {
              let window = lowered[index ..< min(index + terms.count + 8, lowered.count)].joined(separator: " ")
              guard terms.allSatisfy({ window.contains($0) }) else { continue }
              let context = words[max(0, index - 12) ..< min(words.count, index + 20)].map(\.text).joined(separator: " ")
              matches.append(.object(["episode": .string(episode), "seconds": .number(words[index].start),
                "context": .string(context)]))
              if matches.count >= 25 { break }
            }
          } else if let range = document.text.range(of: query, options: [.caseInsensitive, .diacriticInsensitive]) {
            let start = document.text.index(range.lowerBound, offsetBy: -160, limitedBy: document.text.startIndex)
              ?? document.text.startIndex
            let end = document.text.index(range.upperBound, offsetBy: 160, limitedBy: document.text.endIndex)
              ?? document.text.endIndex
            matches.append(.object(["episode": .string(episode), "context": .string(String(document.text[start ..< end]))]))
          }
          if matches.count >= 25 { break }
        }
        return .object(["matches": .array(matches)])
      },
      QuerySpec("notes", "List notes with signed author identity and optional transcript anchor; origin is a legacy self-claim.", [
        FieldSpec("episode", .string, "The episode; omit for all notes."),
      ]) { replica, arguments in
        let listening = try replica.state(of: Podcasts.self)
        let notes = arguments["episode"]?.string.map { listening.notes(for: $0) }
          ?? listening.notes.values.sorted { $0.sequence < $1.sequence }
        return .object(["notes": .array(notes.map {
          .object(["note": .string($0.id), "episode": .string($0.episode), "seconds": JSONValue($0.seconds),
            "show": .string($0.show), "text": .string($0.text), "quote": JSONValue($0.quote),
            "origin": .string($0.origin), "authorID": .string($0.authorID),
            "authorLabel": .string($0.author), "anchorClaimed": .bool($0.hasAnchorClaim),
            "transcriptAnchor": $0.anchor?.json ?? .null])
        })])
      },
      QuerySpec("playlists", "List playlists and their rules. Episodes in a show-based playlist come from the feeds.", [
        FieldSpec("archived", .boolean, "Include archived playlists."),
      ]) { replica, arguments in
        let listening = try replica.state(of: Podcasts.self)
        let lists = arguments["archived"]?.bool == true
          ? listening.playlists.values.sorted { $0.name < $1.name } : listening.activePlaylists
        return .object(["playlists": .array(lists.map {
          .object(["playlist": .string($0.id), "name": .string($0.name), "mode": .string($0.mode.rawValue),
            "allShows": .bool($0.allShows), "shows": .array($0.shows.map(JSONValue.string)),
            "episodes": .array($0.episodes.map(JSONValue.string)), "excluded": .array($0.excluded.map(JSONValue.string)),
            "order": .string($0.order.rawValue), "includeFinished": .bool($0.includeFinished),
            "archived": .bool($0.archived), "revision": .string($0.revision),
            "competingVersions": .number(Double($0.competing.count))])
        })])
      },
    ]
  }

  static func describe(_ state: Listening) -> JSONValue {
    let queueLimit = 50
    let stateLimit = 20
    let latest = state.episodes.values.sorted { ($0.updated, $0.id) > ($1.updated, $1.id) }
    return .object([
      "shows": .array(state.following.map { .object(["show": .string($0.id), "title": .string($0.title), "feed": .string($0.feed)]) }),
      "queue": .array(state.queue.map(JSONValue.string)),
      "queueDetails": .object([
        "episodes": .array(state.queue.prefix(queueLimit).map { episodeDetails($0, in: state) }),
        "total": .number(Double(state.queue.count)), "limit": .number(Double(queueLimit)),
        "hasMore": .bool(state.queue.count > queueLimit),
      ]),
      "listeningState": .object([
        // This projection retains the latest state per episode, not a listening-session log.
        "semantics": .string("latestKnownEpisodeStateNotSessionHistory"),
        "episodes": .array(latest.prefix(stateLimit).map { episode in
          var fields = episodeDetails(episode.id, in: state).object ?? [:]
          fields["seconds"] = .number(episode.seconds)
          fields["consumption"] = JSONValue(episode.consumption)
          fields["stateUpdatedAt"] = .number(episode.updated.timeIntervalSince1970)
          return .object(fields)
        }),
        "total": .number(Double(latest.count)), "limit": .number(Double(stateLimit)),
        "hasMore": .bool(latest.count > stateLimit),
      ]),
      "transcripts": .array(state.transcripts.keys.sorted().map(JSONValue.string)),
      "notes": .number(Double(state.notes.count)),
      "inProgress": .array(latest.lazy.filter { $0.seconds > 0 && $0.consumption != "completed" }.prefix(20).map {
          .object(["episode": .string($0.id), "show": .string($0.show), "seconds": .number($0.seconds),
            "duration": JSONValue($0.duration)])
        }),
    ])
  }

  /// Describes only saved metadata and projected state; absent titles remain explicitly unknown.
  private static func episodeDetails(_ id: String, in state: Listening) -> JSONValue {
    let metadata = state.queuedEpisodeMetadata[id]
    let episode = state.episodes[id]
    let show = metadata?.showID ?? episode?.show
    return .object([
      "episode": .string(id), "show": JSONValue(show),
      "metadataAvailable": .bool(metadata != nil), "title": JSONValue(metadata?.title),
      "showTitle": JSONValue(metadata?.showTitle ?? show.flatMap { state.shows[$0]?.title }),
      "duration": JSONValue(episode?.duration ?? metadata?.duration), "published": JSONValue(metadata?.published),
    ])
  }
}
