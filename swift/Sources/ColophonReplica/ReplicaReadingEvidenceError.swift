/// Reading recovery cannot describe a partial, ambiguous or changed source as complete.
public enum ReplicaReadingEvidenceError: Error, Equatable, Sendable {
  case wrongSnapshot
  case ambiguousOperation(String)
  case missingRecord(String)
  case invalidRecord(String)
  case exceedsLimits
}
