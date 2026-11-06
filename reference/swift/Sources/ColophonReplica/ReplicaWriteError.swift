/// A conditional or reentrant Replica write could not be started safely.
public enum ReplicaWriteError: Error, Equatable, Sendable {
  /// The snapshot belongs elsewhere or is no longer the known complete view.
  case staleSnapshot
  /// A store or identity callback tried to write recursively on the same Replica.
  case reentrantWrite
}
