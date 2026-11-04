/// An evidence reader cannot silently substitute an unbounded transport.
public enum BoundedRecordReadError: Error, Equatable, Sendable {
  case unsupportedStore
  case exceedsLimit
  case invalidFile
  case changedDuringRead
}
