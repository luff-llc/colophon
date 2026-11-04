import ColophonCore
import ColophonReplica
import Foundation

public enum BookIntentError: Error, Equatable {
  case wrongBook
  case missingOrInvalidLoan
  case changedLoan
  case alreadyReturned
  case reusedRequestID
  case unconfirmedIntent
  case invalidRequestID
  case invalidPlanStatus
}

/// Constructs commands for decisions confirmed in the native Shelf UI.
public enum BookIntentCommands {
  /// Returns one existing `book.edit` command. A retry of the same accepted event returns nil.
  /// The caller must read a fresh book immediately before submission; `book.edit` has no fold-level CAS.
  public static func returnCopy(currentBook: Bookshelf.Book, expectedBookID: String,
    expectedLoan: BookCopyLoan, requestID: String, reflection: String?,
    provenance: BookIntentProvenance) throws -> Command?
  {
    guard currentBook.id == expectedBookID else { throw BookIntentError.wrongBook }
    guard !requestID.isEmpty else { throw BookIntentError.invalidRequestID }
    guard provenance.confirmedByUser, !provenance.producerID.isEmpty,
      !provenance.acceptingUserID.isEmpty else { throw BookIntentError.unconfirmedIntent }
    guard expectedLoan.status == .needsReturn else { throw BookIntentError.changedLoan }
    guard let currentLoan = currentBook.copyLoan else { throw BookIntentError.missingOrInvalidLoan }
    let returned = BookCopyLoan(status: .returned, requestID: requestID,
      reflection: reflection, provenance: provenance)
    if currentLoan.status == .returned {
      if currentLoan.requestID == requestID {
        guard currentLoan == returned else { throw BookIntentError.reusedRequestID }
        return nil
      }
      throw BookIntentError.alreadyReturned
    }
    guard expectedLoan.status == .needsReturn, currentLoan == expectedLoan else { throw BookIntentError.changedLoan }
    return Books.edit(book: currentBook.id, extra: [BookCopyLoan.key: returned.json])
  }

  /// Manual and accepted proposals use the same plan command and preserve dates by default.
  /// Provenance is included only when a proposal has been explicitly accepted by a person.
  public static func setReadingPlan(currentBook: Bookshelf.Book, status: String,
    started: String? = nil, finished: String? = nil, reread: Bool = false,
    provenance: BookIntentProvenance? = nil) throws -> Command
  {
    guard ["unplanned", "wantToRead", "reading", "paused", "finished", "doneEnough", "abandoned"].contains(status)
    else { throw BookIntentError.invalidPlanStatus }
    if let provenance {
      guard provenance.confirmedByUser, !provenance.producerID.isEmpty,
        !provenance.acceptingUserID.isEmpty else { throw BookIntentError.unconfirmedIntent }
    }
    let command = Books.setPlan(book: currentBook.id, status: status,
      started: started ?? (reread ? nil : currentBook.current.started),
      finished: finished ?? (reread ? nil : currentBook.current.finished),
      reread: reread, expect: currentBook.revision)
    guard let provenance else { return command }
    var payload = command.payload
    payload["intent"] = provenance.json
    return Command(namespace: command.namespace, kind: command.kind, v: command.v, payload: payload)
  }
}
