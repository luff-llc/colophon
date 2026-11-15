import ColophonSession
import SwiftUI

/// The words the specification asks a host to say (spec §17.5, §18; guide §5).
public enum NoticeWords {
    public static let noHome = "This account has no home. Nothing keeps a record of when things happened on this account. Someone who once held one of your keys can later show a new device a different history, from before you removed that key, and nothing can tell the two apart. Add a home."
    public static let waiting = "Waiting protects who controls your account. It doesn’t protect anything a stolen key could already read."
    public static let oneDevice = "If this device is stolen, nothing can veto what the thief does with it. Add a second key."
    public static func vetoDeadline(_ ms: Int64?) -> String {
        guard let ms else { return "The deadline is not known yet." }
        let date = Date(timeIntervalSince1970: Double(ms) / 1000)
        return "You can say no until " + date.formatted(date: .abbreviated, time: .shortened) + "."
    }
}

/// What a person must see that is not content: a change waiting for its deadline, with who signed it and a
/// one-tap veto; changes that took effect without a key on this device; and an account with no home.
public struct NoticesView: View {
    let session: any LibrarySessionSource
    @State private var action = LibraryActionModel()
    public init(session: any LibrarySessionSource) { self.session = session }
    public var body: some View {
        let notices = session.notices
        VStack(alignment: .leading, spacing: 12) {
            if notices.noHome {
                Label { Text(NoticeWords.noHome) } icon: { Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange) }
                    .accessibilityIdentifier("library.notice.noHome")
            }
            ForEach(notices.pending, id: \.digest) { pending in PendingChangeView(pending: pending, session: session, action: action) }
            if !notices.unseenActivations.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Label("These changes took effect, and no key on this device signed them.", systemImage: "eye.trianglebadge.exclamationmark")
                        .font(.headline)
                    ForEach(notices.unseenActivations, id: \.seq) { activation in
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Entry \(activation.seq)").font(.subheadline.bold())
                            Text("Signed by " + activation.signers.map { String($0.prefix(8)) }.joined(separator: ", ")).font(.footnote)
                            Text(activation.receipted.isEmpty ? "No home has receipted it." :
                                    "Receipted by \(activation.receipted.count) home\(activation.receipted.count == 1 ? "" : "s").").font(.footnote).foregroundStyle(.secondary)
                            Button("I’ve Seen This") { Task { await action.run { await session.acknowledgeActivation(seq: activation.seq) } } }
                                .accessibilityIdentifier("library.notice.acknowledge.\(activation.seq)")
                        }.accessibilityElement(children: .contain).accessibilityIdentifier("library.notice.activation.\(activation.seq)")
                    }
                    Text(NoticeWords.waiting).font(.footnote).foregroundStyle(.secondary)
                }
            }
            LibraryErrorView(message: action.error)
        }.padding(notices == .empty ? 0 : 12)
    }
}

struct PendingChangeView: View {
    let pending: Pending
    let session: any LibrarySessionSource
    let action: LibraryActionModel
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("A change to your account is waiting", systemImage: "hourglass").font(.headline)
            Text("Signed by " + pending.signers.map { "\($0.label) (\(String($0.id.prefix(8))))" }.joined(separator: ", "))
            if let seen = pending.firstSeenSeq { Text("First seen at history entry \(seen)").font(.footnote).foregroundStyle(.secondary) }
            Text(NoticeWords.vetoDeadline(pending.vetoDeadlineMs)).font(.footnote)
            if !pending.adds.isEmpty { Text("Adds " + pending.adds.map { String($0.prefix(8)) }.joined(separator: ", ")).font(.footnote) }
            if !pending.removes.isEmpty { Text("Removes " + pending.removes.map { String($0.prefix(8)) }.joined(separator: ", ")).font(.footnote) }
            Text(NoticeWords.waiting).font(.footnote).foregroundStyle(.secondary)
            if pending.vetoable {
                Button("Veto", role: .destructive) { Task { await action.run { try await session.veto(pending.digest) } } }
                    .disabled(action.isWorking).accessibilityIdentifier("library.notice.veto")
            }
        }.accessibilityElement(children: .contain).accessibilityIdentifier("library.notice.pending.\(pending.digest.prefix(8))")
    }
}
