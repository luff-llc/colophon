import ColophonSession
import SwiftUI

/// The words the specification asks a host to say (spec §17.5, §18; guide §5).
public enum NoticeWords {
    public static let noHome = "This account has no home. Nothing keeps a record of when things happened on this account. Someone who once held one of your keys can later show a new device a different history, from before you removed that key, and nothing can tell the two apart. Add a home."
    public static let waiting = "Waiting protects who controls your account. It doesn’t protect anything a stolen key could already read."
    public static let oneDevice = "If this device is stolen, nothing can veto what the thief does with it. Add a second key."
    public static func dead(receipted: Int, quorum: Int) -> String {
        "Only \(receipted) of the \(quorum) homes this account needs receipted this change within 5 minutes, so it will not take effect. Sign it again to retry."
    }
    public static func vetoDeadline(_ ms: Int64?) -> String {
        guard let ms else { return "The deadline is not known yet." }
        let date = Date(timeIntervalSince1970: Double(ms) / 1000)
        return "You can say no until " + date.formatted(date: .abbreviated, time: .shortened) + "."
    }
}

/// What a person must see that is not content (`GateModel.notices`): a change waiting for its deadline, with who signed it
/// and a one-tap veto; a change that did not take hold, offered to be signed again; changes that took effect without a
/// key on this device, with when each home receipted them; an account with no home, or with one device; homes that
/// cannot tell the person about changes.
public struct NoticesView: View {
    let session: any LibrarySessionSource
    let host: LibraryHostActions
    @State private var action = LibraryActionModel()
    public init(session: any LibrarySessionSource, host: LibraryHostActions = .init()) { self.session = session; self.host = host }
    public var body: some View {
        let cards = GateModel.notices(session.notices, duties: session.duties)
        VStack(alignment: .leading, spacing: 12) {
            ForEach(cards) { card in
                VStack(alignment: .leading, spacing: 6) {
                    Text(card.title).font(.headline).accessibilityAddTraits(.isHeader)
                    ForEach(Array(card.lines.enumerated()), id: \.offset) { _, line in Text(line).font(.footnote) }
                    ForEach(card.controls) { control in
                        GateControlButton(control: control, disabled: action.isWorking) { gateAction in
                            Task { await GateModel.perform(gateAction, session: session, host: host, model: action) { _ in } }
                        }
                    }
                }
                .accessibilityElement(children: .contain)
                .accessibilityIdentifier(card.id)
            }
            LibraryErrorView(message: action.error)
        }.padding(cards.isEmpty ? 0 : 12)
    }
}
