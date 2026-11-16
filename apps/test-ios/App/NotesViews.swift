import ColophonSession
import PhotosUI
import SwiftUI

struct NotesView: View {
    @Environment(AppModel.self) private var model
    @State private var editing: Note?
    @State private var adding = false

    var body: some View {
        Group {
            if let session = model.session {
                switch session.phase {
                case .locked:
                    ContentUnavailableView {
                        Label("Locked", systemImage: "lock")
                    } actions: {
                        Button("Unlock") { Task { await model.unlock() } }.accessibilityIdentifier("unlock")
                    }
                case .ready, .refreshing, .retry, .waitingForDownload:
                    list(session)
                default:
                    ContentUnavailableView("Not ready", systemImage: "exclamationmark.triangle",
                                           description: Text("Phase: \(String(describing: session.phase))\n\(session.lastError ?? "")"))
                }
            }
        }
        .navigationTitle("Notes")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { adding = true } label: { Label("Add", systemImage: "plus") }
                    .accessibilityIdentifier("addNote").disabled(model.session?.hasUsableContent != true)
            }
        }
        .sheet(isPresented: $adding) { NoteEditor(note: nil) }
        .sheet(item: $editing) { NoteEditor(note: $0) }
        .task(id: model.session?.namespaceRevisions[NotesFold.namespace]) { await model.reloadNotes() }
        .task {
            // Automatic sync while this screen is open, besides the session's own loop.
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(15))
                model.session?.requestSync()
            }
        }
    }

    private func list(_ session: ColophonSession) -> some View {
        List {
            if let problem = model.notesProblem {
                Text(problem).foregroundStyle(.red).accessibilityIdentifier("notesProblem")
            }
            if let sync = model.lastSync { SyncOutcomeView(outcome: sync) }
            if model.notes.isEmpty && model.notesProblem == nil {
                Text("No notes yet.").foregroundStyle(.secondary)
            }
            ForEach(model.notes) { note in
                Button { editing = note } label: {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(note.text.isEmpty ? "(empty)" : note.text).foregroundStyle(.primary)
                        HStack {
                            if note.photo != nil { Image(systemName: "photo") }
                            Text("by \(note.authorLabel) · \(note.author.prefix(8))").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                .accessibilityIdentifier("note-\(note.text)")
                .swipeActions {
                    Button("Delete", role: .destructive) { Task { await model.deleteNote(note) } }
                }
            }
        }
        .refreshable { await model.sync() }
    }
}

struct SyncOutcomeView: View {
    let outcome: SyncOutcome
    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("Last sync: \(outcome.kind.rawValue) at \(outcome.at.formatted(date: .omitted, time: .standard))")
                .font(.footnote.bold()).foregroundStyle(outcome.kind == .complete ? Color.green : Color.orange)
                .accessibilityIdentifier("syncOutcome").accessibilityValue(outcome.kind.rawValue)
            Text(outcome.detail).font(.caption2).textSelection(.enabled).accessibilityIdentifier("syncDetail")
        }
    }
}

struct NoteEditor: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let note: Note?
    @State private var text = ""
    @State private var observed: ObservedRevision?
    @State private var pick: PhotosPickerItem?
    @State private var newPhoto: Data?
    @State private var shown: UIImage?
    @State private var photoProblem: String?

    var body: some View {
        NavigationStack {
            Form {
                TextField("Note", text: $text, axis: .vertical).lineLimit(3...10).accessibilityIdentifier("noteText")
                Section("Photo") {
                    if let shown { Image(uiImage: shown).resizable().scaledToFit().frame(maxHeight: 240) }
                    if let photoProblem { Text(photoProblem).foregroundStyle(.red).font(.footnote) }
                    PhotosPicker(newPhoto == nil && note?.photo == nil ? "Attach a photo" : "Replace the photo", selection: $pick, matching: .images)
                }
                if let note {
                    Section {
                        Text("Written by \(note.authorLabel) (\(note.author)) at \(note.created)").font(.caption)
                        Button("Delete", role: .destructive) { Task { await model.deleteNote(note); dismiss() } }
                    }
                }
            }
            .navigationTitle(note == nil ? "New note" : "Edit note")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        guard let observed else { return }
                        Task {
                            if await model.saveNote(id: note?.id, text: text, photo: newPhoto, keepPhoto: note?.photo, observed: observed) { dismiss() }
                        }
                    }
                    .accessibilityIdentifier("saveNote").disabled(model.busy != nil)
                }
            }
            .onAppear {
                text = note?.text ?? ""
                // The write is bound to the revision seen when the person began.
                observed = model.session?.observedRevision
            }
            .task {
                guard let note, note.photo != nil else { return }
                do {
                    let data = try await model.photo(note)
                    shown = await Task.detached { UIImage(data: data) }.value
                } catch { photoProblem = "The photo is not here yet: \(AppModel.message(error))" }
            }
            .onChange(of: pick) { _, item in
                guard let item else { return }
                Task {
                    do {
                        guard let data = try await item.loadTransferable(type: Data.self) else { return }
                        let jpeg = await Task.detached { () -> (Data?, UIImage?) in
                            guard let image = UIImage(data: data) else { return (nil, nil) }
                            let scale = min(1, 1600 / max(image.size.width, image.size.height))
                            let size = CGSize(width: image.size.width * scale, height: image.size.height * scale)
                            let resized = UIGraphicsImageRenderer(size: size).image { _ in image.draw(in: CGRect(origin: .zero, size: size)) }
                            return (resized.jpegData(compressionQuality: 0.7), resized)
                        }.value
                        newPhoto = jpeg.0; shown = jpeg.1
                        if jpeg.0 == nil { photoProblem = "That image could not be read." }
                    } catch { photoProblem = AppModel.message(error) }
                }
            }
        }
    }
}
