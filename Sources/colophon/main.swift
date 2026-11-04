import ColophonAuthority
import ColophonBooks
import ColophonCore
import ColophonListening
import ColophonMCP
import ColophonNotes
import ColophonSaved
import ColophonReplica
import ColophonStore
import CryptoKit
import Foundation

// colophon: join a library as an agent, inspect it, and serve it to an agent harness over MCP.
// The agent is a member like any app: its own key, its own grant, revocable by the holder.

let usage = """
  colophon <library folder> <command> [options]

    status                 Library, members and this agent's access.
    join [--label NAME] [--namespaces a,b]
                           Ask to join as an agent. Prints the pairing code to compare in the
                           app that holds the library.
    code                   Print this agent's pairing code again.
    read <namespace>       Print a namespace as this agent sees it (JSON).
    context list           List immutable transcript references (JSON).
    context read           Read a pinned reference and its contributions (JSON request on stdin).
    context verify         Verify one pinned reference and exact quote without exporting its blob.
    context propose        Add an attributed agent proposal (JSON request on stdin).
                           Provisional extension; acceptance remains an app action.
    context capture-verify Read one exact signed capture for its selected enrolled agent.
                           This is read-only and does not independently verify a physical Save tap.
                           read input: {"reference":<object from context list>}
                           verify input: {"reference":<object>,"quote":<exact text>}
                           propose input: {"reference":<object>,"quote":<exact text>,
                             "text":<suggestion>,"contributionID":<stable ID>,
                             "commandID":<stable retry ID>,"expectedRevision":null}
                           capture-verify input: {"requestID":<ID>,"noteID":<ID>,
                             "requestRevision":<exact note.add op ID>,
                             "expectedSource":<reference or null>,"expectedQuote":<quote or null>}
    questions pending      Poll queued questions assigned to this enrolled agent (JSON).
    questions packet       Export only the exact bounded question packet (JSON stdin).
                           {"requestRevision":<signed request ID>}
    questions respond      Return cited claims using this executor's signature (JSON stdin).
                           {"requestRevision":<ID>,"claims":[{"text":<claim>,
                             "citations":[<exact anchor from packet>]}],"commandID":<stable ID>}
                           The receiving app reviews and keeps the returned answer.
    verify                 Check the authority history and every readable operation.
    mcp                    Serve the library over MCP on stdin/stdout.

  Options:
    --identity PATH        This agent's key file (default ~/.colophon/<library id>/agent.json).
  """

let modules = [ModuleAdapter(SavedLinks.self), ModuleAdapter(Books.self), ModuleAdapter(Podcasts.self),
  ModuleAdapter(Notes.self)]

func fail(_ message: String) -> Never {
  FileHandle.standardError.write(Data((message + "\n").utf8))
  exit(1)
}

var arguments = Array(CommandLine.arguments.dropFirst())
@MainActor func option(_ name: String) -> String? {
  guard let index = arguments.firstIndex(of: name), index + 1 < arguments.count else { return nil }
  defer { arguments.removeSubrange(index ... index + 1) }
  return arguments[index + 1]
}
let identityOption = option("--identity")
let labelOption = option("--label")
let namespacesOption = option("--namespaces")
guard arguments.count >= 2 else { print(usage); exit(64) }

let store = FolderStore(URL(filePath: arguments[0], directoryHint: .isDirectory))
let log = AuthorityLog(store: store)
guard log.exists else { fail("No library in \(arguments[0]).") }

do {
  let state = try log.state()
  let identityURL = identityOption.map { URL(filePath: $0) }
    ?? FileManager.default.homeDirectoryForCurrentUser.appending(path: ".colophon/\(state.libraryID)/agent.json")
  // Agents run outside any app sandbox, so their key is a software key in the user's home,
  // readable only by them. The grant says so.
  let identity: SoftwareIdentity
  if let data = try? Data(contentsOf: identityURL) {
    identity = try Canonical.decode(SoftwareIdentity.self, from: data)
  } else {
    guard arguments[1] != "context", arguments[1] != "questions" else {
      throw ColophonError.malformed("Context and question commands require an existing enrolled identity; no key was created.")
    }
    identity = SoftwareIdentity()
    try FileManager.default.createDirectory(at: identityURL.deletingLastPathComponent(), withIntermediateDirectories: true)
    try Canonical.encode(identity).write(to: identityURL, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: identityURL.path)
  }
  let replica = Replica(store: store, identity: identity)

  switch arguments[1] {
  case "status":
    print("Library: \(state.label) (\(state.libraryID))")
    print("Authority entries: \(state.latest)")
    for member in state.activeMembers {
      let custody = member.custody?.rawValue ?? "unknown"
      print("  \(member.label) · \(member.role.rawValue) · \(member.namespaces.joined(separator: ", ")) · \(custody) key")
    }
    switch try replica.membership() {
    case .pending: print("This agent: not a member yet. Run `join`.")
    case .member(let namespaces, let write): print("This agent: member, \(write ? "read and write" : "read only"): \(namespaces.joined(separator: ", "))")
    case .revoked: print("This agent: access ended.")
    }
  case "join":
    let namespaces = namespacesOption?.split(separator: ",").map(String.init) ?? state.namespaces
    try replica.requestEnrollment(label: labelOption ?? "Agent", role: .agent, namespaces: namespaces)
    print("Asked to join \(state.label) for \(namespaces.joined(separator: ", ")).")
    print("Pairing code: \(try replica.pairingCode()) — approve it in the app that holds the library.")
  case "code":
    print(try replica.pairingCode())
  case "read":
    guard arguments.count >= 3, let module = modules.first(where: { $0.namespace == arguments[2] }) else {
      fail("Name one of: \(modules.map(\.namespace).joined(separator: ", "))")
    }
    let server = MCPServer(replica: replica, modules: [module])
    let request = try Canonical.encode(["jsonrpc": "2.0", "id": .number(1), "method": "tools/call",
      "params": .object(["name": .string(module.namespace.replacingOccurrences(of: ".", with: "_") + "__read")])] as [String: JSONValue])
    if let response = server.handle(request) { print(String(decoding: response, as: UTF8.self)) }
  case "context":
    guard arguments.count == 3 else { fail("Name context list, read, verify, propose, or capture-verify.") }
    try SharedTranscriptCommand.run(arguments[2], replica: replica)
  case "questions":
    guard arguments.count == 3 else { fail("Name questions pending, packet, or respond.") }
    try TranscriptQuestionCommand.run(arguments[2], replica: replica)
  case "verify":
    print("Authority history: \(state.latest) entries verified.")
    for namespace in state.namespaces {
      let view = try replica.read(namespace)
      print("  \(namespace): \(view.admitted.count) admitted, \(view.held.count) held, \(view.rejected.count) refused, \(view.unreadable) not readable by this agent")
      for refused in view.rejected { print("    refused \(refused.path): \(refused.reason)") }
    }
  case "mcp":
    let server = MCPServer(replica: replica, modules: modules, name: "colophon · \(state.label)")
    while let line = readLine(strippingNewline: true) {
      guard !line.isEmpty else { continue }
      if let response = server.handle(Data(line.utf8)) {
        FileHandle.standardOutput.write(response + Data("\n".utf8))
      }
    }
  default:
    print(usage)
    exit(64)
  }
} catch {
  fail("Error: \(error.localizedDescription)")
}
