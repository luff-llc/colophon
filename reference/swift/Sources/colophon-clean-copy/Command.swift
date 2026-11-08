import ColophonCleanCopy
import Darwin
import Foundation

@main
struct CleanCopyCommand {
    @MainActor
    static func main() async {
        do {
            let arguments = Array(CommandLine.arguments.dropFirst())
            func url(_ value: String) -> URL { URL(fileURLWithPath: value, isDirectory: true) }
            switch arguments.first {
            case "snapshot" where arguments.count == 3:
                let work = try CleanCopyWorkspace.snapshot(source: url(arguments[1]), work: url(arguments[2]))
                print("Snapshot: \(work.directory.path)")
            case "request" where arguments.count == 2:
                let work = CleanCopyWorkspace(directory: url(arguments[1]))
                let request = try work.request()
                print("Request: \(work.directory.appendingPathComponent("enrollment-request.json").path)")
                print("Pairing code: \(request.pairingCode)")
                print("Transfer these request bytes to a controller device. Approve in the original library, then rerun snapshot SRC WORK.")
            case "copy" where arguments.count == 3 || (arguments.count == 4 && arguments[3] == "--imported-from"):
                let report = try await CleanCopyWorkspace(directory: url(arguments[1])).copy(to: url(arguments[2]), importedFrom: arguments.count == 4)
                print("Report: \(url(arguments[1]).appendingPathComponent("report.md").path)")
                guard report.verified else { throw CleanCopyError.verificationUnavailable }
            case "verify" where arguments.count == 3:
                let report = try await CleanCopyWorkspace(directory: url(arguments[1])).verify(destination: url(arguments[2]))
                guard report.verified else { throw CleanCopyError.verificationUnavailable }
                print("Verified: \(report.newLibraryID ?? "")")
            default:
                throw UsageError()
            }
        } catch {
            let message = "colophon-clean-copy: \(error.localizedDescription)\n"
            FileHandle.standardError.write(Data(message.utf8))
            exit(1)
        }
    }
}

private struct UsageError: LocalizedError {
    var errorDescription: String? {
        "usage: colophon-clean-copy snapshot SRC WORK | request WORK | copy WORK DEST [--imported-from] | verify WORK DEST"
    }
}
