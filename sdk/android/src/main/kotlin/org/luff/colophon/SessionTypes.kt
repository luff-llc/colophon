package org.luff.colophon

import com.luff.colophon.Access
import com.luff.colophon.AccessRequest
import com.luff.colophon.Denial
import com.luff.colophon.KeyProvider
import com.luff.colophon.LedgerEntry
import com.luff.colophon.Member
import com.luff.colophon.MemberKind
import com.luff.colophon.NamespaceView
import java.io.File
import java.util.UUID

sealed class SessionPhase {
    data object Opening : SessionPhase()
    data object NoLibrary : SessionPhase()
    data object Creating : SessionPhase()
    data class WaitingForApproval(val code: String) : SessionPhase()
    data object Denied : SessionPhase()
    data class Unavailable(val reason: String) : SessionPhase()
    data object Migrating : SessionPhase()
    data object Ready : SessionPhase()
    data class Failed(val reason: String) : SessionPhase()
}

sealed class SessionException(message: String) : Exception(message) {
    /** A new instance per throw. A singleton exception keeps its first stack and coroutines may not catch it again. */
    class NotReady : SessionException("The library is not ready. Restore access and retry.")
    data object StaleRevision : SessionException("The library changed while this action was open. Review the current values and try again.")
    data object DestinationChanged : SessionException("The selected library or member changed. Start this action again.")
    data object InvalidCommand : SessionException("This command or extension envelope is invalid.")
    data object PublicationUncertain : SessionException("Publication needs review. Refresh and inspect the ledger before retrying this action.")
}

/** A command is bound to the context and revision observed before the user's action began. */
data class ObservedRevision(val context: UUID, val revision: ULong)

data class DomainCommand(val namespace: String, val kind: String, val payload: ByteArray) {
    override fun equals(other: Any?) = other is DomainCommand &&
        namespace == other.namespace && kind == other.kind && payload.contentEquals(other.payload)
    override fun hashCode() = 31 * (31 * namespace.hashCode() + kind.hashCode()) + payload.contentHashCode()

    companion object {
        fun saveLink(id: String = UUID.randomUUID().toString(), url: String, title: String): DomainCommand {
            val lower = url.lowercase()
            if ((!lower.startsWith("http://") && !lower.startsWith("https://")) || !url.contains("://") ||
                url.substringAfter("://").substringBefore('/').isEmpty()
            ) {
                throw SessionException.InvalidCommand
            }
            val json = """{"id":${jsonString(id)},"url":${jsonString(url)},"title":${jsonString(title)}}"""
            return DomainCommand("reading.saved", "capture", json.toByteArray(Charsets.UTF_8))
        }
    }
}

sealed class WriteReceipt {
    data class Saved(val operationID: String) : WriteReceipt()
    data object Queued : WriteReceipt()
}

data class SessionConfiguration(
    val memberLabel: String,
    val memberKind: MemberKind = MemberKind.APP,
    val namespaces: List<String>,
    val access: List<Access> = listOf(Access.READ, Access.WRITE),
    val libraryNamespaces: List<String> = namespaces,
    val privateHome: File,
    val keys: KeyProvider,
    val recoveryKeys: KeyProvider? = null,
    val store: RecordStore? = null,
) {
    companion object {
        fun app(
            filesDir: File,
            memberLabel: String,
            namespaces: List<String>,
            keys: KeyProvider,
            memberKind: MemberKind = MemberKind.APP,
        ) = SessionConfiguration(
            memberLabel = memberLabel,
            memberKind = memberKind,
            namespaces = namespaces,
            privateHome = File(filesDir, "colophon"),
            keys = keys,
        )
    }
}

internal data class CoreSnapshot(
    val libraryID: String,
    val me: Member,
    val members: List<Member>,
    val ledger: List<LedgerEntry>,
    val requests: List<AccessRequest>,
    val views: Map<String, NamespaceView>,
    val denials: Map<String, Denial>,
    val records: Map<String, ByteArray>,
)

internal data class SessionSnapshot(
    val phase: SessionPhase,
    val core: CoreSnapshot?,
    val revision: ULong,
    val namespaceRevisions: Map<String, ULong>,
)

internal class PendingPublication(val reason: String) : Exception(reason)
internal class SessionRefusal(val snapshot: SessionSnapshot, val error: SessionException) : Exception(error.message)

internal fun jsonString(value: String): String {
    val escaped = buildString(value.length + 2) {
        append('"')
        for (ch in value) {
            when (ch) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> append(ch)
            }
        }
        append('"')
    }
    return escaped
}
