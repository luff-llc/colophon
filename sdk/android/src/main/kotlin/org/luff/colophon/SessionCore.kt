package org.luff.colophon

import com.luff.colophon.AccessException
import com.luff.colophon.AccessRequest
import com.luff.colophon.BlobReadOutcome
import com.luff.colophon.NativeBlobWriter
import com.luff.colophon.ColophonLibrary
import com.luff.colophon.Denial
import com.luff.colophon.GrantOptions
import com.luff.colophon.KeyProvider
import com.luff.colophon.NamespaceView
import com.luff.colophon.OperationView
import com.luff.colophon.Outcome
import com.luff.colophon.PlatformKeys
import com.luff.colophon.requestInfo

internal interface SessionCore {
    fun open(records: Map<String, ByteArray>, keys: KeyProvider)
    fun create(configuration: SessionConfiguration)
    fun setReadScope(namespaces: List<String>) {}
    fun liveGeneration(path: String, bytes: ByteArray): ULong = throw SessionException.NotReady()
    fun merge(records: Map<String, ByteArray>)
    /** Whole record map. Only rare authority operations use it; writes use [recordsAt]. */
    fun records(): Map<String, ByteArray>
    fun recordsAt(paths: Collection<String>): Map<String, ByteArray> {
        val all = records()
        return paths.mapNotNull { path -> all[path]?.let { path to it } }.toMap()
    }
    /** [requests] holds only `requests/` records; the worker tracks paths, so nothing is copied. */
    fun snapshot(namespaces: List<String>, requests: Map<String, ByteArray>): CoreSnapshot
    fun request(configuration: SessionConfiguration, keys: KeyProvider): AccessRequest
    fun write(command: DomainCommand): OperationView
    /** Writes and reports the signed record paths, so only those records are persisted. */
    fun write(command: DomainCommand, written: MutableList<String>): OperationView = write(command)
    fun query(namespace: String, name: String, arguments: ByteArray): ByteArray = throw SessionException.NotReady()
    fun beginBlob(namespace: String, mediaType: String): NativeBlobWriter = throw SessionException.NotReady()
    fun openBlobChunk(namespace: String, digest: String, index: Int, ciphertext: ByteArray): BlobReadOutcome =
        throw SessionException.NotReady()
    fun approve(request: ByteArray, grant: GrantOptions?)
    fun revoke(id: String)
    fun importRequest(data: ByteArray): AccessRequest
    fun recovery(): KeyProvider?
    fun close()
}

internal class BindingSessionCore : SessionCore {
    private var library: ColophonLibrary? = null
    private var recoveryProvider: KeyProvider? = null

    private fun requireLibrary(): ColophonLibrary =
        library ?: throw SessionException.NotReady()

    override fun open(records: Map<String, ByteArray>, keys: KeyProvider) {
        library?.close()
        library = ColophonLibrary.open(records, keys)
    }

    override fun create(configuration: SessionConfiguration) {
        library?.close()
        val recovery = configuration.recoveryKeys ?: PlatformKeys.software()
        library = ColophonLibrary.create(
            configuration.keys,
            configuration.memberLabel,
            configuration.memberLabel,
            configuration.libraryNamespaces,
            recovery,
        )
        recoveryProvider = library?.recoveryKeys
    }

    override fun merge(records: Map<String, ByteArray>) {
        val library = requireLibrary()
        library.merge(records)
        library.ready()
    }

    override fun setReadScope(namespaces: List<String>) { requireLibrary().native.setReadScope(namespaces) }
    override fun liveGeneration(path: String, bytes: ByteArray): ULong =
        requireLibrary().native.liveGeneration(path, bytes, java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MILLIS).toString())
    override fun records(): Map<String, ByteArray> = requireLibrary().records

    override fun importRequest(data: ByteArray): AccessRequest {
        val library = requireLibrary()
        val request = requestInfo(data, library.id)
        library.merge(mapOf("requests/${request.id}.json" to data))
        return request
    }

    override fun recovery(): KeyProvider? = recoveryProvider

    override fun recordsAt(paths: Collection<String>): Map<String, ByteArray> = requireLibrary().recordsAt(paths.toList())

    override fun write(command: DomainCommand, written: MutableList<String>): OperationView =
        requireLibrary().write(command.namespace, command.kind, command.payload, written).get()

    override fun query(namespace: String, name: String, arguments: ByteArray): ByteArray =
        requireLibrary().query(namespace, name, arguments).get()

    override fun beginBlob(namespace: String, mediaType: String): NativeBlobWriter =
        requireLibrary().beginBlob(namespace, mediaType).get()

    override fun openBlobChunk(namespace: String, digest: String, index: Int, ciphertext: ByteArray): BlobReadOutcome =
        requireLibrary().openBlobChunk(namespace, digest, index, ciphertext)

    override fun snapshot(namespaces: List<String>, requests: Map<String, ByteArray>): CoreSnapshot {
        val library = requireLibrary()
        val id = library.id
        val records = requests
        val views = mutableMapOf<String, NamespaceView>()
        val denials = mutableMapOf<String, Denial>()
        for (namespace in namespaces) {
            when (val result = library.view(namespace)) {
                is Outcome.Success -> views[namespace] = result.value
                is Outcome.Failure -> denials[namespace] = result.denial
            }
        }
        val members = library.members()
        val memberIds = members.map { it.id }.toSet()
        val requests = records.keys.sorted().filter { it.startsWith("requests/") }.map { path ->
            requestInfo(records.getValue(path), id)
        }.filter { it.id !in memberIds }
        return CoreSnapshot(
            libraryID = id,
            me = library.me(),
            members = members,
            ledger = library.ledger(),
            requests = requests,
            views = views,
            denials = denials,
            revision = library.revision,
        )
    }

    override fun request(configuration: SessionConfiguration, keys: KeyProvider): AccessRequest =
        ColophonLibrary.requestAccess(
            requireLibrary().id,
            keys,
            configuration.memberLabel,
            configuration.memberKind,
            configuration.namespaces,
            configuration.access,
        )

    override fun write(command: DomainCommand): OperationView =
        requireLibrary().write(command.namespace, command.kind, command.payload).get()

    override fun approve(request: ByteArray, grant: GrantOptions?) {
        requireLibrary().approve(request, grant).get()
    }

    override fun revoke(id: String) {
        requireLibrary().revoke(id).get()
    }

    override fun close() {
        library?.close()
        library = null
    }
}

internal fun viewsEqual(left: NamespaceView?, right: NamespaceView?): Boolean {
    if (left === right) return true
    if (left == null || right == null) return false
    return left.namespace == right.namespace &&
        left.state.contentEquals(right.state) &&
        left.admitted.map { it.id } == right.admitted.map { it.id }
}

internal fun denialsEqual(left: Map<String, Denial>, right: Map<String, Denial>): Boolean {
    if (left.size != right.size) return false
    return left.all { (namespace, denial) ->
        val other = right[namespace] ?: return false
        denial.reason == other.reason && denial.detail == other.detail
    }
}
