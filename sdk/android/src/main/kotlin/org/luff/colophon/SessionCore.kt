package org.luff.colophon

import com.luff.colophon.BindingException
import com.luff.colophon.AccessException
import com.luff.colophon.AccessRequest
import com.luff.colophon.BlobReadOutcome
import com.luff.colophon.NativeBlobWriter
import com.luff.colophon.ColophonLibrary
import com.luff.colophon.Denial
import com.luff.colophon.GrantOptions
import com.luff.colophon.ControllerProvider
import com.luff.colophon.KeyProvider
import com.luff.colophon.NamespaceView
import com.luff.colophon.OperationView
import com.luff.colophon.Outcome
import com.luff.colophon.requestInfo

internal interface SessionCore {
    /** Retain the current connection until the new identity is accepted or durably queued. */
    fun beginIdentityChange()
    fun finishIdentityChange(keepNew: Boolean)
    fun setOwnerController(provider: ControllerProvider?) {}
    fun changeKeyring(keyring: ByteArray, newSeed: ByteArray?, signers: List<ControllerProvider>) { throw SessionException.NotReady() }
    fun restoreFromKit(configuration: SessionConfiguration, kits: List<ControllerProvider>) { throw SessionException.NotReady() }

    fun openStorage(store: RecordStore, paths: Set<String>, versions: Map<String, String>, pending: Map<String, ByteArray>, keys: KeyProvider, namespaces: List<String>, cache: CheckpointCache, libraryID: String?) {
        open(store.read(paths) + pending, keys); setReadScope(namespaces)
    }
    fun saveCheckpoint() {}
    fun updateVersions(versions: Map<String, String>, store: RecordStore) {}
    fun refreshSource(store: RecordStore, pending: Map<String, ByteArray>) {}
    fun open(records: Map<String, ByteArray>, keys: KeyProvider)
    fun create(configuration: SessionConfiguration)
    fun setReadScope(namespaces: List<String>) {}
    fun liveGeneration(path: String, bytes: ByteArray): ULong = throw SessionException.NotReady()
    fun merge(records: Map<String, ByteArray>)
    fun mergeObserved(records: Map<String, ByteArray>, versions: Map<String, String>) { merge(records) }
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
    fun query(namespace: String, name: String, arguments: ByteArray): ByteArray {
        val snapshot = snapshot(listOf(namespace), emptyMap())
        snapshot.engine?.let { engine ->
            return when (val result = engine.query(namespace, name, arguments, EngineLibrary.now())) {
                is com.luff.colophon.JsonOutcome.Success -> result.value
                is com.luff.colophon.JsonOutcome.Failure -> throw AccessException(result.denial)
            }
        }
        if (name == "read") return snapshot.views[namespace]?.state ?: throw SessionException.NotReady()
        throw SessionException.NotReady()
    }
    fun beginBlob(namespace: String, mediaType: String): NativeBlobWriter = throw SessionException.NotReady()
    fun openBlobChunk(namespace: String, digest: String, index: Int, ciphertext: ByteArray): BlobReadOutcome =
        throw SessionException.NotReady()
    fun approve(request: ByteArray, grant: GrantOptions?)
    fun revoke(id: String)
    fun importRequest(data: ByteArray): AccessRequest
    fun close()
}

internal class BindingSessionCore : SessionCore {
    private var library: EngineLibrary? = null
    private var cache: CheckpointCache? = null
    private var ledger: EngineLedger? = null
    private var ledgerRevision: ULong? = null
    private var ownerController: ControllerProvider? = null
    private val requestRecords = mutableMapOf<String, ByteArray>()
    private data class RetainedSession(
        val library: EngineLibrary?, val cache: CheckpointCache?, val ledger: EngineLedger?,
        val ledgerRevision: ULong?, val requests: Map<String, ByteArray>,
    )
    private var retained: RetainedSession? = null
    override fun setOwnerController(provider: ControllerProvider?) { ownerController = provider }

    override fun beginIdentityChange() {
        check(retained == null) { "Identity change already in progress" }
        retained = RetainedSession(library, cache, ledger, ledgerRevision, requestRecords.toMap())
        library = null; cache = null; ledger = null; ledgerRevision = null; requestRecords.clear()
    }

    override fun finishIdentityChange(keepNew: Boolean) {
        val previous = retained ?: return
        retained = null
        if (keepNew) previous.library?.close()
        else {
            library?.close()
            library = previous.library; cache = previous.cache
            ledger = previous.ledger; ledgerRevision = previous.ledgerRevision
            requestRecords.clear(); requestRecords.putAll(previous.requests)
        }
    }

    private fun requireLibrary(): EngineLibrary =
        library ?: throw SessionException.NotReady()

    override fun openStorage(store: RecordStore, paths: Set<String>, versions: Map<String, String>, pending: Map<String, ByteArray>, keys: KeyProvider, namespaces: List<String>, cache: CheckpointCache, libraryID: String?) {
        val opened = EngineLibrary.open(store, paths, versions, pending, keys, namespaces, cache, libraryID, ownerController)
        library?.close()
        requestRecords.clear()
        library = opened; this.cache = cache; ledger = null; ledgerRevision = null
    }
    override fun open(records: Map<String, ByteArray>, keys: KeyProvider) {
        val store = MemoryRecordStore(records)
        val opened = EngineLibrary.open(store, records.keys, emptyMap(), emptyMap(), keys, emptyList(), null, null, ownerController)
        library?.close()
        requestRecords.clear()
        library = opened; ledger = null; ledgerRevision = null
    }
    override fun refreshSource(store: RecordStore, pending: Map<String, ByteArray>) { requireLibrary().refreshSource(store, pending) }
    override fun updateVersions(versions: Map<String, String>, store: RecordStore) { requireLibrary().acknowledge(versions, store) }
    override fun saveCheckpoint() { library?.let { it.native.verifyBatch(128u); cache?.save(it.checkpoint(), it.id) } }
    override fun create(configuration: SessionConfiguration) {
        val owner = configuration.ownerController ?: throw BindingException.KeyProvider("An owner controller provider is required for creation")
        ColophonLibrary.create(configuration.keys, configuration.memberLabel, configuration.memberLabel, configuration.libraryNamespaces,
            owner, configuration.recoveryKit, configuration.recoveryLabel).use { created ->
            val records = created.records
            openStorage(MemoryRecordStore(records), records.keys, emptyMap(), emptyMap(), configuration.keys, configuration.namespaces,
                CheckpointCache(java.io.File(configuration.privateHome, "Checkpoints")), null)
        }
        cache = CheckpointCache(java.io.File(configuration.privateHome, "Checkpoints"))
    }

    override fun mergeObserved(records: Map<String, ByteArray>, versions: Map<String, String>) {
        val library = requireLibrary(); library.mergeObserved(records, records.keys.mapNotNull { path -> versions[path]?.let { path to it } }.toMap())
        requestRecords.putAll(records.filterKeys { it.startsWith("requests/") })
    }
    override fun merge(records: Map<String, ByteArray>) {
        val library = requireLibrary()
        library.merge(records)
        library.ready()
        requestRecords.putAll(records.filterKeys { it.startsWith("requests/") })
    }

    override fun setReadScope(namespaces: List<String>) {}
    override fun liveGeneration(path: String, bytes: ByteArray): ULong =
        requireLibrary().native.liveGeneration(path, bytes, java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MILLIS).toString())
    override fun records(): Map<String, ByteArray> = requireLibrary().records

    override fun importRequest(data: ByteArray): AccessRequest {
        val library = requireLibrary()
        val request = requestInfo(data, library.id)
        library.merge(mapOf("requests/${request.id}.json" to data))
        requestRecords["requests/${request.id}.json"] = data
        return request
    }

    override fun changeKeyring(keyring: ByteArray, newSeed: ByteArray?, signers: List<ControllerProvider>) {
        requireLibrary().changeKeyring(keyring, newSeed, signers)
    }

    override fun restoreFromKit(configuration: SessionConfiguration, kits: List<ControllerProvider>) {
        requireLibrary().restoreFromKit(configuration, kits)
    }

    override fun recordsAt(paths: Collection<String>): Map<String, ByteArray> {
        val fetched = requireLibrary().recordsAt(paths.filter { it !in requestRecords })
        requestRecords.putAll(fetched.filterKeys { it.startsWith("requests/") })
        return fetched + paths.mapNotNull { path -> requestRecords[path]?.let { path to it } }.toMap()
    }

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
            val denial = library.native.access(namespace, EngineLibrary.now())
            if (denial != null) denials[namespace] = denial
            else views[namespace] = NamespaceView(namespace, emptyList(), emptyList(), emptyList(), byteArrayOf())
        }
        val members = library.members()
        val memberIds = members.map { it.id }.toSet()
        val requests = records.keys.sorted().filter { it.startsWith("requests/") }.map { path ->
            requestInfo(records.getValue(path), id)
        }.filter { it.id !in memberIds }
        if (ledger == null || ledgerRevision != library.revision) { ledger = EngineLedger(library.native); ledgerRevision = library.revision }
        return CoreSnapshot(
            libraryID = id,
            me = library.me(),
            members = members,
            ledger = ledger!!,
            requests = requests,
            views = views,
            denials = denials,
            revision = library.revision,
            engineRevisions = library.native.revisions(),
            engine = library.native,
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
        retained?.library?.close()
        retained = null
        requestRecords.clear()
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
