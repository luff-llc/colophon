package org.luff.colophon

import com.luff.colophon.*
import java.security.SecureRandom
import java.time.Instant
import java.time.temporal.ChronoUnit

/** Worker-confined engine facade; callbacks perform only storage reads. */
internal class EngineLibrary(val native: NativeEngine, private val keys: KeyProvider) : AutoCloseable {
    val id get() = native.id()
    val records get() = native.records()
    val revision get() = native.revision()
    fun recordsAt(paths: List<String>) = native.recordsAt(paths)
    fun me() = native.me()
    fun members() = native.members()
    fun ready() = native.finishUnlockMany(native.beginUnlock().map { UnlockResult(it, keys.agree(it.peer)) })
    fun merge(records: Map<String, ByteArray>) { native.merge(records); ready() }
    fun refreshSource(store: RecordStore, pending: Map<String, ByteArray>) {
        val snapshot = pending.toMap()
        native.setSource(object : EngineRecordSource {
            override fun read(path: String): ByteArray = snapshot[path] ?: store.read(listOf(path))[path]
                ?: throw BindingException.InvalidData("Missing record: $path")
        })
    }
    fun acknowledge(versions: Map<String, String>, store: RecordStore) {
        refreshSource(store, emptyMap())
        native.updateVersions(versions)
    }
    fun checkpoint() = native.checkpoint(entropy())
    fun query(namespace: String, name: String, arguments: ByteArray): Outcome<ByteArray> = when (val result = native.query(namespace, name, arguments, now())) {
        is JsonOutcome.Success -> Outcome.Success(result.value)
        is JsonOutcome.Failure -> Outcome.Failure(result.denial)
    }
    fun write(namespace: String, kind: String, payload: ByteArray, written: MutableList<String> = mutableListOf()): Outcome<OperationView> =
        when (val prepared = native.beginWrite(namespace, kind, payload, now(), entropy())) {
            is PreparedAction.Failure -> Outcome.Failure(prepared.denial)
            is PreparedAction.Ready -> prepared.action.use { action ->
                val paths = action.recordPaths(); written.addAll(paths)
                native.commit(action, action.signWith(keys))
                val path = paths.firstOrNull { it.startsWith("state/") } ?: paths.first { it.startsWith("ops/") }
                when (val result = native.operationAt(path, namespace, now())) {
                    is OperationOutcome.Success -> Outcome.Success(result.value)
                    is OperationOutcome.Failure -> Outcome.Failure(result.denial)
                }
            }
        }
    fun approve(request: ByteArray, grant: GrantOptions?): Outcome<Unit> = execute(native.beginApprove(request, grant, now(), entropy()))
    fun revoke(id: String): Outcome<Unit> = execute(native.beginRevoke(id, now(), entropy()))
    private fun execute(prepared: PreparedAction): Outcome<Unit> = when (prepared) {
        is PreparedAction.Failure -> Outcome.Failure(prepared.denial)
        is PreparedAction.Ready -> prepared.action.use { native.commit(it, it.signWith(keys)); ready(); Outcome.Success(Unit) }
    }
    fun beginBlob(namespace: String, mediaType: String): Outcome<NativeBlobWriter> = when (val result = native.beginBlob(namespace, mediaType, now(), entropy())) {
        is BlobWriteOutcome.Ready -> Outcome.Success(result.writer)
        is BlobWriteOutcome.Failure -> Outcome.Failure(result.denial)
    }
    fun openBlobChunk(namespace: String, digest: String, index: Int, ciphertext: ByteArray) = native.openBlobChunk(namespace, digest, index.toUInt(), ciphertext, now())
    override fun close() = native.close()
    companion object {
        private val random = SecureRandom()
        fun entropy() = ByteArray(32).also(random::nextBytes)
        fun now() = Instant.now().truncatedTo(ChronoUnit.MILLIS).toString()
        fun open(store: RecordStore, paths: Set<String>, versions: Map<String, String>, pending: Map<String, ByteArray>,
                 keys: KeyProvider, namespaces: List<String>, cache: CheckpointCache?, expectedID: String?): EngineLibrary {
            val member = PublicKeys(keys.signingPublicKey(), keys.agreementPublicKey())
            val authority = store.read(paths.filter { it.startsWith("authority/") }) + pending.filterKeys { it.startsWith("authority/") }
            val id = NativeLibrary.open(authority, member).use { it.id() }
            if (expectedID != null && expectedID != id) throw SessionException.DestinationChanged
            val checkpoint = cache?.load(id)
            val key = if (checkpoint != null) NativeCheckpointOpening(checkpoint, id, member).use { it.finish(keys.agree(it.agreementPeer())) }
                else NativeCheckpointPreparation(id, member, entropy()).use { it.finish(keys.sign(it.signingBody())) }
            val pendingSnapshot = pending.toMap()
            val source = object : EngineRecordSource {
                override fun read(path: String): ByteArray = pendingSnapshot[path] ?: store.read(listOf(path))[path]
                    ?: throw BindingException.InvalidData("Missing record: $path")
            }
            val inventory = java.io.ByteArrayOutputStream(paths.size * 180)
            fun append(value: String) {
                val bytes = value.toByteArray(Charsets.UTF_8); val n = bytes.size
                repeat(4) { inventory.write(n ushr (8 * it) and 255) }; inventory.write(bytes)
            }
            for (path in paths + pending.keys) { append(path); append(if (path in pending) "" else versions[path] ?: "") }
            return key.use { EngineLibrary(NativeEngine.openInventory(source, inventory.toByteArray(), member, id, namespaces, key), keys).also { it.ready() } }
        }
    }
}

/** The public ledger keeps List semantics, materializing history only when inspected. */
internal class EngineLedger(private val engine: NativeEngine) : AbstractList<LedgerEntry>() {
    private val entries by lazy { engine.ledger() }
    override val size: Int get() = entries.size
    override fun get(index: Int): LedgerEntry = entries[index]

}
