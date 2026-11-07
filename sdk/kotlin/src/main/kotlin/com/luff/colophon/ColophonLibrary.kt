package com.luff.colophon

import java.security.SecureRandom
import java.time.Instant
import java.time.temporal.ChronoUnit

sealed class Outcome<out T> {
    data class Success<T>(val value: T) : Outcome<T>()
    data class Failure(val denial: Denial) : Outcome<Nothing>()
    fun get(): T = when (this) { is Success -> value; is Failure -> throw AccessException(denial) }
}
class AccessException(val denial: Denial) : Exception(denial.detail)

/** Synchronous local-keystore facade; run on the host's worker dispatcher.
 * For suspending providers use NativeLibrary's two-phase methods directly. */
class ColophonLibrary private constructor(val native: NativeLibrary, private val keys: KeyProvider,
                                         val recoveryKeys: KeyProvider? = null) : AutoCloseable {
    val id get() = native.id()
    val records get() = native.records()
    fun me() = native.me()
    fun members() = native.members()
    fun ledger() = native.ledger()
    fun tools() = native.tools(now())
    fun merge(records: Map<String, ByteArray>) = native.merge(records)
    fun ready() = native.readyWith(keys)
    fun view(namespace: String): Outcome<NamespaceView> = when (val result = native.view(namespace, now())) {
        is ViewOutcome.Success -> Outcome.Success(result.value)
        is ViewOutcome.Failure -> Outcome.Failure(result.denial)
    }
    fun approve(request: ByteArray, grant: GrantOptions? = null): Outcome<Member> {
        ready()
        val info = requestInfo(request, id)
        return execute(native.beginApprove(request, grant, now(), entropy()))?.let { Outcome.Failure(it) }
            ?: Outcome.Success(members().first { it.id == info.id })
    }
    fun revoke(memberID: String): Outcome<Unit> {
        ready()
        return execute(native.beginRevoke(memberID, now(), entropy()))?.let { Outcome.Failure(it) } ?: Outcome.Success(Unit)
    }
    /** Native revision; increases whenever records are added. */
    val revision get() = native.revision()
    /** Exact bytes for [paths], without copying the whole record map. */
    fun recordsAt(paths: List<String>): Map<String, ByteArray> = native.recordsAt(paths)
    /** Read-only named query, including the common engine queries (`blob`, `blobs`, …). */
    fun query(namespace: String, name: String, arguments: ByteArray): Outcome<ByteArray> {
        ready()
        return when (val result = native.query(namespace, name, arguments, now())) {
            is JsonOutcome.Success -> Outcome.Success(result.value)
            is JsonOutcome.Failure -> Outcome.Failure(result.denial)
        }
    }
    /** A grant-checked streaming blob writer; persist each sealed chunk before publishing. */
    fun beginBlob(namespace: String, mediaType: String): Outcome<NativeBlobWriter> {
        ready()
        return when (val result = native.beginBlob(namespace, mediaType, now(), entropy())) {
            is BlobWriteOutcome.Ready -> Outcome.Success(result.writer)
            is BlobWriteOutcome.Failure -> Outcome.Failure(result.denial)
        }
    }
    /** Authenticates fetched ciphertext for chunk [index] under current grants. */
    fun openBlobChunk(namespace: String, digest: String, index: Int, ciphertext: ByteArray): BlobReadOutcome =
        native.openBlobChunk(namespace, digest, index.toUInt(), ciphertext, now())
    /** As [write], also collecting the paths of the signed records into [written]. */
    fun write(namespace: String, kind: String, payload: ByteArray, written: MutableList<String>?): Outcome<OperationView> {
        ready()
        return when (val result = native.beginWrite(namespace, kind, payload, now(), entropy())) {
            is PreparedAction.Failure -> Outcome.Failure(result.denial)
            is PreparedAction.Ready -> result.action.use { action ->
                written?.addAll(action.recordPaths())
                commit(action)
                when (val done = native.writtenOperation(action, namespace, now())) {
                    is OperationOutcome.Success -> Outcome.Success(done.value)
                    is OperationOutcome.Failure -> Outcome.Failure(done.denial)
                }
            }
        }
    }
    fun write(namespace: String, kind: String, payload: ByteArray): Outcome<OperationView> {
        ready()
        return when (val result = native.beginWrite(namespace, kind, payload, now(), entropy())) {
            is PreparedAction.Failure -> Outcome.Failure(result.denial)
            is PreparedAction.Ready -> result.action.use { action ->
                commit(action)
                when (val written = native.writtenOperation(action, namespace, now())) {
                    is OperationOutcome.Success -> Outcome.Success(written.value)
                    is OperationOutcome.Failure -> Outcome.Failure(written.denial)
                }
            }
        }
    }
    fun call(tool: String, input: ByteArray): Outcome<ByteArray> {
        ready()
        return when (val result = native.beginCall(tool, input, now(), entropy())) {
            is PreparedCall.Read -> Outcome.Success(result.value)
            is PreparedCall.Failure -> Outcome.Failure(result.denial)
            is PreparedCall.Write -> result.action.use { action ->
                commit(action)
                when (val written = native.writtenOperationJson(action, tool.substringBefore("__"), now())) {
                    is JsonOutcome.Success -> Outcome.Success(written.value)
                    is JsonOutcome.Failure -> Outcome.Failure(written.denial)
                }
            }
        }
    }
    fun handover(newRoot: KeyProvider, label: String): Outcome<Unit> {
        ready()
        return execute(native.beginHandover(newRoot.publicKeys(), label, now(), entropy()))?.let { Outcome.Failure(it) } ?: Outcome.Success(Unit)
    }
    fun recover(newRoot: KeyProvider, label: String): Outcome<Unit> {
        ready()
        return execute(native.beginRecover(newRoot.publicKeys(), label, now(), entropy()))?.let { Outcome.Failure(it) } ?: Outcome.Success(Unit)
    }
    private fun commit(action: HostAction) {
        native.commit(action, action.signWith(keys))
        ready()
    }
    private fun execute(prepared: PreparedAction): Denial? = when (prepared) {
        is PreparedAction.Failure -> prepared.denial
        is PreparedAction.Ready -> prepared.action.use { commit(it); null }
    }
    override fun close() = native.close()
    companion object {
        private val random = SecureRandom()
        private fun entropy() = ByteArray(32).also(random::nextBytes)
        private fun now() = Instant.now().truncatedTo(ChronoUnit.MILLIS).toString()
        fun create(owner: KeyProvider, label: String, ownerLabel: String, namespaces: List<String>,
                   recovery: KeyProvider = PlatformKeys.software()): ColophonLibrary {
            val records = beginCreate(owner.publicKeys(), recovery.publicKeys(), label, ownerLabel, namespaces, now(), entropy()).use {
                it.finish(it.signWith(owner))
            }
            return ColophonLibrary(NativeLibrary.open(records, owner.publicKeys()), owner, recovery).also { it.ready() }
        }
        fun open(records: Map<String, ByteArray>, me: KeyProvider) =
            ColophonLibrary(NativeLibrary.open(records, me.publicKeys()), me).also { it.ready() }
        fun requestAccess(libraryID: String, keys: KeyProvider, label: String, kind: MemberKind,
                          namespaces: List<String>, access: List<Access>): AccessRequest =
            beginRequest(libraryID, keys.publicKeys(), label, kind, namespaces, access, now()).use {
                requestInfo(it.finish(it.signWith(keys)).values.first(), libraryID)
            }
    }
}
