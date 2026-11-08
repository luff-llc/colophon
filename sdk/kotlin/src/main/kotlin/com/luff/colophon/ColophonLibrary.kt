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
                                         /** External authority provider, separate from the content member. */
                                         val ownerController: ControllerProvider? = null) : AutoCloseable {
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
        unlockVault()
        val info = requestInfo(request, id)
        return executeAuthority(native.beginApprove(request, grant, now(), entropy()))?.let { Outcome.Failure(it) }
            ?: Outcome.Success(members().first { it.id == info.id })
    }
    fun revoke(memberID: String): Outcome<Unit> {
        unlockVault()
        return executeAuthority(native.beginRevoke(memberID, now(), entropy()))?.let { Outcome.Failure(it) } ?: Outcome.Success(Unit)
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
    /** Current authenticated controller keyring as protocol JSON. */
    fun keyring(): ByteArray = native.keyring()

    /** Opens the owner's sealed or PRF route before an authority action. */
    fun unlockVault(providers: List<ControllerProvider> = listOf(requireController())) {
        native.unlockVault(providers)
        native.selectController(requireController().controllerID())
    }

    /** Replace a keyring, providing a fresh seed and replacement slots when rotation is required. */
    fun changeKeyring(keyring: ByteArray, newSeed: ByteArray? = null,
                      signers: List<ControllerProvider> = listOf(requireController())) {
        native.unlockVault(signers)
        native.beginKeyring(keyring, newSeed, signers.map { it.controllerID() }, now(), entropy()).use {
            native.finishAuthority(it, signAction(it, null, signers))
        }
        ready()
    }

    /** Remove a controller with vault rotation; replacement slots are built through [native]. */
    fun removeController(id: String, newSeed: ByteArray, slots: List<ByteArray>,
                         signers: List<ControllerProvider> = listOf(requireController())) {
        native.unlockVault(signers)
        native.beginRemoveController(id, newSeed, slots, signers.map { it.controllerID() }, now(), entropy()).use {
            native.finishAuthority(it, signAction(it, null, signers))
        }
        ready()
    }

    private fun requireController(): ControllerProvider = ownerController
        ?: throw BindingException.KeyProvider("An owner controller provider is required")

    private fun executeAuthority(prepared: PreparedAction): Denial? = when (prepared) {
        is PreparedAction.Failure -> prepared.denial
        is PreparedAction.Ready -> prepared.action.use {
            native.finishAuthority(it, signAction(it, null, listOf(requireController())))
            ready()
            null
        }
    }
    private fun commit(action: HostAction) {
        native.commit(action, action.signWith(keys))
        ready()
    }
    override fun close() = native.close()
    companion object {
        private val random = SecureRandom()
        private fun entropy() = ByteArray(32).also(random::nextBytes)
        private fun now() = Instant.now().truncatedTo(ChronoUnit.MILLIS).toString()
        /**
         * Creates layout 2 with separate member and raw owner controller keys in two signing rounds.
         * A host-supplied recovery kit at genesis is blocked until the core exposes that creation API.
         */
        fun create(member: KeyProvider, label: String, ownerLabel: String, namespaces: List<String>,
                   ownerController: ControllerProvider, recoveryKit: ControllerProvider? = null): ColophonLibrary {
            if (recoveryKit != null) throw BindingException.InvalidData("Core creation API cannot include a recovery-kit controller in genesis")
            if (ownerController.form() != KeyForm.RAW) throw BindingException.InvalidData("Core creation API requires a raw owner controller")
            val seed = entropy()
            val records = try {
                beginCreate(member.publicKeys(), ownerController.controllerPublic(), seed, label, ownerLabel, namespaces, now(), entropy()).use { first ->
                    first.advanceCreate(signAction(first, member, listOf(ownerController)).map { it.signature }).use { final ->
                        final.finishAuthority(signAction(final, null, listOf(ownerController)))
                    }
                }
            } finally { seed.fill(0) }
            return open(records, member, ownerController)
        }

        /** Opens member epochs; the optional external controller is used only for authority actions. */
        fun open(records: Map<String, ByteArray>, me: KeyProvider, ownerController: ControllerProvider? = null): ColophonLibrary {
            val library = ColophonLibrary(NativeLibrary.open(records, me.publicKeys()), me, ownerController)
            try { library.ready(); return library }
            catch (error: Exception) { library.close(); throw error }
        }

        /**
         * Restores a new device through an existing kit slot and a recovery-rule keyring addition,
         * then grants its separate member. The core enforces the recovery quorum and role limits.
         */
        fun restoreFromKit(records: Map<String, ByteArray>, member: KeyProvider, ownerController: ControllerProvider,
                           ownerLabel: String, namespaces: List<String>, kits: List<ControllerProvider>): ColophonLibrary {
            val lib = open(records, member, ownerController)
            try {
                lib.native.unlockVault(kits)
                val ring = keyObject(lib.keyring())
                fun threshold(name: String) = (ring.fields[name] as? KeyJson.Number)?.raw?.toInt()
                    ?: throw BindingException.InvalidData("Missing keyring threshold")
                val roles = if (threshold("recoverThreshold") < threshold("threshold")) listOf("approve") else listOf("approve", "control")
                val controller = controllerJSON(ownerController, ownerLabel, roles)
                val slot = lib.native.buildSealedSlot(controller, ownerLabel, null, entropy())
                lib.native.beginRecoveryAdd(controller, slot, kits.map { it.controllerID() }, now()).use {
                    lib.native.finishAuthority(it, signAction(it, null, kits))
                }
                val request = records["requests/${keyID(member.signingPublicKey())}.json"]
                    ?: requestAccess(lib.id, member, ownerLabel, MemberKind.DEVICE, namespaces, listOf(Access.READ, Access.WRITE)).record
                lib.approve(request).get()
                return lib
            } catch (error: Exception) { lib.close(); throw error }
        }
        fun requestAccess(libraryID: String, keys: KeyProvider, label: String, kind: MemberKind,
                          namespaces: List<String>, access: List<Access>): AccessRequest =
            beginRequest(libraryID, keys.publicKeys(), label, kind, namespaces, access, now()).use {
                requestInfo(it.finish(it.signWith(keys)).values.first(), libraryID)
            }
    }
}
