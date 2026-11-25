package com.luff.colophon.session

import com.luff.colophon.AccountIdentity
import com.luff.colophon.AccountIdentityKind
import com.luff.colophon.Controller
import com.luff.colophon.ControllerRole
import com.luff.colophon.ControllerSpec
import com.luff.colophon.Pending
import com.luff.colophon.Policy
import com.luff.colophon.RuleKind
import com.luff.colophon.SignForm
import com.luff.colophon.SignerNeed
import com.luff.colophon.SlotInfo
import com.luff.colophon.SlotPlan
import com.luff.colophon.accountControllerJson
import com.luff.colophon.accountKeyId
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import java.util.Base64

/** The outcome of `removeController`, `replaceController` and `completeKeyChanges`. */
sealed class KeyringChange {
    /**
     * The change is in force and nothing it leaves is owed by this host: the vault is not retiring, every namespace has an
     * epoch introduced after the latest rotation, and a replacement key has its own slot.
     */
    object Done : KeyringChange() { override fun toString() = "Done" }
    /**
     * Not done yet. [transitions] are the digests of the pending transitions this host signed that carry the change (sorted;
     * each was submitted to every home); empty when only an activation's finality, or a duty another host must do, is
     * awaited. Call the same function again with the same arguments later to finish: it never signs anything twice.
     */
    data class Pending(val transitions: List<String>) : KeyringChange()
}

/**
 * What removing (or replacing) a controller would do, judged before anything is signed (spec §6.2, §6.4, §8.3, §8.4).
 * `removeController` and `replaceController` refuse with `InvalidCommand` whenever [refusal] is set; the [warnings] are what
 * spec §6.4 says a host MUST say, in words, before it signs.
 */
data class RemovalCheck(
    val controller: String,
    /** Every controller the transition removes: the one asked about and what it added (§8.4). */
    val removes: List<String>,
    val refusal: Refusal?,
    /** The removal rotates the vault in the same transition (§8.3), so it never retires. */
    val rotatesAtOnce: Boolean,
    /**
     * For a replacement: the new key is added and the old one removed by one transition. When false the replacement is
     * staged (spec §8.3): the new key is added first, gets its own slot, and only then is the old one removed with a
     * rotation, so there is never a moment with fewer ways in.
     */
    val inOneTransition: Boolean,
    val warnings: List<Warning>,
) {
    val allowed: Boolean get() = refusal == null

    enum class Refusal {
        /** The ID names no controller of the account. */
        NOT_A_CONTROLLER,
        /** No controller with `control` would remain (§6.2). */
        LAST_CONTROL_KEY,
        /** Fewer `control` units than the threshold would remain (§6.2): the transition would be void. */
        NO_CONTROL_QUORUM,
        /** Fewer `recover` units than `recoverThreshold` would remain (§6.2): the transition would be void. */
        NO_RECOVERY_QUORUM,
        /** No remaining controller would have a slot: nobody could open the vault (§6.4). */
        NO_OPENABLE_SLOT,
        /** The replacement key is already a controller, or the ID is the replacement key itself. */
        REPLACEMENT_PRESENT,
    }

    sealed class Warning(val words: String) {
        /** Losing any one more control unit would leave no control quorum (§6.4). */
        object OneLossFromNoControlQuorum : Warning("After this change, losing one more key leaves nobody able to change the account's keys.")
        /** Only one remaining controller has a slot: losing it leaves no way to open the vault (§6.4). */
        object OneLossFromNoOpenableSlot : Warning("After this change, only one key can open your library. If you lose it, the library cannot be opened.")
        /** The `recover` controllers would form exactly one unit (§6.4). */
        object SingleRecoveryUnit : Warning("After this change, one recovery key remains. A thief holding any one of your other keys could then block recovery; add a second recovery key.")
        /** These remaining controllers would have no slot after the change (§6.4, §8.3): each must be used once more ([ColophonSession.restoreSlot]). */
        data class KeysWithoutSlot(val ids: List<String>) : Warning("Some of your keys will need to be used once more on a device that has your library before they can open it again.")
        /** The vault retires at activation until a `vault` entry rotates it (§8.3); the removed key reads what is written meanwhile. */
        object VaultRetiresUntilRotated : Warning("Until your library is re-locked under a new key, the removed key can still read what is written. This app re-locks it as soon as the change takes effect.")
        /** The removal also removes these `approve` or `sign` controllers the removed key added (§8.4 removal follow-up). */
        data class AlsoRemoves(val ids: List<String>) : Warning("Keys that the removed key added are removed with it.")
        /** This device's owner key is removed: configure another owner controller for this session afterwards. */
        object RemovesThisDevicesOwner : Warning("This removes the key this device uses to manage your account. Choose another key for this device afterwards.")
        override fun toString(): String = this::class.simpleName ?: "Warning"
    }
}

/** The steps of `removeController` and `replaceController`, for the tests that stop a call between two of them. */
internal enum class KeyringStep { SIGNED, RECORDED, SLOTTED }
internal class KeyringStopped : Exception("stopped for a test")

/** The pure judgement behind [RemovalCheck], over what the account states and what this host holds. */
internal object RemovalAnalysis {
    class Facts(val controllers: List<Controller>, val slots: List<SlotInfo>, val policy: Policy, val held: Set<String>, val ownerId: String?)

    private fun unit(c: Controller, holders: Boolean) = if (holders) (c.holder ?: c.id) else c.id

    /** `adding`: the replacement's ID and roles, counted as remaining (it is current once its activation is final). */
    fun check(remove: String, adding: Pair<String, List<ControllerRole>>?, f: Facts): RemovalCheck {
        fun refused(r: RemovalCheck.Refusal) = RemovalCheck(remove, listOf(remove), r, false, false, listOf())
        if (f.controllers.none { it.id == remove }) return refused(RemovalCheck.Refusal.NOT_A_CONTROLLER)
        if (adding != null && (adding.first == remove || f.controllers.any { it.id == adding.first })) return refused(RemovalCheck.Refusal.REPLACEMENT_PRESENT)
        val planted = f.controllers.filter { c ->
            c.id != remove && remove in c.addedBy && c.roles.isNotEmpty() && c.roles.all { it == ControllerRole.APPROVE || it == ControllerRole.SIGN }
        }.map { it.id }.sorted()
        val removes = listOf(remove) + planted
        val removed = removes.toSet()
        val remaining = f.controllers.filter { it.id !in removed }
        val holders = f.policy.countByHolders
        val controlUnits = remaining.filter { ControllerRole.CONTROL in it.roles }.map { unit(it, holders) }.toMutableSet()
        val recoverUnits = remaining.filter { ControllerRole.RECOVER in it.roles }.map { unit(it, holders) }.toMutableSet()
        if (adding != null) {
            if (ControllerRole.CONTROL in adding.second) controlUnits.add(adding.first)
            if (ControllerRole.RECOVER in adding.second) recoverUnits.add(adding.first)
        }
        if (controlUnits.isEmpty()) return refused(RemovalCheck.Refusal.LAST_CONTROL_KEY)
        if (controlUnits.size.toULong() < f.policy.threshold) return refused(RemovalCheck.Refusal.NO_CONTROL_QUORUM)
        if (f.policy.recoverThreshold > 0uL && recoverUnits.size.toULong() < f.policy.recoverThreshold) return refused(RemovalCheck.Refusal.NO_RECOVERY_QUORUM)
        val form = f.controllers.associate { it.id to it.form }
        val remainingSlots = f.slots.filter { s -> s.controllers.none { it.id in removed } }
        if (remainingSlots.isEmpty() && adding == null) return refused(RemovalCheck.Refusal.NO_OPENABLE_SLOT)
        // A slot this host can build again for a new vault: every PRF route's credential is held.
        fun buildable(s: SlotInfo) = s.controllers.all { form[it.id] != SignForm.WEBAUTHN || it.id in f.held }
        val removesSlotted = f.slots.any { s -> s.controllers.any { it.id in removed } }
        val inOne = adding != null && oneTransitionReplacement(removed, f)
        val rotates = adding == null && removesSlotted && remainingSlots.all(::buildable)
        val warnings = ArrayList<RemovalCheck.Warning>()
        if (planted.isNotEmpty()) warnings.add(RemovalCheck.Warning.AlsoRemoves(planted))
        if (f.ownerId != null && f.ownerId in removed) warnings.add(RemovalCheck.Warning.RemovesThisDevicesOwner)
        if (controlUnits.size.toULong() <= f.policy.threshold) warnings.add(RemovalCheck.Warning.OneLossFromNoControlQuorum)
        if (recoverUnits.size == 1) warnings.add(RemovalCheck.Warning.SingleRecoveryUnit)
        val slotted: Set<String> = when {
            rotates || adding != null -> remainingSlots.filter(::buildable).flatMap { s -> s.controllers.map { it.id } }.toSet() + listOfNotNull(adding?.first)
            removesSlotted -> remainingSlots.filter(::buildable).flatMap { s -> s.controllers.map { it.id } }.toSet()
            else -> remainingSlots.flatMap { s -> s.controllers.map { it.id } }.toSet()
        }
        val without = remaining.filter { it.roles != listOf(ControllerRole.SIGN) && it.id !in slotted }.map { it.id }.sorted()
        if (without.isNotEmpty()) warnings.add(RemovalCheck.Warning.KeysWithoutSlot(without))
        if (slotted.size <= 1) warnings.add(RemovalCheck.Warning.OneLossFromNoOpenableSlot)
        if (adding == null && removesSlotted && !rotates) warnings.add(RemovalCheck.Warning.VaultRetiresUntilRotated)
        if (adding != null && removesSlotted && (inOne || !remainingSlots.all(::buildable))) warnings.add(RemovalCheck.Warning.VaultRetiresUntilRotated)
        return RemovalCheck(remove, removes, null, rotates, inOne, warnings)
    }

    /**
     * A replacement is one transition only when, after it activates, this host can still open the retiring vault and write
     * its `vault` entry (§8.3): a held controller other than the removed ones, current, holding `control` or `recover`, with
     * a slot this host can open. Otherwise it is staged (a slot in a transition's `vault` component for a key the same
     * transition adds is dropped at activation).
     */
    fun oneTransitionReplacement(removed: Set<String>, f: Facts): Boolean = f.controllers.any { c ->
        c.id !in removed && c.id in f.held && !c.provisional && !c.suspended &&
            (ControllerRole.CONTROL in c.roles || ControllerRole.RECOVER in c.roles) &&
            f.slots.any { s -> s.controllers.any { it.id == c.id } && s.controllers.all { it.id in f.held } }
    }

    /**
     * The namespaces owed a `rekey` (§8.3): every namespace whose latest epoch was introduced before the latest vault change
     * (a genesis, a `vault` entry, or an activation whose transition has a `vault` component). Null when an entry is missing.
     */
    fun rekeyOwed(bodies: Map<ULong, Map<*, *>>, head: ULong): List<String>? {
        var vaultSeq = 0uL
        val latest = HashMap<String, ULong>()
        var seq = 1uL
        while (seq <= head) {
            val body = bodies[seq] ?: return null
            when (body["kind"] as? String) {
                "genesis" -> {
                    vaultSeq = seq
                    for (ns in (body["namespaces"] as? List<*>).orEmpty()) if (ns is String && ns !in latest) latest[ns] = 0uL
                }
                "vault" -> vaultSeq = seq
                "activate" -> {
                    val inner = (body["transition"] as? String)?.let(::embeddedBody)
                    if ((inner?.get("change") as? Map<*, *>)?.containsKey("vault") == true) vaultSeq = seq
                }
                "rekey", "revoke" -> for (e in (body["epochs"] as? List<*>).orEmpty()) {
                    ((e as? Map<*, *>)?.get("namespace") as? String)?.let { latest[it] = seq }
                }
            }
            seq++
        }
        return latest.filter { it.value < vaultSeq }.keys.sorted()
    }

    /** The body of an envelope (`{"body": base64, …}`) given as its own JSON bytes. */
    fun envelopeBody(bytes: ByteArray): Map<*, *>? = try {
        val envelope = Json.obj(String(bytes, Charsets.UTF_8))
        Json.obj(String(Base64.getDecoder().decode(envelope?.get("body") as String), Charsets.UTF_8))
    } catch (_: Exception) { null }
    /** The body of an embedded envelope (standard base64 of its canonical JSON, §2.2). */
    fun embeddedBody(text: String): Map<*, *>? = try { envelopeBody(Base64.getDecoder().decode(text)) } catch (_: Exception) { null }
}

// The worker's half: removing and replacing controllers, cosigned transitions, and the duties a removal leaves.

internal fun SessionWorker.reachedKeyring(step: KeyringStep) { if (keyringStopForTests == step) throw KeyringStopped() }

/** The providers this host holds for owner operations: the owner controller, the recovery kit, then `extra`. */
internal suspend fun SessionWorker.heldCustody(extra: List<AsyncKeyProvider>): KeyCustody {
    var custody = ownerCustody()
    for (p in extra) custody = custody.merging(KeyCustody.keyId(p), SessionKeys(p))
    return custody
}
internal suspend fun keyIds(providers: List<AsyncKeyProvider>): List<String> = providers.map { KeyCustody.keyId(it) }
internal suspend fun merged(base: KeyCustody, extra: List<AsyncKeyProvider>): KeyCustody {
    var custody = base
    for (p in extra) custody = custody.merging(KeyCustody.keyId(p), SessionKeys(p))
    return custody
}

/**
 * Opens a controller engine as a key this host holds (the owner controller while it is one, else the first held current
 * controller), unlocks it by a slot every route of which this host holds (the owner's own first), runs `body`, locks it.
 */
internal suspend fun <T> SessionWorker.withControllers(extra: List<AsyncKeyProvider>, unlock: Boolean = true,
                                                       body: suspend (ColophonEngine, KeyCustody, String) -> T): T {
    val account = accountId ?: throw SessionError.NotReady()
    val custody = heldCustody(extra)
    val ownerId = KeyCustody.keyId(configuration.ownerController)
    suspend fun open(id: String): ColophonEngine = tracked(configuration.deviceSecrets.key(account).use { key ->
        ColophonEngine.open(label = "colophon-owner", source = MediumSource(storage()), listing = listed(storage().listing()),
            identity = AccountIdentity(AccountIdentityKind.CONTROLLER, id), account = account,
            namespaces = listOf(), saved = null, deviceKey = key, nowMs = nowMs)
    })
    var engine = open(ownerId)
    try {
        var primary = ownerId
        val controllers = engine.run { it.controllers() }
        if (controllers.none { it.id == ownerId }) {
            val other = controllers.firstOrNull { custody.holds(it.id) && !it.provisional && it.roles != listOf(ControllerRole.SIGN) }
                ?: throw SessionError.OwnerRequired()
            release(engine)
            primary = other.id
            engine = open(primary)
        }
        if (unlock && !unlockHeld(engine, custody, primary)) throw SessionError.OwnerRequired()
        return body(engine, custody, primary)
    } finally {
        release(engine)
    }
}

/** Opens a slot of the current vault that this host holds every route of, unless the engine already holds its seed. */
internal suspend fun unlockHeld(engine: ColophonEngine, custody: KeyCustody, prefer: String): Boolean {
    if (engine.run { it.isUnlocked() }) return true
    val slots = engine.run { it.slots() }
    val open = slots.filter { s -> s.controllers.all { custody.holds(it.id) } }
    val slot = open.firstOrNull { s -> s.controllers.map { it.id } == listOf(prefer) }
        ?: open.firstOrNull { s -> s.controllers.any { it.id == prefer } } ?: open.firstOrNull() ?: return false
    val inputs = engine.run { it.beginUnlockSlot(slot.index) }
    engine.finishUnlockSlot(slot.index, custody.answerUnlock(inputs))
    return true
}

/**
 * The signers of a change: those the engine suggests from `primary` and `cosigners`, then every other cosigner that is a
 * current `control` or `recover` controller, so one change can be signed by every key the person holds here (§8.7 full set).
 */
internal suspend fun signerSet(engine: ColophonEngine, primary: String, need: SignerNeed, cosigners: List<String>): List<String> {
    val available = listOf(primary) + cosigners.filter { it != primary }
    val set = engine.run { it.suggestSigners(available, need) }.ifEmpty { listOf(primary) }.toMutableList()
    if (cosigners.isEmpty()) return set
    val controllers = engine.run { it.controllers() }
    for (id in cosigners) {
        if (id in set) continue
        val c = controllers.firstOrNull { it.id == id } ?: continue
        if (c.provisional || c.suspended || (ControllerRole.CONTROL !in c.roles && ControllerRole.RECOVER !in c.roles)) continue
        set.add(id)
    }
    return set
}

internal suspend fun SessionWorker.removalFacts(engine: ColophonEngine, custody: KeyCustody): RemovalAnalysis.Facts {
    val ownerId = try { KeyCustody.keyId(configuration.ownerController) } catch (e: CancellationException) { throw e } catch (_: Exception) { null }
    return RemovalAnalysis.Facts(engine.run { it.controllers() }, engine.run { it.slots() }, engine.run { it.policy() }, custody.providers.keys, ownerId)
}

/** Records what is due (§8.7) and persists it, then makes sure the engine holds the current vault's seed. */
internal suspend fun SessionWorker.recordDueHeld(engine: ColophonEngine, custody: KeyCustody, primary: String) {
    val at = nowMs
    engine.run { it.advance(at) }
    withContext(NonCancellable) { for (due in engine.run { it.recordDue() }) persist(due, engine) }
    try { unlockHeld(engine, custody, primary) } catch (e: CancellationException) { throw e } catch (_: Exception) {}
}

/** The namespaces owed a `rekey` at the verified head, read from the stored authority entries and cached by head. */
internal suspend fun SessionWorker.rekeyOwed(engine: ColophonEngine): List<String>? {
    val head = engine.run { it.headSeq() }
    val digest = engine.run { it.headDigest() }
    rekeyCache?.let { (h, d, owed) -> if (h == head && d == digest) return owed }
    val bodies = HashMap<ULong, Map<*, *>>()
    var seq = 1uL
    while (seq <= head) {
        val bytes = try { storage().read("authority/%08d.json".format(seq.toLong())) } catch (e: CancellationException) { throw e } catch (_: Exception) { null } ?: break
        bodies[seq] = RemovalAnalysis.envelopeBody(bytes) ?: break
        seq++
    }
    val owed = RemovalAnalysis.rekeyOwed(bodies, head)
    rekeyCache = Triple(head, digest, owed)
    return owed
}

/** Builds `id`'s own slot of the current vault (a self-slot `keyring` entry, §8.4), unless a slot already names only it. */
internal suspend fun SessionWorker.buildOwnSlot(engine: ColophonEngine, custody: KeyCustody, id: String, label: String, possession: TransitionPossessionPrf?) {
    if (engine.run { it.slots() }.any { s -> s.controllers.map { it.id } == listOf(id) }) return
    val ownerId = try { KeyCustody.keyId(configuration.ownerController) } catch (e: CancellationException) { throw e } catch (_: Exception) { null }
    val entrySigner = engine.run { e ->
        val held = e.controllers().firstOrNull { it.id == ownerId }
        if (ownerId != null && ownerId != id && e.policy().addThreshold == 1uL && held?.form == SignForm.RAW &&
            ControllerRole.CONTROL in held.roles && !held.provisional && !held.suspended) ownerId else id
    }
    val input = possession?.input
    val plan = SlotPlan(listOf(id), label)
    engine.execute(custody, persistOn(engine)) { e ->
        withEntropy(32) { e.beginAddSlotWithSigners(listOf(entrySigner), plan, input?.salt, input?.challenge, it) }
    }
}

/**
 * What a removal leaves this host to do (§8.3): while the vault is retiring, the `vault` entry, signed by the longest-standing
 * held `control` or `recover` controller, with every slot this host can build and a slot of its own for each held controller
 * that has none; then the `rekey` of every namespace owed one; then `newKey`'s own slot. True when nothing is left.
 */
internal suspend fun SessionWorker.performKeyDuties(engine: ColophonEngine, custody: KeyCustody, primary: String,
                                                    newKey: Pair<String, String>?, possession: TransitionPossessionPrf?): Boolean {
    val held = custody.providers.keys
    var retiring = engine.run { it.notices(0uL, listOf(), listOf()) }.vaultRetiring
    if (retiring) {
        val controllers = engine.run { it.controllers() }
        val slots = engine.run { it.slots() }
        val form = controllers.associate { it.id to it.form }
        val signer = controllers.filter {
            it.id in held && !it.provisional && !it.suspended && (ControllerRole.CONTROL in it.roles || ControllerRole.RECOVER in it.roles)
        }.sortedWith(compareBy({ it.addedSeq }, { it.id })).firstOrNull()
        if (signer != null && unlockHeld(engine, custody, primary)) {
            val plans = slots.filter { s -> s.controllers.all { form[it.id] != SignForm.WEBAUTHN || it.id in held } }
                .map { s -> SlotPlan(s.controllers.map { it.id }, s.label) }.toMutableList()
            val named = plans.flatMap { it.controllers }.toSet()
            for (c in controllers) if (c.id in held && !c.provisional && c.roles != listOf(ControllerRole.SIGN) && c.id !in named) plans.add(SlotPlan(listOf(c.id), c.label))
            engine.execute(custody, persistOn(engine)) { e -> withEntropy(64) { e.beginRotateVault(signer.id, true, plans, it) } }
            retiring = false
        }
    }
    if (retiring) return false
    var owedLeft = false
    val owed = rekeyOwed(engine)
    if (!owed.isNullOrEmpty()) {
        if (unlockHeld(engine, custody, primary)) {
            val available = listOf(primary) + engine.run { it.controllers() }.filter { it.id in held && it.id != primary }.map { it.id }
            val signers = engine.run { it.suggestSigners(available, SignerNeed.REKEY) }
            engine.execute(custody, persistOn(engine)) { e -> withEntropy(32) { e.beginRekey(owed, signers, it) } }
        } else owedLeft = true
    }
    if (newKey != null) {
        val c = engine.run { it.controllers() }.firstOrNull { it.id == newKey.first }
        if (c == null || c.provisional) return false
        buildOwnSlot(engine, custody, newKey.first, newKey.second, possession)
    }
    return !owedLeft
}

internal suspend fun SessionWorker.checkRemoval(id: String, replacingWith: AsyncKeyProvider?, roles: List<ControllerRole>,
                                                cosigners: List<AsyncKeyProvider>): RemovalCheck = gated {
    if (engine == null) reconcile()
    val adding = replacingWith?.let { KeyCustody.keyId(it) to roles }
    withControllers(cosigners + listOfNotNull(replacingWith), unlock = false) { owner, custody, _ ->
        RemovalAnalysis.check(id, adding, removalFacts(owner, custody))
    }
}

private suspend fun SessionWorker.signRemoval(owner: ColophonEngine, custody: KeyCustody, check: RemovalCheck, signers: List<String>,
                                              signed: MutableList<Pair<String, String>>): String? {
    val remove = check.removes
    val rotate = check.rotatesAtOnce
    val written = owner.execute(custody, persistOn(owner)) { e ->
        if (rotate) withEntropy(64) { e.beginRemoveController(remove, listOf(), signers, RuleKind.CONTROL, true, it) }
        else e.beginRemoveController(remove, listOf(), signers, RuleKind.CONTROL, false, ByteArray(0))
    }
    val digest = SessionWorker.objectDigest(written.stores, "transitions/") ?: return null
    // A removal without a rotation can be signed again as it stands (§17.5); one with a rotation carries a seed this call
    // held only once, so it is not kept for re-signing.
    if (!rotate) signed.add(digest to Json.write(mapOf("keyring" to mapOf("remove" to remove))))
    return digest
}

private fun SessionWorker.keepSigned(signed: List<Pair<String, String>>) {
    if (signed.isEmpty()) return
    loadJournal()
    journal.signedChanges = journal.signedChanges + signed
    saveJournal()
}

/**
 * Removes controller `id` by one transition (§8.7) signed by the owner and `cosigners`. When the removed key had a slot and
 * this host can build every remaining slot again, the transition rotates the vault at once (§8.3); otherwise the vault
 * retires at activation and this host writes the `vault` entry then. After activation it appends the `rekey`. Idempotent.
 */
internal suspend fun SessionWorker.removeController(id: String, cosigners: List<AsyncKeyProvider>): Pair<KeyringChange, SessionSnapshot> = gated {
    if (engine == null) reconcile()
    val cosignerIds = keyIds(cosigners)
    val signed = ArrayList<Pair<String, String>>()
    val outcome = withControllers(cosigners) { owner, custody, primary ->
        val held = custody.providers.keys
        val inFlight = ArrayList<String>()
        if (owner.run { it.controllers() }.any { it.id == id }) {
            val mine = owner.run { it.pending() }.filter { it.by in held && id in it.removes }
            if (mine.isNotEmpty()) inFlight.addAll(mine.map { it.digest })
            else {
                val check = RemovalAnalysis.check(id, null, removalFacts(owner, custody))
                if (!check.allowed) throw SessionError.InvalidCommand()
                val signers = signerSet(owner, primary, SignerNeed.CONTROL, cosignerIds)
                signRemoval(owner, custody, check, signers, signed)?.let { inFlight.add(it) }
                reachedKeyring(KeyringStep.SIGNED)
            }
        }
        recordDueHeld(owner, custody, primary)
        reachedKeyring(KeyringStep.RECORDED)
        if (owner.run { it.controllers() }.any { it.id == id }) return@withControllers KeyringChange.Pending(inFlight.toSortedSet().toList())
        if (performKeyDuties(owner, custody, primary, null, null)) KeyringChange.Done else KeyringChange.Pending(listOf())
    }
    keepSigned(signed)
    outcome to reconcile()
}

/**
 * Replaces controller `id` with `spec` (signed for by `key`): ONE transition adding the new key and removing the old one when
 * this host keeps another key that can rotate the vault; otherwise staged (add, own slot, then remove with a rotation signed
 * by both). See `ColophonSession.replaceController`. Idempotent.
 */
internal suspend fun SessionWorker.replaceController(id: String, spec: ControllerSpec, key: AsyncKeyProvider,
                                                     cosigners: List<AsyncKeyProvider>): Pair<KeyringChange, SessionSnapshot> = gated {
    if (engine == null) reconcile()
    val newId = accountKeyId(spec.key.signing)
    if (newId == id) throw SessionError.InvalidCommand()
    val requested = Json.parse(accountControllerJson(spec))
    val cosignerIds = keyIds(cosigners)
    val signed = ArrayList<Pair<String, String>>()
    val outcome = withControllers(cosigners + key) { owner, base, primary ->
        val held = base.providers.keys
        val inFlight = ArrayList<String>()
        var possession: TransitionPossessionPrf? = null
        try {
            var custody = base
            suspend fun mine(): List<Pending> = owner.run { it.pending() }.filter { it.by in held }
            suspend fun controllers(): List<Controller> = owner.run { it.controllers() }
            // A: the new key, in the keyring, pending, or added here (with the old key's removal when one transition is safe).
            val present = controllers().firstOrNull { it.id == newId }
            val proposed = if (present == null) mine().firstOrNull { newId in it.adds } else null
            when {
                present != null -> if (present.label != spec.label || present.roles.toSet() != spec.roles.toSet()) throw SessionError.InvalidCommand()
                proposed != null -> {
                    val add = ((pendingChange(proposed.digest)?.get("keyring") as? Map<*, *>)?.get("add") as? List<*>).orEmpty()
                        .firstOrNull { SessionWorker.controllerKeyId(it) == newId }
                    if (add == null || Json.write(add) != Json.write(requested)) throw SessionError.InvalidCommand()
                    inFlight.add(proposed.digest)
                }
                else -> {
                    if (controllers().none { it.id == id }) throw SessionError.InvalidCommand()
                    val check = RemovalAnalysis.check(id, newId to spec.roles, removalFacts(owner, custody))
                    if (!check.allowed) throw SessionError.InvalidCommand()
                    if (spec.key.form == SignForm.WEBAUTHN && key.supportsPrf) {
                        possession = TransitionPossessionPrf(newId)
                        custody = KeyCustody(custody.providers, possession)
                    }
                    val keyring = LinkedHashMap<String, Any?>()
                    keyring["add"] = listOf(requested)
                    if (check.inOneTransition) keyring["remove"] = check.removes
                    val json = Json.write(mapOf("keyring" to keyring))
                    val signers = signerSet(owner, primary, SignerNeed.CONTROL, cosignerIds)
                    val written = owner.execute(custody, persistOn(owner)) { it.beginTransition(json, signers, RuleKind.CONTROL, ByteArray(0)) }
                    SessionWorker.objectDigest(written.stores, "transitions/")?.let { inFlight.add(it); signed.add(it to json) }
                    reachedKeyring(KeyringStep.SIGNED)
                }
            }
            recordDueHeld(owner, custody, primary)
            reachedKeyring(KeyringStep.RECORDED)
            val added = controllers().firstOrNull { it.id == newId }
            if (added == null || added.provisional) return@withControllers KeyringChange.Pending(inFlight.toSortedSet().toList())
            // B: the new key's own slot, before the old key goes (while the vault retires, the `vault` entry builds it).
            if (!owner.run { it.notices(0uL, listOf(), listOf()) }.vaultRetiring) {
                buildOwnSlot(owner, custody, newId, spec.label, possession)
                reachedKeyring(KeyringStep.SLOTTED)
            }
            // C: the old key, if still there (the staged replacement): removed with a rotation, signed by the new key too.
            if (controllers().any { it.id == id }) {
                val p = mine().firstOrNull { id in it.removes }
                if (p != null) inFlight.add(p.digest)
                else {
                    val check = RemovalAnalysis.check(id, null, removalFacts(owner, custody))
                    if (!check.allowed) throw SessionError.InvalidCommand()
                    val signers = signerSet(owner, primary, SignerNeed.CONTROL, cosignerIds + newId)
                    signRemoval(owner, custody, check, signers, signed)?.let { inFlight.add(it) }
                    reachedKeyring(KeyringStep.SIGNED)
                    recordDueHeld(owner, custody, primary)
                }
                if (controllers().any { it.id == id }) return@withControllers KeyringChange.Pending(inFlight.toSortedSet().toList())
            }
            // D: what the removal leaves: the `vault` entry, the `rekey`, the new key's slot.
            if (performKeyDuties(owner, custody, primary, newId to spec.label, possession)) KeyringChange.Done else KeyringChange.Pending(listOf())
        } finally {
            possession?.close()
        }
    }
    keepSigned(signed)
    outcome to reconcile()
}

/** The duties a removal left (the `vault` entry while the vault is retiring, the `rekey` after a rotation). */
internal suspend fun SessionWorker.completeKeyChanges(cosigners: List<AsyncKeyProvider>): Pair<KeyringChange, SessionSnapshot> = gated {
    if (engine == null) reconcile()
    val outcome = withControllers(cosigners) { owner, custody, primary ->
        recordDueHeld(owner, custody, primary)
        if (performKeyDuties(owner, custody, primary, null, null)) KeyringChange.Done else KeyringChange.Pending(listOf())
    }
    outcome to reconcile()
}

/** Gives `key` (a current controller with no slot of its own) its own slot of the current vault, opened by another held key. */
internal suspend fun SessionWorker.restoreSlot(key: AsyncKeyProvider, label: String): SessionSnapshot = gated {
    if (engine == null) reconcile()
    val id = KeyCustody.keyId(key)
    withControllers(listOf(key)) { owner, custody, _ ->
        val c = owner.run { it.controllers() }.firstOrNull { it.id == id }
        if (c == null || c.provisional || c.roles == listOf(ControllerRole.SIGN)) throw SessionError.InvalidCommand()
        buildOwnSlot(owner, custody, id, label, null)
    }
    reconcile()
}
