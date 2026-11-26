package com.luff.colophon.session

import com.luff.colophon.AccountHistoryRead
import com.luff.colophon.ByteString
import com.luff.colophon.Header
import com.luff.colophon.HistoryReadSpec
import com.luff.colophon.HttpAnswer
import com.luff.colophon.HttpMethod
import com.luff.colophon.HttpRequest
import com.luff.colophon.KeyDescriptorView
import com.luff.colophon.Signature
import com.luff.colophon.accountCurrentWebauthnController
import com.luff.colophon.accountFormatDate
import com.luff.colophon.accountHistoryPage
import com.luff.colophon.accountHistoryPagePath
import com.luff.colophon.accountPasskeyPoints
import com.luff.colophon.accountVerifyAtHead
import com.luff.colophon.accountVerifyWithPasskey
import com.luff.colophon.PasskeyControllerView
import com.luff.colophon.ControllerRole
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** What [ColophonJoin.fetchHistory] found. */
sealed class JoinHistory {
    /**
     * Not yet admitted, or no longer admitted; the home's answer is the same for both by design. The home refused the
     * read with `403 refused:revoked` (the result spec 0.5 gives a key no current grant names, before an approval and
     * after a revocation alike), or the history it served names no member with this ID. A host shows that it is
     * waiting for approval and, at its own deadline, that the device was not approved or is no longer allowed.
     */
    object NotAdmitted : JoinHistory() { override fun toString() = "NotAdmitted" }
    /**
     * The accepted history: it verified from seq 1 as the account's, holds the given entry at its seq, ends at a fresh
     * head signed by a current home serving at the base, and grants this member from its exact request. Only
     * [ColophonJoin.fetchHistory] makes one, after every acceptance condition held: the constructor is private and its
     * factory hidden from Java.
     */
    class Admitted private constructor(files: Map<String, ByteArray>) : JoinHistory() {
        private val held: Map<String, ByteArray> = files.mapValues { it.value.copyOf() }
        /** The files to store (`authority/<seq, eight digits>.json`) before the session is opened (copies). */
        val files: Map<String, ByteArray> get() = held.mapValues { it.value.copyOf() }

        /**
         * The passkey of controller [keyId] in this accepted history, when it is a current WebAuthn controller; null for a
         * removed, provisional, suspended or raw controller, or one the keyring does not hold.
         */
        fun ownerDescriptor(keyId: String, nowMs: Long = System.currentTimeMillis()): OwnerPasskey? {
            val entries = held.filterKeys { it.startsWith("authority/") }.toSortedMap().values.map { ByteString(it.copyOf()) }
            return accountCurrentWebauthnController(entries, keyId, nowMs)?.let { OwnerPasskey.of(it) }
        }

        internal companion object {
            @JvmSynthetic internal fun accepted(files: Map<String, ByteArray>) = Admitted(files)
        }
    }
}

/**
 * A current WebAuthn controller's descriptor read from an accepted history ([JoinHistory.Admitted.ownerDescriptor] is the
 * only way to get one): [view] is its protocol form (`rp`, credential, origins), and [registrationDescriptor] the
 * registration parser's JSON a passkey provider restores from (Android: `PasskeyProvider.restore`).
 */
class OwnerPasskey private constructor(private val key: KeyDescriptorView) {
    /** The descriptor as the history names it. */
    val view: KeyDescriptorView get() = key.copy(signing = key.signing.copyOf(), credential = key.credential?.copyOf())

    /**
     * `form`, `signing`, `rp`, `credential`, and `origins` when present, keys sorted: the form a device that joined as a
     * passkey owner stores and restores at every launch (Android: `PasskeyProvider.restore`). Restore only a descriptor
     * this device stored after an accepted join, never data received from elsewhere; the authority verifier still checks
     * every signature the key makes.
     */
    fun registrationDescriptor(): ByteArray {
        val b64 = java.util.Base64.getEncoder()
        val fields = linkedMapOf<String, Any?>("credential" to b64.encodeToString(key.credential), "form" to "webauthn")
        if (key.origins.isNotEmpty()) fields["origins"] = key.origins
        fields["rp"] = key.rp
        fields["signing"] = b64.encodeToString(key.signing)
        return Json.write(fields).toByteArray()
    }

    internal companion object {
        /** Only for a view the core returned as a current WebAuthn controller. */
        @JvmSynthetic internal fun of(view: KeyDescriptorView): OwnerPasskey? =
            if (view.form == com.luff.colophon.SignForm.WEBAUTHN && view.rp != null && view.credential != null && view.signing.size == 65) OwnerPasskey(view) else null
    }
}

/**
 * One WebAuthn get, as a platform passkey API returns it: the credential's raw ID and the exact signed bytes (DER
 * signature, authenticator data, client data JSON).
 */
class PasskeyGet(val credential: ByteArray, val signature: ByteArray, val authenticatorData: ByteArray, val clientData: ByteArray) {
    override fun toString(): String = "PasskeyGet(redacted)"
}

/**
 * The passkeys of one relying party, for a device that may not know their public keys yet (Colophon 0.5.7): a joining
 * or recovering device that holds no history. Android: `CredentialManagerPasskeys` in the Android library.
 */
interface PasskeyAuthenticator {
    /** The relying-party ID the passkeys belong to. */
    val rp: String
    /**
     * A WebAuthn get over [challenge] (unpadded base64url), user verification required: for any passkey of [rp] (a
     * discoverable get) when [credential] is null, else only that credential.
     */
    suspend fun get(challenge: String, credential: ByteArray?): PasskeyGet
}

/**
 * A history read with a passkey before admission and accepted ([ColophonJoin.readHistoryWithPasskey] makes one only after
 * every acceptance condition held): it verified from seq 1 as the account's, holds the given entry, ends at a fresh head
 * signed by a current home serving at the base, and names the passkey that read it as a current WebAuthn controller.
 */
class PasskeyHistory private constructor(
    files: Map<String, ByteArray>,
    /** The passkey that read the history, as the history names it: restore it as the owner controller. */
    val signer: OwnerPasskey,
    /** The same controller's ID, label, roles and whether it holds a slot of its own. */
    val signerController: PasskeyControllerView,
    /** Every current WebAuthn controller at the tip, the signer included. */
    val controllers: List<PasskeyControllerView>,
) {
    private val held: Map<String, ByteArray> = files.mapValues { it.value.copyOf() }
    /** The files to store (`authority/<seq, eight digits>.json`) before a session is opened (copies). */
    val files: Map<String, ByteArray> get() = held.mapValues { it.value.copyOf() }

    internal companion object {
        @JvmSynthetic internal fun accepted(files: Map<String, ByteArray>, signer: OwnerPasskey, signerController: PasskeyControllerView,
                                            controllers: List<PasskeyControllerView>) = PasskeyHistory(files, signer, signerController, controllers)
    }
}

/** Why a join at an invite's head failed. Anything here is an error, never "not admitted". */
sealed class JoinError(message: String) : Exception(message) {
    /** The home refused the read for another reason than "not a member" ([status], and the `result` it gave, validated). */
    class Refused(val status: Int, val code: String?) : JoinError("the home refused the history read: $status ${code ?: ""}")
    /**
     * The fetched history was not accepted ([code] as the core gives it): another account or digest at the invite's
     * seq (`refused:fork`), a history shorter than the signed head (`refused:rollback`), this member revoked
     * (`refused:revoked`) or expired (`refused:expired`), a grant of another request (`refused:conflict`), a history
     * that does not reach the invite's head or a head that stayed behind (`unavailable`), or a page that is not one.
     */
    class Rejected(val code: String, val detail: String) : JoinError("the history was not accepted: $code $detail")
    /** The request stored at `requests/<member ID>.json` names another account (an earlier join on this medium). */
    class OtherRequest(val path: String) : JoinError("the request at $path is for another account")
}

/**
 * Joining an account at an invite's head (Colophon 0.5.2): a device that holds only the account ID, the home's base, the
 * invite's head `(seq, entry digest)` and its own member keys asks to join and, once approved, fetches and verifies the
 * account's history from the home.
 *
 * - [request] makes this device's signed membership request exactly as the session does and stores it at
 *   `requests/<member ID>.json` in the configuration's medium (or returns the one stored there), so a session opened
 *   later with the same configuration finds and reuses it. Show it as the request QR code.
 * - [fetchHistory] reads `GET {home}/authority` page by page, each with a `colophon.history.read` call signed by the
 *   member key whose `asOf` is the invite's head, and `GET {home}/head`. It accepts the history only when it verifies
 *   completely, is the account's, holds the invite's head at its seq, ends at the home's signed head and grants this
 *   member from exactly the stored request, still current. Write the files to the medium, then open the session.
 *
 * The transport is the configured home whose endpoint is [home] (same base), else HTTPS with no loopback.
 */
class ColophonJoin(
    val configuration: SessionConfiguration,
    val account: String,
    val home: String,
    val seq: Long,
    val head: String,
) {
    private val keys: AsyncKeyProvider = SessionKeys(configuration.keys)
    private val base = home.trimEnd('/')
    private val homeConfiguration: HomeConfiguration = configuration.homes.firstOrNull { it.endpoint.trimEnd('/') == base }
        ?: HomeConfiguration("$base/")
    private val now: Long get() = configuration.now()

    /** This device's member ID (the key ID of its member signing key). */
    suspend fun memberId(): String = KeyCustody.keyId(keys)

    /** The signed request, made as the session's own (stored once in the medium, then reused). */
    suspend fun request(): ByteArray = withContext(Dispatchers.IO) {
        val id = memberId()
        val raw = OwnRequest.ensure(configuration, keys, account, id, now)
        if (OwnRequest.account(raw) != account) throw JoinError.OtherRequest(OwnRequest.path(id))
        raw
    }

    /**
     * Fetch and verify the history. [JoinHistory.NotAdmitted] while this member is not (or no longer) admitted;
     * [JoinError] for any other refusal or a history that is not accepted; a transport failure is thrown as it came
     * ([HomeTransportException]). A home whose signed head moved while the history was read (`unavailable`: behind;
     * `refused:rollback`: beyond what was served) is read again, at most [ATTEMPTS] times in all; a home that keeps
     * serving less than it signed then fails with `refused:rollback`.
     */
    suspend fun fetchHistory(): JoinHistory = withContext(Dispatchers.IO) { fetch() }

    private suspend fun fetch(): JoinHistory {
        val request = request()
        val member = memberId()
        var attempt = 0
        while (true) {
            attempt++
            val entries = when (val read = readHistory()) {
                null -> return JoinHistory.NotAdmitted
                else -> read
            }
            val signedHead = get("/head", null)
            if (signedHead.status.toInt() != 200) throw refused(signedHead)
            val verdict = try {
                accountVerifyAtHead(account, seq.toULong(), head, member, request, base, signedHead.body, entries, now)
            } catch (e: com.luff.colophon.AccountException) {
                if ((e.code == "unavailable" || e.code == "refused:rollback") && attempt < ATTEMPTS) continue
                throw JoinError.Rejected(e.code, e.message ?: "")
            }
            if (!verdict.admitted) return JoinHistory.NotAdmitted
            return JoinHistory.Admitted.accepted(verdict.stores.associate { it.path to it.bytes })
        }
    }

    /** Every page of the history, or null when the home refuses the read as from a non-member. */
    private suspend fun readHistory(): List<ByteString>? {
        val signing = keys.publicKeys().signing
        val entries = ArrayList<ByteString>()
        var after = 0uL
        var pages = 0
        var bytes = 0L
        while (true) {
            if (++pages > MAX_PAGES) throw JoinError.Rejected("malformed", "the history has too many pages")
            val path = accountHistoryPagePath(after)
            val call = withEntropy(32) { id ->
                AccountHistoryRead.prepare(HistoryReadSpec(account, seq.toULong(), head, signing, base, path, id.copyOf(), accountFormatDate(now)))
            }.use { prepared -> prepared.finish(Signature(keys.sign(prepared.step().body), null, null)) }
            val answer = get(path, call.authorization)
            val status = answer.status.toInt()
            if (status == 403 && HomeRefusal.result(answer.body) == WAITING_CODE) return null
            if (status != 200) throw refused(answer)
            val page = try { accountHistoryPage(answer.body) } catch (e: com.luff.colophon.AccountException) {
                throw JoinError.Rejected(e.code, e.message ?: "")
            }
            if (page.more && page.entries.isEmpty()) throw JoinError.Rejected("malformed", "a history page made no progress")
            bytes = bounded(bytes, entries.size, page.entries, MAX_HISTORY_BYTES, MAX_ENTRIES)
            entries.addAll(page.entries)
            after += page.entries.size.toULong()
            if (!page.more) return entries
        }
    }

    /**
     * Read and verify the history with a passkey, before this device is a member (Colophon 0.5.7, spec 0.5 §12.3 and
     * §13.4): a home serves the history to a current controller holding `approve`, `control` or `recover`. Works for an
     * invite's head and, with `seq` 1 and the account ID as `head` ([recovery]), for a device that knows only the
     * account and its home.
     *
     * A discoverable get returns no public key, so the passkey is asked first over a challenge this device chose, and
     * its signing point is recovered from that assertion ([ownerKeyId], an invite's owner key ID, picks it at once;
     * without one, the first read's assertion settles which of the two candidate points it is). Each page is then read
     * with its own `colophon.history.read` call signed by that passkey (`asOf` the given entry), and the history is
     * accepted only when it verifies completely, is the account's, holds the given entry, ends at the home's fresh
     * signed head and names the passkey as a current WebAuthn controller. The person is asked once to identify the
     * passkey and once per page of 64 entries (once more without [ownerKeyId] half of the time).
     *
     * Nothing is stored. A home that refuses the passkey (`403 refused:revoked`: not a current controller of this
     * account) or a history that is not accepted throws [JoinError]; a passkey failure is thrown as the authenticator
     * gave it.
     */
    suspend fun readHistoryWithPasskey(passkey: PasskeyAuthenticator, ownerKeyId: String? = null): PasskeyHistory =
        withContext(Dispatchers.IO) { passkeyFetch(passkey, ownerKeyId) }

    /**
     * Approve this device's own request with a passkey, without another device (Colophon 0.5.7): [readHistoryWithPasskey],
     * then the accepted history is stored in the configuration's medium beside this device's request, [open] makes the
     * session that holds the passkey as its owner controller (restore it from [OwnerPasskey.registrationDescriptor];
     * close any other session open on this medium first), and that session approves its own request
     * ([ColophonSession.approveOwnRequest]: exactly the request this join stored, for this account; the passkey opens
     * its own slot and signs the grant) and syncs. Returns the session, ready, once the home holds the grant (this
     * member's own key reads the history there); otherwise [JoinError.Rejected] `unavailable`, with the grant stored on
     * this device for the session's next sync to publish.
     *
     * The passkey must hold `approve` or `control` and a slot of its own (a `recover`-only key proposes recovery with a
     * delay instead, which this does not do): otherwise [JoinError.Rejected] `refused:outOfScope` before anything is
     * stored or signed.
     */
    suspend fun approveOwnJoinWithPasskey(
        passkey: PasskeyAuthenticator,
        ownerKeyId: String? = null,
        open: suspend (OwnerPasskey) -> ColophonSession,
    ): ColophonSession {
        val request = request()
        val member = memberId()
        val history = readHistoryWithPasskey(passkey, ownerKeyId)
        val roles = history.signerController.roles
        if (ControllerRole.APPROVE !in roles && ControllerRole.CONTROL !in roles) {
            throw JoinError.Rejected("refused:outOfScope", "the passkey holds neither approve nor control")
        }
        if (!history.signerController.ownSlot) throw JoinError.Rejected("refused:outOfScope", "the passkey holds no slot of its own")
        withContext(Dispatchers.IO) { store(history.files, request, member) }
        val session = open(history.signer)
        val owner = KeyCustody.keyId(session.worker.configuration.ownerController)
        if (owner != history.signerController.id) throw JoinError.Rejected("refused:conflict", "the session's owner controller is not this passkey")
        if (KeyCustody.keyId(session.worker.configuration.keys) != member) throw JoinError.Rejected("refused:conflict", "the session's member key is not this device's")
        // The session must sign on exactly the history verified here: its medium holds every
        // verified entry, byte for byte, and no other authority entry.
        val opened = session.worker.configuration.medium
        val authority = opened.listing().map { it.path }.filter { it.startsWith("authority/") }.toSet()
        if (authority != history.files.keys.filter { it.startsWith("authority/") }.toSet() ||
            history.files.any { (path, bytes) -> !opened.read(path).contentEquals(bytes) }) {
            throw JoinError.Rejected("refused:conflict", "the session's store holds another history")
        }
        session.restore()
        if (session.libraryId != account) throw JoinError.Rejected("refused:conflict", "the session opened another account")
        session.approveOwnRequest(request)
        // Returned once the home holds the grant: this member's own key then reads the history there.
        repeat(ATTEMPTS) {
            session.syncNow()
            if (fetchHistory() is JoinHistory.Admitted) return session
        }
        throw JoinError.Rejected("unavailable", "the grant is stored on this device but the home does not hold it yet; the session publishes it at its next sync")
    }

    /** The files of an accepted history, stored where they are missing; one already stored must hold the same bytes. */
    private fun store(files: Map<String, ByteArray>, request: ByteArray, member: String) {
        val medium = configuration.medium
        val held = medium.listing().map { it.path }.toSet()
        val writes = ArrayList<MediumWrite>()
        for ((path, bytes) in files.toSortedMap()) {
            if (path in held) {
                if (!medium.read(path).contentEquals(bytes)) throw JoinError.Rejected("refused:fork", "$path holds another entry")
            } else writes.add(MediumWrite(path, bytes))
        }
        val requestPath = OwnRequest.path(member)
        if (requestPath !in held) writes.add(MediumWrite(requestPath, request))
        if (writes.isNotEmpty()) medium.write(writes)
    }

    private suspend fun passkeyFetch(passkey: PasskeyAuthenticator, ownerKeyId: String?): PasskeyHistory {
        // Identify: one get over a body this device chose, never sent anywhere.
        val body = ByteArray(32).also(java.security.SecureRandom()::nextBytes)
        val first = passkey.get(P256.base64url(java.security.MessageDigest.getInstance("SHA-256").digest(body)), null)
        val credential = first.credential.copyOf()
        var candidates = points(body, passkey.rp, first, ownerKeyId)
        var attempt = 0
        while (true) {
            attempt++
            val (point, entries) = passkeyPages(passkey, credential, candidates)
            candidates = listOf(point)
            val signedHead = get("/head", null)
            if (signedHead.status.toInt() != 200) throw refused(signedHead)
            val verdict = try {
                accountVerifyWithPasskey(account, seq.toULong(), head, point, base, signedHead.body, entries, now)
            } catch (e: com.luff.colophon.AccountException) {
                if ((e.code == "unavailable" || e.code == "refused:rollback") && attempt < ATTEMPTS) continue
                throw JoinError.Rejected(e.code, e.message ?: "")
            }
            val signer = OwnerPasskey.of(verdict.signer.key)
                ?: throw JoinError.Rejected("malformed", "the signer is not a passkey the history names")
            if (verdict.signer.key.rp != passkey.rp) throw JoinError.Rejected("badSignature", "the history names the passkey under another relying party")
            if (verdict.signer.key.credential?.contentEquals(credential) != true) {
                throw JoinError.Rejected("badSignature", "the passkey's credential is not the one the history names")
            }
            return PasskeyHistory.accepted(verdict.stores.associate { it.path to it.bytes }, signer, verdict.signer, verdict.controllers)
        }
    }

    /** The candidate points of a passkey assertion over `body` (exactly one with [keyId]). */
    private fun points(body: ByteArray, rp: String, get: PasskeyGet, keyId: String?): List<ByteArray> = try {
        accountPasskeyPoints(body, rp, get.authenticatorData, get.clientData, get.signature, keyId).map { it.bytes }
    } catch (e: com.luff.colophon.AccountException) {
        throw JoinError.Rejected(e.code, e.message ?: "")
    }

    /**
     * Every page of the history read with the passkey, and the passkey's point. With two candidates the first page's
     * assertion, recovered again over its own body, names the one true point; a call made with the other is signed
     * again with it (one more get), never sent.
     */
    private suspend fun passkeyPages(passkey: PasskeyAuthenticator, credential: ByteArray, candidates: List<ByteArray>): Pair<ByteArray, List<ByteString>> {
        var point = candidates.first()
        var known = candidates.size == 1
        val entries = ArrayList<ByteString>()
        var after = 0uL
        var pages = 0
        var bytes = 0L
        while (true) {
            if (++pages > MAX_PAGES) throw JoinError.Rejected("malformed", "the history has too many pages")
            val path = accountHistoryPagePath(after)
            var call: com.luff.colophon.HistoryReadCall? = null
            while (call == null) {
                val prepared = withEntropy(32) { id ->
                    AccountHistoryRead.preparePasskey(HistoryReadSpec(account, seq.toULong(), head, point, base, path, id.copyOf(), accountFormatDate(now)))
                }
                call = prepared.use { p ->
                    val step = p.step()
                    val challenge = step.challenge ?: throw JoinError.Rejected("malformed", "a passkey read has no challenge")
                    val signed = passkey.get(challenge, credential)
                    if (!signed.credential.contentEquals(credential)) throw JoinError.Rejected("badSignature", "another passkey answered")
                    if (!known) {
                        val again = points(step.body, passkey.rp, signed, null)
                        val truth = candidates.filter { c -> again.any { it.contentEquals(c) } }
                        if (truth.size != 1) throw JoinError.Rejected("badSignature", "the passkey's assertions name no one key")
                        known = true
                        if (!truth[0].contentEquals(point)) { point = truth[0]; return@use null }
                    }
                    try { p.finish(Signature(signed.signature, signed.authenticatorData, signed.clientData)) } catch (e: com.luff.colophon.AccountException) {
                        throw JoinError.Rejected(e.code, e.message ?: "")
                    }
                }
            }
            val answer = get(path, call.authorization)
            if (answer.status.toInt() != 200) throw refused(answer)
            val page = try { accountHistoryPage(answer.body) } catch (e: com.luff.colophon.AccountException) {
                throw JoinError.Rejected(e.code, e.message ?: "")
            }
            if (page.more && page.entries.isEmpty()) throw JoinError.Rejected("malformed", "a history page made no progress")
            bytes = bounded(bytes, entries.size, page.entries, MAX_HISTORY_BYTES, MAX_ENTRIES)
            entries.addAll(page.entries)
            after += page.entries.size.toULong()
            if (!page.more) return point to entries
        }
    }

    private suspend fun get(path: String, authorization: String?): HttpAnswer {
        val url = base + path
        if (!homeConfiguration.isAllowed) throw HomeTransportException.InsecureEndpoint(homeConfiguration.endpoint)
        val headers = authorization?.let { listOf(Header("Authorization", it)) } ?: listOf()
        val answer = homeConfiguration.transport.send(HttpRequest(0uL, "", HttpMethod.GET, url, headers, ByteArray(0)))
        val limit = HomeLimits.responseBytes(url)
        if (answer.body.size > limit) throw HomeTransportException.ResponseTooLarge(limit)
        return answer
    }

    private fun refused(answer: HttpAnswer) = JoinError.Refused(answer.status.toInt(), HomeRefusal.result(answer.body))

    companion object {
        /**
         * A recovery (Colophon 0.5.7): a device that knows only the account ID and its home's base reads the history at
         * the genesis, `(1, account)` (the account ID is the genesis body's digest, spec 0.5 §5.1), which every history
         * of the account holds. Use [readHistoryWithPasskey] and [approveOwnJoinWithPasskey] on it, or
         * [recoverWithPasskey].
         */
        fun recovery(configuration: SessionConfiguration, account: String, home: String): ColophonJoin =
            ColophonJoin(configuration, account, home, 1, account)

        /**
         * Recover an account onto this device with its passkey, from its home alone (Colophon 0.5.7): the history is read
         * and verified with the passkey ([readHistoryWithPasskey] at the genesis), stored, and this device's new member is
         * approved by the passkey and opened ([approveOwnJoinWithPasskey]). [open] makes the session with the passkey as
         * its owner controller.
         */
        suspend fun recoverWithPasskey(
            configuration: SessionConfiguration,
            account: String,
            home: String,
            passkey: PasskeyAuthenticator,
            ownerKeyId: String? = null,
            open: suspend (OwnerPasskey) -> ColophonSession,
        ): ColophonSession = recovery(configuration, account, home).approveOwnJoinWithPasskey(passkey, ownerKeyId, open)

        /**
         * The joining device's bounds, checked while paging (the core checks them again): the bytes so far plus this
         * page's, which must stay within [maxBytes], and the entries so far plus this page's within [maxEntries]. Pure;
         * paging passes the fixed [MAX_HISTORY_BYTES] and [MAX_ENTRIES]. Returns the new byte total.
         */
        @JvmSynthetic internal fun bounded(bytes: Long, count: Int, page: List<ByteString>, maxBytes: Long, maxEntries: Int): Long {
            val total = bytes + page.sumOf { it.bytes.size.toLong() }
            if (total > maxBytes || count + page.size > maxEntries) {
                throw JoinError.Rejected("unavailable", "the history passes what a joining device holds (2^18 entries, 256 MiB)")
            }
            return total
        }
        /** The result a home gives a call from a key no grant names (spec 0.5 keeps it; `refused:notGranted` is reserved). */
        const val WAITING_CODE = "refused:revoked"
        private const val MAX_PAGES = 4096
        /** Reads of the history and head in one [fetchHistory] when the signed head moved meanwhile. */
        const val ATTEMPTS = 3
        /** Spec §2.4's portability floor for envelopes: the most entry bytes a joining device holds. */
        const val MAX_HISTORY_BYTES = 256L * 1024 * 1024
        /** 4,096 pages of 64 entries. */
        const val MAX_ENTRIES = 1 shl 18

    }
}
