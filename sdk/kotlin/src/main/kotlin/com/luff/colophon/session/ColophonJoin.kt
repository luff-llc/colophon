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
import com.luff.colophon.accountVerifyAtHead
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
