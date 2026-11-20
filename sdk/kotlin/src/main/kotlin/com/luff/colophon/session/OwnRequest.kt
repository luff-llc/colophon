package com.luff.colophon.session

import com.luff.colophon.AccountRequest
import com.luff.colophon.RequestSpec
import com.luff.colophon.Signature
import com.luff.colophon.accountFormatDate

/**
 * This device's own membership request (spec §9.1), one code path the session and anything that asks for it before the session opens share: the terms are
 * the configuration's (namespaces, access, services), the label and kind its member's, `created` a second before
 * `nowMs`. It is stored once at `requests/<member ID>.json` and reused from there, so a session opened after a join
 * finds the very request the owner approved.
 */
internal object OwnRequest {
    fun path(memberId: String) = "requests/$memberId.json"

    suspend fun make(configuration: SessionConfiguration, keys: AsyncKeyProvider, account: String, nowMs: Long): ByteArray {
        val public = keys.publicKeys()
        val spec = RequestSpec(account, public.signing, public.agreement, configuration.memberLabel, configuration.memberKind,
            SessionWorker.terms(configuration.namespaces, configuration.access, null, null, configuration.services),
            accountFormatDate(nowMs - 1000), null, null, listOf())
        return AccountRequest.prepare(spec).use { request ->
            val signature = keys.sign(request.step().body)
            request.finish(Signature(signature, null, null)).raw
        }
    }

    /** The stored request of `memberId`, or a new one made and stored. */
    suspend fun ensure(configuration: SessionConfiguration, keys: AsyncKeyProvider, account: String, memberId: String, nowMs: Long): ByteArray {
        val medium = configuration.medium
        val path = path(memberId)
        try { return medium.read(path) } catch (_: StorageException) {}
        val bytes = make(configuration, keys, account, nowMs)
        medium.write(listOf(MediumWrite(path, bytes)))
        return bytes
    }

    /** The account a request envelope names (its body's `account`), or null when it does not parse. */
    fun account(raw: ByteArray): String? = try {
        val body = Json.obj(raw.toString(Charsets.UTF_8))?.string("body") ?: null
        body?.let { Json.obj(java.util.Base64.getDecoder().decode(it).toString(Charsets.UTF_8))?.string("account") }
    } catch (_: IllegalArgumentException) { null }
}
