package com.luff.colophon.hosts

import com.luff.colophon.AccountEngine
import com.luff.colophon.session.ColophonSession
import com.luff.colophon.session.HomeTransport
import com.luff.colophon.session.SessionError

/**
 * What the 0.6 hosts need from the account: the member engine, the ticket call, an exchange pass, and the member key
 * for one raw signature. [accountOf] provides it from a [ColophonSession]; anything else may implement it.
 */
interface HostAccount {
    /** The account (64 hex). */
    val account: String
    /** This device's member ID. */
    val member: String
    /**
     * The member engine as it is now. Stream and endpoint calls take it; it is read again for every call, so a locked
     * or reopened engine is seen at once (a locked one throws `Locked`; a reopened one is another engine to an endpoint).
     * Called from a host's serial context: it must not suspend or wait on that context.
     */
    fun engine(): AccountEngine
    /** The `colophon.home.stream` call for `home`, signed and judged by the core, as the envelope's bytes. */
    suspend fun streamCall(home: String): ByteArray
    /** One ordinary exchange pass with the homes (the stream's `Wake`). */
    suspend fun exchange()
    /** A raw P-256 signature (`r || s`) by this member's key over `body` (a session delegation, sessions §S2). */
    suspend fun signRaw(body: ByteArray): ByteArray
}

/**
 * The host account of a restored [ColophonSession]. The session keeps owning the engine, its lock and its exchange;
 * this only reaches them. [HostAccount.exchange] is the session's own `syncNow`, so passes never overlap its poll loop.
 */
fun accountOf(session: ColophonSession): HostAccount {
    val account = session.libraryId ?: throw SessionError.NotReady()
    val member = session.memberId ?: throw SessionError.NotReady()
    val worker = session.worker
    return object : HostAccount {
        override val account = account
        override val member = member
        override fun engine(): AccountEngine = worker.requireEngine().current()
        override suspend fun streamCall(home: String): ByteArray = worker.streamCall(home)
        override suspend fun exchange() { session.syncNow() }
        override suspend fun signRaw(body: ByteArray): ByteArray = worker.configuration.keys.sign(body)
    }
}

/** The transport `session` was configured with for `home` (its ticket requests go there), if any. */
suspend fun transportOf(session: ColophonSession, home: String): HomeTransport? = session.worker.transportOf(home)
