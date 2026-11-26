package com.luff.colophon.hosts

import com.luff.colophon.HttpAnswer

/**
 * What a socket reports, from any thread (the stream host moves every report onto its serial context). Each is called
 * at most as the socket's life allows: [open] once, then messages, then exactly one of [refused] or [closed].
 */
interface SocketHandlers {
    /** The upgrade succeeded (HTTP 101). */
    fun open()
    /** One whole text message, exactly as received (fragments already joined). */
    fun message(text: String)
    /**
     * The home refused the upgrade with this HTTP answer. Only a client that can see the refused answer calls it; it
     * passes the status and headers, and the body when the client exposes it (else an empty body).
     */
    fun refused(answer: HttpAnswer)
    /** The socket ended: the close code, or null when the transport failed or the socket never opened. */
    fun closed(code: Int?)
}

/** An open (or opening) socket. Thread-safe: sends from several threads are carried whole, one after another. */
interface HostSocket {
    /**
     * Sends one text message. Throws when it cannot be sent now (the caller treats that as loss, and `done` is not
     * called). Otherwise `done` is called exactly once, from any thread: true when the message was handed to the
     * connection, false when it was not (the connection failed or closed first).
     */
    fun send(text: String, done: (Boolean) -> Unit)
    /**
     * Closes with `code` (an implementation may substitute 1000 for a code its client cannot send). Reports nothing
     * afterwards. Closing a socket that is still opening abandons the upgrade and drops the connection if it completes.
     */
    fun close(code: Int)
}

/**
 * Opens a WebSocket at `url` and reports to `handlers`. The URL carries the stream ticket, a bearer credential: an
 * implementation must never log it (the stream host logs only the core's redacted form). The factory may call
 * `handlers` before it returns; the host does not act on them until it owns the socket.
 */
fun interface SocketFactory {
    fun open(url: String, handlers: SocketHandlers): HostSocket
}
