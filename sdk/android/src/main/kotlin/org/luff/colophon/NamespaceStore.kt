package org.luff.colophon

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.util.UUID
import java.util.concurrent.CancellationException

/**
 * A bounded set of typed query slices. Rendering reads [cached], never decodes or folds.
 * Await [load] for cold completion; warming is independently observable.
 */
class NamespaceStore<Query, Result>(
    private val session: ColophonSession,
    val namespace: String,
    private val maximumQueries: Int = 64,
    private val evaluate: (Query, ByteArray) -> Result,
) {
    enum class State { Idle, Warming, Ready, Unavailable }

    private val _state = MutableStateFlow(State.Idle)
    val state: StateFlow<State> = _state.asStateFlow()
    private val _revision = MutableStateFlow(0uL)
    val revision: StateFlow<ULong> = _revision.asStateFlow()
    private val results = linkedMapOf<Query, Result>()
    private var registration: UUID? = session.registerCache { changed, lost ->
        if (!lost && namespace !in changed) return@registerCache
        synchronized(results) { results.clear() }
        _revision.value = session.namespaceRevisions.value[namespace] ?: 0u
        _state.value = if (lost) State.Unavailable else State.Idle
    }

    fun cached(query: Query): Result? = synchronized(results) { results[query] }

    suspend fun load(query: Query): Result {
        session.restore()
        synchronized(results) { results[query] }?.let { return it }
        val lease = session.observedRevision.context
        val observed = session.namespaceRevisions.value[namespace] ?: 0u
        val data = session.projection(namespace)
        _state.value = State.Warming
        return try {
            val result = withContext(Dispatchers.Default) { evaluate(query, data) }
            if (session.observedRevision.context != lease || !session.hasUsableContent ||
                (session.namespaceRevisions.value[namespace] ?: 0u) != observed
            ) {
                throw SessionException.StaleRevision
            }
            synchronized(results) {
                if (results.size >= maximumQueries.coerceAtLeast(1)) results.clear()
                results[query] = result
            }
            _revision.value = observed
            _state.value = State.Ready
            result
        } catch (error: Exception) {
            if (error is CancellationException) throw error
            _state.value = State.Unavailable
            throw error
        }
    }

    fun close() {
        registration?.let { session.unregisterCache(it) }
        registration = null
        synchronized(results) { results.clear() }
        _state.value = State.Unavailable
    }

    companion object {
        fun savedLinks(session: ColophonSession): NamespaceStore<SavedLinksQuery, List<SavedLink>> =
            NamespaceStore(session, "reading.saved") { query, bytes ->
                decodeSavedLinks(bytes, query.limit)
            }
    }
}

data class SavedLink(
    val id: String,
    val url: String,
    val title: String?,
    val deleted: Boolean? = null,
)

data class SavedLinksQuery(val limit: Int = 100) {
    init {
        require(limit in 0..1000)
    }
}

internal fun decodeSavedLinks(bytes: ByteArray, limit: Int): List<SavedLink> {
    val root = JsonParser(bytes.decodeToString()).parseValue() as? Json.Obj
        ?: throw SessionException.InvalidCommand
    val items = mutableListOf<SavedLink>()
    for (entry in root.array("items")) {
        if (items.size >= limit) break
        val obj = entry as? Json.Obj ?: continue
        val deleted = obj.bool("deleted")
        if (deleted == true) continue
        val id = obj.string("id") ?: continue
        val url = obj.string("url") ?: continue
        items.add(SavedLink(id = id, url = url, title = obj.string("title"), deleted = deleted))
    }
    return items
}
