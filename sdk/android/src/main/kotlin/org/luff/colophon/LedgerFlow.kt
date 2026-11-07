package org.luff.colophon

import com.luff.colophon.LedgerEntry
import kotlinx.coroutines.InternalCoroutinesApi
import kotlinx.coroutines.flow.FlowCollector
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** Identity of the snapshot drives publication; comparing lazy List values would load history. */
internal class LedgerFlow : StateFlow<List<LedgerEntry>> {
    private class Snapshot(val entries: List<LedgerEntry>)
    private val state = MutableStateFlow(Snapshot(emptyList()))
    override var value: List<LedgerEntry>
        get() = state.value.entries
        set(value) { if (state.value.entries !== value) state.value = Snapshot(value) }
    override val replayCache: List<List<LedgerEntry>> get() = listOf(value)
    @OptIn(InternalCoroutinesApi::class)
    override suspend fun collect(collector: FlowCollector<List<LedgerEntry>>): Nothing =
        state.collect { collector.emit(it.entries) }
}
