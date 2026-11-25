package com.luff.colophon.hosts

/**
 * Where a cell's persisted claim lives, fenced so that no save can overwrite a newer one, whichever client makes it
 * (docs/hosts-06.md §3 and §3a).
 *
 * Every save carries a fence `{generation, seq}` (non-negative integers up to 2^53 − 1, compared in that order) and the
 * fence its caller last saw held. The store applies it as one linearizable compare-and-set across every client of the
 * same underlying storage: it writes only if the fence it holds is exactly the expected one and the new fence is
 * greater. A host instance takes its generation, when it opens and when it rebuilds its endpoint, by such a save (the
 * claim it holds under `{generation + 1, 0}`), and numbers its later saves within that generation. Two instances that
 * read the same held fence cannot both reserve the next generation. The held fence therefore never goes back and
 * changes only by a save made from exactly the previous one, so a save from an older instance or attempt that settles
 * late finds a fence it did not expect and changes nothing.
 *
 * A store that reads, compares and writes in separate steps is incorrect: two clients can both read fence F, both pass
 * the comparison, and both write, so two hosts would believe they own the cell.
 */
data class Fence(val generation: Long, val seq: Long) : Comparable<Fence> {
    init { require(isValid(generation) && isValid(seq)) { "a fence is two non-negative integers up to 2^53 - 1" } }
    override fun compareTo(other: Fence): Int =
        if (generation != other.generation) generation.compareTo(other.generation) else seq.compareTo(other.seq)
    override fun toString() = "Fence($generation, $seq)"
    companion object {
        /** The largest value either half may take (the safe-integer bound every host shares). */
        const val MAX: Long = (1L shl 53) - 1
        fun isValid(v: Long) = v in 0..MAX
    }
}

/** A claim (the `Persist` effect's `persisted_json`, or none yet) with the fence it was saved under. */
data class StoredClaim(val claim: String?, val fence: Fence)

/** What a compare-and-set save did. */
enum class SaveResult { STORED, STALE }

/**
 * The store contract. [load] returns what is held. [save] is a linearizable compare-and-set across every client of the
 * same storage: if the held fence equals `expected` (null: nothing is held) and `record.fence` is greater, the record
 * is written durably and it returns [SaveResult.STORED]; otherwise nothing is written and it returns
 * [SaveResult.STALE]. It throws when the write failed (and then it may or may not have been written: the host reads
 * again). The calls suspend and must not block their caller's thread (a store doing blocking I/O moves it to an I/O
 * dispatcher itself). A store must also keep the three properties of docs/hosts-06.md §3a: no reader sees a commit
 * before it is irrevocable; success only once the commit is durable; anything unrecognised fails closed.
 */
interface ClaimStore {
    suspend fun load(): StoredClaim?
    /** The held fence alone, read cheaply (a host asks every beat). */
    suspend fun fence(): Fence?
    suspend fun save(record: StoredClaim, expected: Fence?): SaveResult
}

/** The compare-and-set every store applies: the record to write, or null when the save is stale. */
fun compareAndSet(held: StoredClaim?, record: StoredClaim, expected: Fence?): StoredClaim? {
    if (held?.fence != expected) return null
    if (held != null && record.fence <= held.fence) return null
    return record
}

/**
 * A claim store in memory: every client that shares this object shares the record, and [save] compares and writes in
 * one step under the object's lock (tests, previews, a JVM process that keeps no claim across restarts).
 */
class MemoryClaimStore(initial: StoredClaim? = null) : ClaimStore {
    private val lock = Any()
    private var record: StoredClaim? = initial
    override suspend fun load(): StoredClaim? = synchronized(lock) { record }
    override suspend fun fence(): Fence? = synchronized(lock) { record?.fence }
    override suspend fun save(record: StoredClaim, expected: Fence?): SaveResult = synchronized(lock) {
        val next = compareAndSet(this.record, record, expected) ?: return SaveResult.STALE
        this.record = next
        SaveResult.STORED
    }
}
