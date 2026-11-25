package org.luff.colophon.hosts

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import com.luff.colophon.hosts.ClaimStore
import com.luff.colophon.hosts.Fence
import com.luff.colophon.hosts.SaveResult
import com.luff.colophon.hosts.StoredClaim
import com.luff.colophon.hosts.compareAndSet
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException

/** The claim database holds something this store did not write, or cannot read: nothing is trusted from it. */
class ClaimStoreCorrupt(message: String) : IOException(message)

/**
 * A durable [ClaimStore] for Android on the platform's SQLite (`android.database.sqlite`, part of the OS; no
 * dependency). One database file holds one table, one row per cell; every client of the same file (another store
 * object, another thread, another process of the app) shares it.
 *
 * - **The compare-and-set is one transaction.** [save] runs `BEGIN IMMEDIATE` (`beginTransactionNonExclusive`), which
 *   takes the database's write lock before anything is read, then reads the held fence, applies [compareAndSet] and
 *   writes the row, then commits. Two clients cannot both read fence F and both write: the second waits for the
 *   first's lock and then reads the first's commit. A stale save rolls back and writes nothing.
 * - **Journal and synchronous mode, chosen deliberately.** The file is opened in WAL mode with `synchronous=FULL`, and
 *   both are read back on open (anything else fails). In WAL mode with FULL, a commit syncs the log before the
 *   wal-index is updated, so another connection can see a commit only once it is durable (§3a property 1), and
 *   [save] returns [SaveResult.STORED] only after the commit returned (property 2). Android's default for databases
 *   that choose nothing is WAL with `synchronous=NORMAL`, under which a commit seen by a reader can be lost at power
 *   failure: that is why the mode is set and checked rather than left to the platform.
 * - **Fails closed (§3a property 3).** The schema must be exactly this store's (one table, its primary-key index,
 *   nothing else), and a row must hold a text or null claim and two integers in the fence's range; anything else is
 *   [ClaimStoreCorrupt] from [load], [fence] and [save], never skipped.
 * - The I/O runs on `Dispatchers.IO`, never on the caller's (the host's serial) thread.
 *
 * Keep the file in app-private storage outside backups (`noBackupFilesDir`, the default of [open] with a context): a
 * restored backup would bring back an old fence.
 */
class SqliteClaimStore private constructor(private val db: SQLiteDatabase, private val cell: String) : ClaimStore, AutoCloseable {
    companion object {
        const val TABLE = "CREATE TABLE claims (cell TEXT PRIMARY KEY NOT NULL, claim TEXT, generation INTEGER NOT NULL, seq INTEGER NOT NULL)"

        /** The store for `cell` (any stable name, such as `"<namespace>/<cell>"`) in the app's `noBackupFilesDir`. */
        fun open(context: Context, cell: String, fileName: String = "colophon-claims.db"): SqliteClaimStore =
            open(File(context.noBackupFilesDir, fileName), cell)

        /** The store for `cell` in the database `file`, made if missing. Throws when the file is not this store's. */
        fun open(file: File, cell: String): SqliteClaimStore {
            val params = SQLiteDatabase.OpenParams.Builder()
                // No `android_metadata` table: the file holds this store's table and nothing else.
                .addOpenFlags(SQLiteDatabase.CREATE_IF_NECESSARY or SQLiteDatabase.NO_LOCALIZED_COLLATORS)
                .setJournalMode("WAL")
                .setSynchronousMode("FULL")
                .build()
            val db = SQLiteDatabase.openDatabase(file, params)
            try {
                check(db, "PRAGMA journal_mode", "wal")
                check(db, "PRAGMA synchronous", "2")
                db.beginTransaction()
                try {
                    if (objects(db).isEmpty()) db.execSQL(TABLE)
                    db.setTransactionSuccessful()
                } finally { db.endTransaction() }
                val found = objects(db)
                val expected = listOf(Triple("index", "sqlite_autoindex_claims_1", null), Triple("table", "claims", TABLE))
                if (found != expected) throw ClaimStoreCorrupt("the claim database holds other objects than its own table")
            } catch (e: Exception) {
                db.close()
                throw e
            }
            return SqliteClaimStore(db, cell)
        }

        private fun check(db: SQLiteDatabase, pragma: String, want: String) {
            val got = db.rawQuery(pragma, null).use { c -> if (c.moveToFirst()) c.getString(0) else null }
            if (got?.lowercase() != want) throw ClaimStoreCorrupt("$pragma is $got, not $want")
        }
        private fun objects(db: SQLiteDatabase): List<Triple<String, String, String?>> =
            db.rawQuery("SELECT type, name, sql FROM sqlite_master ORDER BY type, name", null).use { c ->
                val out = ArrayList<Triple<String, String, String?>>()
                while (c.moveToNext()) out.add(Triple(c.getString(0), c.getString(1), if (c.isNull(2)) null else c.getString(2)))
                out
            }
    }

    /** The row for this cell, validated; null when there is none. */
    private fun read(): StoredClaim? =
        db.rawQuery("SELECT claim, generation, seq, typeof(claim), typeof(generation), typeof(seq) FROM claims WHERE cell = ?", arrayOf(cell)).use { c ->
            if (!c.moveToFirst()) return null
            val claimType = c.getString(3); val gType = c.getString(4); val sType = c.getString(5)
            if (claimType != "text" && claimType != "null") throw ClaimStoreCorrupt("a stored claim is $claimType")
            if (gType != "integer" || sType != "integer") throw ClaimStoreCorrupt("a stored fence is $gType, $sType")
            val generation = c.getLong(1); val seq = c.getLong(2)
            if (!Fence.isValid(generation) || !Fence.isValid(seq)) throw ClaimStoreCorrupt("a stored fence is out of range")
            if (c.moveToNext()) throw ClaimStoreCorrupt("two rows for one cell")
            StoredClaim(if (claimType == "null") null else c.getString(0), Fence(generation, seq))
        }

    override suspend fun load(): StoredClaim? = withContext(Dispatchers.IO) { read() }
    override suspend fun fence(): Fence? = withContext(Dispatchers.IO) { read()?.fence }

    override suspend fun save(record: StoredClaim, expected: Fence?): SaveResult = withContext(Dispatchers.IO) {
        // BEGIN IMMEDIATE: the write lock is held from before the read until the commit.
        db.beginTransactionNonExclusive()
        try {
            val next = compareAndSet(read(), record, expected) ?: return@withContext SaveResult.STALE
            db.execSQL("INSERT OR REPLACE INTO claims (cell, claim, generation, seq) VALUES (?, ?, ?, ?)",
                arrayOf<Any?>(cell, next.claim, next.fence.generation, next.fence.seq))
            db.setTransactionSuccessful()
        } finally {
            // Commits (or, for a stale save or a failure, rolls back). A failed commit throws: the save failed.
            db.endTransaction()
        }
        SaveResult.STORED
    }

    /** The journal and synchronous modes of this store's own connection (`synchronous` is per connection). */
    internal fun modes(): Pair<String?, String?> {
        fun read(pragma: String) = db.rawQuery(pragma, null).use { c -> if (c.moveToFirst()) c.getString(0) else null }
        return read("PRAGMA journal_mode")?.lowercase() to read("PRAGMA synchronous")
    }

    override fun close() = db.close()
}
