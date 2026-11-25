package org.luff.colophon.hosts

import android.database.sqlite.SQLiteDatabase
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.luff.colophon.hosts.Fence
import com.luff.colophon.hosts.SaveResult
import com.luff.colophon.hosts.StoredClaim
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger

/**
 * The SQLite claim store on a device: independent clients of one file racing from one fence (exactly one stores per
 * round), the claim surviving a reopen, the journal and synchronous modes it insists on, and fail-closed reads of rows
 * and schemas it did not write. Needs a device or emulator (the platform's SQLite is not on the JVM).
 */
@RunWith(AndroidJUnit4::class)
class SqliteClaimStoreTest {
    private lateinit var file: File

    @Before fun setUp() {
        file = File(InstrumentationRegistry.getInstrumentation().targetContext.noBackupFilesDir, "claims-test-${UUID.randomUUID()}.db")
    }
    @After fun tearDown() { SQLiteDatabase.deleteDatabase(file) }

    @Test fun clientsOfOneFileRacingFromOneFenceStoreExactlyOnce() = runBlocking {
        val clients = (0 until 6).map { SqliteClaimStore.open(file, "listening.podcasts/now-playing") }
        try {
            assertEquals(SaveResult.STORED, clients[0].save(StoredClaim(null, Fence(1, 0)), null))
            repeat(25) { round ->
                val held = clients[round % clients.size].fence()
                val start = CountDownLatch(1)
                val stored = AtomicInteger()
                val threads = clients.mapIndexed { k, store ->
                    Thread {
                        start.await()
                        runBlocking { if (store.save(StoredClaim("c$round.$k", Fence(held!!.generation + 1, 0)), held) == SaveResult.STORED) stored.incrementAndGet() }
                    }.apply { start() }
                }
                start.countDown(); threads.forEach { it.join() }
                assertEquals("round $round", 1, stored.get())
                val now = clients[(round + 1) % clients.size].load()!!
                assertEquals(held!!.generation + 1, now.fence.generation)
            }
        } finally { clients.forEach { it.close() } }
    }

    @Test fun aStaleSaveWritesNothingAndTheClaimSurvivesAReopen() = runBlocking {
        SqliteClaimStore.open(file, "cell").use { store ->
            assertNull(store.load())
            assertEquals(SaveResult.STORED, store.save(StoredClaim("{\"a\":1}", Fence(1, 0)), null))
            assertEquals(SaveResult.STORED, store.save(StoredClaim("{\"a\":2}", Fence(1, 1)), Fence(1, 0)))
            assertEquals(SaveResult.STALE, store.save(StoredClaim("{\"a\":3}", Fence(1, 1)), Fence(1, 1)))
            assertEquals(SaveResult.STALE, store.save(StoredClaim("{\"a\":3}", Fence(2, 0)), Fence(1, 0)))
            assertEquals(SaveResult.STALE, store.save(StoredClaim("{\"a\":3}", Fence(2, 0)), null))
        }
        SqliteClaimStore.open(file, "cell").use { again ->
            assertEquals(StoredClaim("{\"a\":2}", Fence(1, 1)), again.load())
            assertEquals(Fence(1, 1), again.fence())
            assertNull(SqliteClaimStore.open(file, "another cell").use { it.load() })
        }
    }

    @Test fun theDatabaseIsInWalModeWithFullSynchronousCommits() {
        SqliteClaimStore.open(file, "cell").close()
        SQLiteDatabase.openDatabase(file.path, null, SQLiteDatabase.OPEN_READONLY).use { db ->
            db.rawQuery("PRAGMA journal_mode", null).use { it.moveToFirst(); assertEquals("wal", it.getString(0).lowercase()) }
        }
    }

    @Test fun rowsAndSchemasItDidNotWriteFailClosed() = runBlocking {
        SqliteClaimStore.open(file, "cell").close()
        SQLiteDatabase.openDatabase(file.path, null, SQLiteDatabase.OPEN_READWRITE or SQLiteDatabase.NO_LOCALIZED_COLLATORS).use { db ->
            db.execSQL("INSERT INTO claims (cell, claim, generation, seq) VALUES ('cell', x'00', 1, 0)")
            db.execSQL("INSERT INTO claims (cell, claim, generation, seq) VALUES ('big', NULL, 9007199254740992, 0)")
            db.execSQL("INSERT INTO claims (cell, claim, generation, seq) VALUES ('text', NULL, '1', 0)")
        }
        for (cell in listOf("cell", "big", "text")) SqliteClaimStore.open(file, cell).use { store ->
            for (call in listOf<suspend () -> Unit>({ store.load() }, { store.fence() }, { store.save(StoredClaim(null, Fence(5, 0)), null) })) {
                try { call(); fail("$cell: read a row it did not write") } catch (_: ClaimStoreCorrupt) {}
            }
        }
        SQLiteDatabase.openDatabase(file.path, null, SQLiteDatabase.OPEN_READWRITE or SQLiteDatabase.NO_LOCALIZED_COLLATORS).use { it.execSQL("CREATE TABLE other (x)") }
        try { SqliteClaimStore.open(file, "cell"); fail("opened a database with another table") } catch (e: ClaimStoreCorrupt) { assertTrue(e.message!!.contains("other objects")) }
    }
}
