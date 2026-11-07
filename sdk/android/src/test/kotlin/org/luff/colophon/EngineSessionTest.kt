package org.luff.colophon

import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import java.nio.file.Files

class EngineSessionTest {
    @Test fun checkpointSkipsHistoryAndAdmitsOnlySuffix() = runBlocking {
        val home = Files.createTempDirectory("colophon-engine-checkpoint").toFile()
        try {
            val keys = SoftwareKeys.ephemeral(); val store = MemoryRecordStore()
            val configuration = SessionConfiguration(memberLabel="Engine", namespaces=listOf("notes"), privateHome=home, store=store, keys=keys)
            val first = SessionWorker(configuration)
            var snapshot = first.create()
            snapshot = first.write(DomainCommand("notes","createNotebook","""{"id":"n","title":"Notebook"}""".toByteArray()), snapshot.revision).second
            first.saveCheckpoint()
            val reopened = SessionWorker(configuration)
            val restored = reopened.restore()
            assertEquals(SessionPhase.Ready,restored.phase)
            val work = restored.core!!.engine!!.work()
            assertEquals("VerifiedPrefix",work.openMode)
            assertEquals(0uL,work.signaturesVerified);assertEquals(0uL,work.payloadsDecrypted);assertEquals(0uL,work.appliedOperations)
            first.write(DomainCommand("notes","addNote","""{"id":"a","notebook":"n","text":"Suffix"}""".toByteArray()),snapshot.revision)
            val third = SessionWorker(configuration)
            val changed = third.restore().core!!.engine!!.work()
            assertEquals("VerifiedPrefix",changed.openMode);assertEquals(1uL,changed.signaturesVerified);assertEquals(1uL,changed.appliedOperations)
            assertTrue(third.core.query("notes","note","""{"id":"a"}""".toByteArray()).decodeToString().contains("Suffix"))
        } finally { home.deleteRecursively() }
    }
}
