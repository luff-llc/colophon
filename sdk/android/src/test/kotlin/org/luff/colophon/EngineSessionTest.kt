package org.luff.colophon

import com.luff.colophon.MemberKind
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import java.nio.file.Files

class EngineSessionTest {
    @Test fun thirdReviewWaitingMemberWithLiveStateCanCheckpoint() = runBlocking {
        val home = Files.createTempDirectory("colophon-third-waiting").toFile()
        try {
            val store = MemoryRecordStore()
            val owner = SessionWorker(SessionConfiguration(memberLabel="Owner", namespaces=listOf("listening.podcasts"), privateHome=java.io.File(home,"owner"), store=store, keys=SoftwareKeys.ephemeral(), ownerController = com.luff.colophon.RawControllerProvider(SoftwareKeys.ephemeral())))
            val created = owner.create()
            owner.write(DomainCommand("listening.podcasts", "position", """{"id":"ep","seconds":10}""".toByteArray()), created.revision)
            val reader = SessionWorker(SessionConfiguration(memberLabel="Reader", memberKind=MemberKind.AGENT, namespaces=listOf("listening.podcasts"), privateHome=java.io.File(home,"reader"), store=store, keys=SoftwareKeys.ephemeral(), ownerController = com.luff.colophon.RawControllerProvider(SoftwareKeys.ephemeral())))
            assertTrue(reader.restore().phase is SessionPhase.WaitingForApproval)
            reader.saveCheckpoint()
            assertTrue(reader.refresh().phase is SessionPhase.WaitingForApproval)
        } finally { home.deleteRecursively() }
    }
    @Test fun thirdReviewAuthorityRefreshVerifiesHistoryOnce() = runBlocking {
        val home = Files.createTempDirectory("colophon-third-authority").toFile()
        try {
            val store = MemoryRecordStore(); val keys = SoftwareKeys.ephemeral()
            fun configuration(name: String, identity: SoftwareKeys, kind: MemberKind = MemberKind.APP) = SessionConfiguration(memberLabel=name, memberKind=kind, namespaces=listOf("notes"), privateHome=java.io.File(home,name), store=store, keys=identity, ownerController = com.luff.colophon.RawControllerProvider(SoftwareKeys.ephemeral()))
            val owner = SessionWorker(configuration("owner",keys))
            val created = owner.create()
            owner.write(DomainCommand("notes","createNotebook","""{"id":"n","title":"N"}""".toByteArray()), created.revision)
            val joining = SessionWorker(configuration("joining",SoftwareKeys.ephemeral(),MemberKind.AGENT))
            joining.restore()
            val request = owner.refresh().core!!.requests.first()
            owner.approve(request.record,null)
            val reader = SessionWorker(configuration("reader",keys))
            val engine = reader.restore().core!!.engine!!
            val before = engine.work()
            owner.revoke(request.id)
            assertEquals(SessionPhase.Ready,reader.refresh().phase)
            assertEquals(1uL,engine.work().signaturesVerified-before.signaturesVerified)
            assertEquals(1uL,engine.work().appliedOperations-before.appliedOperations)
            reader.saveCheckpoint()
        } finally { home.deleteRecursively() }
    }
    @Test fun checkpointSkipsHistoryAndAdmitsOnlySuffix() = runBlocking {
        val home = Files.createTempDirectory("colophon-engine-checkpoint").toFile()
        try {
            val keys = SoftwareKeys.ephemeral(); val store = MemoryRecordStore()
            val configuration = SessionConfiguration(memberLabel="Engine", namespaces=listOf("notes"), privateHome=home, store=store, keys=keys, ownerController = com.luff.colophon.RawControllerProvider(SoftwareKeys.ephemeral()))
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
