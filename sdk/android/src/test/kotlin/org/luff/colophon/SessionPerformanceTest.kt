package org.luff.colophon

import com.luff.colophon.PlatformKeys
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.junit.Assume.assumeTrue
import org.junit.Assert.*
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.math.BigInteger
import java.security.*
import java.security.spec.*

class SessionPerformanceTest {
    @Test fun nativeSessionTimings() = runBlocking {
        val mode = System.getenv("COLOPHON_SESSION_BENCH")
        assumeTrue(mode != null)
        val root = File(System.getenv("COLOPHON_SESSION_FIXTURE") ?: "../../target/engine-sessions").canonicalFile
        val parameters = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
        fun pair(name: String): KeyPair {
            val factory = KeyFactory.getInstance("EC")
            val secret = File(root, "$name-private.bin").readBytes()
            val public = File(root, "$name-public.bin").readBytes()
            return KeyPair(factory.generatePublic(ECPublicKeySpec(ECPoint(BigInteger(1, public.copyOfRange(1,33)), BigInteger(1,public.copyOfRange(33,65))), parameters)), factory.generatePrivate(ECPrivateKeySpec(BigInteger(1,secret),parameters)))
        }
        val keys = PlatformKeys(pair("signing"), pair("agreement"))
        val records = load(File(root, "100k.records")); val suffix = load(File(root, "suffix.records")); val taupe = load(File(root, "taupe.records"))
        val home = java.nio.file.Files.createTempDirectory("colophon-session-bench").toFile()
        val sessions = mutableListOf<ColophonSession>()
        val cores = mutableMapOf<ColophonSession, SessionCore>()
        fun session(store: MemoryRecordStore, home: File, taupeOnly: Boolean = false): ColophonSession {
            val config = SessionConfiguration(memberLabel="Bench", namespaces=if (taupeOnly) listOf("listening.podcasts") else listOf("notes","listening.podcasts","reading.saved","reading.books"), privateHome=home, keys=keys, store=store)
            val core = if (mode == "legacy") CompatibilitySessionCore() else BindingSessionCore()
            return ColophonSession(config, core, store, ColophonSession.sessionDispatcher).also { sessions.add(it); cores[it] = core }
        }
        try {
            val store = MemoryRecordStore(records)
            val first = session(store,home); first.restore(); assertEquals(SessionPhase.Ready,first.phase.value)
            if (mode != "legacy") first.flushCheckpoint()
            first.close()
            val suffixHome=File(home.parentFile,home.name+"-suffix");home.copyRecursively(suffixHome)
            val reopened = session(store,home)
            var start = System.nanoTime(); reopened.restore(); report("checkpoint_open",start); assertEquals(SessionPhase.Ready,reopened.phase.value)
            if (mode != "legacy") {
                val work = cores.getValue(reopened).snapshot(emptyList(), emptyMap()).engine!!.work()
                println("SESSION_WORK checkpoint $work")
                assertEquals(0uL, work.signaturesVerified); assertEquals(0uL, work.payloadsDecrypted); assertEquals(0uL, work.appliedOperations)
            }
            start=System.nanoTime(); reopened.perform(DomainCommand("listening.podcasts","position","""{"id":"ep1","seconds":300000}""".toByteArray()),reopened.observedRevision); report("passive_write",start)
            start=System.nanoTime(); reopened.perform(DomainCommand("notes","addNote","""{"id":"session-bench-note","notebook":"journal","text":"Measured note"}""".toByteArray()),reopened.observedRevision); report("notes_write",start)
            reopened.close()
            val added=session(MemoryRecordStore(records+suffix),suffixHome)
            start=System.nanoTime();added.restore();report("checkpoint_plus_1_percent",start);assertEquals(SessionPhase.Ready,added.phase.value)
            if (mode != "legacy") {
                val work = cores.getValue(added).snapshot(emptyList(), emptyMap()).engine!!.work()
                println("SESSION_WORK suffix $work")
                assertEquals(1000uL, work.signaturesVerified); assertEquals(1000uL, work.payloadsDecrypted); assertEquals(1000uL, work.appliedOperations)
            }
            added.close()
            val small=session(MemoryRecordStore(taupe),File(home,"taupe"),true)
            start=System.nanoTime();small.restore();report("taupe_open",start);assertEquals(SessionPhase.Ready,small.phase.value)
        } finally { sessions.forEach { it.close() }; home.deleteRecursively(); File(home.parentFile,home.name+"-suffix").deleteRecursively() }
    }
    private fun report(label:String,start:Long) { println("SESSION_BENCH kotlin $label %.3f ms".format((System.nanoTime()-start)/1e6)) }
    private fun load(file:File):Map<String,ByteArray> {
        val b=ByteBuffer.wrap(file.readBytes()).order(ByteOrder.LITTLE_ENDIAN)
        val records=HashMap<String,ByteArray>()
        repeat(b.long.toInt()) { val p=ByteArray(b.long.toInt());b.get(p);val value=ByteArray(b.long.toInt());b.get(value);records[p.decodeToString()]=value }
        return records
    }
}
