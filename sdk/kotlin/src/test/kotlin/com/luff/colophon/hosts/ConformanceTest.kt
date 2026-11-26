package com.luff.colophon.hosts

import com.luff.colophon.session.Json
import com.luff.colophon.sessionClockSample
import com.luff.colophon.sessionDefaultPolicy
import org.junit.Test
import uniffi.colophon_conformance.ConformanceAccess
import uniffi.colophon_conformance.ConformanceEpochKey
import uniffi.colophon_conformance.ConformanceEpochs
import uniffi.colophon_conformance.ConformanceException
import uniffi.colophon_conformance.ConformanceMachine
import uniffi.colophon_conformance.ConformanceMember
import uniffi.colophon_conformance.ConformanceReceiver
import uniffi.colophon_conformance.ConformanceRecordEntry
import uniffi.colophon_conformance.ConformanceSender
import uniffi.colophon_conformance.ConformanceView
import java.io.File
import java.math.BigInteger
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The 0.6 session conformance vectors replayed from Kotlin through the conformance crate's artifact
 * (`libcolophon_conformance`, bindings in `src/conformance`, test-only), as js/test06/conformance.test.ts and the
 * crate's own `tests/vectors.rs` replay them. The shipped module neither contains nor names it (checked below).
 */
class ConformanceTest {
    private val repo = File(System.getProperty("colophon.repo") ?: "../..").canonicalFile
    private val dir = File(repo, "conformance/0.6-sessions")
    @Suppress("UNCHECKED_CAST") private fun read(f: File) = Json.parse(f.readText()) as Map<String, Any?>
    @Suppress("UNCHECKED_CAST") private fun Map<String, Any?>.m(k: String) = this[k] as Map<String, Any?>
    @Suppress("UNCHECKED_CAST") private fun Map<String, Any?>.l(k: String) = this[k] as List<Map<String, Any?>>
    private fun Map<String, Any?>.s(k: String) = this[k] as String
    private fun Map<String, Any?>.n(k: String) = (this[k] as Number).toLong()
    private fun unhex(t: String) = ByteArray(t.length / 2) { t.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    private fun unb64(t: String) = Base64.getDecoder().decode(t)
    private fun codeOf(run: () -> Unit): String {
        try { run() } catch (e: ConformanceException.Failed) { return e.code }
        fail("expected a refusal")
    }

    /** Every machine transcript: one machine per member, each step's outputs compared in order, restarts from `persisted_json`. */
    private fun replayMachines(): Int {
        var replayed = 0
        for (file in dir.listFiles { f -> f.name.endsWith(".json") }!!.sortedBy { it.name }) {
            val v = read(file)
            if (v["format"] != "colophon/session-vectors/6") continue
            val policy = Json.write(v["policy"]); val fixes = Json.write(v["fixes"])
            val machines = HashMap<String, ConformanceMachine>(); val canWrite = HashMap<String, Boolean>()
            for (m in v.l("members")) {
                machines[m.s("id")] = ConformanceMachine(m.s("id"), m["canWrite"] as Boolean, policy, m["persisted"]?.let { Json.write(it) }, fixes,
                    (m["freshSeed"] as String?)?.let { unhex(it) })
                canWrite[m.s("id")] = m["canWrite"] as Boolean
            }
            v.l("steps").forEachIndexed { k, step ->
                val member = step.s("member")
                if (step.containsKey("restart")) {
                    val persisted = machines.getValue(member).persistedJson()
                    machines.getValue(member).close()
                    machines[member] = ConformanceMachine(member, canWrite.getValue(member), policy, persisted, fixes, null)
                    return@forEachIndexed
                }
                val got = Json.parse(machines.getValue(member).handle(Json.write(step["input"]), step.n("at").toULong()))
                assertEquals(step["outputs"], got, "${file.name} step $k")
            }
            for (f in v.l("final")) {
                val m = machines.getValue(f.s("member"))
                assertEquals(f.s("digest"), m.digest(), "${file.name} digest")
                assertEquals(f["view"], Json.parse(m.viewJson()), "${file.name} view")
            }
            machines.values.forEach { it.close() }
            replayed++
        }
        return replayed
    }

    /** `offset.json`'s single samples (integers read losslessly). */
    private fun replayOffsets(): Int {
        val cases = read(File(dir, "offset.json")).l("cases")
        fun big(c: Map<String, Any?>, k: String) = when (val x = c[k]) { is BigInteger -> x; is Number -> BigInteger.valueOf(x.toLong()); else -> error(k) }
        for (c in cases) {
            val s = sessionClockSample(big(c, "now").toLong().toULong(), big(c, "t").toLong().toULong(), big(c, "echo").toLong().toULong(), big(c, "hold").toLong().toULong())
            assertEquals(listOf(big(c, "rtt"), big(c, "offset"), big(c, "error")), listOf(BigInteger(s.rtt.toString()), BigInteger.valueOf(s.offset), BigInteger(s.error.toString())), "$c")
        }
        return cases.size
    }

    private fun members(list: List<Map<String, Any?>>, ns: String) = list.map {
        ConformanceMember(unb64(it.s("signing")), it.n("session").toULong(), null,
            listOf(ConformanceRecordEntry(ns, if (it["access"] == "write") ConformanceAccess.WRITE else ConformanceAccess.READ)))
    }
    private fun held(rx: ConformanceReceiver) = rx.keys().map { Triple(it.member, it.key, rx.windowHigh(it.member, it.key)) }

    /** The wire file: positive frames, scenarios and negative frames. Returns (frames, steps, negative). */
    private fun replayWire(): Triple<Int, Int, Int> {
        val v = read(File(dir, "wire/vectors.json"))
        val account = v.s("account"); val ns = v.s("namespace"); val cell = v.s("cell"); val me = v.s("receiver")
        val clock = v.n("clockMs"); val max = v.n("maxPayload").toULong()
        val table = ConformanceEpochs(ns, v.l("epochs").map { ConformanceEpochKey(it.n("epoch").toULong(), unhex(it.s("key"))) })
        assertEquals(1uL, table.currentEpoch())
        val view = ConformanceView(account, members(v.l("members"), ns))

        // The session key and the exact delegation body; a changed signature refused, the real one installed.
        val sk = v.m("sessionKey")
        val tx = ConformanceSender(account, ns, cell, sk.s("member"), unhex(sk.s("privateKey")))
        assertEquals(sk.s("id"), tx.keyId())
        val body = tx.delegationBody(0uL, clock, clock + 86_400_000)
        assertEquals(v.m("delegation").s("body"), String(body))
        val signature = unb64(v.m("delegation").s("signature"))
        val forged = signature.copyOf().also { it[5] = (it[5].toInt() xor 1).toByte() }
        assertEquals("session:delegation", codeOf { tx.install(body, forged, view, clock) })
        tx.install(body, signature, view, clock)

        val rx = ConformanceReceiver(account, ns, cell, me)
        for (f in v.l("frames")) {
            val r = rx.open(f.s("frame").toByteArray(), view, table, clock, max)
            assertNull(r.dropped?.reason, f.s("name"))
            val o = r.opened!!
            assertEquals(f.s("plaintext"), String(o.plaintext), f.s("name"))
            assertEquals(listOf(f["writer"], f.n("n").toULong(), f["to"], 1uL), listOf(o.writer, o.n, o.to, o.epoch), f.s("name"))
        }

        var steps = 0
        for (sc in v.l("scenarios")) {
            val rx2 = ConformanceReceiver(account, ns, cell, sc["receiver"] as String? ?: me)
            var current = ConformanceView(account, members(v.m("views").l("default"), ns))
            sc.l("steps").forEachIndexed { k, step ->
                steps++
                val ex = step.m("expect"); val what = "${sc.s("name")} step $k"
                if (step.containsKey("setView")) {
                    current = ConformanceView(account, members(v.m("views").l(step.s("setView")), ns))
                    val gone = rx2.setAccount(current, clock)
                    assertEquals(ex["forgottenMembers"], gone.members, what)
                    assertEquals(ex["closedKeys"], gone.keys.map { listOf(it.member, it.key) }, what)
                    return@forEachIndexed
                }
                val at = if (step.containsKey("clockMs")) step.n("clockMs") else clock
                val before = held(rx2)
                val r = rx2.open(step.s("open").toByteArray(), current, table, at, max)
                if (ex["drop"] == null) {
                    assertNull(r.dropped?.reason, what)
                    ex["writer"]?.let { assertEquals(it, r.opened!!.writer, what) }
                } else {
                    assertEquals(ex["drop"], r.dropped?.reason, what)
                    assertNull(r.opened, what)
                    assertEquals(before, held(rx2), "$what: a drop changes nothing")
                    if (ex.containsKey("helloTo")) assertEquals(ex["helloTo"], r.dropped!!.helloTo, what)
                }
            }
        }

        for (n in v.l("negative")) {
            val rx3 = ConformanceReceiver(account, ns, cell, me)
            val at = if (n.containsKey("clockMs")) n.n("clockMs") else clock
            val maxp = if (n.containsKey("maxPayload")) n.n("maxPayload").toULong() else max
            @Suppress("UNCHECKED_CAST") for (a in n["accept"] as List<String>) assertNotNull(rx3.open(a.toByteArray(), view, table, clock, max).opened, n.s("name"))
            val before = held(rx3)
            val r = rx3.open(n.s("frame").toByteArray(), view, table, at, maxp)
            if (n["drop"] == null) {
                assertTrue(r.opened != null && r.dropped == null, n.s("name"))
            } else {
                assertEquals(n["drop"], r.dropped?.reason, n.s("name"))
                assertEquals(before, held(rx3), n.s("name"))
            }
        }
        return Triple(v.l("frames").size, steps, v.l("negative").size)
    }

    @Test fun everyMachineTranscriptTheOffsetCasesAndTheWireFileReplay() {
        val machines = replayMachines()
        val offsets = replayOffsets()
        val (frames, steps, negative) = replayWire()
        println("conformance: $machines machine transcripts, $offsets offset cases, wire $frames frames / $steps scenario steps / $negative negative frames")
        assertEquals(26, machines)
        assertEquals(9, offsets)
        assertTrue(frames > 0 && steps > 0 && negative > 0)
    }

    @Test fun sessionInputsAreDecodedStrictly() {
        val policy = sessionDefaultPolicy()
        val m = ConformanceMachine("a", true, policy, null, null, null)
        for (bad in listOf("""{"input":"wave"}""", """{"input":"tick","extra":1}""", """{"input":"app","command":{"command":"jump"}}""", """{"input":"app","command":{"command":"join"}}""", "not json")) {
            assertEquals("malformed", codeOf { m.handle(bad, 0uL) }, bad)
        }
        @Suppress("UNCHECKED_CAST") val surprising = Json.write((Json.parse(policy) as Map<String, Any?>) + ("surprise" to true))
        assertEquals("malformed", codeOf { ConformanceMachine("a", true, surprising, null, null, null) })
        assertEquals("malformed", codeOf { ConformanceMachine("a", true, policy, """{"claim":{"term":0,"rank":0,"holder":"a"},"released":false}""", null, null) })
        assertEquals("bound", codeOf { ConformanceMachine("a", true, policy, null, null, ByteArray(15)) })
        assertEquals("bound", codeOf { ConformanceEpochs("listening.podcasts", listOf(ConformanceEpochKey(1uL, ByteArray(31)))) })
    }

    @Test fun theShippedModuleNeitherContainsNorNamesTheConformanceBindings() {
        val shipped = listOf(File(repo, "sdk/kotlin/src/main"), File(repo, "sdk/kotlin/src/jvm"), File(repo, "sdk/android/src/main"))
        for (root in shipped) root.walkTopDown().filter { it.isFile }.forEach { f ->
            assertFalse(Regex("colophon_conformance|Conformance(Machine|View|Epochs|Receiver|Sender)").containsMatchIn(f.readText()), "${f.path} names the conformance surface")
        }
        val gradle = File(repo, "sdk/kotlin/build.gradle.kts").readText()
        assertTrue(gradle.contains("test { kotlin.srcDir(\"src/conformance/kotlin\") }"), "the conformance bindings are a test source only")
        assertFalse(File(repo, "sdk/android/build.gradle.kts").readText().contains("conformance"), "the Android library never compiles them")
    }
}
