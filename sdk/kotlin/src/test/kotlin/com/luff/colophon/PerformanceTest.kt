package com.luff.colophon

import java.io.File
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement
import kotlin.test.*
import org.junit.Assume.assumeTrue

class PerformanceTest {
    @Test fun ffiPerformance() {
        assumeTrue(System.getenv("COLOPHON_FFI_BENCH") == "1")
        val dir = File(System.getProperty("colophon.fixture"))
        val public = PublicKeys(File(dir, "signing.bin").readBytes(), File(dir, "agreement.bin").readBytes())
        val recordsDir = File(dir, "records")
        val records = recordsDir.walkTopDown().filter { it.isFile }.associate { it.relativeTo(recordsDir).invariantSeparatorsPath to it.readBytes() }
        val signatures = File(dir, "signatures.bin").readBytes().toList().chunked(64).map { it.toByteArray() }
        val parameters = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
        val factory = KeyFactory.getInstance("EC")
        val key = factory.generatePrivate(ECPrivateKeySpec(BigInteger(1, ByteArray(32) { 2 }), parameters))
        fun open(): NativeLibrary {
            val lib = NativeLibrary.open(records, public)
            for (step in lib.beginUnlock()) {
                val peer = factory.generatePublic(ECPublicKeySpec(ECPoint(BigInteger(1, step.peer.copyOfRange(1, 33)), BigInteger(1, step.peer.copyOfRange(33, 65))), parameters))
                val shared = KeyAgreement.getInstance("ECDH").apply { init(key); doPhase(peer, true) }.generateSecret()
                try { lib.finishUnlock(step, shared) } finally { shared.fill(0) }
            }
            return lib
        }
        val now = "2026-11-06T00:00:00Z"
        val input = "{}".toByteArray()
        val payload = """{"id":"bench-note","notebook":"book","text":"One more note"}""".toByteArray()
        val queries = mutableListOf<Double>()
        val writes = mutableListOf<Double>()
        open().use { lib ->
            repeat(200) { lib.beginCall("notes__read", input, now, ByteArray(32)) }
            repeat(100) {
                val start = System.nanoTime()
                val result = lib.beginCall("notes__read", input, now, ByteArray(32))
                queries += (System.nanoTime() - start) / 1000.0
                assertTrue((result as PreparedCall.Read).value.isNotEmpty())
            }
        }
        repeat(60) { index ->
            open().use { lib ->
                val start = System.nanoTime()
                val prepared = lib.beginWrite("notes", "addNote", payload, now, ByteArray(32) { 201.toByte() }) as PreparedAction.Ready
                prepared.action.use { action ->
                    lib.commit(action, signatures)
                    val result = lib.writtenOperation(action, "notes", now)
                    if (index >= 10) writes += (System.nanoTime() - start) / 1000.0
                    assertIs<OperationOutcome.Success>(result)
                }
            }
        }
        queries.sort(); writes.sort()
        println("FFI_KOTLIN {\"unit\":\"microseconds_median\",\"query\":${queries[queries.size / 2]},\"write\":${writes[writes.size / 2]}}")
    }
}
