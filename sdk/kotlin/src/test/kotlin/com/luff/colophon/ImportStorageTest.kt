package com.luff.colophon

import kotlin.test.*

class ImportStorageTest {
    @Test fun atomicEvidenceAndStreamingBlobsCrossGeneratedAbi() {
        val owner = PlatformKeys.software()
        ColophonLibrary.create(owner, "Import", "Owner", listOf("notes")).use { root ->
            val now = "2026-11-06T18:00:00Z"
            val writer = (root.native.beginBlob("notes", "text/plain", now, ByteArray(32) { 7 }) as BlobWriteOutcome.Ready).writer
            val plaintext = "retained original".toByteArray()
            val chunk = writer.push(plaintext)
            val manifest = writer.finish().decodeToString()
            val digest = java.security.MessageDigest.getInstance("SHA-256").digest(plaintext).joinToString("") { "%02x".format(it) }
            val body = """{"key":"source/author/op/digest/transform-1","evidence":{"sourceLibrary":"old","authorLabel":"Old phone","losingCandidates":["old conflict"]},"children":[{"key":"child","kind":"createNotebook","payload":{"id":"n","title":"Imported"}}],"blobs":[$manifest]}""".toByteArray()
            val action = (root.native.beginImport("notes", body, now, ByteArray(32) { 8 }) as PreparedAction.Ready).action
            assertEquals(1, action.signingSteps().size)
            root.native.commit(action, action.signWith(owner))
            val evidence = (root.native.query("notes", "importEvidence", "{}".toByteArray(), now) as JsonOutcome.Success).value.decodeToString()
            assertTrue(evidence.contains("Old phone"))
            assertTrue(evidence.contains(importOutputId(root.id, "notes", "source/author/op/digest/transform-1", "child")))
            val source = object : BlobSource {
                override fun read(path: String): BlobReadOutcome {
                    assertEquals(chunk.path, path)
                    // Reentry proves native host callbacks do not run under the library mutex.
                    assertEquals(root.id, root.native.id())
                    return BlobReadOutcome.Available(chunk.bytes)
                }
            }
            val read = root.native.readBlobChunk("notes", digest, 0u, now, source) as BlobReadOutcome.Available
            assertContentEquals(plaintext, read.bytes)
            val missing = object : BlobSource { override fun read(path: String) = BlobReadOutcome.Missing }
            assertTrue(root.native.readBlobChunk("notes", digest, 0u, now, missing) is BlobReadOutcome.Missing)
            val bad = object : BlobSource { override fun read(path: String) = BlobReadOutcome.Available(byteArrayOf(0)) }
            assertTrue(root.native.readBlobChunk("notes", digest, 0u, now, bad) is BlobReadOutcome.Invalid)
            val changes = reconcileImportPrefix("{\"a\":{\"outcome\":\"applied\"}}".toByteArray(), "{\"a\":{\"outcome\":\"conflict\"}}".toByteArray(), "{}".toByteArray())
            assertTrue(changes.decodeToString().contains("sourceOutcomeChanged"))
            assertEquals("notebook", importIdentityCategory("notes", "createNotebook"))
        }
    }
}
