package com.luff.colophon

import kotlin.test.*

class ImportStorageTest {
    @Test fun atomicEvidenceAndStreamingBlobsCrossGeneratedAbi() {
        val owner = PlatformKeys.software()
        val controller = RawControllerProvider(PlatformKeys.software())
        ColophonLibrary.create(PlatformKeys.software(), "Import", "Owner", listOf("notes"), controller).use { authority ->
            val now = java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MILLIS).toString()
            authority.unlockVault()
            val request = ColophonLibrary.requestAccess(authority.id, owner, "Copying app", MemberKind.APP,
                listOf("notes"), listOf(Access.READ, Access.WRITE)).record
            val expires = java.time.Instant.now().plusSeconds(3600).truncatedTo(java.time.temporal.ChronoUnit.MILLIS).toString()
            val grant = """{"namespaces":["notes"],"access":["read","write"],"expires":"$expires","import":true}""".toByteArray()
            authority.native.beginImportGrant(request, grant, listOf(controller.controllerID()), now, ByteArray(32) { 9 }).use {
                authority.native.finishAuthority(it, it.signControllerWith(controller))
            }
            ColophonLibrary.open(authority.records, owner).use { copying ->
                val writer = (copying.native.beginBlob("notes", "text/plain", now, ByteArray(32) { 7 }) as BlobWriteOutcome.Ready).writer
                val plaintext = "retained original".toByteArray()
                val chunk = writer.push(plaintext)
                val manifest = writer.finish().decodeToString()
                val digest = java.security.MessageDigest.getInstance("SHA-256").digest(plaintext).joinToString("") { "%02x".format(it) }
                val body = """{"key":"source/author/op/digest/transform-1","evidence":{"sourceLibrary":"old","authorLabel":"Old phone","losingCandidates":["old conflict"]},"children":[{"key":"child","kind":"createNotebook","payload":{"id":"n","title":"Imported"}}],"blobs":[$manifest]}""".toByteArray()
                val action = (copying.native.beginImport("notes", body, now, ByteArray(32) { 8 }) as PreparedAction.Ready).action
                assertEquals(1, action.signingSteps().size)
                copying.native.commit(action, action.signWith(owner))
                val evidence = (copying.native.query("notes", "importEvidence", "{}".toByteArray(), now) as JsonOutcome.Success).value.decodeToString()
                assertTrue(evidence.contains("Old phone"))
                assertTrue(evidence.contains(importOutputId(copying.id, "notes", "source/author/op/digest/transform-1", "child")))
                val source = object : BlobSource {
                    override fun read(path: String): BlobReadOutcome {
                        assertEquals(chunk.path, path)
                        // Reentry proves native host callbacks do not run under the library mutex.
                        assertEquals(copying.id, copying.native.id())
                        return BlobReadOutcome.Available(chunk.bytes)
                    }
                }
                val read = copying.native.readBlobChunk("notes", digest, 0u, now, source) as BlobReadOutcome.Available
                assertContentEquals(plaintext, read.bytes)
                val missing = object : BlobSource { override fun read(path: String) = BlobReadOutcome.Missing }
                assertTrue(copying.native.readBlobChunk("notes", digest, 0u, now, missing) is BlobReadOutcome.Missing)
                val bad = object : BlobSource { override fun read(path: String) = BlobReadOutcome.Available(byteArrayOf(0)) }
                assertTrue(copying.native.readBlobChunk("notes", digest, 0u, now, bad) is BlobReadOutcome.Invalid)
                val changes = reconcileImportPrefix("{\"a\":{\"outcome\":\"applied\"}}".toByteArray(), "{\"a\":{\"outcome\":\"conflict\"}}".toByteArray(), "{}".toByteArray())
                assertTrue(changes.decodeToString().contains("sourceOutcomeChanged"))
                assertEquals("notebook", importIdentityCategory("notes", "createNotebook"))
            }
        }
    }
}
