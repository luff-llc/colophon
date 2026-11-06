package com.luff.colophon

import kotlin.test.*

class MigrationTest {
    @Test fun pureImportCrossesTheGeneratedAbi() {
        val source = LegacyImportOperation(
            sourceLibrary = "old-library", authorId = "old-author", authorLabel = "Old phone",
            operationId = "old-operation", signedBodyDigest = "a".repeat(64), kind = "book.add",
            version = 1uL, payloadJson = """{"book":"book","title":"A book","author":"An author"}""".toByteArray(),
            admittedOrder = 0uL, claimedDateJson = "\"2026-11-06T00:00:00Z\"".toByteArray(),
            admission = "admitted", outcome = "applied", contextJson = "{}".toByteArray())
        val plan = importLegacyBatch("reading.books", listOf(source), "{}".toByteArray())
        assertEquals("addBook", plan.commands.single().kind)
        assertTrue(plan.evidenceJson.decodeToString().contains("Old phone"))
        val state = bindLegacyImportState("reading.books", plan.stateJson,
            mapOf(plan.commands.single().outputKey to "signed-destination-id"))
        val duplicate = importLegacyBatch("reading.books", listOf(source), state)
        assertTrue(duplicate.commands.isEmpty())
        val held = importLegacyBatch("reading.books", listOf(source.copy(admission = "held")), "{}".toByteArray())
        assertTrue(held.commands.isEmpty())
        assertTrue(held.evidenceJson.decodeToString().contains("unresolved"))
    }
}
