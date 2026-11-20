package com.luff.colophon.session

import com.luff.colophon.accountFormatDate
import kotlinx.coroutines.runBlocking
import org.junit.Test
import kotlin.test.*

/** `perform(command, observed, claimedMs)`: an import keeps each note's original date as the operation's `created`. */
class ClaimedDateTest {
    private val listening = "listening.podcasts"

    private fun addNote(id: String) =
        DomainCommand(listening, "addNote", Json.write(mapOf("id" to id, "episode" to "e1", "show" to "show", "text" to "An old thought")))

    private suspend fun created(session: ColophonSession, id: String): String? =
        Json.obj(session.query(listening, "note", Json.write(mapOf("id" to id))))?.obj("value")?.obj("note")?.string("created")

    @Test fun aClaimedDateIsTheNotesCreatedAndAFutureOneIsRefused() = runBlocking<Unit> {
        val device = Device(namespaces = listOf(listening))
        try {
            device.session.create()
            assertEquals(SessionPhase.Ready, device.session.phase, device.describe())
            // 2019-03-04T05:06:07.890Z, years before the account.
            val claimed = 1_551_675_967_890L
            val receipt = device.session.perform(addNote("old"), device.session.observedRevision, claimedMs = claimed)
            assertTrue(receipt is WriteReceipt.Saved && receipt.operationId.isNotEmpty(), "$receipt")
            assertEquals("2019-03-04T05:06:07.890Z", created(device.session, "old"))
            assertEquals(accountFormatDate(claimed), created(device.session, "old"))

            // Without a claim the date is now.
            val before = System.currentTimeMillis() - 2_000
            device.session.perform(addNote("new"), device.session.observedRevision)
            val now = assertNotNull(created(device.session, "new"))
            assertTrue(java.time.Instant.parse(now).toEpochMilli() >= before, now)

            // A claimed date later than now is refused and writes nothing.
            val ops = device.medium.listing().count { it.path.startsWith("ops/") }
            assertFailsWith<SessionError.InvalidCommand> {
                device.session.perform(addNote("future"), device.session.observedRevision, claimedMs = System.currentTimeMillis() + 3_600_000)
            }
            assertEquals(ops, device.medium.listing().count { it.path.startsWith("ops/") })
            assertNull(created(device.session, "future"))

            // Extremes outside the years 0001–9999 are refused before the engine sees them, and write nothing.
            for (bad in listOf(Long.MIN_VALUE, Long.MIN_VALUE + 1, -62_135_596_800_001L, Long.MAX_VALUE)) {
                assertFailsWith<SessionError.InvalidCommand>("$bad") {
                    device.session.perform(addNote("bad"), device.session.observedRevision, claimedMs = bad)
                }
            }
            assertEquals(ops, device.medium.listing().count { it.path.startsWith("ops/") })
            // The first instant of year 1 is a date.
            device.session.perform(addNote("first"), device.session.observedRevision, claimedMs = -62_135_596_800_000L)
            assertEquals("0001-01-01T00:00:00Z", created(device.session, "first"))
        } finally {
            device.close()
        }
    }
}
