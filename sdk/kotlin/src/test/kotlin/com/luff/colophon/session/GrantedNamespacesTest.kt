package com.luff.colophon.session

import kotlinx.coroutines.runBlocking
import org.junit.Test
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.concurrent.atomic.AtomicLong
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A session whose library declares more namespaces than its own member was granted (`libraryNamespaces` wider than
 * `namespaces`). The session is `Denied` only when its member lost access it was granted, never because the library
 * declares namespaces this member never had, including after an approval that narrowed the request (from the
 * fix-051 branch, folded into 0.5.0).
 */
class GrantedNamespacesTest {
    /** The namespaces published in the snapshot, without the authority's own revision. */
    private fun published(session: ColophonSession): Set<String> =
        session.state.value.namespaceRevisions.keys.filter { it != "colophon.authority" }.toSet()

    @Test fun aMemberOfAWiderLibraryIsReadyAfterCreation() = runBlocking<Unit> {
        val cases = listOf(
            listOf("listening.podcasts") to listOf("listening.podcasts", "reading.saved", "notes", "reading.books"),
            listOf("reading.saved") to listOf("reading.saved", "notes"),
            listOf("reading.saved", "notes") to listOf("reading.saved", "notes"),
        )
        for ((namespaces, library) in cases) {
            val d = Device(namespaces = namespaces, libraryNamespaces = library)
            try {
                d.session.create()
                assertEquals(SessionPhase.Ready, d.session.phase, "$namespaces of $library: ${d.describe()}")
                assertEquals(namespaces.toSet(), published(d.session), "$namespaces of $library: ${d.session.state.value.namespaceRevisions}")
            } finally { d.close() }
        }
    }

    /** A member of a wider library that is later revoked is still `Denied`. */
    @Test fun aRevokedMemberOfAWiderLibraryIsDenied() = runBlocking<Unit> {
        val library = listOf("reading.saved", "notes")
        val first = Device(namespaces = listOf("reading.saved"), libraryNamespaces = library)
        val second = Device(medium = first.medium, namespaces = listOf("notes"), libraryNamespaces = library)
        try {
            first.session.create()
            assertEquals(SessionPhase.Ready, first.session.phase, first.describe())
            second.session.restore()
            approveByScan(second.session, first.session)
            second.session.refresh()
            assertEquals(SessionPhase.Ready, second.session.phase, second.describe())
            assertEquals(setOf("notes"), published(second.session))
            first.session.revoke(assertNotNull(second.session.memberId))
            second.session.refresh()
            assertEquals(SessionPhase.Denied, second.session.phase, second.describe())
            assertTrue(second.session.state.value.namespaceRevisions.isEmpty())
        } finally { second.close(); first.close() }
    }

    /**
     * A device that asks for two namespaces of the library and is granted one (the approver narrows the terms) is `Ready`,
     * publishes only the granted namespace, and is refused a write to the other.
     */
    @Test fun aNarrowedApprovalIsReadyAndRefusesTheUngrantedNamespace() = runBlocking<Unit> {
        val library = listOf("reading.saved", "notes", "reading.books")
        val first = Device(namespaces = listOf("reading.books"), libraryNamespaces = library)
        val second = Device(medium = first.medium, namespaces = listOf("reading.saved", "notes"), libraryNamespaces = library)
        try {
            first.session.create()
            assertEquals(SessionPhase.Ready, first.session.phase, first.describe())
            second.session.restore()
            approveByScan(second.session, first.session, """{"records":[{"namespace":"reading.saved","access":"write"}]}""")
            second.session.refresh()
            assertEquals(SessionPhase.Ready, second.session.phase, second.describe())
            assertEquals(setOf("reading.saved"), published(second.session))
            val before = first.medium.snapshot().size
            val refused = assertFailsWith<com.luff.colophon.AccountException.Denied> { note(second.session, "x") }
            assertEquals(com.luff.colophon.AccountDenialReason.NOT_GRANTED, refused.reason)
            assertEquals(before, first.medium.snapshot().size, "a refused write stores nothing")
            // The refusal starts a refresh (the engine's access check decides the phase), and the approval's writes may have
            // started a batch refresh: the phase to judge is the one they settle on, not `Refreshing` while one runs.
            second.session.refusalRefresh?.join()
            second.session.flushExternalChanges()
            assertEquals(SessionPhase.Ready, second.session.phase, second.describe())
        } finally { second.close(); first.close() }
    }

    /** A member of a wider library whose grant has expired is still `Denied`. Driven by the injected clock, no sleeping. */
    @Test fun anExpiredMemberOfAWiderLibraryIsDenied() = runBlocking<Unit> {
        val library = listOf("reading.saved", "notes")
        val clock = AtomicLong(System.currentTimeMillis())
        val first = Device(namespaces = listOf("reading.saved"), libraryNamespaces = library, now = { clock.get() })
        val second = Device(medium = first.medium, namespaces = listOf("notes"), libraryNamespaces = library, now = { clock.get() })
        try {
            first.session.create()
            assertEquals(SessionPhase.Ready, first.session.phase, first.describe())
            second.session.restore()
            val expires = Instant.ofEpochMilli(clock.get() + 3_600_000).truncatedTo(ChronoUnit.SECONDS).toString()
            approveByScan(second.session, first.session, """{"records":[{"namespace":"notes","access":"write"}],"expires":"$expires"}""")
            second.session.refresh()
            assertEquals(SessionPhase.Ready, second.session.phase, second.describe())
            assertEquals(setOf("notes"), published(second.session))
            clock.addAndGet(7_200_000)
            second.session.refresh()
            assertEquals(SessionPhase.Denied, second.session.phase, second.describe())
            assertTrue(second.session.state.value.namespaceRevisions.isEmpty())
        } finally { second.close(); first.close() }
    }
}
