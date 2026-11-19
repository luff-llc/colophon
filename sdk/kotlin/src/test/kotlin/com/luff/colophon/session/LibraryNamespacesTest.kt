package com.luff.colophon.session

import kotlinx.coroutines.runBlocking
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A session whose `libraryNamespaces` (what the account declares at genesis) is wider than its own `namespaces` (what its
 * member is granted) is ready after `create()`: readiness and published revisions follow the member's own namespaces.
 * Before 0.5.0's final commit it came out denied. Each case runs without a home and with the real relay as its home.
 */
class LibraryNamespacesTest {
    private val all = listOf("listening.podcasts", "notes", "reading.books", "reading.saved")

    private fun createdIsReady(namespaces: List<String>, library: List<String>, withHome: Boolean) = runBlocking<Unit> {
        val relay = if (withHome) RelayHome("https://library-namespaces.test/v1/accounts/kotlin") else null
        val homes = relay?.let { r ->
            listOf(HomeConfiguration("${r.base}/", request = { account -> r.start(account); r.memberRequest(account) }, transport = r.transport()))
        } ?: listOf()
        val d = Device(homes = homes, createWithoutHome = relay == null, namespaces = namespaces, libraryNamespaces = library)
        try {
            d.session.create()
            assertEquals(SessionPhase.Ready, d.session.phase, d.describe())
            assertTrue(d.session.state.value.members.any { it.grant?.namespaces == namespaces.sorted() }, "the member holds only its own namespaces")
        } finally { d.close(); relay?.stop() }
    }

    @Test fun oneOwnNamespaceOfAllFourIsReady() = createdIsReady(listOf("listening.podcasts"), all, withHome = false)
    @Test fun oneOwnNamespaceOfAllFourIsReadyWithAHome() = createdIsReady(listOf("listening.podcasts"), all, withHome = true)
    @Test fun aNarrowerMemberThanTheLibraryIsReady() = createdIsReady(listOf("reading.saved"), listOf("reading.saved", "notes"), withHome = false)
    @Test fun aNarrowerMemberThanTheLibraryIsReadyWithAHome() = createdIsReady(listOf("reading.saved"), listOf("reading.saved", "notes"), withHome = true)
    @Test fun equalListsAreReady() = createdIsReady(listOf("notes", "reading.saved"), listOf("notes", "reading.saved"), withHome = false)
    @Test fun equalListsAreReadyWithAHome() = createdIsReady(listOf("notes", "reading.saved"), listOf("notes", "reading.saved"), withHome = true)
}

/**
 * The owner's engine sees every namespace of the account, whatever the app's own `libraryNamespaces`: a revoke made from
 * an app whose library is narrower keeps what the revoked member wrote in the other namespaces. Before 0.5.0's final
 * commit the owner engine was scoped to the app's library, so "keep everything" named no heads outside it and the
 * revoked member's notes were dropped.
 */
class OwnerScopeTest {
    @Test fun aRevokeFromANarrowerAppKeepsWhatTheMemberWroteElsewhere() = runBlocking<Unit> {
        val all = listOf("notes", "reading.saved")
        val writer = Device(namespaces = listOf("notes"), libraryNamespaces = all)
        val saved = Device(medium = writer.medium, owner = writer.owner, namespaces = listOf("reading.saved"))
        val reader = Device(medium = writer.medium, owner = writer.owner, namespaces = listOf("notes"), libraryNamespaces = all)
        try {
            writer.session.create()
            assertEquals(SessionPhase.Ready, writer.session.phase, writer.describe())
            note(writer.session, "kept")
            saved.session.restore(); approveByScan(saved.session, writer.session); saved.session.refresh()
            assertEquals(SessionPhase.Ready, saved.session.phase, saved.describe())
            reader.session.restore(); approveByScan(reader.session, writer.session); reader.session.refresh()
            assertEquals(SessionPhase.Ready, reader.session.phase, reader.describe())
            assertEquals(1, admitted(reader.session))
            // The reading.saved app, whose library is only reading.saved, revokes the writer.
            saved.session.revoke(checkNotNull(writer.session.memberId))
            reader.session.refresh()
            assertEquals(SessionPhase.Ready, reader.session.phase, reader.describe())
            assertEquals(1, admitted(reader.session), "the revoked member's note is kept")
        } finally { reader.close(); saved.close(); writer.close() }
    }
}
