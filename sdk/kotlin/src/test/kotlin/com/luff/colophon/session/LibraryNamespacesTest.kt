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
