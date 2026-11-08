package com.luff.colophon

import kotlin.test.*

class JourneyTest {
    @Test fun agentJourney() {
        val owner = PlatformKeys.software()
        val controller = RawControllerProvider(PlatformKeys.software())
        val keys = PlatformKeys.software()
        ColophonLibrary.create(owner, "Library", "Owner", listOf("notes", "reading.saved"), controller).use { library ->
            library.call("notes__createNotebook", """{"id":"book","title":"Ideas"}""".toByteArray()).get()
            val request = ColophonLibrary.requestAccess(library.id, keys, "Muse", MemberKind.AGENT,
                listOf("notes", "reading.saved"), listOf(Access.READ, Access.WRITE))
            assertEquals(6, request.pairingCode.length)
            val member = library.approve(request.record, GrantOptions(listOf("notes"), null, null, 3uL)).get()
            assertEquals(listOf("notes"), member.grant?.namespaces)
            ColophonLibrary.open(library.records, keys).use { agent ->
                val note = agent.write("notes", "addNote", """{"id":"note","notebook":"book","text":"Keep this","origin":"person"}""".toByteArray()).get()
                assertEquals(Origin.AI, note.origin)
                assertEquals(request.id, note.author)
                assertEquals(DenialReason.NOT_GRANTED, (agent.view("reading.saved") as Outcome.Failure).denial.reason)
                assertEquals(1uL, library.merge(agent.records).recordsAdded)
                library.revoke(request.id).get()
                agent.merge(library.records)
                val refused = agent.write("notes", "addNote", """{"id":"later","notebook":"book","text":"No"}""".toByteArray())
                assertEquals(DenialReason.REVOKED, (refused as Outcome.Failure).denial.reason)
                ColophonLibrary.open(library.records, owner).use { reopened ->
                    val view = reopened.view("notes").get()
                    assertTrue(view.admitted.any { it.id == note.id && it.origin == Origin.AI && it.authorLabel == "Muse" })
                    assertTrue(view.state.decodeToString().contains("Keep this"))
                    assertTrue(reopened.ledger().any { it.event == LedgerEvent.REVOKED })
                    assertTrue(reopened.ledger().any { it.event == LedgerEvent.WROTE && it.origin == Origin.AI })
                    assertTrue(reopened.tools().any { it.name == "notes__addNote" })
                    val query = reopened.call("notes__read", "{}".toByteArray()).get()
                    assertTrue(query.decodeToString().contains("Keep this"))
                }
            }
        }
    }
    @Test fun providers() {
        val a = PlatformKeys.software()
        val b = PlatformKeys.software()
        assertEquals(65, a.signingPublicKey().size)
        assertEquals(64, a.sign("body".toByteArray()).size)
        assertContentEquals(a.agree(b.agreementPublicKey()), b.agree(a.agreementPublicKey()))
        assertFailsWith<BindingException.KeyProvider> { a.agree(byteArrayOf(0)) }
    }
}
