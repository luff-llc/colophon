package com.luff.colophon.session

import com.luff.colophon.AccountDenial
import com.luff.colophon.AccountDenialReason
import kotlinx.coroutines.runBlocking
import org.junit.Test
import java.time.Instant
import java.util.concurrent.atomic.AtomicLong
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class MemberReadinessTest {
    @Test fun expiryIsCheckedWithoutAnyGrantedLibraryNamespace() = runBlocking<Unit> {
        for (namespaces in listOf(emptyList(), listOf("notes"))) for (library in listOf(emptyList(), listOf("reading.saved"))) {
            val clock = AtomicLong(1_800_000_000_000)
            val first = Device(namespaces = listOf("notes"), libraryNamespaces = listOf("notes", "reading.saved"), now = clock::get)
            val services = listOf(ServiceTerms("urn:test", listOf("read")))
            val second = Device(medium = first.medium, namespaces = namespaces, libraryNamespaces = library, services = services, now = clock::get)
            try {
                first.session.create()
                second.session.restore()
                val expires = Instant.ofEpochMilli(clock.get() + 3_600_000).toString()
                val terms = SessionWorker.terms(namespaces, setOf(com.luff.colophon.AccessKind.WRITE), expires, null, services)
                approveByScan(second.session, first.session, terms)
                clock.addAndGet(3_600_000)
                second.session.refresh()
                assertEquals(SessionPhase.Ready, second.session.phase, second.describe()) // Inclusive expiry bound, like the core.
                clock.incrementAndGet()
                second.session.refresh()
                assertEquals(SessionPhase.Denied, second.session.phase, second.describe())
                assertTrue(second.session.state.value.namespaceRevisions.isEmpty())
            } finally { second.close(); first.close() }
        }
    }

    @Test fun provisionalAndRevokedMembersAreDeniedAndMissingEpochKeysStayUnavailable() = runBlocking<Unit> {
        val device = Device()
        try {
            device.session.create()
            val member = assertNotNull(device.session.state.value.members.find { it.id == device.session.memberId })
            for (namespaces in listOf(emptyList(), listOf("notes"))) {
                for (denied in listOf(member.copy(grant = member.grant?.copy(namespaces = emptyList()), provisional = true),
                    member.copy(grant = member.grant?.copy(namespaces = emptyList()), revokedAt = 1uL))) {
                    var calls = 0
                    val result = memberReadiness(denied, 0, namespaces) { calls++; null }
                    assertEquals(SessionPhase.Denied to emptyList<String>(), result)
                    assertEquals(0, calls)
                }
            }
            for (reason in listOf(AccountDenialReason.UNAVAILABLE, AccountDenialReason.NOT_READABLE)) {
                val checked = ArrayList<String>()
                val result = memberReadiness(member, 0, listOf("notes")) { namespace ->
                    checked.add(namespace)
                    AccountDenial(reason, null, "epoch key not held")
                }
                assertEquals(listOf("notes"), checked)
                assertEquals(SessionPhase.Unavailable("epoch key not held") to emptyList<String>(), result)
            }
        } finally { device.close() }
    }
    @Test fun aRealMemberEngineWithoutUnlockedEpochKeysIsUnavailable() = runBlocking<Unit> {
        val device = Device()
        var engine: ColophonEngine? = null
        try {
            device.session.create()
            val account = assertNotNull(device.session.libraryId)
            val opened = device.secrets.key(account).use { key ->
                ColophonEngine.open(source = MediumSource(device.medium),
                    listing = device.medium.listing().map { com.luff.colophon.ListedPath(it.path, it.version) },
                    identity = com.luff.colophon.AccountIdentity(com.luff.colophon.AccountIdentityKind.MEMBER, assertNotNull(device.session.memberId)),
                    account = account, namespaces = listOf("notes"), deviceKey = key, nowMs = System.currentTimeMillis())
            }
            engine = opened
            val member = assertNotNull(opened.run { it.me() }.member)
            val denial = assertNotNull(opened.run { it.access("notes") })
            assertEquals(AccountDenialReason.NOT_READABLE, denial.reason)
            val result = memberReadiness(member, System.currentTimeMillis(), listOf("notes")) { denial }
            assertTrue(result.first is SessionPhase.Unavailable)
            assertTrue(result.second.isEmpty())
        } finally { engine?.lock(); device.close() }
    }

}
