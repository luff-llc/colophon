package com.luff.colophon.session

import com.luff.colophon.AccountIdentity
import com.luff.colophon.AccountIdentityKind
import com.luff.colophon.Controller
import com.luff.colophon.ControllerRole
import com.luff.colophon.ListedPath
import com.luff.colophon.SlotInfo
import kotlinx.coroutines.runBlocking
import org.junit.Test
import java.time.Instant
import java.util.concurrent.atomic.AtomicLong
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * `removeController`, `replaceController`, `completeKeyChanges`, `restoreSlot` and cosigned transitions (spec §8.3, §8.7).
 * Accounts without a home record every transition at once; the journeys with a home run against the real relay
 * ([RelayHome]) on one clock the test moves. The same cases as the Swift `KeyringChangeTests`.
 */
class KeyringChangeTest {
    private val start = Instant.parse("2026-11-20T09:00:00Z").toEpochMilli()
    private val now = AtomicLong(start)
    private val clock = { now.get() }

    private fun appointable(relay: RelayHome): HomeConfiguration {
        var started = false
        return HomeConfiguration("${relay.base}/", label = "Relay home", request = { account ->
            synchronized(relay) { if (!started) { relay.start(account); started = true } }
            relay.memberRequest(account)
        }, transport = relay.transport())
    }
    private suspend fun settle(device: Device, relay: RelayHome) {
        repeat(6) {
            now.addAndGet(1000)
            val ok = device.session.syncNow()
            relay.tick()
            if (ok && device.session.homeIssues.isEmpty() && device.session.homeFaults.isEmpty()) return
        }
        fail("did not settle: ${device.describe()}")
    }
    private fun transitions(medium: MemoryMedium) = medium.snapshot().keys.count { it.startsWith("transitions/") }
    private suspend fun controllerEngine(medium: MemoryMedium, id: String, account: String): ColophonEngine =
        ColophonEngine.open(label = "test-controller", source = MediumSource(medium), listing = medium.listing().map { ListedPath(it.path, it.version) },
            identity = AccountIdentity(AccountIdentityKind.CONTROLLER, id), account = account, deviceKey = SecretBytes.random(32), nowMs = now.get())
    private class State(val controllers: List<Controller>, val slots: List<SlotInfo>, val epoch: ULong)
    private suspend fun state(device: Device, id: String): State {
        val engine = controllerEngine(device.medium, id, assertNotNull(device.session.libraryId))
        try {
            return State(engine.run { it.controllers() }, engine.run { it.slots() }, engine.run { it.latestEpoch("notes") })
        } finally { engine.lock() }
    }
    private suspend fun unlocksAlone(device: Device, key: AsyncKeyProvider): Boolean {
        val id = KeyCustody.keyId(key)
        val engine = controllerEngine(device.medium, id, assertNotNull(device.session.libraryId))
        try {
            val slot = engine.run { it.slots() }.firstOrNull { s -> s.controllers.map { it.id } == listOf(id) } ?: return false
            val inputs = engine.run { it.beginUnlockSlot(slot.index) }
            engine.finishUnlockSlot(slot.index, KeyCustody.of(listOf(key)).answerUnlock(inputs))
            return engine.run { it.isUnlocked() }
        } finally { engine.lock() }
    }
    /** The kinds of the stored authority entries in seq order; an activation whose transition rotates the vault is `activate+vault`. */
    private fun kinds(medium: MemoryMedium): List<String> = medium.snapshot().filterKeys { it.startsWith("authority/") }.toSortedMap().values.mapNotNull { bytes ->
        val body = RemovalAnalysis.envelopeBody(bytes) ?: return@mapNotNull null
        val kind = body["kind"] as? String ?: return@mapNotNull null
        val inner = if (kind == "activate") (body["transition"] as? String)?.let(RemovalAnalysis::embeddedBody) else null
        if ((inner?.get("change") as? Map<*, *>)?.containsKey("vault") == true) "activate+vault" else kind
    }
    /** A second raw control key, added by a transition (final at once without a home), with its own slot. */
    private suspend fun addSecondControlKey(device: Device): Pair<SoftwareKeys, String> {
        val other = SoftwareKeys()
        device.session.addController(other, "Second", listOf(ControllerRole.CONTROL), immediate = false)
        device.session.refresh()
        device.session.restoreSlot(other, "Second")
        return other to KeyCustody.keyId(other)
    }
    private fun <T> withDevices(body: suspend (ArrayList<Device>) -> T) = runBlocking<Unit> {
        val devices = ArrayList<Device>()
        try { body(devices) } finally { devices.forEach { it.close() } }
    }

    @Test fun removingAKeyRotatesAtOnceAndRekeys() = withDevices { devices ->
        val first = Device(createWithoutHome = true, now = clock).also { devices.add(it) }
        first.session.create()
        assertEquals(SessionPhase.Ready, first.session.phase, first.describe())
        note(first.session, "a")
        val ownerId = KeyCustody.keyId(first.owner)
        val (_, otherId) = addSecondControlKey(first)
        val before = state(first, ownerId)
        assertEquals(2, before.controllers.size)
        assertTrue(before.slots.any { s -> s.controllers.map { it.id } == listOf(otherId) })

        val check = first.session.checkRemoval(otherId)
        assertTrue(check.allowed && check.rotatesAtOnce && check.removes == listOf(otherId), "$check")
        assertTrue(RemovalCheck.Warning.VaultRetiresUntilRotated !in check.warnings)
        assertEquals(KeyringChange.Done, first.session.removeController(otherId))

        val after = state(first, ownerId)
        assertEquals(listOf(ownerId), after.controllers.map { it.id })
        assertTrue(after.slots.none { s -> s.controllers.any { it.id == otherId } }, "no slot of the new vault names the removed key")
        assertTrue(after.epoch > before.epoch, "a rekey after the rotation")
        val k = kinds(first.medium)
        assertTrue("activate+vault" in k, "the removal carried the vault component: $k")
        assertEquals("rekey", k.last(), "$k")
        val duties = first.session.duties
        assertTrue(!duties.vaultRotationOwed && duties.rekeyOwed.isEmpty() && duties.keysWithoutSlot.isEmpty(), "$duties")
        note(first.session, "b")
        assertEquals(2, admitted(first.session))
        assertTrue(unlocksAlone(first, first.owner))
    }

    @Test fun theLastControlKeyCannotBeRemoved() = withDevices { devices ->
        val first = Device(createWithoutHome = true, now = clock).also { devices.add(it) }
        first.session.create()
        val ownerId = KeyCustody.keyId(first.owner)
        assertEquals(RemovalCheck.Refusal.LAST_CONTROL_KEY, first.session.checkRemoval(ownerId).refusal)
        val files = first.medium.snapshot().size
        assertFailsWith<SessionError.InvalidCommand> { first.session.removeController(ownerId) }
        assertEquals(files, first.medium.snapshot().size, "nothing signed")
        assertEquals(RemovalCheck.Refusal.NOT_A_CONTROLLER, first.session.checkRemoval("0".repeat(32)).refusal)
    }

    @Test fun theOnlyPasskeyIsReplaced() = withDevices { devices ->
        val old = TestPasskey(credential = byteArrayOf(1, 1, 1))
        val first = Device(createWithoutHome = true, ownerKey = old, now = clock).also { devices.add(it) }
        first.session.create()
        assertEquals(SessionPhase.Ready, first.session.phase, first.describe())
        note(first.session, "a")
        val oldId = KeyCustody.keyId(old)
        val next = TestPasskey(credential = byteArrayOf(2, 2, 2))
        val nextId = KeyCustody.keyId(next)
        val epoch = state(first, oldId).epoch

        val check = first.session.checkRemoval(oldId, replacingWith = next)
        assertTrue(check.allowed && !check.inOneTransition, "staged: $check")
        assertTrue(RemovalCheck.Warning.RemovesThisDevicesOwner in check.warnings)
        assertEquals(KeyringChange.Done, first.session.replaceController(oldId, next, "New passkey"))

        val after = state(first, nextId)
        assertEquals(listOf(nextId), after.controllers.map { it.id })
        assertEquals(listOf(ControllerRole.CONTROL, ControllerRole.RECOVER), after.controllers.first().roles)
        assertEquals(listOf(listOf(nextId)), after.slots.map { s -> s.controllers.map { it.id } })
        assertTrue(after.epoch > epoch)
        assertTrue("activate+vault" in kinds(first.medium))
        assertTrue(unlocksAlone(first, next), "the new passkey unlocks alone")

        val again = Device(medium = first.medium, member = first.member, ownerKey = next, now = clock).also { devices.add(it) }
        again.session.restore()
        assertEquals(SessionPhase.Ready, again.session.phase, again.describe())
        assertEquals(1, admitted(again.session))
        assertEquals(RemovalCheck.Refusal.LAST_CONTROL_KEY, again.session.checkRemoval(nextId).refusal)
        assertTrue(again.session.duties.rekeyOwed.isEmpty() && !again.session.duties.vaultRotationOwed)
    }

    @Test fun aRetiringVaultIsRotatedByThisHost() = withDevices { devices ->
        val first = Device(createWithoutHome = true, now = clock).also { devices.add(it) }
        first.session.create()
        note(first.session, "a")
        val ownerId = KeyCustody.keyId(first.owner)
        val (_, otherId) = addSecondControlKey(first)
        val epoch = state(first, ownerId).epoch
        first.session.proposeTransition("{\"keyring\":{\"remove\":[\"$otherId\"]}}")
        first.session.refresh()
        assertTrue(first.session.duties.vaultRotationOwed, "the vault is retiring")
        assertEquals(epoch, state(first, ownerId).epoch)

        assertEquals(KeyringChange.Done, first.session.completeKeyChanges())
        assertTrue(!first.session.duties.vaultRotationOwed && first.session.duties.rekeyOwed.isEmpty())
        assertTrue(state(first, ownerId).epoch > epoch)
        val k = kinds(first.medium)
        assertEquals(listOf("vault", "rekey"), k.takeLast(2), "$k")
        assertTrue(unlocksAlone(first, first.owner))
        note(first.session, "b")
        assertEquals(2, admitted(first.session))
    }

    @Test fun aStoppedRemovalOwesItsRekeyUntilCalledAgain() = withDevices { devices ->
        val first = Device(createWithoutHome = true, now = clock).also { devices.add(it) }
        first.session.create()
        val (_, otherId) = addSecondControlKey(first)
        val before = transitions(first.medium)
        first.session.worker.keyringStopForTests = KeyringStep.RECORDED
        assertFailsWith<KeyringStopped> { first.session.removeController(otherId) }
        first.session.worker.keyringStopForTests = null
        val again = Device(medium = first.medium, member = first.member, owner = first.owner, secrets = first.secrets, dir = first.dir, now = clock)
            .also { devices.add(it) }
        again.session.restore()
        assertEquals(listOf("notes"), again.session.duties.rekeyOwed)
        assertEquals(KeyringChange.Done, again.session.removeController(otherId))
        assertTrue(again.session.duties.rekeyOwed.isEmpty())
        assertEquals(before + 1, transitions(first.medium), "one removal")
    }

    @Test fun aCosignedRemovalIsAFullSetAndActivatesAtOnce() = withDevices { devices ->
        val relay = RelayHome("https://keyring.test/v1/accounts/kotlin-fullset", clockSource = clock)
        try {
            val first = Device(createWithoutHome = true, now = clock).also { devices.add(it) }
            first.session.create()
            note(first.session, "a")
            val ownerId = KeyCustody.keyId(first.owner)
            val (other, otherId) = addSecondControlKey(first)
            assertEquals(HomesAppointment.Done, first.session.appointHomes(listOf(appointable(relay))))
            first.session.stopSync()
            settle(first, relay)

            val outcome = first.session.removeController(otherId, cosigners = listOf(other))
            first.session.stopSync()
            val pending = assertIs<KeyringChange.Pending>(outcome)
            val digest = pending.transitions.single()
            val body = assertNotNull(RemovalAnalysis.envelopeBody(first.medium.read("transitions/$digest.json")))
            assertEquals(setOf(ownerId, otherId), (body["signers"] as List<*>).toSet(), "signed by every control key")
            settle(first, relay)
            assertEquals(KeyringChange.Done, first.session.removeController(otherId, cosigners = listOf(other)), "no delay to wait out")
            first.session.stopSync()
            assertTrue(now.get() - start < 600_000, "far less than the recovery delay passed")
            assertEquals(listOf(ownerId), state(first, ownerId).controllers.map { it.id })
            assertTrue(first.session.duties.rekeyOwed.isEmpty())
        } finally { relay.stop() }
    }

    @Test fun aReplacementIsOneTransitionAndIdempotent() = withDevices { devices ->
        val relay = RelayHome("https://keyring.test/v1/accounts/kotlin-replace", clockSource = clock)
        try {
            val first = Device(createWithoutHome = true, now = clock).also { devices.add(it) }
            first.session.create()
            note(first.session, "a")
            val ownerId = KeyCustody.keyId(first.owner)
            val old = TestPasskey(credential = byteArrayOf(3, 3, 3))
            assertEquals(HomesAppointment.Done, first.session.appointHomes(listOf(appointable(relay)),
                AdditionalController(old, "Passkey", listOf(ControllerRole.CONTROL, ControllerRole.RECOVER))))
            first.session.stopSync()
            settle(first, relay)
            val oldId = KeyCustody.keyId(old)
            val next = TestPasskey(credential = byteArrayOf(4, 4, 4))
            val nextId = KeyCustody.keyId(next)
            val check = first.session.checkRemoval(oldId, replacingWith = next)
            assertTrue(check.allowed && check.inOneTransition, "$check")

            val before = transitions(first.medium)
            first.session.worker.keyringStopForTests = KeyringStep.SIGNED
            assertFailsWith<KeyringStopped> { first.session.replaceController(oldId, next, "New passkey") }
            first.session.worker.keyringStopForTests = null
            first.session.stopSync()
            assertEquals(before + 1, transitions(first.medium))
            val again = Device(medium = first.medium, member = first.member, owner = first.owner, secrets = first.secrets, dir = first.dir,
                homes = listOf(HomeConfiguration("${relay.base}/", transport = relay.transport())), createWithoutHome = false, now = clock).also { devices.add(it) }
            again.session.restore()
            again.session.stopSync()
            val pending = assertIs<KeyringChange.Pending>(again.session.replaceController(oldId, next, "New passkey"))
            again.session.stopSync()
            assertEquals(1, pending.transitions.size)
            assertEquals(before + 1, transitions(first.medium), "the same transition, not a second one")
            assertEquals(pending, again.session.replaceController(oldId, next, "New passkey"))
            again.session.stopSync()
            settle(again, relay)

            now.addAndGet(259_200_000L + 600_000L)
            var outcome: KeyringChange = pending
            repeat(6) {
                if (outcome == KeyringChange.Done) return@repeat
                settle(again, relay)
                outcome = again.session.replaceController(oldId, next, "New passkey")
                again.session.stopSync()
            }
            assertEquals(KeyringChange.Done, outcome, again.describe())
            assertEquals(before + 1, transitions(first.medium))
            assertEquals(setOf(ownerId, nextId), state(first, ownerId).controllers.map { it.id }.toSet())
            assertTrue(unlocksAlone(first, next), "the vault entry built the new passkey's slot")
            assertTrue(unlocksAlone(first, first.owner))
            assertTrue("vault" in kinds(first.medium))
            val duties = again.session.duties
            assertTrue(duties.rekeyOwed.isEmpty() && !duties.vaultRotationOwed && duties.keysWithoutSlot.isEmpty(), "$duties")
        } finally { relay.stop() }
    }
}
