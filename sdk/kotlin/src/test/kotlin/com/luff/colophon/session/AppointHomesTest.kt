package com.luff.colophon.session

import com.luff.colophon.AccountIdentity
import com.luff.colophon.AccountIdentityKind
import com.luff.colophon.ControllerRole
import com.luff.colophon.KeyDescriptorView
import com.luff.colophon.ListedPath
import com.luff.colophon.PublicKeys
import com.luff.colophon.SignForm
import kotlinx.coroutines.runBlocking
import org.junit.Test
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.time.Instant
import java.util.concurrent.atomic.AtomicLong
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * A software WebAuthn authenticator: assertions as a platform passkey makes them (authenticator data with UP and UV, client
 * data over the core's challenge, a DER signature) and a deterministic PRF. A test double, not a key store.
 */
class TestPasskey(private val rp: String = "id.luff.works", private val credential: ByteArray = byteArrayOf(1, 2, 3)) : AsyncKeyProvider {
    private val key = P256.generate()
    private val point = P256.point(key.public as ECPublicKey)
    override val form get() = SignForm.WEBAUTHN
    private fun prfOf(salt: ByteArray) = SecretBytes.adopt(MessageDigest.getInstance("SHA-256").digest("test-prf".toByteArray() + salt))
    override suspend fun publicKeys() = PublicKeys(point, ByteArray(0))
    override suspend fun sign(body: ByteArray): ByteArray = throw UnsupportedOperationException("a passkey signs assertions")
    override suspend fun sharedSecret(peer: ByteArray): SecretBytes = throw UnsupportedOperationException("a passkey has no agreement key")
    override suspend fun keyDescriptor() = KeyDescriptorView(SignForm.WEBAUTHN, point, null, rp, credential, listOf(), listOf())
    override suspend fun assert(challenge: String, prfSalt: ByteArray?): KeyAssertion {
        val clientData = """{"challenge":"$challenge","origin":"https://$rp","type":"webauthn.get"}""".toByteArray()
        val sha = { b: ByteArray -> MessageDigest.getInstance("SHA-256").digest(b) }
        val authData = sha(rp.toByteArray()) + byteArrayOf(0x05, 0, 0, 0, 0)
        val signature = java.security.Signature.getInstance("SHA256withECDSA").run { initSign(key.private); update(authData + sha(clientData)); sign() }
        return KeyAssertion(signature, authData, clientData, prfSalt?.let(::prfOf))
    }
    override suspend fun prf(salt: ByteArray): SecretBytes = prfOf(salt)
}

/**
 * `appointHomes` against the REAL relay ([RelayHome]): an account created without a home appoints one later and adds a
 * passkey-form controller in one transition. Every session and relay run on one clock the test moves, and the relay has no
 * scheduler timer (heads are published by [RelayHome.tick]), so nothing waits on real time.
 */
class AppointHomesTest {
    private val now = AtomicLong(Instant.parse("2026-11-20T09:00:00Z").toEpochMilli())
    private val clock = { now.get() }
    private val passkeyRoles = listOf(ControllerRole.CONTROL, ControllerRole.RECOVER)

    /** Starts its relay the first time the session asks for the home's request; later calls get a fresh request from it. */
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
    /** The passkey opens its own slot with nothing else: the account unlocks by it alone. */
    private suspend fun unlocksAlone(medium: MemoryMedium, passkey: TestPasskey, account: String): Boolean {
        val id = KeyCustody.keyId(passkey)
        val engine = controllerEngine(medium, id, account)
        try {
            val slot = engine.run { it.slots() }.firstOrNull { s -> s.controllers.map { it.id } == listOf(id) } ?: return false
            val inputs = engine.run { it.beginUnlockSlot(slot.index) }
            engine.finishUnlockSlot(slot.index, KeyCustody.of(listOf(passkey)).answerUnlock(inputs))
            return engine.run { it.isUnlocked() }
        } finally { engine.lock() }
    }

    /**
     * (2) Created without a home, records written, then one `appointHomes` appoints the relay and adds a passkey (control,
     * recover): done at once, the session uploads without a relaunch, a second device joins through the home and reads the
     * records, and the passkey unlocks the account alone.
     */
    @Test fun aHomeAppointedLaterWithAPasskeyServesASecondDevice() = runBlocking<Unit> {
        val relay = RelayHome("https://appoint.test/v1/accounts/kotlin", clockSource = clock)
        val devices = ArrayList<Device>()
        try {
            val first = Device(createWithoutHome = true, now = clock).also { devices.add(it) }
            first.session.create()
            assertEquals(SessionPhase.Ready, first.session.phase, first.describe())
            assertTrue(first.session.homes.isEmpty() && first.session.notices.noHome)
            note(first.session, "a"); note(first.session, "b")
            val account = assertNotNull(first.session.libraryId)

            val passkey = TestPasskey()
            val outcome = first.session.appointHomes(listOf(appointable(relay)), AdditionalController(passkey, "Passkey", passkeyRoles))
            first.session.stopSync()
            assertEquals(HomesAppointment.Done, outcome, "no home before: final at once")
            assertEquals(1, first.session.homes.size)
            assertTrue(!first.session.notices.noHome)
            assertTrue(first.session.state.value.syncState != HomeSyncState.Disabled, "the running session syncs with the appointed home")
            val passkeyId = KeyCustody.keyId(passkey)
            val keyring = controllerEngine(first.medium, passkeyId, account)
            val added = try { keyring.run { it.controllers() }.first { it.id == passkeyId } } finally { keyring.lock() }
            assertEquals(passkeyRoles, added.roles)
            assertTrue(added.hasSlot && !added.provisional && added.form == SignForm.WEBAUTHN)
            settle(first, relay)

            // A second device holding the account's history (as a folder would deliver it), and no records, joins through the home.
            val second = Device(medium = MemoryMedium(first.medium.snapshot().filterKeys { it.startsWith("authority/") }),
                homes = listOf(HomeConfiguration("${relay.base}/", transport = relay.transport())), createWithoutHome = false, now = clock).also { devices.add(it) }
            second.session.restore()
            second.session.stopSync()
            assertEquals(SessionPhase.WaitingForApproval, second.session.phase, second.describe())
            approveByCode(second.session, first.session)
            settle(first, relay)
            settle(second, relay)
            second.session.refresh()
            assertEquals(SessionPhase.Ready, second.session.phase, second.describe())
            settle(second, relay)
            assertEquals(2, admitted(second.session), "the second device reads, through the home, what was written before the home existed")
            assertTrue(unlocksAlone(second.medium, passkey, account), "the passkey unlocks alone")
        } finally {
            devices.forEach { it.close() }
            relay.stop()
        }
    }

    /**
     * (3) A call that stops after any one of its steps (the transition signed, then recorded, then the slot built) is
     * finished by the same call on a relaunched session: one transition, one controller, one slot, one home.
     */
    @Test fun aCallStoppedBetweenStepsIsFinishedByCallingAgain() = runBlocking<Unit> {
        for (step in SessionWorker.AppointStep.entries) {
            val relay = RelayHome("https://appoint.test/v1/accounts/kotlin-crash-${step.name.lowercase()}", clockSource = clock)
            val devices = ArrayList<Device>()
            try {
                val first = Device(createWithoutHome = true, now = clock).also { devices.add(it) }
                first.session.create()
                assertEquals(SessionPhase.Ready, first.session.phase, first.describe())
                note(first.session, "a")
                val account = assertNotNull(first.session.libraryId)
                val home = appointable(relay)
                val passkey = TestPasskey()
                first.session.worker.appointStopForTests = step
                assertFailsWith<SessionWorker.AppointStopped> { first.session.appointHomes(listOf(home), AdditionalController(passkey, "Passkey", passkeyRoles)) }
                first.session.stopSync()
                assertEquals(1, transitions(first.medium), "$step: one transition signed before the stop")

                // A relaunch: a new session over the same store, private directory and device secrets.
                val again = Device(medium = first.medium, member = first.member, owner = first.owner, secrets = first.secrets, dir = first.dir, now = clock)
                again.session.restore()
                now.addAndGet(1000)
                val outcome = again.session.appointHomes(listOf(home), AdditionalController(passkey, "Passkey", passkeyRoles))
                again.session.stopSync()
                assertEquals(HomesAppointment.Done, outcome, "$step")
                assertEquals(1, transitions(first.medium), "$step: nothing was appointed or added twice")
                assertEquals(1, again.session.homes.size, "$step")
                val passkeyId = KeyCustody.keyId(passkey)
                val keyring = controllerEngine(first.medium, passkeyId, account)
                try {
                    val controllers = keyring.run { it.controllers() }
                    assertEquals(1, controllers.count { it.id == passkeyId }, "$step")
                    assertEquals(2, controllers.size, "$step")
                    assertEquals(1, keyring.run { it.slots() }.count { s -> s.controllers.map { it.id } == listOf(passkeyId) }, "$step: one slot of its own")
                } finally { keyring.lock() }
                assertTrue(unlocksAlone(first.medium, passkey, account), "$step")
                again.session.shutdown()
            } finally {
                devices.forEach { it.close() }
                relay.stop()
            }
        }
    }

    /**
     * (4) With a home already current the same call is an ordinary pending transition: it answers `Pending`, and calling it
     * again answers the same transition without signing another.
     */
    @Test fun withAHomeAlreadyCurrentTheCallIsPending() = runBlocking<Unit> {
        val current = RelayHome("https://appoint.test/v1/accounts/kotlin-a", clockSource = clock)
        val next = RelayHome("https://appoint.test/v1/accounts/kotlin-b", clockSource = clock)
        val devices = ArrayList<Device>()
        try {
            val first = Device(homes = listOf(appointable(current)), createWithoutHome = false, now = clock).also { devices.add(it) }
            first.session.create()
            first.session.stopSync()
            assertEquals(SessionPhase.Ready, first.session.phase, first.describe())
            settle(first, current)
            val before = transitions(first.medium)
            val passkey = TestPasskey()
            val home = appointable(next)
            val outcome = first.session.appointHomes(listOf(home), AdditionalController(passkey, "Passkey", passkeyRoles))
            first.session.stopSync()
            val pending = assertIs<HomesAppointment.Pending>(outcome)
            assertEquals(1, pending.transitions.size)
            assertEquals(before + 1, transitions(first.medium))
            assertEquals(1, first.session.homes.size, "not appointed before its delay")
            assertTrue(first.session.notices.pending.any { it.digest == pending.transitions[0] })
            now.addAndGet(1000)
            val repeated = first.session.appointHomes(listOf(home), AdditionalController(passkey, "Passkey", passkeyRoles))
            first.session.stopSync()
            assertEquals(pending, repeated, "the same transition, not a second one")
            assertEquals(before + 1, transitions(first.medium))
        } finally {
            devices.forEach { it.close() }
            current.stop(); next.stop()
        }
    }

    /**
     * A home that answers with another identity after a crash (same endpoint, another member) is not appointed again: the
     * pending appointment names its endpoint. A request that does not name the configured endpoint is refused unsigned.
     */
    @Test fun aHomeIsBoundByItsEndpointNotByTheMemberItAnswersWith() = runBlocking<Unit> {
        val relay = RelayHome("https://appoint.test/v1/accounts/kotlin-rotating", clockSource = clock)
        val impostor = RelayHome(relay.base, clockSource = clock)
        val elsewhere = RelayHome("https://elsewhere.test/v1/accounts/kotlin", clockSource = clock)
        val devices = ArrayList<Device>()
        try {
            val first = Device(createWithoutHome = true, now = clock).also { devices.add(it) }
            first.session.create()
            assertEquals(SessionPhase.Ready, first.session.phase, first.describe())
            val wrong = HomeConfiguration("${relay.base}/", request = { elsewhere.memberRequest(it) }, transport = relay.transport())
            assertFailsWith<SessionError.InvalidCommand> { first.session.appointHomes(listOf(wrong)) }
            assertEquals(0, transitions(first.medium))
            var started = false
            val rotating = HomeConfiguration("${relay.base}/", request = { account ->
                if (!started) { relay.start(account); started = true; relay.memberRequest(account) } else impostor.memberRequest(account)
            }, transport = relay.transport())
            first.session.worker.appointStopForTests = SessionWorker.AppointStep.SIGNED
            assertFailsWith<SessionWorker.AppointStopped> { first.session.appointHomes(listOf(rotating)) }
            first.session.stopSync()
            val again = Device(medium = first.medium, member = first.member, owner = first.owner, secrets = first.secrets, dir = first.dir, now = clock)
            again.session.restore()
            val outcome = again.session.appointHomes(listOf(rotating))
            again.session.stopSync()
            assertEquals(HomesAppointment.Done, outcome)
            assertEquals(1, transitions(first.medium), "not appointed twice")
            assertEquals(listOf(relay.id), again.session.homes.map { it.id }, "the home first appointed, not the impostor")
            again.session.shutdown()
        } finally {
            devices.forEach { it.close() }
            relay.stop(); impostor.stop(); elsewhere.stop()
        }
    }

    /** A key already in the keyring with other roles than asked is refused, not taken as done; nothing is signed. */
    @Test fun anExistingKeyWithOtherRolesIsRefused() = runBlocking<Unit> {
        val relay = RelayHome("https://appoint.test/v1/accounts/kotlin-roles", clockSource = clock)
        val devices = ArrayList<Device>()
        try {
            val first = Device(createWithoutHome = true, now = clock).also { devices.add(it) }
            first.session.create()
            val key = SoftwareKeys()
            first.session.addController(key, "Key", listOf(ControllerRole.APPROVE), immediate = true)
            val before = first.medium.snapshot().size
            assertFailsWith<SessionError.InvalidCommand> {
                first.session.appointHomes(listOf(appointable(relay)), AdditionalController(key, "Key", passkeyRoles))
            }
            assertEquals(before, first.medium.snapshot().size, "nothing signed")
            assertEquals(0, transitions(first.medium))
            assertTrue(first.session.homes.isEmpty())
        } finally {
            devices.forEach { it.close() }
            relay.stop()
        }
    }

    /** A key that is a controller but held only in a combined [owner, key] slot gets its own slot: done means it unlocks alone. */
    @Test fun aKeyInOnlyACombinedSlotGetsItsOwn() = runBlocking<Unit> {
        val relay = RelayHome("https://appoint.test/v1/accounts/kotlin-combined", clockSource = clock)
        val devices = ArrayList<Device>()
        try {
            val first = Device(createWithoutHome = true, now = clock).also { devices.add(it) }
            first.session.create()
            val account = assertNotNull(first.session.libraryId)
            val key = SoftwareKeys()
            first.session.addController(key, "Key", listOf(ControllerRole.APPROVE), immediate = true)
            val ownerId = KeyCustody.keyId(first.owner); val keyId = KeyCustody.keyId(key)
            // The owner builds a slot both keys must open together.
            val owner = controllerEngine(first.medium, ownerId, account)
            val custody = KeyCustody.of(listOf(first.owner, key))
            val written = try {
                val own = owner.run { it.slots() }.first { s -> s.controllers.map { it.id } == listOf(ownerId) }
                val inputs = owner.run { it.beginUnlockSlot(own.index) }
                owner.finishUnlockSlot(own.index, custody.answerUnlock(inputs))
                owner.execute(custody) { e -> withEntropy(32) { e.beginAddSlot(ownerId, com.luff.colophon.SlotPlan(listOf(ownerId, keyId), "Both"), it) } }
            } finally { owner.lock() }
            first.medium.write(written.stores.map { MediumWrite(it.path, it.bytes) })
            val outcome = first.session.appointHomes(listOf(appointable(relay)), AdditionalController(key, "Key", listOf(ControllerRole.APPROVE)))
            first.session.stopSync()
            assertEquals(HomesAppointment.Done, outcome)
            val keyring = controllerEngine(first.medium, keyId, account)
            val slots = try { keyring.run { it.slots() } } finally { keyring.lock() }
            assertEquals(1, slots.count { s -> s.controllers.map { it.id } == listOf(keyId) }, "its own slot was built")
            assertTrue(slots.any { s -> s.controllers.map { it.id }.toSet() == setOf(ownerId, keyId) })
        } finally {
            devices.forEach { it.close() }
            relay.stop()
        }
    }
}
