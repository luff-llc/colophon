import ColophonAuthority
import ColophonCore
import ColophonSaved
import ColophonReplica
import ColophonStore
import CryptoKit
import Foundation
import Testing

/// A software WebAuthn authenticator. It speaks the same bytes `Controller.verify` checks.
struct SyntheticAuthenticator: Sendable {
  let rpID: String
  let signingKey: P256.Signing.PrivateKey
  let credential: Data

  init(rpID: String = "id.luff.works", signingKey: P256.Signing.PrivateKey = P256.Signing.PrivateKey(),
    credential: Data? = nil)
  {
    self.rpID = rpID
    self.signingKey = signingKey
    self.credential = credential ?? SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
  }

  var publicKey: Data { signingKey.publicKey.x963Representation }
  var signingScalar: Data { signingKey.rawRepresentation }

  func controller(roles: [String], verification: Bool? = nil, label: String = "Passkey") throws -> Controller {
    try Controller.webauthn(coseKey: coseKey(), rpID: rpID, credential: credential, label: label, roles: roles,
      verification: verification)
  }

  /// ES256 COSE_Key for this public key. `algorithm` defaults to -7; other values are for rejection tests.
  func coseKey(algorithm: Int = -7) throws -> Data {
    let raw = publicKey
    guard raw.count == 65, algorithm < 0, algorithm > -24 else { throw ColophonError.malformed("COSE key") }
    var data = Data([0xa5, 0x01, 0x02, 0x03, 0x20 | UInt8(-1 - algorithm), 0x20, 0x01, 0x21, 0x58, 0x20])
    data.append(raw.subdata(in: 1 ..< 33))
    data.append(contentsOf: [0x22, 0x58, 0x20])
    data.append(raw.subdata(in: 33 ..< 65))
    return data
  }

  func signer(controller: Controller, userVerified: Bool = true) throws -> WebAuthnControllerSigner {
    let authenticator = self
    return try WebAuthnControllerSigner(controller: controller) { challenge in
      let made = try authenticator.assertion(challenge: challenge, userVerified: userVerified)
      return (made.signature, made.authenticatorData, made.clientData)
    }
  }

  /// `challenge` is the raw bytes placed in clientData, not hashed again. Signers pass SHA-256(body).
  func assertion(challenge: Data, userPresent: Bool = true, userVerified: Bool = true, origin: String? = nil,
    type: String = "webauthn.get", crossOrigin: Bool? = nil, rpIDForHash: String? = nil,
    key: P256.Signing.PrivateKey? = nil) throws -> SyntheticAssertion
  {
    let client = ClientData(type: type, challenge: base64url(challenge), origin: origin ?? "https://\(rpID)",
      crossOrigin: crossOrigin)
    let clientData = try Canonical.encode(client)
    var flags: UInt8 = 0
    if userPresent { flags |= 0x01 }
    if userVerified { flags |= 0x04 }
    var authenticatorData = Data(SHA256.hash(data: Data((rpIDForHash ?? rpID).utf8)))
    authenticatorData.append(flags)
    authenticatorData.append(contentsOf: [0, 0, 0, 0])
    let message = authenticatorData + Data(SHA256.hash(data: clientData))
    let signature = try (key ?? signingKey).signature(for: message).derRepresentation
    return SyntheticAssertion(signature: signature, authenticatorData: authenticatorData, clientData: clientData)
  }

  private struct ClientData: Encodable {
    let type: String
    let challenge: String
    let origin: String
    let crossOrigin: Bool?
  }
}

struct SyntheticAssertion: Sendable {
  let signature: Data
  let authenticatorData: Data
  let clientData: Data
  var assertion: Assertion { Assertion(authenticatorData: authenticatorData, clientData: clientData) }
}

func p256Controller(_ identity: some Identity, roles: [String], label: String) -> Controller {
  Controller(kind: "p256", key: identity.publicIdentity.signing, rpID: nil, credential: nil, label: label, roles: roles,
    verification: nil)
}

func random32() -> Data { SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) } }

func cosignature(_ signer: some ControllerSigner, over body: Data) throws -> SignedRecord.Cosignature {
  let signed = try signer.sign(body)
  return SignedRecord.Cosignature(signer: signer.controller.id, signature: signed.signature, assertion: signed.assertion)
}

func base64url(_ data: Data) -> String {
  data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
    .replacingOccurrences(of: "=", with: "")
}

/// Controller keyring (spec §6.6), including the recovery-policy format.
@Suite struct KeyringTests {
  let store = MemoryStore()
  let root = SoftwareIdentity()
  let phone = SoftwareIdentity()

  func library(in store: MemoryStore, namespaces: [String] = [SavedLinks.namespace]) throws -> (AuthorityHolder, RecoveryKit) {
    try AuthorityHolder.create(in: store, label: "Library", root: root, firstMember: phone.publicIdentity, memberLabel: "Phone",
      custody: .software, namespaces: namespaces)
  }

  func latest(in store: MemoryStore) throws -> Int {
    var seq = 1
    while try store.read(LibraryPath.authority(seq + 1)) != nil { seq += 1 }
    return seq
  }

  func refused(_ seq: Int) -> ColophonError { .badSignature("authority entry \(seq)") }

  func entryObject(in store: MemoryStore, at seq: Int) throws -> [String: JSONValue] {
    let record = try Canonical.decode(SignedRecord.self, from: #require(try store.read(LibraryPath.authority(seq))))
    return try Canonical.decode([String: JSONValue].self, from: record.body)
  }

  func json(_ value: some Encodable) throws -> JSONValue {
    try Canonical.decode(JSONValue.self, from: Canonical.encode(value))
  }

  @discardableResult
  func writeEntry(in store: MemoryStore, _ fields: [String: JSONValue], signer: (any Identity)? = nil) throws -> Int {
    let seq = try latest(in: store) + 1
    let previous = try Canonical.decode(SignedRecord.self, from: #require(try store.read(LibraryPath.authority(seq - 1))))
    var entry = fields
    entry["seq"] = .number(Double(seq))
    entry["previous"] = .string(Canonical.digest(previous.body))
    if entry["issued"] == nil { entry["issued"] = .string("2026-10-26T12:00:00Z") }
    let body = try Canonical.encode(JSONValue.object(entry))
    let record: SignedRecord
    if let signer {
      record = try SignedRecord(signing: body, with: signer)
    } else {
      record = SignedRecord(body: body, signature: Data(repeating: 0, count: 64))
    }
    try store.create(LibraryPath.authority(seq), Canonical.encode(record))
    return seq
  }

  /// A root-signed entry with something extra on the record, for upgrade rejections.
  @discardableResult
  func writeDecorated(in store: MemoryStore, _ fields: [String: JSONValue],
    decorate: (inout SignedRecord) -> Void) throws -> Int
  {
    let seq = try latest(in: store) + 1
    let previous = try Canonical.decode(SignedRecord.self, from: #require(try store.read(LibraryPath.authority(seq - 1))))
    var entry = fields
    entry["seq"] = .number(Double(seq))
    entry["previous"] = .string(Canonical.digest(previous.body))
    if entry["issued"] == nil { entry["issued"] = .string("2026-10-26T12:00:00Z") }
    let body = try Canonical.encode(JSONValue.object(entry))
    var record = try SignedRecord(signing: body, with: root)
    decorate(&record)
    try store.create(LibraryPath.authority(seq), Canonical.encode(record))
    return seq
  }

  // MARK: Upgrade and 0.1

  @Test func upgradeKeepsTheLibraryAndRefusesTheRoot() throws {
    let (holder, _) = try library(in: store)
    let phoneReplica = Replica(store: store, identity: phone)
    let beforeWrite = try phoneReplica.perform(SavedLinks.capture(url: "https://example.com/before", title: "Before"))
    let libraryID = try holder.state().libraryID
    let adoptedBefore = try holder.state().isKeyring
    #expect(adoptedBefore == false)

    let owner = SoftwareIdentity()
    let ownerController = p256Controller(owner, roles: ["approve", "control"], label: "Owner")
    _ = try holder.upgrade(to: [ownerController], threshold: 1) { key in
      [try VaultSlot.sealed(seed: key.seed, to: owner.publicIdentity, controller: ownerController.id, label: "Owner")]
    }
    let state = try AuthorityLog(store: store).state()
    #expect(state.libraryID == libraryID)
    #expect(state.isKeyring)
    #expect(state.keyring?.recoverThreshold == 1)
    let omitted = try entryObject(in: store, at: state.latest)["recoverThreshold"]
    #expect(omitted == nil)

    let afterWrite = try phoneReplica.perform(SavedLinks.capture(url: "https://example.com/after", title: "After"))
    let ids = try phoneReplica.read(SavedLinks.namespace).admitted.map(\.id)
    #expect(ids.contains(beforeWrite.id))
    #expect(ids.contains(afterWrite.id))

    #expect(throws: ColophonError.notTheRoot) {
      try AuthorityHolder(log: AuthorityLog(store: store), root: root)
    }
    let seq = try latest(in: store)
    #expect(throws: ColophonError.notTheRoot) {
      try holder.admit(SoftwareIdentity().publicIdentity, label: "Later", role: .app, custody: .software,
        namespaces: [SavedLinks.namespace], write: false)
    }
    let afterRefusal = try latest(in: store)
    #expect(afterRefusal == seq)
  }

  @Test func aControllerSignatureBeforeUpgradeIsBad() throws {
    _ = try library(in: store)
    let seq = try writeEntry(in: store, ["kind": .string("grant"), "by": .string("controller"), "signer": .string(phone.id)],
      signer: phone)
    #expect(throws: refused(seq)) { try AuthorityLog(store: store).state() }
  }

  @Test func passkeyApprovesTwoNamespacesInOneCall() throws {
    let (holder, _) = try library(in: store, namespaces: [SavedLinks.namespace, "notes"])
    let phoneReplica = Replica(store: store, identity: phone)
    let saved = try phoneReplica.perform(SavedLinks.capture(url: "https://example.com/a", title: "Saved"))
    let note = try phoneReplica.perform(Command(namespace: "notes", kind: "notebook.create",
      payload: ["notebook": "n", "title": "Notes"]))
    let authenticator = SyntheticAuthenticator()
    let passkey = try authenticator.controller(roles: ["approve", "control"], verification: true)
    let output = random32()
    let salt = random32()
    let vault = try holder.upgrade(to: [passkey], threshold: 1) { key in
      [try VaultSlot.prf(seed: key.seed, prfOutput: output, salt: salt, credential: authenticator.credential,
        controller: passkey.id, label: "Passkey")]
    }
    let opened = try KeyringHolder.openVault(state: try AuthorityLog(store: store).state(), prfOutput: output,
      credential: authenticator.credential)
    #expect(opened.seed == vault.seed)

    let ring = try KeyringHolder(log: AuthorityLog(store: store), signer: try authenticator.signer(controller: passkey),
      vault: vault)
    let app = SoftwareIdentity()
    let appReplica = Replica(store: store, identity: app)
    try appReplica.requestEnrollment(label: "Later", role: .app, namespaces: [SavedLinks.namespace, "notes"], write: true)
    try ring.approveAsRequested(try #require(ring.pendingRequests().first))
    let savedIDs = try appReplica.read(SavedLinks.namespace).admitted.map(\.id)
    let noteIDs = try appReplica.read("notes").admitted.map(\.id)
    #expect(savedIDs.contains(saved.id))
    #expect(noteIDs.contains(note.id))
    let nextSaved = try appReplica.perform(SavedLinks.capture(url: "https://example.com/b", title: "Next"))
    let nextNote = try appReplica.perform(Command(namespace: "notes", kind: "notebook.create",
      payload: ["notebook": "m", "title": "More"]))
    let savedAfter = try appReplica.read(SavedLinks.namespace).admitted.map(\.id)
    let notesAfter = try appReplica.read("notes").admitted.map(\.id)
    #expect(savedAfter.contains(nextSaved.id))
    #expect(notesAfter.contains(nextNote.id))
  }

  // MARK: Signatures and slots

  @Test func webAuthnVerificationRefusesTamperedAssertions() throws {
    let authenticator = SyntheticAuthenticator()
    let strict = try authenticator.controller(roles: ["approve"], verification: true)
    let relaxed = try authenticator.controller(roles: ["approve"], verification: nil)
    let body = Data("keyring-body".utf8)
    let challenge = Data(SHA256.hash(data: body))
    let good = try authenticator.assertion(challenge: challenge)
    #expect(strict.verify(signature: good.signature, assertion: good.assertion, over: body, requireVerification: false))

    let subdomain = try authenticator.assertion(challenge: challenge, origin: "https://www.id.luff.works")
    #expect(strict.verify(signature: subdomain.signature, assertion: subdomain.assertion, over: body, requireVerification: false))

    let otherChallenge = try authenticator.assertion(challenge: Data("other".utf8))
    #expect(!strict.verify(signature: otherChallenge.signature, assertion: otherChallenge.assertion, over: body,
      requireVerification: false))
    let otherRP = try authenticator.assertion(challenge: challenge, rpIDForHash: "evil.example")
    #expect(!strict.verify(signature: otherRP.signature, assertion: otherRP.assertion, over: body, requireVerification: false))
    let otherOrigin = try authenticator.assertion(challenge: challenge, origin: "https://evil.example")
    #expect(!strict.verify(signature: otherOrigin.signature, assertion: otherOrigin.assertion, over: body,
      requireVerification: false))
    let prefixed = try authenticator.assertion(challenge: challenge, origin: "https://evil-id.luff.works")
    #expect(!strict.verify(signature: prefixed.signature, assertion: prefixed.assertion, over: body,
      requireVerification: false))
    let suffixed = try authenticator.assertion(challenge: challenge, origin: "https://id.luff.works.evil.com")
    #expect(!strict.verify(signature: suffixed.signature, assertion: suffixed.assertion, over: body,
      requireVerification: false))
    let emptyLabel = try authenticator.assertion(challenge: challenge, origin: "https://.id.luff.works")
    #expect(!strict.verify(signature: emptyLabel.signature, assertion: emptyLabel.assertion, over: body,
      requireVerification: false))
    let port = try authenticator.assertion(challenge: challenge, origin: "https://id.luff.works:443")
    #expect(!strict.verify(signature: port.signature, assertion: port.assertion, over: body, requireVerification: false))
    let created = try authenticator.assertion(challenge: challenge, type: "webauthn.create")
    #expect(!strict.verify(signature: created.signature, assertion: created.assertion, over: body, requireVerification: false))
    let crossed = try authenticator.assertion(challenge: challenge, crossOrigin: true)
    #expect(!strict.verify(signature: crossed.signature, assertion: crossed.assertion, over: body, requireVerification: false))
    let noUP = try authenticator.assertion(challenge: challenge, userPresent: false)
    #expect(!strict.verify(signature: noUP.signature, assertion: noUP.assertion, over: body, requireVerification: false))
    let noUV = try authenticator.assertion(challenge: challenge, userVerified: false)
    #expect(!strict.verify(signature: noUV.signature, assertion: noUV.assertion, over: body, requireVerification: false))
    #expect(!relaxed.verify(signature: noUV.signature, assertion: noUV.assertion, over: body, requireVerification: true))
    #expect(relaxed.verify(signature: noUV.signature, assertion: noUV.assertion, over: body, requireVerification: false))
    let other = SyntheticAuthenticator()
    let foreign = try authenticator.assertion(challenge: challenge, key: other.signingKey)
    #expect(!strict.verify(signature: foreign.signature, assertion: foreign.assertion, over: body, requireVerification: false))

    let owner = SoftwareIdentity()
    let p256 = p256Controller(owner, roles: ["approve"], label: "Phone")
    let signature = try owner.sign(body)
    #expect(p256.verify(signature: signature, assertion: nil, over: body, requireVerification: false))
    #expect(!p256.verify(signature: signature, assertion: good.assertion, over: body, requireVerification: false))
  }

  @Test func coseKeyRoundTripsAndRejectsOtherAlgorithms() throws {
    let authenticator = SyntheticAuthenticator()
    let controller = try authenticator.controller(roles: ["approve"])
    #expect(controller.key == authenticator.publicKey)
    #expect(throws: ColophonError.malformed("COSE key")) {
      try Controller.webauthn(coseKey: authenticator.coseKey(algorithm: -8), rpID: authenticator.rpID,
        credential: authenticator.credential, label: "Passkey", roles: ["approve"], verification: nil)
    }
  }

  @Test func prfAndCombinedSlots() throws {
    let seed = random32()
    let output = random32()
    let salt = random32()
    let credential = Data("credential".utf8)
    let prf = try VaultSlot.prf(seed: seed, prfOutput: output, salt: salt, credential: credential, controller: nil,
      label: "Passkey")
    let opened = try prf.open(prfOutput: output)
    #expect(opened.seed == seed)
    #expect(throws: ColophonError.vaultLocked) { try prf.open(prfOutput: random32()) }

    let (part, secret) = try VaultSlotPart.prf(prfOutput: output, salt: salt, credential: credential, controller: nil)
    let derived = try part.secret(prfOutput: output)
    #expect(derived == secret)

    let alice = SoftwareIdentity()
    let bob = SoftwareIdentity()
    let (partA, _) = try VaultSlotPart.sealed(to: alice.publicIdentity, controller: nil)
    let (partB, _) = try VaultSlotPart.sealed(to: bob.publicIdentity, controller: nil)
    let secretA = try partA.secret(with: alice)
    let secretB = try partB.secret(with: bob)
    let combined = try VaultSlot.combined(seed: seed, parts: [(partA, secretA), (partB, secretB)], controller: nil,
      label: "Two keys")
    let both = try combined.open(partSecrets: [secretA, secretB])
    #expect(both.seed == seed)
    #expect(throws: ColophonError.vaultLocked) { try combined.open(partSecrets: [secretA]) }
    #expect(throws: ColophonError.vaultLocked) { try combined.open(partSecrets: [secretB, secretA]) }
    let wrong = random32()
    #expect(throws: ColophonError.vaultLocked) { try combined.open(partSecrets: [secretA, wrong]) }
    #expect(throws: ColophonError.malformed("vault slot")) {
      try VaultSlot.combined(seed: seed, parts: [(partA, secretA)], controller: nil, label: "One")
    }
  }

  @Test func enrollmentRequestWithoutWriteDecodes() throws {
    let member = SoftwareIdentity().publicIdentity
    let older = EnrollmentRequest(member: member, label: "Phone", role: .device, custody: .software,
      namespaces: [SavedLinks.namespace], write: nil)
    let encoded = try Canonical.encode(older)
    let fields = try Canonical.decode([String: JSONValue].self, from: encoded)
    #expect(fields["write"] == nil)
    let decoded = try Canonical.decode(EnrollmentRequest.self, from: encoded)
    #expect(decoded.write == nil)

    let current = EnrollmentRequest(member: member, label: "Phone", role: .device, custody: .software,
      namespaces: [SavedLinks.namespace], write: true)
    var withWrite = try Canonical.decode([String: JSONValue].self, from: Canonical.encode(current))
    withWrite.removeValue(forKey: "write")
    let stripped = try Canonical.decode(EnrollmentRequest.self, from: Canonical.encode(withWrite))
    #expect(stripped.write == nil)

    _ = try library(in: store)
    let request = try Replica(store: store, identity: phone).requestEnrollment(label: "Phone", role: .device,
      namespaces: [SavedLinks.namespace])
    #expect(request.write == true)
  }

  // MARK: Changes

  @Test func recoveryKitCanAddButNotRemoveOrLowerTheThreshold() throws {
    let (holder, kit) = try library(in: store)
    let first = SoftwareIdentity()
    let second = SoftwareIdentity()
    let firstController = p256Controller(first, roles: ["approve", "control"], label: "First")
    let secondController = p256Controller(second, roles: ["approve", "control"], label: "Second")
    let kitIdentity = try kit.identity()
    let kitController = p256Controller(kitIdentity, roles: ["recover"], label: "Recovery kit")
    let vault = try holder.upgrade(to: [firstController, secondController, kitController], threshold: 2) { key in
      [try VaultSlot.sealed(seed: key.seed, to: kitIdentity.publicIdentity, controller: kitController.id, label: "Kit")]
    }
    let kitSigner = try P256ControllerSigner(identity: kitIdentity, controller: kitController)
    let kitHolder = try KeyringHolder(log: AuthorityLog(store: store), signer: kitSigner, vault: nil)
    let ipad = SoftwareIdentity()
    let ipadController = p256Controller(ipad, roles: ["approve"], label: "iPad")
    try kitHolder.addController(ipadController, slot: try VaultSlot.sealed(seed: vault.seed, to: ipad.publicIdentity,
      controller: ipadController.id, label: "iPad"))
    let added = try kitHolder.state().keyring?.controllers[ipadController.id]
    #expect(added != nil)

    let before = try latest(in: store)
    #expect(throws: refused(before + 1)) {
      try kitHolder.removeController(id: ipadController.id) { newKey in
        [try VaultSlot.sealed(seed: newKey.seed, to: first.publicIdentity, controller: firstController.id, label: "First")]
      }
    }
    let body = try kitHolder.keyringChange { ring in
      (controllers: Array(ring.controllers.values), threshold: 1, slots: ring.slots, rotateVault: false,
        recoverThreshold: ring.recoverThreshold)
    }
    #expect(throws: refused(before + 1)) {
      try kitHolder.completeKeyringChange(body: body, signatures: [try cosignature(kitSigner, over: body)])
    }
    let after = try latest(in: store)
    #expect(after == before)
  }

  @Test func thresholdTwoNeedsTwoControlSignatures() throws {
    let (holder, _) = try library(in: store)
    let first = SoftwareIdentity()
    let second = SoftwareIdentity()
    let firstController = p256Controller(first, roles: ["approve", "control"], label: "First")
    let secondController = p256Controller(second, roles: ["approve", "control"], label: "Second")
    _ = try holder.upgrade(to: [firstController, secondController], threshold: 2) { key in
      [try VaultSlot.sealed(seed: key.seed, to: first.publicIdentity, controller: firstController.id, label: "First")]
    }
    let firstSigner = try P256ControllerSigner(identity: first, controller: firstController)
    let secondSigner = try P256ControllerSigner(identity: second, controller: secondController)
    let ring = try KeyringHolder(log: AuthorityLog(store: store), signer: firstSigner, vault: nil)
    let added = SoftwareIdentity()
    let addedController = p256Controller(added, roles: ["approve"], label: "Added")
    let body = try ring.keyringChange { current in
      var controllers = Array(current.controllers.values)
      controllers.append(addedController)
      return (controllers: controllers, threshold: current.threshold, slots: current.slots, rotateVault: false,
        recoverThreshold: current.recoverThreshold)
    }
    let before = try latest(in: store)
    #expect(throws: refused(before + 1)) {
      try ring.completeKeyringChange(body: body, signatures: [try cosignature(firstSigner, over: body)])
    }
    try ring.completeKeyringChange(body: body, signatures: [
      try cosignature(secondSigner, over: body),
      try cosignature(firstSigner, over: body),
    ])
    let present = try ring.state().keyring?.controllers[addedController.id]
    #expect(present != nil)
    let after = try latest(in: store)
    #expect(after == before + 1)
  }

  @Test func removingAControllerRotatesTheVault() throws {
    let (holder, _) = try library(in: store)
    let owner = SoftwareIdentity()
    let guest = SoftwareIdentity()
    let ownerController = p256Controller(owner, roles: ["approve", "control"], label: "Owner")
    let guestController = p256Controller(guest, roles: ["approve", "control"], label: "Guest")
    let vault = try holder.upgrade(to: [ownerController, guestController], threshold: 1) { key in
      [
        try VaultSlot.sealed(seed: key.seed, to: owner.publicIdentity, controller: ownerController.id, label: "Owner"),
        try VaultSlot.sealed(seed: key.seed, to: guest.publicIdentity, controller: guestController.id, label: "Guest"),
      ]
    }
    let before = try AuthorityLog(store: store).state()
    let oldVault = try #require(before.keyring).vault
    let guestSlot = try #require(before.keyring?.slots.first { $0.controller == guestController.id })
    let signer = try P256ControllerSigner(identity: owner, controller: ownerController)
    let ring = try KeyringHolder(log: AuthorityLog(store: store), signer: signer, vault: vault)
    try ring.removeController(id: guestController.id) { newKey in
      [try VaultSlot.sealed(seed: newKey.seed, to: owner.publicIdentity, controller: ownerController.id, label: "Owner")]
    }
    let state = try ring.state()
    let newVault = try #require(state.keyring).vault
    #expect(newVault != oldVault)
    #expect(throws: ColophonError.vaultLocked) { try KeyringHolder.openVault(state: state, with: guest) }
    let openedOld = try guestSlot.open(with: guest)
    let openedIdentity = try openedOld.identity().publicIdentity
    #expect(openedIdentity == oldVault)
    let epoch = try #require(state.epoch(of: SavedLinks.namespace))
    let shares = try #require(state.keys[SavedLinks.namespace]?[epoch])
    let oldShare = shares[oldVault.id]
    let rootShare = shares[root.id]
    let phoneShare = shares[phone.id]
    let newShare = shares[newVault.id]
    #expect(oldShare == nil)
    #expect(rootShare == nil)
    #expect(phoneShare != nil)
    #expect(newShare != nil)
  }

  @Test func unknownKeyringVocabularyNeedsANewerClient() throws {
    let smartcard = Controller(kind: "smartcard", key: Data(repeating: 0x04, count: 65), rpID: nil, credential: nil,
      label: "Card", roles: ["approve"], verification: nil)
    let administered = Controller(kind: "p256", key: SoftwareIdentity().publicIdentity.signing, rpID: nil, credential: nil,
      label: "Phone", roles: ["administer"], verification: nil)
    let known = p256Controller(SoftwareIdentity(), roles: ["control"], label: "Phone")
    let shamir = VaultSlot(kind: "shamir", controller: nil, label: "Split", recipient: nil, sealed: nil, credential: nil,
      salt: nil, box: nil)
    let xor = VaultSlotPart(kind: "xor", credential: nil, salt: nil, recipient: nil, sealed: nil, controller: nil)
    let combined = VaultSlot(kind: "combined", controller: nil, label: "Split", recipient: nil, sealed: nil, credential: nil,
      salt: nil, box: Data([1]), parts: [xor])
    let cases: [[String: JSONValue]] = [
      ["kind": .string("keyring"), "by": .string("root"), "controllers": .array([try json(smartcard)])],
      ["kind": .string("keyring"), "by": .string("root"), "controllers": .array([try json(administered)])],
      ["kind": .string("keyring"), "by": .string("root"), "controllers": .array([try json(known)]),
        "slots": .array([try json(shamir)])],
      ["kind": .string("keyring"), "by": .string("root"), "controllers": .array([try json(known)]),
        "slots": .array([try json(combined)])],
    ]
    for fields in cases {
      let local = MemoryStore()
      _ = try library(in: local)
      let seq = try writeEntry(in: local, fields)
      #expect(throws: ColophonError.newerAuthority(seq)) { try AuthorityLog(store: local).state() }
    }
  }

  @Test func incompleteKeyringBreaksTheChain() throws {
    let owner = SoftwareIdentity()
    let control = p256Controller(owner, roles: ["control"], label: "Owner")
    let recovering = p256Controller(owner, roles: ["control", "recover"], label: "Owner")
    let missing = VaultSlot(kind: "combined", controller: nil, label: "Two", recipient: nil, sealed: nil, credential: nil,
      salt: nil, box: nil)
    let vault = VaultKey()
    let sealed = try VaultSlot.sealed(seed: vault.seed, to: owner.publicIdentity, controller: recovering.id, label: "Owner")
    let cases: [[String: JSONValue]] = [
      try keyringFields(controllers: [control], slots: [missing]),
      try keyringFields(controllers: [recovering], slots: [sealed], recoverThreshold: 5),
      try keyringFields(controllers: [control], slots: [sealed], recoverThreshold: 1),
    ]
    for fields in cases {
      let local = MemoryStore()
      _ = try library(in: local)
      let seq = try writeEntry(in: local, fields, signer: root)
      #expect(throws: ColophonError.brokenAuthorityChain(seq)) { try AuthorityLog(store: local).state() }
    }
  }

  func keyringFields(controllers: [Controller], slots: [VaultSlot], threshold: Int = 1, recoverThreshold: Int? = nil)
    throws -> [String: JSONValue]
  {
    var fields: [String: JSONValue] = [
      "kind": .string("keyring"),
      "by": .string("root"),
      "threshold": .number(Double(threshold)),
      "controllers": .array(try controllers.map { try json($0) }),
      "slots": .array(try slots.map { try json($0) }),
      "vault": try json(root.publicIdentity),
    ]
    if let recoverThreshold { fields["recoverThreshold"] = .number(Double(recoverThreshold)) }
    return fields
  }

  // MARK: Recovery policy

  @Test func standardPolicyRecoversWithThePasskey() throws {
    let (holder, _) = try library(in: store)
    let authenticator = SyntheticAuthenticator()
    let passkey = try authenticator.controller(roles: ["approve", "control", "recover"], verification: true)
    let output = random32()
    let salt = random32()
    let vault = try holder.upgrade(to: [passkey], threshold: 1) { key in
      [try VaultSlot.prf(seed: key.seed, prfOutput: output, salt: salt, credential: authenticator.credential,
        controller: passkey.id, label: "Passkey")]
    }
    let state = try AuthorityLog(store: store).state()
    let opened = try KeyringHolder.openVault(state: state, prfOutput: output, credential: authenticator.credential)
    #expect(opened.seed == vault.seed)
    #expect(state.keyring?.recoverThreshold == 1)
    let omitted = try entryObject(in: store, at: state.latest)["recoverThreshold"]
    #expect(omitted == nil)

    let ring = try KeyringHolder(log: AuthorityLog(store: store), signer: try authenticator.signer(controller: passkey),
      vault: vault)
    let ipad = SoftwareIdentity()
    let ipadController = p256Controller(ipad, roles: ["approve"], label: "iPad")
    try ring.addController(ipadController, slot: try VaultSlot.sealed(seed: vault.seed, to: ipad.publicIdentity,
      controller: ipadController.id, label: "iPad"))
    let added = try ring.state().keyring?.controllers[ipadController.id]
    #expect(added != nil)
  }

  @Test func twoKeysRefusesOneKeyAndAcceptsTwo() throws {
    let (holder, _) = try library(in: store)
    let first = SoftwareIdentity()
    let second = SoftwareIdentity()
    let device = SoftwareIdentity()
    let firstController = p256Controller(first, roles: ["approve", "control", "recover"], label: "Passkey")
    let secondController = p256Controller(second, roles: ["approve", "control", "recover"], label: "Security key")
    let deviceController = p256Controller(device, roles: ["approve"], label: "iPhone")
    let (partA, secretA) = try VaultSlotPart.sealed(to: first.publicIdentity, controller: firstController.id)
    let (partB, secretB) = try VaultSlotPart.sealed(to: second.publicIdentity, controller: secondController.id)
    let vault = try holder.upgrade(to: [firstController, secondController, deviceController], threshold: 2, recoverThreshold: 2)
    { key in
      let combined = try VaultSlot.combined(seed: key.seed, parts: [(partA, secretA), (partB, secretB)], controller: nil,
        label: "Two keys")
      let deviceSlot = try VaultSlot.sealed(seed: key.seed, to: device.publicIdentity, controller: deviceController.id,
        label: "iPhone")
      return [combined, deviceSlot]
    }
    let state = try AuthorityLog(store: store).state()
    #expect(state.keyring?.recoverThreshold == 2)
    let recorded = try entryObject(in: store, at: state.latest)["recoverThreshold"]?.int
    #expect(recorded == 2)
    let deviceVault = try KeyringHolder.openVault(state: state, with: device)
    #expect(deviceVault.seed == vault.seed)
    #expect(throws: ColophonError.vaultLocked) { try KeyringHolder.openVault(state: state, with: first) }

    let combined = try #require(state.keyring?.slots.first { $0.kind == "combined" })
    let parts = try #require(combined.parts)
    var ordered: [Data] = []
    for part in parts {
      if part.controller == firstController.id { ordered.append(try part.secret(with: first)) }
      else { ordered.append(try part.secret(with: second)) }
    }
    #expect(throws: ColophonError.vaultLocked) { try combined.open(partSecrets: [ordered[0]]) }
    let opened = try combined.open(partSecrets: ordered)
    #expect(opened.seed == vault.seed)

    let firstSigner = try P256ControllerSigner(identity: first, controller: firstController)
    let secondSigner = try P256ControllerSigner(identity: second, controller: secondController)
    let ring = try KeyringHolder(log: AuthorityLog(store: store), signer: firstSigner, vault: nil)
    let added = SoftwareIdentity()
    let addedController = p256Controller(added, roles: ["approve"], label: "iPad")
    let before = try latest(in: store)
    #expect(throws: refused(before + 1)) { try ring.addController(addedController, slot: nil) }
    let unchanged = try latest(in: store)
    #expect(unchanged == before)
    let body = try ring.keyringChange { current in
      var controllers = Array(current.controllers.values)
      controllers.append(addedController)
      return (controllers: controllers, threshold: current.threshold, slots: current.slots, rotateVault: false,
        recoverThreshold: current.recoverThreshold)
    }
    try ring.completeKeyringChange(body: body, signatures: [
      try cosignature(secondSigner, over: body),
      try cosignature(firstSigner, over: body),
    ])
    let present = try ring.state().keyring?.controllers[addedController.id]
    #expect(present != nil)
  }

  @Test func leavingTwoKeysNeedsTheRecoveryThreshold() throws {
    let (holder, _) = try library(in: store)
    let first = SoftwareIdentity()
    let second = SoftwareIdentity()
    let kit = SoftwareIdentity()
    let firstController = p256Controller(first, roles: ["approve", "control", "recover"], label: "Passkey")
    let secondController = p256Controller(second, roles: ["approve", "control"], label: "Security key")
    let kitController = p256Controller(kit, roles: ["recover"], label: "Recovery kit")
    _ = try holder.upgrade(to: [firstController, secondController, kitController], threshold: 2, recoverThreshold: 2) { key in
      [try VaultSlot.sealed(seed: key.seed, to: first.publicIdentity, controller: firstController.id, label: "Passkey")]
    }
    let firstSigner = try P256ControllerSigner(identity: first, controller: firstController)
    let secondSigner = try P256ControllerSigner(identity: second, controller: secondController)
    let kitSigner = try P256ControllerSigner(identity: kit, controller: kitController)
    let ring = try KeyringHolder(log: AuthorityLog(store: store), signer: firstSigner, vault: nil)
    let body = try ring.keyringChange { current in
      (controllers: Array(current.controllers.values), threshold: current.threshold, slots: current.slots, rotateVault: false,
        recoverThreshold: 1)
    }
    let before = try latest(in: store)
    #expect(throws: refused(before + 1)) {
      try ring.completeKeyringChange(body: body, signatures: [try cosignature(firstSigner, over: body)])
    }
    #expect(throws: refused(before + 1)) {
      try ring.completeKeyringChange(body: body, signatures: [
        try cosignature(firstSigner, over: body),
        try cosignature(secondSigner, over: body),
      ])
    }
    let unchanged = try latest(in: store)
    #expect(unchanged == before)
    try ring.completeKeyringChange(body: body, signatures: [
      try cosignature(firstSigner, over: body),
      try cosignature(secondSigner, over: body),
      try cosignature(kitSigner, over: body),
    ])
    let state = try ring.state()
    #expect(state.keyring?.recoverThreshold == 1)
    let omitted = try entryObject(in: store, at: state.latest)["recoverThreshold"]
    #expect(omitted == nil)
  }

  @Test func recoverySignersCannotLowerTheThreshold() throws {
    let (holder, _) = try library(in: store)
    let controlA = SoftwareIdentity()
    let controlB = SoftwareIdentity()
    let first = SoftwareIdentity()
    let second = SoftwareIdentity()
    let controlAController = p256Controller(controlA, roles: ["approve", "control"], label: "Passkey")
    let controlBController = p256Controller(controlB, roles: ["approve", "control"], label: "Security key")
    let firstController = p256Controller(first, roles: ["recover"], label: "Recovery kit")
    let secondController = p256Controller(second, roles: ["recover"], label: "Second kit")
    _ = try holder.upgrade(to: [controlAController, controlBController, firstController, secondController], threshold: 2,
      recoverThreshold: 2) { key in
      [try VaultSlot.sealed(seed: key.seed, to: controlA.publicIdentity, controller: controlAController.id, label: "Passkey")]
    }
    let firstSigner = try P256ControllerSigner(identity: first, controller: firstController)
    let secondSigner = try P256ControllerSigner(identity: second, controller: secondController)
    let ring = try KeyringHolder(log: AuthorityLog(store: store), signer: firstSigner, vault: nil)
    let body = try ring.keyringChange { current in
      (controllers: Array(current.controllers.values), threshold: current.threshold, slots: current.slots, rotateVault: false,
        recoverThreshold: 1)
    }
    let before = try latest(in: store)
    #expect(throws: refused(before + 1)) {
      try ring.completeKeyringChange(body: body, signatures: [
        try cosignature(firstSigner, over: body),
        try cosignature(secondSigner, over: body),
      ])
    }
    let after = try latest(in: store)
    #expect(after == before)
  }

  @Test func noPasskeyKeepsApprovalWithoutRecovery() throws {
    let (holder, kit) = try library(in: store)
    let authenticator = SyntheticAuthenticator()
    let passkey = try authenticator.controller(roles: ["approve"], verification: true, label: "Passkey")
    let security = SoftwareIdentity()
    let securityController = p256Controller(security, roles: ["control"], label: "Security key")
    let kitIdentity = try kit.identity()
    let kitController = p256Controller(kitIdentity, roles: ["recover"], label: "Recovery kit")
    let vault = try holder.upgrade(to: [passkey, securityController, kitController], threshold: 1) { key in
      [try VaultSlot.sealed(seed: key.seed, to: kitIdentity.publicIdentity, controller: kitController.id, label: "Kit")]
    }
    let state = try AuthorityLog(store: store).state()
    #expect(throws: ColophonError.vaultLocked) {
      try KeyringHolder.openVault(state: state, prfOutput: random32(), credential: authenticator.credential)
    }
    let opened = try KeyringHolder.openVault(state: state, with: kitIdentity)
    #expect(opened.seed == vault.seed)

    let passkeyHolder = try KeyringHolder(log: AuthorityLog(store: store),
      signer: try authenticator.signer(controller: passkey), vault: vault)
    let app = SoftwareIdentity()
    let appReplica = Replica(store: store, identity: app)
    let request = try appReplica.requestEnrollment(label: "Later", role: .app, namespaces: [SavedLinks.namespace], write: true)
    #expect(request.write == true)
    try passkeyHolder.approveAsRequested(try #require(passkeyHolder.pendingRequests().first))
    let capture = try appReplica.perform(SavedLinks.capture(url: "https://example.com/later", title: "Later"))
    let ids = try appReplica.read(SavedLinks.namespace).admitted.map(\.id)
    #expect(ids.contains(capture.id))

    let before = try latest(in: store)
    #expect(throws: refused(before + 1)) {
      try passkeyHolder.addController(p256Controller(SoftwareIdentity(), roles: ["approve"], label: "Extra"), slot: nil)
    }
    let unchanged = try latest(in: store)
    #expect(unchanged == before)
    let kitSigner = try P256ControllerSigner(identity: kitIdentity, controller: kitController)
    let kitHolder = try KeyringHolder(log: AuthorityLog(store: store), signer: kitSigner, vault: nil)
    let extra = SoftwareIdentity()
    let extraController = p256Controller(extra, roles: ["approve"], label: "Extra")
    try kitHolder.addController(extraController, slot: nil)
    let present = try kitHolder.state().keyring?.controllers[extraController.id]
    #expect(present != nil)
  }

  @Test func keyringChangeRequiresUserVerification() throws {
    let (holder, _) = try library(in: store)
    let authenticator = SyntheticAuthenticator()
    let passkey = try authenticator.controller(roles: ["approve", "control", "recover"], verification: nil)
    let output = random32()
    let salt = random32()
    let vault = try holder.upgrade(to: [passkey], threshold: 1) { key in
      [try VaultSlot.prf(seed: key.seed, prfOutput: output, salt: salt, credential: authenticator.credential,
        controller: passkey.id, label: "Passkey")]
    }
    let lax = try authenticator.signer(controller: passkey, userVerified: false)
    let ring = try KeyringHolder(log: AuthorityLog(store: store), signer: lax, vault: vault)
    let before = try latest(in: store)
    #expect(throws: refused(before + 1)) {
      try ring.addController(p256Controller(SoftwareIdentity(), roles: ["approve"], label: "iPad"), slot: nil)
    }
    let after = try latest(in: store)
    #expect(after == before)
  }

  // MARK: Review fixes

  @Test func twoKeysRequiresTheControlThreshold() throws {
    let owner = SoftwareIdentity()
    let kit = SoftwareIdentity()
    let ownerController = p256Controller(owner, roles: ["approve", "control", "recover"], label: "Passkey")
    let kitController = p256Controller(kit, roles: ["recover"], label: "Recovery kit")
    let (holder, _) = try library(in: store)
    #expect(throws: ColophonError.malformed("keyring threshold")) {
      try holder.upgrade(to: [ownerController, kitController], threshold: 1, recoverThreshold: 2) { key in
        [try VaultSlot.sealed(seed: key.seed, to: owner.publicIdentity, controller: ownerController.id, label: "Passkey")]
      }
    }
    let adopted = try holder.state().isKeyring
    #expect(adopted == false)

    let local = MemoryStore()
    _ = try library(in: local)
    let vault = VaultKey()
    let slot = try VaultSlot.sealed(seed: vault.seed, to: owner.publicIdentity, controller: ownerController.id, label: "Passkey")
    let fields = try keyringFields(controllers: [ownerController, kitController], slots: [slot], threshold: 1, recoverThreshold: 2)
    let seq = try writeEntry(in: local, fields, signer: root)
    #expect(throws: ColophonError.brokenAuthorityChain(seq)) { try AuthorityLog(store: local).state() }
  }

  @Test func explicitRecoverThresholdOfOneBreaksTheChain() throws {
    _ = try library(in: store)
    let owner = SoftwareIdentity()
    let controller = p256Controller(owner, roles: ["control", "recover"], label: "Owner")
    let vault = VaultKey()
    let slot = try VaultSlot.sealed(seed: vault.seed, to: owner.publicIdentity, controller: controller.id, label: "Owner")
    let fields = try keyringFields(controllers: [controller], slots: [slot], recoverThreshold: 1)
    let seq = try writeEntry(in: store, fields, signer: root)
    #expect(throws: ColophonError.brokenAuthorityChain(seq)) { try AuthorityLog(store: store).state() }
  }

  @Test func vaultRotationNeedsTheCurrentVault() throws {
    let (holder, _) = try library(in: store)
    let owner = SoftwareIdentity()
    let guest = SoftwareIdentity()
    let ownerController = p256Controller(owner, roles: ["approve", "control"], label: "Owner")
    let guestController = p256Controller(guest, roles: ["approve", "control"], label: "Guest")
    _ = try holder.upgrade(to: [ownerController, guestController], threshold: 1) { key in
      [try VaultSlot.sealed(seed: key.seed, to: owner.publicIdentity, controller: ownerController.id, label: "Owner")]
    }
    let signer = try P256ControllerSigner(identity: owner, controller: ownerController)
    let locked = try KeyringHolder(log: AuthorityLog(store: store), signer: signer, vault: nil)
    let before = try latest(in: store)
    #expect(throws: ColophonError.vaultLocked) {
      try locked.removeController(id: guestController.id) { newKey in
        [try VaultSlot.sealed(seed: newKey.seed, to: owner.publicIdentity, controller: ownerController.id, label: "Owner")]
      }
    }
    let after = try latest(in: store)
    #expect(after == before)
  }

  @Test func vaultRotationKeepsEpochHistory() throws {
    let (holder, _) = try library(in: store)
    let owner = SoftwareIdentity()
    let guest = SoftwareIdentity()
    let ownerController = p256Controller(owner, roles: ["approve", "control"], label: "Owner")
    let guestController = p256Controller(guest, roles: ["approve", "control"], label: "Guest")
    let vault = try holder.upgrade(to: [ownerController, guestController], threshold: 1) { key in
      [
        try VaultSlot.sealed(seed: key.seed, to: owner.publicIdentity, controller: ownerController.id, label: "Owner"),
        try VaultSlot.sealed(seed: key.seed, to: guest.publicIdentity, controller: guestController.id, label: "Guest"),
      ]
    }
    let phoneReplica = Replica(store: store, identity: phone)
    let capture = try phoneReplica.perform(SavedLinks.capture(url: "https://example.com/epoch-1", title: "Epoch 1"))
    let signer = try P256ControllerSigner(identity: owner, controller: ownerController)
    let ring = try KeyringHolder(log: AuthorityLog(store: store), signer: signer, vault: vault)
    var rotated: VaultKey?
    try ring.removeController(id: guestController.id) { newKey in
      rotated = newKey
      return [try VaultSlot.sealed(seed: newKey.seed, to: owner.publicIdentity, controller: ownerController.id, label: "Owner")]
    }
    let nextVault = try #require(rotated)
    let ownerAfter = try KeyringHolder(log: AuthorityLog(store: store), signer: signer, vault: nextVault)

    let app = SoftwareIdentity()
    let appReplica = Replica(store: store, identity: app)
    try appReplica.requestEnrollment(label: "Later", role: .app, namespaces: [SavedLinks.namespace], write: true)
    try ownerAfter.approveAsRequested(try #require(ownerAfter.pendingRequests().first))
    let readIDs = try appReplica.read(SavedLinks.namespace).admitted.map(\.id)
    #expect(readIDs.contains(capture.id))

    try ownerAfter.revoke(phone.id)
    let revoked = try #require(ownerAfter.state().members[phone.id])
    let kept = revoked.kept
    #expect(kept.contains(capture.id))
  }

  @Test func recoveryCannotGrantControlBelowTheThreshold() throws {
    let (holder, kit) = try library(in: store)
    let first = SoftwareIdentity()
    let second = SoftwareIdentity()
    let firstController = p256Controller(first, roles: ["approve", "control"], label: "First")
    let secondController = p256Controller(second, roles: ["approve", "control"], label: "Second")
    let kitIdentity = try kit.identity()
    let kitController = p256Controller(kitIdentity, roles: ["recover"], label: "Recovery kit")
    _ = try holder.upgrade(to: [firstController, secondController, kitController], threshold: 2) { key in
      [try VaultSlot.sealed(seed: key.seed, to: kitIdentity.publicIdentity, controller: kitController.id, label: "Kit")]
    }
    let kitSigner = try P256ControllerSigner(identity: kitIdentity, controller: kitController)
    let kitHolder = try KeyringHolder(log: AuthorityLog(store: store), signer: kitSigner, vault: nil)
    let additions: [(String, [String])] = [("Sybil", ["approve", "control"]), ("Second kit", ["recover"])]
    for (label, roles) in additions {
      let extra = p256Controller(SoftwareIdentity(), roles: roles, label: label)
      let body = try kitHolder.keyringChange { ring in
        var controllers = Array(ring.controllers.values)
        controllers.append(extra)
        return (controllers: controllers, threshold: ring.threshold, slots: ring.slots, rotateVault: false,
          recoverThreshold: ring.recoverThreshold)
      }
      let before = try latest(in: store)
      #expect(throws: refused(before + 1)) {
        try kitHolder.completeKeyringChange(body: body, signatures: [try cosignature(kitSigner, over: body)])
      }
      let after = try latest(in: store)
      #expect(after == before)
    }
  }

  @Test func standardRecoveryCanGrantControl() throws {
    let (holder, kit) = try library(in: store)
    let owner = SoftwareIdentity()
    let ownerController = p256Controller(owner, roles: ["approve", "control", "recover"], label: "Passkey")
    let kitIdentity = try kit.identity()
    let kitController = p256Controller(kitIdentity, roles: ["recover"], label: "Recovery kit")
    let vault = try holder.upgrade(to: [ownerController, kitController], threshold: 1) { key in
      [try VaultSlot.sealed(seed: key.seed, to: kitIdentity.publicIdentity, controller: kitController.id, label: "Kit")]
    }
    let kitSigner = try P256ControllerSigner(identity: kitIdentity, controller: kitController)
    let kitHolder = try KeyringHolder(log: AuthorityLog(store: store), signer: kitSigner, vault: nil)
    let device = SoftwareIdentity()
    let deviceController = p256Controller(device, roles: ["approve", "control", "recover"], label: "Recovered phone")
    try kitHolder.addController(deviceController, slot: try VaultSlot.sealed(seed: vault.seed, to: device.publicIdentity,
      controller: deviceController.id, label: "Recovered phone"))
    let added = try kitHolder.state().keyring?.controllers[deviceController.id]
    let roles = added?.roles
    let fullControl = ["approve", "control", "recover"]
    #expect(roles == fullControl)
  }

  @Test func coseParsingAcceptsASliceAndRejectsAnOffCurvePoint() throws {
    let authenticator = SyntheticAuthenticator()
    let cose = try authenticator.coseKey()
    var padded = Data(count: 55)
    padded.append(cose)
    let slice = padded[55...]
    let sliceStart = slice.startIndex
    #expect(sliceStart == 55)
    let parsed = try Controller.webauthn(coseKey: slice, rpID: authenticator.rpID, credential: authenticator.credential,
      label: "Passkey", roles: ["approve"], verification: nil)
    #expect(parsed.key == authenticator.publicKey)

    var offCurve = Data(cose.prefix(10))
    offCurve.append(Data(repeating: 0, count: 32))
    offCurve.append(cose.subdata(in: 42 ..< 45))
    offCurve.append(Data(repeating: 0, count: 32))
    let offCurveCount = offCurve.count
    #expect(offCurveCount == cose.count)
    #expect(throws: ColophonError.malformed("COSE key")) {
      try Controller.webauthn(coseKey: offCurve, rpID: authenticator.rpID, credential: authenticator.credential,
        label: "Passkey", roles: ["approve"], verification: nil)
    }
  }

  @Test func controlOnlyControllerCanRemoveThePasskey() throws {
    let (holder, kit) = try library(in: store)
    let authenticator = SyntheticAuthenticator()
    let passkey = try authenticator.controller(roles: ["approve"], verification: true, label: "Passkey")
    let security = SoftwareIdentity()
    let securityController = p256Controller(security, roles: ["control"], label: "Security key")
    let kitIdentity = try kit.identity()
    let kitController = p256Controller(kitIdentity, roles: ["recover"], label: "Recovery kit")
    let vault = try holder.upgrade(to: [passkey, securityController, kitController], threshold: 1) { key in
      [try VaultSlot.sealed(seed: key.seed, to: kitIdentity.publicIdentity, controller: kitController.id, label: "Kit")]
    }
    let signer = try P256ControllerSigner(identity: security, controller: securityController)
    let securityHolder = try KeyringHolder(log: AuthorityLog(store: store), signer: signer, vault: vault)
    let before = try latest(in: store)
    #expect(throws: ColophonError.notTheRoot) {
      try securityHolder.admit(SoftwareIdentity().publicIdentity, label: "No", role: .app, custody: .software,
        namespaces: [SavedLinks.namespace], write: false)
    }
    let unchanged = try latest(in: store)
    #expect(unchanged == before)
    try securityHolder.removeController(id: passkey.id) { newKey in
      [try VaultSlot.sealed(seed: newKey.seed, to: kitIdentity.publicIdentity, controller: kitController.id, label: "Kit")]
    }
    let state = try securityHolder.state()
    let removed = state.keyring?.controllers[passkey.id]
    let kept = state.keyring?.controllers[securityController.id]
    #expect(removed == nil)
    #expect(kept != nil)
  }

  @Test func controlOnlyControllerCannotShareAKeyWithAnOutsider() throws {
    let (holder, kit) = try library(in: store)
    let authenticator = SyntheticAuthenticator()
    let passkey = try authenticator.controller(roles: ["approve"], verification: true, label: "Passkey")
    let security = SoftwareIdentity()
    let securityController = p256Controller(security, roles: ["control"], label: "Security key")
    let kitIdentity = try kit.identity()
    let kitController = p256Controller(kitIdentity, roles: ["recover"], label: "Recovery kit")
    _ = try holder.upgrade(to: [passkey, securityController, kitController], threshold: 1) { key in
      [try VaultSlot.sealed(seed: key.seed, to: kitIdentity.publicIdentity, controller: kitController.id, label: "Kit")]
    }
    let outsider = SoftwareIdentity()
    let sealed = try SealedKey(SymmetricKey(size: .bits256), to: outsider.publicIdentity)
    let seq = try writeEntry(in: store, ["kind": .string("shareKey"), "by": .string("controller"),
      "signer": .string(securityController.id), "memberID": .string(outsider.id),
      "namespace": .string(SavedLinks.namespace), "epoch": .number(1), "key": try json(sealed)], signer: security)
    #expect(throws: refused(seq)) { try AuthorityLog(store: store).state() }
  }

  @Test func rotatingNeedsTheCurrentVaultEvenWithoutNamespaces() throws {
    let (holder, _) = try library(in: store, namespaces: [])
    let ownerController = p256Controller(root, roles: ["approve", "control"], label: "Owner")
    let other = SoftwareIdentity()
    let otherController = p256Controller(other, roles: ["approve"], label: "Other")
    _ = try holder.upgrade(to: [ownerController, otherController], threshold: 1) { key in
      [try VaultSlot.sealed(seed: key.seed, to: root.publicIdentity, controller: ownerController.id, label: "Owner")]
    }
    let signer = try P256ControllerSigner(identity: root, controller: ownerController)
    let before = try latest(in: store)
    #expect(throws: ColophonError.vaultLocked) {
      let ring = try KeyringHolder(log: AuthorityLog(store: store), signer: signer, vault: VaultKey())
      try ring.removeController(id: otherController.id) { newKey in
        [try VaultSlot.sealed(seed: newKey.seed, to: root.publicIdentity, controller: ownerController.id, label: "Owner")]
      }
    }
    let after = try latest(in: store)
    #expect(after == before)
  }

  @Test func prfSlotRejectsAnEmptyOutputAndAShortSalt() throws {
    let seed = random32()
    let output = random32()
    let salt = random32()
    let credential = Data("credential".utf8)
    #expect(throws: ColophonError.malformed("vault slot")) {
      try VaultSlot.prf(seed: seed, prfOutput: Data(), salt: salt, credential: credential, controller: nil, label: "Passkey")
    }
    let slot = try VaultSlot.prf(seed: seed, prfOutput: output, salt: salt, credential: credential, controller: nil,
      label: "Passkey")
    #expect(throws: ColophonError.malformed("vault slot")) { try slot.open(prfOutput: Data()) }
    let shortSalt = VaultSlot(kind: "prf", controller: nil, label: "Passkey", recipient: nil, sealed: nil,
      credential: credential, salt: Data(count: 16), box: slot.box, parts: nil)
    #expect(throws: ColophonError.malformed("vault slot")) { try shortSalt.open(prfOutput: output) }
  }

  @Test func openVaultSkipsAStaleSlot() throws {
    let owner = SoftwareIdentity()
    let ownerController = p256Controller(owner, roles: ["approve", "control"], label: "Owner")
    let staleSeed = random32()
    let (holder, _) = try library(in: store)
    let vault = try holder.upgrade(to: [ownerController], threshold: 1) { key in
      [
        try VaultSlot.sealed(seed: staleSeed, to: owner.publicIdentity, controller: ownerController.id, label: "Stale"),
        try VaultSlot.sealed(seed: key.seed, to: owner.publicIdentity, controller: ownerController.id, label: "Current"),
      ]
    }
    let opened = try KeyringHolder.openVault(state: try AuthorityLog(store: store).state(), with: owner)
    #expect(opened.seed == vault.seed)

    let onlyStale = MemoryStore()
    let (other, _) = try library(in: onlyStale)
    _ = try other.upgrade(to: [ownerController], threshold: 1) { _ in
      [try VaultSlot.sealed(seed: staleSeed, to: owner.publicIdentity, controller: ownerController.id, label: "Stale")]
    }
    let staleState = try AuthorityLog(store: onlyStale).state()
    #expect(throws: ColophonError.vaultLocked) { try KeyringHolder.openVault(state: staleState, with: owner) }
  }

  @Test func recoveryAtTheRecoveryThresholdCanAddAController() throws {
    let (holder, _) = try library(in: store)
    let alpha = SoftwareIdentity()
    let beta = SoftwareIdentity()
    let kitA = SoftwareIdentity()
    let kitB = SoftwareIdentity()
    let alphaController = p256Controller(alpha, roles: ["approve", "control"], label: "Alpha")
    let betaController = p256Controller(beta, roles: ["approve", "control"], label: "Beta")
    let kitAController = p256Controller(kitA, roles: ["recover"], label: "Kit A")
    let kitBController = p256Controller(kitB, roles: ["recover"], label: "Kit B")
    _ = try holder.upgrade(to: [alphaController, betaController, kitAController, kitBController], threshold: 2,
      recoverThreshold: 2) { key in
      [try VaultSlot.sealed(seed: key.seed, to: alpha.publicIdentity, controller: alphaController.id, label: "Alpha")]
    }
    let kitASigner = try P256ControllerSigner(identity: kitA, controller: kitAController)
    let kitBSigner = try P256ControllerSigner(identity: kitB, controller: kitBController)
    let ring = try KeyringHolder(log: AuthorityLog(store: store), signer: kitASigner, vault: nil)
    let added = SoftwareIdentity()
    let addedController = p256Controller(added, roles: ["approve", "control"], label: "Recovered")
    let body = try ring.keyringChange { current in
      var controllers = Array(current.controllers.values)
      controllers.append(addedController)
      return (controllers: controllers, threshold: current.threshold, slots: current.slots, rotateVault: false,
        recoverThreshold: current.recoverThreshold)
    }
    let one = try latest(in: store)
    #expect(throws: refused(one + 1)) {
      try ring.completeKeyringChange(body: body, signatures: [try cosignature(kitASigner, over: body)])
    }
    try ring.completeKeyringChange(body: body, signatures: [
      try cosignature(kitBSigner, over: body),
      try cosignature(kitASigner, over: body),
    ])
    let present = try ring.state().keyring?.controllers[addedController.id]
    let roles = present?.roles
    let controlling = ["approve", "control"]
    #expect(roles == controlling)
  }

  @Test func recoverySignedOnlyByKeysThatAreNotDevicesRaisesANotice() throws {
    let (holder, _) = try library(in: store)
    let device = SoftwareIdentity()
    let deviceController = p256Controller(device, roles: ["approve", "control"], label: "iPhone")
    let passkeyAuth = SyntheticAuthenticator()
    let securityAuth = SyntheticAuthenticator()
    let passkey = try passkeyAuth.controller(roles: ["approve", "control", "recover"], verification: true, label: "Passkey")
    let security = try securityAuth.controller(roles: ["approve", "control", "recover"], verification: true, label: "Security Key")
    let output = random32()
    let salt = random32()
    let vault = try holder.upgrade(to: [deviceController, passkey, security], threshold: 2, recoverThreshold: 2) { key in
      [
        try VaultSlot.sealed(seed: key.seed, to: device.publicIdentity, controller: deviceController.id, label: "iPhone"),
        try VaultSlot.prf(seed: key.seed, prfOutput: output, salt: salt, credential: passkeyAuth.credential, controller: passkey.id,
          label: "Passkey"),
      ]
    }
    let ipad = SoftwareIdentity()
    let ipadController = p256Controller(ipad, roles: ["approve", "control"], label: "iPad")
    let recovering = try KeyringHolder(log: AuthorityLog(store: store), signer: try passkeyAuth.signer(controller: passkey),
      vault: vault)
    let body = try recovering.keyringChange { current in
      var controllers = Array(current.controllers.values)
      controllers.append(ipadController)
      var slots = current.slots
      slots.append(try VaultSlot.sealed(seed: vault.seed, to: ipad.publicIdentity, controller: ipadController.id, label: "iPad"))
      return (controllers, current.threshold, slots, false, current.recoverThreshold)
    }
    try recovering.completeKeyringChange(body: body, signatures: [
      try cosignature(try passkeyAuth.signer(controller: passkey), over: body),
      try cosignature(try securityAuth.signer(controller: security), over: body),
    ])
    let noticed = try recovering.state().recoveryAdditions.contains { $0.controllerID == ipadController.id }
    #expect(noticed)

    let mac = SoftwareIdentity()
    let macController = p256Controller(mac, roles: ["approve", "control"], label: "Mac")
    let ordinary = try KeyringHolder(log: AuthorityLog(store: store),
      signer: try P256ControllerSigner(identity: device, controller: deviceController), vault: vault)
    let ordinaryBody = try ordinary.keyringChange { current in
      var controllers = Array(current.controllers.values)
      controllers.append(macController)
      var slots = current.slots
      slots.append(try VaultSlot.sealed(seed: vault.seed, to: mac.publicIdentity, controller: macController.id, label: "Mac"))
      return (controllers, current.threshold, slots, false, current.recoverThreshold)
    }
    try ordinary.completeKeyringChange(body: ordinaryBody, signatures: [
      try cosignature(try P256ControllerSigner(identity: device, controller: deviceController), over: ordinaryBody),
      try cosignature(try passkeyAuth.signer(controller: passkey), over: ordinaryBody),
    ])
    let quiet = try ordinary.state().recoveryAdditions.contains { $0.controllerID == macController.id }
    #expect(!quiet)
  }

  @Test func approveIntentClearsWhenTheMemberWasAlreadyDecided() throws {
    let (holder, _) = try library(in: store)
    try holder.revoke(phone.publicIdentity.id)
    let revokedState = try holder.state()
    let revokedIntent = approveIntent(libraryID: revokedState.libraryID, memberID: phone.publicIdentity.id, write: true)
    let revoked = AuthorityIntentRebase.action(revokedIntent, state: revokedState, pendingMemberIDs: [])
    #expect(revoked == .clear)

    let open = MemoryStore()
    let (fresh, _) = try library(in: open)
    let stranger = SoftwareIdentity()
    try fresh.admit(stranger.publicIdentity, label: "Later", role: .app, custody: .software,
      namespaces: [SavedLinks.namespace], write: false)
    let narrowed = try fresh.state()
    let wider = approveIntent(libraryID: narrowed.libraryID, memberID: stranger.publicIdentity.id, write: true)
    let keptNarrow = AuthorityIntentRebase.action(wider, state: narrowed, pendingMemberIDs: [])
    #expect(keptNarrow == .clear)
  }

  private func approveIntent(libraryID: String, memberID: String, write: Bool) -> AuthorityWriteIntent {
    AuthorityWriteIntent(libraryID: libraryID, kind: "approve", memberID: memberID, namespaces: [SavedLinks.namespace],
      write: write, caveats: [], sequences: [9], digests: ["gone"], label: nil, role: nil, custody: nil, keyOperator: nil,
      grantSequence: nil, app: nil, device: nil)
  }

  @Test func staleRevokeClearsWhenTheGrantIsNewerThanTheIntent() throws {
    let local = MemoryStore()
    let (holder, _) = try library(in: local)
    let before = try holder.state()
    let head = before.latest
    try holder.admit(phone.publicIdentity, label: "Phone", role: .app, custody: .software,
      namespaces: [SavedLinks.namespace], write: false)
    let state = try holder.state()
    let grant = try #require(state.members[phone.publicIdentity.id]?.current)
    let newer = grant.seq > head
    #expect(newer)
    let stale = revokeIntent(libraryID: state.libraryID, memberID: phone.publicIdentity.id, sequences: [head + 1])
    let cleared = AuthorityIntentRebase.action(stale, state: state, pendingMemberIDs: [])
    #expect(cleared == .clear)
    let current = revokeIntent(libraryID: state.libraryID, memberID: phone.publicIdentity.id, sequences: [state.latest + 1])
    let replay = AuthorityIntentRebase.action(current, state: state, pendingMemberIDs: [])
    #expect(replay == .revoke)
    var noBase = current
    noBase.sequences = []
    let still = AuthorityIntentRebase.action(noBase, state: state, pendingMemberIDs: [])
    #expect(still == .revoke)
  }

  private func revokeIntent(libraryID: String, memberID: String, sequences: [Int]) -> AuthorityWriteIntent {
    AuthorityWriteIntent(libraryID: libraryID, kind: "revoke", memberID: memberID, namespaces: [], write: false, caveats: [],
      sequences: sequences, digests: sequences.map { _ in "gone" }, label: nil, role: nil, custody: nil, keyOperator: nil,
      grantSequence: nil, app: nil, device: nil)
  }

  @Test func approveIntentKeepsCaveatsAndAMissingRequestStaysUntilTheFolderIsComplete() throws {
    let (holder, _) = try library(in: store)
    let state = try holder.state()
    let stranger = SoftwareIdentity().publicIdentity.id
    let caveat = Caveat.only(["follow"], in: SavedLinks.namespace)
    var intent = approveIntent(libraryID: state.libraryID, memberID: stranger, write: true)
    intent.caveats = [caveat]
    let pending = AuthorityIntentRebase.action(intent, state: state, pendingMemberIDs: [stranger])
    let expected = AuthorityIntentAction.approve(namespaces: [SavedLinks.namespace], write: true, caveats: [caveat])
    #expect(pending == expected)
    let gone = AuthorityIntentRebase.action(intent, state: state, pendingMemberIDs: [], requestsComplete: true)
    #expect(gone == .clear)
    let waiting = AuthorityIntentRebase.action(intent, state: state, pendingMemberIDs: [], requestsComplete: false)
    #expect(waiting == .keep)
  }

  @Test func intentStoreKeepsEveryPendingDecision() throws {
    let directory = FileManager.default.temporaryDirectory.appending(path: "intents-" + UUID().uuidString,
      directoryHint: .isDirectory)
    defer { try? FileManager.default.removeItem(at: directory) }
    let intents = AuthorityIntentStore(directory: directory)
    let first = approveIntent(libraryID: "library", memberID: "a", write: true)
    let second = approveIntent(libraryID: "library", memberID: "b", write: false)
    try intents.save(first)
    try intents.save(second)
    let loaded = intents.load(libraryID: "library")
    let ids = Set(loaded.map(\.memberID))
    let expected: Set<String> = ["a", "b"]
    #expect(ids == expected)
    var replaced = first
    replaced.write = false
    try intents.save(replaced)
    let again = intents.load(libraryID: "library")
    let count = again.count
    #expect(count == 2)
    let write = again.first { $0.memberID == "a" }?.write
    #expect(write == false)
    let legacyDirectory = FileManager.default.temporaryDirectory.appending(path: "legacy-intent-" + UUID().uuidString,
      directoryHint: .isDirectory)
    defer { try? FileManager.default.removeItem(at: legacyDirectory) }
    try FileManager.default.createDirectory(at: legacyDirectory, withIntermediateDirectories: true)
    let legacy = approveIntent(libraryID: "library", memberID: "solo", write: true)
    try Canonical.encode(legacy).write(to: legacyDirectory.appending(path: "library.json"), options: [.atomic])
    let read = AuthorityIntentStore(directory: legacyDirectory).load(libraryID: "library")
    let legacyCount = read.count
    #expect(legacyCount == 1)
    let legacyMember = read.first?.memberID
    #expect(legacyMember == "solo")
  }

  @Test func upgradedLibraryRejectsRetiredEntries() throws {
    let owner = SoftwareIdentity()
    let controller = p256Controller(owner, roles: ["approve", "control"], label: "Owner")
    for kind in ["genesis", "handover", "stewards", "rotateRecovery"] {
      let local = MemoryStore()
      let (holder, _) = try library(in: local)
      _ = try holder.upgrade(to: [controller], threshold: 1) { key in
        [try VaultSlot.sealed(seed: key.seed, to: owner.publicIdentity, controller: controller.id, label: "Owner")]
      }
      let seq = try writeEntry(in: local, ["kind": .string(kind), "by": .string("root")], signer: root)
      #expect(throws: ColophonError.brokenAuthorityChain(seq)) { try AuthorityLog(store: local).state() }
    }
    for by in ["root", "recovery", "quorum"] {
      let local = MemoryStore()
      let (holder, _) = try library(in: local)
      _ = try holder.upgrade(to: [controller], threshold: 1) { key in
        [try VaultSlot.sealed(seed: key.seed, to: owner.publicIdentity, controller: controller.id, label: "Owner")]
      }
      let seq = try writeEntry(in: local, ["kind": .string("grant"), "by": .string(by)], signer: root)
      #expect(throws: refused(seq)) { try AuthorityLog(store: local).state() }
    }
  }

  @Test func duplicateCosignersAndInvalidCosignaturesAreRejected() throws {
    let (holder, _) = try library(in: store)
    let first = SoftwareIdentity()
    let second = SoftwareIdentity()
    let firstController = p256Controller(first, roles: ["approve", "control", "recover"], label: "First")
    let secondController = p256Controller(second, roles: ["approve", "control", "recover"], label: "Second")
    _ = try holder.upgrade(to: [firstController, secondController], threshold: 2, recoverThreshold: 2) { key in
      [try VaultSlot.sealed(seed: key.seed, to: first.publicIdentity, controller: firstController.id, label: "First")]
    }
    let firstSigner = try P256ControllerSigner(identity: first, controller: firstController)
    let ring = try KeyringHolder(log: AuthorityLog(store: store), signer: firstSigner, vault: nil)
    let added = p256Controller(SoftwareIdentity(), roles: ["approve"], label: "Added")
    let body = try ring.keyringChange { current in
      var controllers = Array(current.controllers.values)
      controllers.append(added)
      return (controllers: controllers, threshold: current.threshold, slots: current.slots, rotateVault: false,
        recoverThreshold: current.recoverThreshold)
    }
    let primary = try cosignature(firstSigner, over: body)
    var duplicated = SignedRecord(body: body, signature: primary.signature, assertion: primary.assertion)
    duplicated.cosignatures = [primary]
    let duplicateSeq = try latest(in: store) + 1
    try store.create(LibraryPath.authority(duplicateSeq), Canonical.encode(duplicated))
    #expect(throws: refused(duplicateSeq)) { try AuthorityLog(store: store).state() }

    let invalid = MemoryStore()
    let (other, _) = try library(in: invalid)
    _ = try other.upgrade(to: [firstController, secondController], threshold: 2, recoverThreshold: 2) { key in
      [try VaultSlot.sealed(seed: key.seed, to: first.publicIdentity, controller: firstController.id, label: "First")]
    }
    let otherRing = try KeyringHolder(log: AuthorityLog(store: invalid), signer: firstSigner, vault: nil)
    let otherBody = try otherRing.keyringChange { current in
      var controllers = Array(current.controllers.values)
      controllers.append(added)
      return (controllers: controllers, threshold: current.threshold, slots: current.slots, rotateVault: false,
        recoverThreshold: current.recoverThreshold)
    }
    let valid = try cosignature(firstSigner, over: otherBody)
    let forged = SignedRecord.Cosignature(signer: secondController.id, signature: Data(repeating: 0, count: 64))
    var broken = SignedRecord(body: otherBody, signature: valid.signature, assertion: valid.assertion)
    broken.cosignatures = [forged]
    let forgedSeq = try latest(in: invalid) + 1
    try invalid.create(LibraryPath.authority(forgedSeq), Canonical.encode(broken))
    #expect(throws: refused(forgedSeq)) { try AuthorityLog(store: invalid).state() }

    let recovery = MemoryStore()
    let (third, _) = try library(in: recovery)
    let kit = SoftwareIdentity()
    let kitController = p256Controller(kit, roles: ["recover"], label: "Kit")
    _ = try third.upgrade(to: [firstController, secondController, kitController], threshold: 2, recoverThreshold: 2) { key in
      [try VaultSlot.sealed(seed: key.seed, to: first.publicIdentity, controller: firstController.id, label: "First")]
    }
    let kitSigner = try P256ControllerSigner(identity: kit, controller: kitController)
    let kitRing = try KeyringHolder(log: AuthorityLog(store: recovery), signer: kitSigner, vault: nil)
    let recoveryBody = try kitRing.keyringChange { current in
      var controllers = Array(current.controllers.values)
      controllers.append(added)
      return (controllers: controllers, threshold: current.threshold, slots: current.slots, rotateVault: false,
        recoverThreshold: current.recoverThreshold)
    }
    let kitSignature = try cosignature(kitSigner, over: recoveryBody)
    var repeated = SignedRecord(body: recoveryBody, signature: kitSignature.signature, assertion: kitSignature.assertion)
    repeated.cosignatures = [kitSignature]
    let repeatedSeq = try latest(in: recovery) + 1
    try recovery.create(LibraryPath.authority(repeatedSeq), Canonical.encode(repeated))
    #expect(throws: refused(repeatedSeq)) { try AuthorityLog(store: recovery).state() }
  }

  @Test func upgradeEntryRejectsAssertionCosignaturesAndOtherSigners() throws {
    let owner = SoftwareIdentity()
    let controller = p256Controller(owner, roles: ["control"], label: "Owner")
    let vault = VaultKey()
    let slot = try VaultSlot.sealed(seed: vault.seed, to: owner.publicIdentity, controller: controller.id, label: "Owner")
    let fields = try keyringFields(controllers: [controller], slots: [slot])

    let withAssertion = MemoryStore()
    _ = try library(in: withAssertion)
    let assertionSeq = try writeDecorated(in: withAssertion, fields) { record in
      record.assertion = Assertion(authenticatorData: Data(repeating: 1, count: 37), clientData: Data("{}".utf8))
    }
    #expect(throws: refused(assertionSeq)) { try AuthorityLog(store: withAssertion).state() }

    let withCosigner = MemoryStore()
    _ = try library(in: withCosigner)
    let cosignedSeq = try writeDecorated(in: withCosigner, fields) { record in
      record.cosignatures = [SignedRecord.Cosignature(signer: controller.id, signature: Data(repeating: 1, count: 64))]
    }
    #expect(throws: refused(cosignedSeq)) { try AuthorityLog(store: withCosigner).state() }

    for signer in ["controller", "recovery", "quorum"] {
      let local = MemoryStore()
      _ = try library(in: local)
      var altered = fields
      altered["by"] = .string(signer)
      if signer == "controller" { altered["signer"] = .string(controller.id) }
      let seq = try writeEntry(in: local, altered, signer: root)
      #expect(throws: refused(seq)) { try AuthorityLog(store: local).state() }
    }
  }

  @Test func recoveryCannotRewriteAControllerOrDropASlot() throws {
    let (holder, kit) = try library(in: store)
    let first = SoftwareIdentity()
    let second = SoftwareIdentity()
    let firstController = p256Controller(first, roles: ["approve", "control"], label: "First")
    let secondController = p256Controller(second, roles: ["approve", "control"], label: "Second")
    let kitIdentity = try kit.identity()
    let kitController = p256Controller(kitIdentity, roles: ["recover"], label: "Recovery kit")
    _ = try holder.upgrade(to: [firstController, secondController, kitController], threshold: 2) { key in
      [try VaultSlot.sealed(seed: key.seed, to: kitIdentity.publicIdentity, controller: kitController.id, label: "Kit")]
    }
    let kitSigner = try P256ControllerSigner(identity: kitIdentity, controller: kitController)
    let kitHolder = try KeyringHolder(log: AuthorityLog(store: store), signer: kitSigner, vault: nil)
    let renamed = p256Controller(first, roles: ["approve", "control"], label: "Renamed")
    let demoted = p256Controller(first, roles: ["control"], label: "First")
    let proposals: [[Controller]] = [
      [renamed, secondController, kitController],
      [demoted, secondController, kitController],
    ]
    for controllers in proposals {
      let body = try kitHolder.keyringChange { ring in
        (controllers: controllers, threshold: ring.threshold, slots: ring.slots, rotateVault: false,
          recoverThreshold: ring.recoverThreshold)
      }
      let before = try latest(in: store)
      #expect(throws: refused(before + 1)) {
        try kitHolder.completeKeyringChange(body: body, signatures: [try cosignature(kitSigner, over: body)])
      }
    }
    let dropped = try kitHolder.keyringChange { ring in
      (controllers: Array(ring.controllers.values), threshold: ring.threshold, slots: [], rotateVault: false,
        recoverThreshold: ring.recoverThreshold)
    }
    let beforeDrop = try latest(in: store)
    #expect(throws: refused(beforeDrop + 1)) {
      try kitHolder.completeKeyringChange(body: dropped, signatures: [try cosignature(kitSigner, over: dropped)])
    }
    let present = try kitHolder.state().keyring?.controllers[firstController.id]
    let label = present?.label
    let slotCount = try #require(kitHolder.state().keyring).slots.count
    #expect(label == "First")
    #expect(slotCount == 1)
  }
}
