import XCTest

/// UI tests of the flows one device can run alone, against the local home service (apps/test-home, started by
/// `scripts/build-test-ios.sh --test`). The `testScript…` steps are single steps of the two-device run (iPhone and
/// Android); they take their input from `TEST_RUNNER_COLOPHON_NOTE` and are run one at a time with -only-testing.
@MainActor final class ColophonTestUITests: XCTestCase {
    private var app: XCUIApplication!

    override func setUp() {
        continueAfterFailure = false
        app = XCUIApplication()
    }

    private func launch(reset: Bool, link: String? = nil) {
        app.launchArguments = reset ? ["-uiTestReset"] : []
        if let link { app.launchEnvironment["COLOPHON_OPEN_URL"] = link }
        if reset, let token = env("COLOPHON_PROVISIONER_TOKEN") { app.launchEnvironment["COLOPHON_PROVISIONER_TOKEN"] = token }
        app.launch()
    }

    private func wait(_ element: XCUIElement, _ seconds: TimeInterval = 60, _ message: String = "") {
        if !element.waitForExistence(timeout: seconds) {
            XCTFail((message.isEmpty ? "\(element) did not appear" : message) + "\n" + String(app.debugDescription.prefix(6000)))
        }
    }

    private func waitEnabled(_ element: XCUIElement, _ seconds: TimeInterval) {
        expectation(for: NSPredicate(format: "exists == true AND enabled == true"), evaluatedWith: element)
        waitForExpectations(timeout: seconds)
    }

    /// Scrolls the current list until `element` can be tapped, then taps it.
    private func scrollTap(_ element: XCUIElement) {
        for _ in 0..<10 where !(element.exists && element.isHittable) { app.swipeUp() }
        element.tap()
    }

    private func tapTab(_ name: String) { app.buttons.matching(NSPredicate(format: "label == %@", name)).firstMatch.tap() }

    private func createWithSoftwareOwner() {
        let create = app.buttons["createSoftware"]
        // The setup form is longer than the screen: scroll until the button is there.
        for _ in 0..<8 where !create.exists { app.swipeUp() }
        wait(create, 20)
        create.tap()
        wait(app.navigationBars["Notes"], 90, "the account was not created; is apps/test-home running?")
        waitEnabled(app.buttons["addNote"], 90)
    }

    private func addNote(_ text: String) {
        app.buttons["addNote"].tap()
        let field = app.descendants(matching: .any).matching(identifier: "noteText").firstMatch
        wait(field, 10)
        field.tap()
        field.typeText(text)
        app.buttons["saveNote"].tap()
        wait(app.buttons["note-\(text)"], 30, "the note \(text) is not in the list")
    }

    private func syncUntil(_ element: XCUIElement, tries: Int = 30) -> Bool {
        for _ in 0..<tries {
            if element.exists { return true }
            tapTab("Status")
            scrollTap(app.buttons["syncNow"])
            sleep(2)
            tapTab("Notes")
            if element.waitForExistence(timeout: 2) { return true }
        }
        return element.exists
    }

    /// Create an account (software owner), add, edit and delete a note, sync, lock and unlock, sign out.
    func testOneDeviceJourney() {
        launch(reset: true)
        createWithSoftwareOwner()
        addNote("first note")

        app.buttons["note-first note"].tap()
        let field = app.descendants(matching: .any).matching(identifier: "noteText").firstMatch
        wait(field, 10)
        field.tap()
        field.press(forDuration: 1.2)
        if app.menuItems["Select All"].waitForExistence(timeout: 2) { app.menuItems["Select All"].tap() }
        field.typeText(XCUIKeyboardKey.delete.rawValue)
        field.typeText("edited note")
        app.buttons["saveNote"].tap()
        wait(app.buttons["note-edited note"], 30, "the edit is not in the list")
        XCTAssertFalse(app.buttons["note-first note"].exists, "the old text is gone")

        app.buttons["note-edited note"].swipeLeft()
        app.buttons["Delete"].tap()
        let gone = NSPredicate(format: "exists == false")
        expectation(for: gone, evaluatedWith: app.buttons["note-edited note"])
        waitForExpectations(timeout: 30)

        tapTab("Status")
        wait(app.staticTexts["ready"], 10, "the status screen shows the phase ready")
        XCTAssertFalse(app.staticTexts["stoppedNotice"].exists, "a ready account shows no stopped notice")
        XCTAssertFalse(app.staticTexts["waitingNotice"].exists, "an approved device is not waiting")
        scrollTap(app.buttons["syncNow"])
        let outcome = app.staticTexts["syncOutcome"]
        wait(outcome, 60)
        XCTAssertEqual(outcome.value as? String, "complete", "the sync left no fault: \(app.debugDescription.prefix(2000))")
        let head = app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS 'seq ' OR value CONTAINS 'seq '")).firstMatch
        for _ in 0..<12 where !head.exists { app.swipeDown(velocity: .slow) }
        XCTAssertTrue(head.exists, "the last head is shown\n\(app.debugDescription.prefix(5000))")

        scrollTap(app.buttons["lock"])
        tapTab("Notes")
        wait(app.buttons["unlock"], 20, "the notes are hidden while locked")
        app.buttons["unlock"].tap()
        wait(app.buttons["addNote"], 20)

        tapTab("Status")
        app.swipeUp()
        scrollTap(app.buttons["signOut"])
        app.buttons["confirmSignOut"].firstMatch.tap()
        wait(app.navigationBars["Colophon test"], 30, "after sign out the device is back at setup")
    }

    // MARK: Steps of the two-device run

    private func env(_ name: String) -> String? { ProcessInfo.processInfo.environment[name].flatMap { $0.isEmpty ? nil : $0 } }
    private var note: String { ProcessInfo.processInfo.environment["COLOPHON_NOTE"] ?? "note from the iPhone" }

    /// Step: create an account and show the invite (debug builds write it to Documents/outbox.txt).
    func testScriptCreateAndInvite() {
        launch(reset: true)
        createWithSoftwareOwner()
        tapTab("Devices")
        app.buttons["showInvite"].tap()
        wait(app.buttons["copyPayload"], 20)
    }

    /// Step: approve the request the harness read off the joining device's screen (`colophontest://request?p=…`, debug
    /// builds only: the harness stands in for the camera). The scan confirms a pairing for that request's key; the person
    /// still approves it.
    func testScriptApprove() {
        launch(reset: false, link: env("COLOPHON_REQUEST").map { "colophontest://request?p=\($0)" })
        wait(app.buttons.matching(NSPredicate(format: "label == %@", "Devices")).firstMatch, 30)
        tapTab("Devices")
        wait(app.staticTexts["scannedRequest"], 60, "the scanned request is not shown")
        waitEnabled(app.buttons["approve"], 10)
        app.buttons["approve"].tap()
        let gone = NSPredicate(format: "exists == false")
        expectation(for: gone, evaluatedWith: app.buttons["approve"])
        waitForExpectations(timeout: 60)
    }

    /// Step: join with the invite in `TEST_RUNNER_COLOPHON_INVITE` and wait for approval (the request is shown as a QR code).
    func testScriptJoin() {
        launch(reset: true, link: env("COLOPHON_INVITE").map { "colophontest://join?p=\($0)" })
        // The link only fills the confirmation screen; the person confirms.
        wait(app.buttons["confirmJoin"], 30, "the confirmation screen did not appear")
        XCTAssertTrue(app.staticTexts["confirmHost"].exists || app.descendants(matching: .any)["confirmHost"].exists)
        app.buttons["confirmJoin"].tap()
        wait(app.staticTexts["waitingForApproval"], 60, "the device did not reach waiting for approval")
    }

    /// Step: write a note.
    func testScriptWrite() {
        launch(reset: false)
        waitEnabled(app.buttons["addNote"], 60)
        addNote(note)
        tapTab("Status")
        scrollTap(app.buttons["syncNow"])
        wait(app.staticTexts["syncOutcome"], 60)
        XCTAssertEqual(app.staticTexts["syncOutcome"].value as? String, "complete", "the note did not reach the home: \(app.staticTexts["syncDetail"].label)")
        sleep(1)
    }

    /// Step: sync until the note written on the other device is listed.
    func testScriptSee() {
        launch(reset: false)
        waitEnabled(app.buttons["addNote"], 60)
        XCTAssertTrue(syncUntil(app.buttons["note-\(note)"]), "the other device's note \(note) did not arrive")
    }
}
