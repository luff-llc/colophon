plugins { kotlin("jvm") version "2.2.21" }
group = "com.luff"
version = "0.4.0"
repositories { mavenCentral() }
dependencies {
    implementation("net.java.dev.jna:jna:5.18.1")
    // The 0.5 session (com.luff.colophon.session): StateFlow, serial dispatchers, suspend calls.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    testImplementation(kotlin("test-junit"))
}
kotlin { jvmToolchain(17) }
// The native library and the relay home module follow CARGO_TARGET_DIR, as the scripts do.
val cargoTarget = System.getenv("CARGO_TARGET_DIR")?.let { file(it) } ?: rootDir.resolve("../../target")
tasks.test {
    systemProperty("jna.library.path", cargoTarget.resolve("release").canonicalPath)
    systemProperty("colophon.fixture", cargoTarget.resolve("ffi-bench").canonicalPath)
    systemProperty("colophon.repo", rootDir.resolve("../..").canonicalPath)
    systemProperty("colophon.homeWasm", System.getenv("COLOPHON_HOME_WASM")
        ?: cargoTarget.resolve("wasm32-unknown-unknown/release/colophon_home_wasm.wasm").canonicalPath)
    System.getenv("COLOPHON_BUN")?.let { systemProperty("colophon.bun", it) }
    System.getenv("COLOPHON_RELAY_TAG")?.let { systemProperty("colophon.relayTag", it) }
    maxHeapSize = "1g"
    testLogging {
        showStandardStreams = System.getenv("COLOPHON_FFI_BENCH") == "1" || System.getenv("COLOPHON_TEST_VERBOSE") == "1"
        events("passed", "skipped", "failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
tasks.wrapper { distributionType = Wrapper.DistributionType.BIN }

// Test-only main, launched directly by Bun (no Gradle process between its stdin/stdout and the test).
tasks.register("crossDeviceClasspath") {
    dependsOn(tasks.testClasses)
    doLast {
        layout.buildDirectory.file("cross-device-classpath.txt").get().asFile
            .writeText(sourceSets["test"].runtimeClasspath.asPath)
    }
}
