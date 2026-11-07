plugins { kotlin("jvm") version "2.2.21" }
group = "com.luff"
version = "0.3.0"
repositories { mavenCentral() }
dependencies {
    implementation("net.java.dev.jna:jna:5.18.1")
    testImplementation(kotlin("test-junit"))
}
kotlin { jvmToolchain(17) }
tasks.test {
    systemProperty("jna.library.path", rootDir.resolve("../../target/release").canonicalPath)
    systemProperty("colophon.fixture", rootDir.resolve("../../target/ffi-bench").canonicalPath)
    testLogging { showStandardStreams = System.getenv("COLOPHON_FFI_BENCH") == "1"; events("passed", "skipped", "failed") }
}
tasks.wrapper { distributionType = Wrapper.DistributionType.BIN }
