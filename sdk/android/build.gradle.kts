plugins {
    id("com.android.library") version "8.7.3"
    kotlin("android") version "2.2.21"
}

group = "org.luff.colophon"
version = "0.3.0"

android {
    namespace = "org.luff.colophon"
    compileSdk = 35
    defaultConfig {
        minSdk = 33
        consumerProguardFiles("consumer-rules.pro")
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    sourceSets {
        getByName("main") {
            kotlin.srcDir("../kotlin/src/main/kotlin")
            // Outside layout.buildDirectory so `clean` cannot drop the cargo-ndk libraries.
            jniLibs.srcDir(layout.projectDirectory.dir("native/jni"))
        }
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
    testOptions {
        unitTests.isReturnDefaultValues = true
        unitTests.all {
            it.jvmArgs(if (System.getenv("COLOPHON_SESSION_BENCH") != null) "-Xmx2g" else "-Xmx512m")
            val hostLibs = rootDir.resolve("../../target/release").canonicalPath
            it.systemProperty("jna.library.path", hostLibs)
            it.systemProperty("java.library.path", hostLibs)
            it.environment("DYLD_LIBRARY_PATH", hostLibs)
            it.systemProperty("colophon.consumerRules", rootDir.resolve("consumer-rules.pro").absolutePath)
            it.systemProperty("colophon.buildGradle", rootDir.resolve("build.gradle.kts").absolutePath)
            it.systemProperty("colophon.buildScript", rootDir.resolve("../../scripts/build-android.sh").canonicalPath)
            it.systemProperty("colophon.relayScript", rootDir.resolve("../../relay/server.js").canonicalPath)
        }
    }
    publishing {
        singleVariant("release") { withSourcesJar() }
    }
}

kotlin { jvmToolchain(17) }

dependencies {
    implementation("androidx.credentials:credentials:1.5.0")
    implementation("androidx.credentials:credentials-play-services-auth:1.5.0")
    implementation("net.java.dev.jna:jna:5.18.1@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    testImplementation("net.java.dev.jna:jna:5.18.1")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")
    androidTestImplementation("net.java.dev.jna:jna:5.18.1@aar")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:rules:1.6.1")
    androidTestImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
}

val checkNativeLibs = tasks.register("checkNativeLibs") {
    val nativeDir = layout.projectDirectory.dir("native/jni").asFile
    doLast {
        for (abi in listOf("arm64-v8a", "x86_64")) {
            val so = nativeDir.resolve("$abi/libcolophon_ffi.so")
            if (!so.isFile) {
                throw GradleException("Missing JNI library ${so.absolutePath}")
            }
        }
    }
}

tasks.configureEach {
    if (name == "mergeReleaseJniLibFolders" || name == "mergeDebugJniLibFolders") {
        dependsOn(checkNativeLibs)
    }
}

tasks.withType<Test>().configureEach {
    testLogging { events("passed", "skipped", "failed"); showStandardStreams = false }
}


