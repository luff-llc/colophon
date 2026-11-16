plugins {
    id("com.android.application")
    kotlin("android")
}

// Build defaults, overridable with -P (scripts/build-test-android.sh passes the COLOPHON_* environment through).
fun setting(name: String, fallback: String): String = (findProperty(name) as String?)?.takeIf { it.isNotBlank() } ?: fallback
fun quoted(value: String) = "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

android {
    namespace = "works.luff.colophon.testapp"
    compileSdk = 35
    defaultConfig {
        applicationId = "works.luff.colophon.testapp"
        minSdk = 33
        targetSdk = 35
        versionCode = 1
        versionName = "0.5"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
        // The home URL prefix a new account's home is named under (an https name; the slot is appended).
        buildConfigField("String", "HOME_PREFIX", quoted(setting("COLOPHON_HOME_PREFIX", "https://home.test/v1/libraries/")))
        // Where the home's requests go instead: the emulator reaches this Mac's loopback through `adb reverse`.
        buildConfigField("String", "HOME_REACH", quoted(setting("COLOPHON_HOME_REACH", "http://127.0.0.1:8790/v1/libraries/")))
        // The home service that provisions a new account's slot (apps/test-home).
        buildConfigField("String", "PROVISIONER", quoted(setting("COLOPHON_PROVISIONER", "http://127.0.0.1:8791/provision")))
        // The WebAuthn relying party of the person's passkey.
        buildConfigField("String", "RELYING_PARTY", quoted(setting("COLOPHON_RELYING_PARTY", "id.toolsperson.com")))
        // The staging home, reached directly; its home service is not deployed yet.
        buildConfigField("String", "STAGING_PREFIX", quoted(setting("COLOPHON_STAGING_PREFIX", "https://colophon.toolsperson.com/v1/libraries/")))
        buildConfigField("String", "STAGING_PROVISIONER", quoted(setting("COLOPHON_STAGING_PROVISIONER", "")))
    }
    buildFeatures { buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    packaging {
        resources { excludes += "/META-INF/{AL2.0,LGPL2.1}" }
        jniLibs { useLegacyPackaging = false }
    }
}

kotlin { jvmToolchain(17) }

dependencies {
    implementation("org.luff.colophon:colophon-android")
    implementation("net.java.dev.jna:jna:5.18.1@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    implementation("androidx.credentials:credentials:1.5.0")
    implementation("androidx.credentials:credentials-play-services-auth:1.5.0")
    // QR codes: encode and decode (Android has no platform QR API). Apache-2.0; recorded in docs/architecture.md.
    implementation("com.google.zxing:core:3.5.3")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:core:1.6.1")
}
