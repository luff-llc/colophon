plugins {
    id("com.android.library") version "8.7.3"
    kotlin("android") version "2.2.21"
}

group = "org.luff.colophon"
version = "0.2.0"

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
            jniLibs.srcDir(layout.buildDirectory.dir("native/jni"))
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
            it.jvmArgs("-Xmx512m")
            val hostLibs = rootDir.resolve("../../target/release").canonicalPath
            it.systemProperty("jna.library.path", hostLibs)
            it.systemProperty("java.library.path", hostLibs)
            it.environment("DYLD_LIBRARY_PATH", hostLibs)
        }
    }
    publishing {
        singleVariant("release") { withSourcesJar() }
    }
}

kotlin { jvmToolchain(17) }

dependencies {
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

tasks.withType<Test>().configureEach {
    testLogging { events("passed", "skipped", "failed"); showStandardStreams = false }
}


