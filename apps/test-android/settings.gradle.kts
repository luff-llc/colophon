pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "colophon-test-android"
// The Colophon Android SDK from source (sdk/android, with its JNI libraries built by cargo-ndk), substituted for
// org.luff.colophon:colophon-android.
includeBuild("../../sdk/android")
include(":app")
