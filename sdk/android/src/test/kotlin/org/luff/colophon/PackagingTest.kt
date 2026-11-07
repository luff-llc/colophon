package org.luff.colophon

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Guards the packaging rules the release AAR and a minified app depend on. */
class PackagingTest {
    @Test
    fun consumerRulesKeepAnnotationsAndIgnoreAwt() {
        val rules = File(System.getProperty("colophon.consumerRules")).readText()
        assertTrue(rules.contains("-keepattributes *Annotation*,EnclosingMethod,InnerClasses,Signature"))
        assertTrue(rules.contains("-dontwarn java.awt.**"))
    }

    @Test
    fun nativeLibrariesAreOutsideTheBuildDirectoryAndTheReleaseAarIsExplicit() {
        val gradle = File(System.getProperty("colophon.buildGradle")).readText()
        assertFalse(gradle.contains("layout.buildDirectory.dir(\"native/jni\")"))
        assertTrue(gradle.contains("layout.projectDirectory.dir(\"native/jni\")"))
        assertTrue(gradle.contains("checkNativeLibs"))
        val script = File(System.getProperty("colophon.buildScript")).readText()
        assertTrue(script.contains("sdk/android/native/jni"))
        assertTrue(script.contains("colophon-android-release.aar"))
        assertFalse(script.contains("find sdk/android/build/outputs/aar"))
    }
}
