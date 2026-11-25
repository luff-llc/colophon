package com.luff.colophon.hosts

import org.junit.Test
import java.io.File
import java.lang.reflect.Modifier
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Pins the hosts' public surface: no public declaration of `com.luff.colophon.hosts` hands out or takes the engine, a
 * session endpoint, the stream client, an account view, the account adapter or a signer. An application gets value
 * snapshots and the hosts' own calls, and cannot act on a core object outside a host's serial context or ask the
 * member key to sign. Checked over the compiled classes (Kotlin `internal` members compile to names with a `$`, and
 * `internal` classes are found in the sources).
 */
class ApiSurfaceTest {
    private val forbidden = Regex(
        "com\\.luff\\.colophon\\.(AccountEngine|SessionEndpoint|HomeStream|SessionAccountView|AccountAction)\\b|" +
            "com\\.luff\\.colophon\\.session\\.(ColophonEngine|KeyCustody|AsyncKeyProvider|SessionWorker)\\b|com\\.luff\\.colophon\\.hosts\\.HostAccount\\b")
    private val repo = File(System.getProperty("colophon.repo") ?: "../..").canonicalFile
    private val sources = listOf(File(repo, "sdk/kotlin/src/main/kotlin/com/luff/colophon/hosts"), File(repo, "sdk/kotlin/src/jvm/kotlin/com/luff/colophon/hosts"))

    /** Classes declared `internal` or `private` in the sources (public in bytecode, not part of the API). */
    private fun hidden(): Set<String> {
        val decl = Regex("^\\s*(?:internal|private)\\s+(?:(?:sealed|data|abstract|open|inner|enum|fun)\\s+)*(?:class|interface|object)\\s+(\\w+)", RegexOption.MULTILINE)
        return sources.flatMap { d -> d.listFiles()!!.filter { it.extension == "kt" }.flatMap { f -> decl.findAll(f.readText()).map { it.groupValues[1] }.toList() } }.toSet()
    }

    @Test fun noPublicDeclarationExposesACoreObjectOrASigner() {
        val root = File(HostAccess::class.java.protectionDomain.codeSource.location.toURI())
        val dir = File(root, "com/luff/colophon/hosts")
        val hidden = hidden()
        assertTrue("HostAccount" in hidden, "the account adapter is internal")
        val classes = dir.listFiles()!!.filter { it.extension == "class" }.map { "com.luff.colophon.hosts." + it.nameWithoutExtension.replace('$', '.') }
        val offending = ArrayList<String>()
        var checked = 0
        for (name in classes) {
            val parts = name.removePrefix("com.luff.colophon.hosts.").split('.')
            if (parts.any { it in hidden || it.isEmpty() || it.first().isDigit() || it.contains("Lambda") }) continue
            val c = try { Class.forName(name.replaceAfter("hosts.", parts.joinToString("$"))) } catch (_: Throwable) { continue }
            if (!Modifier.isPublic(c.modifiers) || c.isSynthetic) continue
            checked++
            for (m in c.declaredMethods) {
                if (!Modifier.isPublic(m.modifiers) || m.isSynthetic || m.name.contains('$')) continue
                val types = listOf(m.genericReturnType.typeName) + m.genericParameterTypes.map { it.typeName }
                if (types.any { forbidden.containsMatchIn(it) } || m.name == "signRaw" || m.name == "engine") offending.add("${c.name}.${m.name}")
            }
            for (k in c.declaredConstructors) {
                if (!Modifier.isPublic(k.modifiers) || k.isSynthetic) continue
                if (k.genericParameterTypes.any { forbidden.containsMatchIn(it.typeName) }) offending.add("${c.name}.<init>")
            }
            for (f in c.declaredFields) {
                if (Modifier.isPublic(f.modifiers) && forbidden.containsMatchIn(f.genericType.typeName)) offending.add("${c.name}.${f.name}")
            }
        }
        assertTrue(checked >= 20, "the public classes were found ($checked)")
        assertEquals(listOf(), offending)
    }
}
