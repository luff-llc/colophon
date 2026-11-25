package com.luff.colophon.hosts

import com.luff.colophon.session.ColophonSession
import com.luff.colophon.session.Device
import kotlinx.coroutines.runBlocking
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.lang.reflect.Modifier
import java.net.URI
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import javax.tools.JavaFileObject
import javax.tools.SimpleJavaFileObject
import javax.tools.ToolProvider
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Pins the module's surface as Java sees it: no member a Java caller can reach without reflection hands out or takes
 * the engine, a session endpoint, the stream client, an account view, the account adapter or a signer, except the
 * generated bindings and the members listed, each with its reason, in [allowed]. Kotlin `internal` compiles to
 * public bytecode (mangled with `$`), so every member of every public class of the module is inspected, `$` names
 * included; only synthetic members, which javac does not let code call, are exempt. A Java snippet that reaches for
 * one of those members must not compile, and a Java application opens a host through the public API.
 */
class ApiSurfaceTest {
    /** What may neither be handed out nor taken: core objects, the session's internals, the account adapter. */
    private val forbidden = Regex(
        "com\\.luff\\.colophon\\.(AccountEngine|SessionEndpoint|HomeStream|SessionAccountView|AccountAction)(?![\\w$])|" +
            "com\\.luff\\.colophon\\.session\\.(ColophonEngine|KeyCustody|SessionWorker)(?![\\w$])|com\\.luff\\.colophon\\.hosts\\.HostAccount(?![\\w$])")
    /** What may not be handed out: also a signer (an application gives the session its own key providers; none comes back). */
    private val forbiddenOut = Regex(forbidden.pattern + "|com\\.luff\\.colophon\\.session\\.AsyncKeyProvider(?![\\w$])")

    /** Every class the module compiles (`src/main` and `src/jvm`), from its class files. */
    private fun allClasses(): List<Class<*>> {
        val root = File(HostAccess::class.java.protectionDomain.codeSource.location.toURI())
        return root.walkTopDown().filter { it.isFile && it.extension == "class" && it.name != "module-info.class" }
            .map { Class.forName(it.relativeTo(root).path.removeSuffix(".class").replace(File.separatorChar, '.'), false, javaClass.classLoader) }.toList()
    }
    /** The classes inspected: every class of the module. */
    private fun inspected(): List<Class<*>> = allClasses()

    /**
     * The generated binding surface (`colophon_ffi.kt`, package `com.luff.colophon`): it defines `AccountEngine`,
     * `HomeStream` and the rest, so its members name them by definition. One package entry; the hand-written classes of
     * that package (the 0.4 wrappers) are not covered by it and are checked like any other.
     */
    private val generatedPackage = "com.luff.colophon"
    private val handWritten: Set<String> by lazy {
        val repo = File(System.getProperty("colophon.repo") ?: "../..").canonicalFile
        val decl = Regex("^(?:public |internal |private )?(?:(?:data|sealed|abstract|open|enum|fun|value|annotation)\\s+)*(?:class|interface|object)\\s+(\\w+)", RegexOption.MULTILINE)
        File(repo, "sdk/kotlin/src/main/kotlin/com/luff/colophon").listFiles()!!.filter { it.isFile && it.extension == "kt" && it.name != "colophon_ffi.kt" }
            .flatMap { f -> decl.findAll(f.readText()).map { it.groupValues[1] } + (f.nameWithoutExtension + "Kt") }.toSet()
    }
    private fun generated(c: Class<*>): Boolean = c.packageName == generatedPackage && c.name.removePrefix("$generatedPackage.").substringBefore('$') !in handWritten

    /**
     * Each member outside the generated bindings that carries one of these types on purpose, as `class#member`, with its
     * reason. Anything not listed fails.
     */
    private val allowed = mapOf(
        // The 0.5 session's engine on its own lane (public 0.5 API): `run` and `execute` take a function of the
        // `AccountEngine`, run on that lane; `open` and `openCreated` return the engine they open.
        "com.luff.colophon.session.ColophonEngine#run" to "0.5 API: runs a call on the engine's lane",
        "com.luff.colophon.session.ColophonEngine#execute" to "0.5 API: an action from begin to written",
        "com.luff.colophon.session.ColophonEngine\$Companion#open" to "0.5 API: opens an engine",
        "com.luff.colophon.session.ColophonEngine\$Companion#openCreated" to "0.5 API: opens a created engine",
        // The 0.5 key custody (public 0.5 API): it holds the application's own key providers and answers the engine's
        // signing steps with them.
        "com.luff.colophon.session.KeyCustody#provider" to "0.5 API: the application's own provider for a key",
        "com.luff.colophon.session.KeyCustody#getProviders" to "0.5 API: the application's own providers",
        "com.luff.colophon.session.KeyCustody#merging" to "0.5 API: custody over more of the application's providers",
        "com.luff.colophon.session.KeyCustody\$Companion#of" to "0.5 API: custody over the application's providers",
        // The application's own key providers, given to the session by it and read back from its own configuration.
        "com.luff.colophon.session.SessionConfiguration#getKeys" to "the application's member key provider",
        "com.luff.colophon.session.SessionConfiguration#getRecoveryKeys" to "the application's recovery key provider",
        "com.luff.colophon.session.SessionConfiguration#getOwnerController" to "the application's owner controller",
        "com.luff.colophon.session.AdditionalController#getProvider" to "the application's controller key provider",
        "com.luff.colophon.session.KeysKt#asAsync" to "0.5 API: adapts the application's own synchronous provider",
    )
    /** Kotlin mangles a member taking an inline value class (`open-tHZpf6s`); its source name is before the `-`. */
    private fun allowed(c: Class<*>, member: String): Boolean = generated(c) || "${c.name}#${member.substringBefore('-')}" in allowed.keys

    private fun visible(modifiers: Int) = Modifier.isPublic(modifiers) || Modifier.isProtected(modifiers)
    private fun names(types: List<java.lang.reflect.Type>) = types.map { it.typeName }

    /** Every non-synthetic member of a public class whose signature names a forbidden type. */
    private fun reachable(c: Class<*>): List<String> {
        if (!Modifier.isPublic(c.modifiers) || c.isSynthetic) return listOf()
        val out = ArrayList<String>()
        for (m in c.declaredMethods) {
            if (m.isSynthetic || !visible(m.modifiers)) continue
            if (forbiddenOut.containsMatchIn(m.genericReturnType.typeName) || names(m.genericParameterTypes.toList()).any { forbidden.containsMatchIn(it) } ||
                m.name.startsWith("signRaw")) out.add("${c.name}.${m.name}")
        }
        for (k in c.declaredConstructors) {
            if (!k.isSynthetic && visible(k.modifiers) && names(k.genericParameterTypes.toList()).any { forbidden.containsMatchIn(it) }) out.add("${c.name}.<init>")
        }
        for (f in c.declaredFields) {
            if (!f.isSynthetic && visible(f.modifiers) && forbiddenOut.containsMatchIn(f.genericType.typeName)) out.add("${c.name}.${f.name}")
        }
        return out
    }

    @Test fun noMemberReachableFromJavaExposesACoreObjectOrASigner() {
        val classes = inspected()
        assertTrue(classes.size >= 200, "the classes were found (${classes.size})")
        assertEquals(listOf(), classes.flatMap { c -> reachable(c).filterNot { allowed(c, it.substringAfterLast('.')) } })
        // Every entry of the allow-list still names a member that exists: a stale entry is removed, not kept.
        val used = classes.filterNot { generated(it) }.flatMap { c -> reachable(c).map { "${c.name}#${it.substringAfterLast('.').substringBefore('-')}" } }.toSet()
        assertEquals(setOf(), allowed.keys - used)
    }

    /** The internal members that do carry such types: they exist, and they are synthetic. */
    private fun hiddenMembers(): List<Pair<Class<*>, java.lang.reflect.Method>> = inspected().filter { !generated(it) }.flatMap { c ->
        c.declaredMethods.filter { m ->
            m.isSynthetic && m.name.contains('$') && !m.name.startsWith("access$") && visible(m.modifiers) &&
                m.name.all { ch -> Character.isJavaIdentifierPart(ch) } &&
                names(listOf(m.genericReturnType) + m.genericParameterTypes).any { forbidden.containsMatchIn(it) }
        }.map { c to it }
    }

    private fun compile(name: String, source: String): Pair<Boolean, String> {
        val compiler = ToolProvider.getSystemJavaCompiler() ?: error("this JVM has no Java compiler")
        val out = Files.createTempDirectory("colophon-api-").toFile()
        try {
            val file = object : SimpleJavaFileObject(URI.create("string:///$name.java"), JavaFileObject.Kind.SOURCE) {
                override fun getCharContent(ignoreEncodingErrors: Boolean): CharSequence = source
            }
            val errors = ByteArrayOutputStream()
            val writer = errors.writer()
            val ok = compiler.getTask(writer, null, null, listOf("-proc:none", "-classpath", System.getProperty("java.class.path"), "-d", out.path), null, listOf(file)).call()
            writer.flush()
            return ok to errors.toString()
        } finally { out.deleteRecursively() }
    }

    @Test fun javaCodeCompilesAgainstThePublicApiAndCannotReachTheEngineOrTheEndpoint() {
        val (ok, errors) = compile("Uses", """
            import com.luff.colophon.hosts.*;
            import com.luff.colophon.session.ColophonSession;
            class Uses {
                static Object open(ColophonSession session, CellCarrier carrier) {
                    CellHostOptions options = new CellHostOptions(HostAccess.of(session), carrier, "listening.podcasts", "now-playing", new MemoryClaimStore());
                    return SessionCellHost.openFuture(options);
                }
            }
        """.trimIndent())
        assertTrue(ok, "the public API compiles from Java: $errors")

        val hidden = hiddenMembers()
        val found = hidden.map { it.second.name }
        for (prefix in listOf("getHost$", "getCurrent$", "getWorker$")) assertTrue(found.any { it.startsWith(prefix) }, "$prefix exists and is synthetic: $found")
        for ((c, m) in hidden) {
            val type = c.name.replace('$', '.')
            val receiver = if (Modifier.isStatic(m.modifiers)) type else "(($type) null)"
            val args = m.parameterTypes.joinToString(", ") { "null" }
            val (compiled, why) = compile("Reaches", "class Reaches { Object x() throws Throwable { return $receiver.${m.name}($args); } }")
            assertTrue(!compiled && why.contains("cannot find symbol"), "${c.name}.${m.name} must not be callable from Java: $why")
        }
    }

    @Test fun theAndroidLibraryDoesNotCarryTheHosts() {
        val repo = File(System.getProperty("colophon.repo") ?: "../..").canonicalFile
        val gradle = File(repo, "sdk/android/build.gradle.kts").readText()
        assertTrue(gradle.contains("""tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach { exclude("com/luff/colophon/hosts/**") }"""))
        assertTrue(gradle.contains("""tasks.withType<Jar>().configureEach { exclude("com/luff/colophon/hosts/**") }"""))
        val android = File(repo, "sdk/android/src").walkTopDown().filter { it.isFile && it.extension == "kt" }.filter { it.readText().contains("com.luff.colophon.hosts") }.toList()
        assertEquals(listOf(), android, "no Android source uses the hosts")
    }

    @Test(timeout = 120_000) fun aJavaApplicationOpensAHostThroughThePublicApi() = runBlocking {
        val device = Device(namespaces = listOf(NS))
        try {
            device.session.create()
            val host = JavaHostUse.open(device.session)
            assertEquals(SessionCellHost.Phase.OPEN, host.phase)
            host.close()
        } finally { device.close() }
    }
}
