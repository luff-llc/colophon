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
 * Pins the hosts' surface as Java sees it: no member a Java caller can reach without reflection hands out or takes the
 * engine, a session endpoint, the stream client, an account view, the account adapter or a signer. Kotlin `internal`
 * compiles to public bytecode (mangled with `$`), so every member of every public class is inspected, `$` names
 * included; only synthetic members, which javac does not let code call, are exempt. A Java snippet that reaches for
 * one of those members must not compile, and a Java application opens a host through the public API.
 */
class ApiSurfaceTest {
    /** What may neither be handed out nor taken: core objects, the session's internals, the account adapter. */
    private val forbidden = Regex(
        "com\\.luff\\.colophon\\.(AccountEngine|SessionEndpoint|HomeStream|SessionAccountView|AccountAction)\\b|" +
            "com\\.luff\\.colophon\\.session\\.(ColophonEngine|KeyCustody|SessionWorker)\\b|com\\.luff\\.colophon\\.hosts\\.HostAccount\\b")
    /** What may not be handed out: also a signer (an application gives the session its own key providers; none comes back). */
    private val forbiddenOut = Regex(forbidden.pattern + "|com\\.luff\\.colophon\\.session\\.AsyncKeyProvider\\b")

    private fun hostClasses(): List<Class<*>> {
        val root = File(HostAccess::class.java.protectionDomain.codeSource.location.toURI())
        return File(root, "com/luff/colophon/hosts").listFiles()!!.filter { it.extension == "class" }
            .map { Class.forName("com.luff.colophon.hosts." + it.nameWithoutExtension, false, javaClass.classLoader) }
    }
    /** The classes inspected: every class of the hosts package, and the session an application holds. */
    private fun inspected(): List<Class<*>> = hostClasses() + ColophonSession::class.java

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
        assertTrue(classes.size >= 40, "the classes were found (${classes.size})")
        assertEquals(listOf(), classes.flatMap { reachable(it) })
    }

    /** The internal members that do carry such types: they exist, and they are synthetic. */
    private fun hiddenMembers(): List<Pair<Class<*>, java.lang.reflect.Method>> = inspected().flatMap { c ->
        c.declaredMethods.filter { m ->
            m.isSynthetic && m.name.contains('$') && !m.name.startsWith("access$") && visible(m.modifiers) &&
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
