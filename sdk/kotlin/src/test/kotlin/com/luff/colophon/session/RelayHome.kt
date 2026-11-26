package com.luff.colophon.session

import com.luff.colophon.AccountMemberKind
import com.luff.colophon.AccountRequest
import com.luff.colophon.HttpAnswer
import com.luff.colophon.HttpRequest
import com.luff.colophon.RequestSpec
import com.luff.colophon.Signature
import com.luff.colophon.accountFormatDate
import com.luff.colophon.accountKeyId
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.ServerSocket
import java.nio.file.Files
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.util.Collections
import java.util.concurrent.TimeUnit

/**
 * The real relay as a home: `bun relay/server.js --test-clock` on loopback with a temporary data directory, one slot
 * provisioned for one account, the Rust home module in WebAssembly. Its key is a P-256 key this test made, given to
 * the relay as a private JWK; the home's signed member request is made with the same key, so the account can appoint
 * it. Missing Bun or the module fails the test (it never passes by skipping). Every relay this process starts is
 * killed by [stop], and by a shutdown hook if a test dies first; its data directory names
 * `colophon-kotlin-relay` so `scripts/test-kotlin.sh` can check that none is left behind.
 */
class RelayHome(val base: String,
                /** 0: the relay binds a port of its own choosing and reports it (no window between choosing and binding). */
                port: Int = freePort(),
                /** With a clock, the relay runs on it (set before every request and pass) with no scheduler timer: heads
                 *  are published only by [tick], so nothing waits on real time. */
                private val clockSource: (() -> Long)? = null) {
    private val ticks = java.util.concurrent.LinkedBlockingQueue<Unit>()
    private val key = P256.generate()
    private val agreement = P256.generate()
    private val dir: File = Files.createTempDirectory("colophon-kotlin-relay-${ProcessHandle.current().pid()}-").toFile()
    private val clock = File(dir, "clock")
    @Volatile private var process: Process? = null
    /** The port the relay listens on (known once it started when it was made with port 0). */
    @Volatile var port: Int = port; private set
    /** The relay's standard error, kept in its directory so a failing test can show it. */
    private val stderr = File(dir, "stderr.log")
    /** The last `lines` lines the relay wrote to standard error. */
    fun errors(lines: Int = 40): String = try { stderr.readLines().takeLast(lines).joinToString("\n") } catch (_: Exception) { "" }

    val id: String get() = accountKeyId(P256.point(key.public as ECPublicKey))

    companion object {
        private val running: MutableSet<Process> = Collections.synchronizedSet(HashSet())
        init {
            Runtime.getRuntime().addShutdownHook(Thread { synchronized(running) { running.forEach { it.destroyForcibly() } } })
        }
        val repository: File get() = File(System.getProperty("colophon.repo") ?: "../..").canonicalFile
        fun freePort(): Int = ServerSocket(0).use { it.localPort }
        fun bun(): String {
            System.getProperty("colophon.bun")?.let { return it }
            val candidates = (System.getenv("PATH") ?: "").split(':').map { "$it/bun" } +
                listOf("${System.getProperty("user.home")}/.bun/bin/bun", "/opt/homebrew/bin/bun", "/usr/local/bin/bun")
            return candidates.firstOrNull { File(it).canExecute() } ?: error("relay prerequisite missing: bun (set COLOPHON_BUN)")
        }
        fun module(): File {
            val f = File(System.getProperty("colophon.homeWasm") ?: error("colophon.homeWasm is not set"))
            check(f.isFile) { "relay prerequisite missing: the home module at ${f.path} (build it with scripts/test-kotlin.sh)" }
            return f
        }
        private fun b64(bytes: ByteArray) = P256.base64url(bytes)
    }

    private val jwk: String
        get() {
            val point = P256.point(key.public as ECPublicKey)
            val d = P256.scalar((key.private as ECPrivateKey).s)
            return Json.write(mapOf("kty" to "EC", "crv" to "P-256", "x" to b64(point.copyOfRange(1, 33)), "y" to b64(point.copyOfRange(33, 65)), "d" to b64(d)))
        }

    /** Starts the relay for `account`; `peers` are the account's other homes (it forwards to them). `provision` is the
     *  config file's `provision` object (the door), as JSON. */
    fun start(account: String, peers: List<RelayHome> = listOf(), provision: String? = null) {
        val bun = bun(); val module = module()
        clock.writeText((clockSource?.invoke() ?: System.currentTimeMillis()).toString())
        val config = File(dir, "config.json")
        val settings = linkedMapOf<String, Any?>("resolve" to peers.associate { it.base to "http://127.0.0.1:${it.port}/v1/libraries/home" })
        if (provision != null) settings["provision"] = Json.parse(provision)
        config.writeText(Json.write(settings))
        val builder = ProcessBuilder(bun, File(repository, "relay/server.js").path, "--test-clock", "--config", config.path)
        builder.environment().apply {
            put("COLOPHON_RELAY_PORT", port.toString())
            put("COLOPHON_RELAY_DATA", File(dir, "data").path)
            put("COLOPHON_RELAY_HOME_SLOTS", "home=$account@$base")
            put("COLOPHON_HOME_KEY", jwk)
            put("COLOPHON_HOME_WASM", module.path)
            put("COLOPHON_RELAY_CLOCK_FILE", clock.path)
            put("COLOPHON_RELAY_TICK_MS", if (clockSource == null) "50" else "0")
        }
        builder.redirectError(ProcessBuilder.Redirect.appendTo(stderr))
        val p = builder.start()
        process = p; running.add(p)
        // The first stdout line is machine-readable: {"listening":{...}}.
        val reader = BufferedReader(InputStreamReader(p.inputStream))
        val line = reader.readLine() ?: ""
        check(line.contains("\"listening\"")) { "the relay did not start: $line\n${errors()}" }
        if (port == 0) port = (Json.obj(line)?.obj("listening")?.long("port") ?: error("no port in $line")).toInt()
        // Keep draining stdout so the relay never blocks on a full pipe; each {"ticked":true} answers a [tick].
        Thread { try { while (true) { val l = reader.readLine() ?: break; if (l.contains("\"ticked\"")) ticks.put(Unit) } } catch (_: Exception) {} }.apply { isDaemon = true }.start()
    }

    fun stop() {
        process?.let { p ->
            p.destroy()
            if (!p.waitFor(5, TimeUnit.SECONDS)) { p.destroyForcibly(); p.waitFor(5, TimeUnit.SECONDS) }
            running.remove(p)
        }
        process = null
        dir.deleteRecursively()
    }

    fun setClock(ms: Long) { clock.writeText(ms.toString()) }
    /** Sets the relay's clock: to the injected clock when there is one, else to now. */
    fun touch() = setClock(clockSource?.invoke() ?: System.currentTimeMillis())
    /** One scheduler pass of the relay (its test hook: a `tick` line on stdin), on its clock, finished when it answers. */
    fun tick() {
        touch()
        val p = checkNotNull(process) { "the relay is not running" }
        p.outputStream.write("tick\n".toByteArray()); p.outputStream.flush()
        // A bound for a dead relay only: the pass answers when it is done, whatever the time.
        checkNotNull(ticks.poll(60, TimeUnit.SECONDS)) { "the relay did not answer its tick" }
    }

    /** The home's signed member request (§9.1) naming `account`, as a home service answers it. */
    fun memberRequest(account: String): ByteArray {
        val spec = RequestSpec(account, P256.point(key.public as ECPublicKey), P256.point(agreement.public as ECPublicKey), "Relay home",
            AccountMemberKind.SERVER, "{\"serves\":[\"home\"]}", accountFormatDate((clockSource?.invoke() ?: System.currentTimeMillis()) - 5_000), null, null, listOf("$base/"))
        return AccountRequest.prepare(spec).use { r ->
            r.finish(Signature(P256.sign(key.private, r.step().body), null, null)).raw
        }
    }

    /** This relay's door (`POST /v1/provision`) on loopback. */
    val door: String get() = "http://127.0.0.1:$port/v1/provision"
    /** A transport to the door that sets the relay's clock first. */
    fun doorTransport(): HomeTransport {
        val inner = HttpHomeTransport(allowingLoopbackHttp = true)
        return HomeTransport { request -> touch(); inner.send(request) }
    }
    /** The transport to a slot this relay provisioned: `slotBase` (its `https://` name) goes to `/v1/libraries/<slot>`. */
    fun slotTransport(slotBase: String, slot: String): HomeTransport {
        val inner = HttpHomeTransport(allowingLoopbackHttp = true)
        return HomeTransport { request ->
            touch()
            check(request.url.startsWith(slotBase)) { "a request for another host: ${request.url}" }
            inner.send(HttpRequest(request.ticket, request.home, request.method, "http://127.0.0.1:$port/v1/libraries/$slot" + request.url.substring(slotBase.length), request.headers, request.body))
        }
    }

    /** The refusals one device's transports saw, in order (the `result` of every 403). */
    class Refusals {
        private val codes = Collections.synchronizedList(ArrayList<String>())
        fun add(code: String) { codes.add(code) }
        val all: List<String> get() = synchronized(codes) { codes.toList() }
        fun clear() = codes.clear()
    }

    /**
     * The session's transport to this relay: the account's `https://` name goes to the process on loopback (plain
     * `http` allowed for loopback only, by the SDK's testing option), and the relay's clock is set to now first.
     */
    fun transport(refusals: Refusals? = null): HomeTransport {
        val inner = HttpHomeTransport(allowingLoopbackHttp = true)
        return HomeTransport { request ->
            touch()
            check(request.url.startsWith(base)) { "a request for another host: ${request.url}" }
            val local = "http://127.0.0.1:$port/v1/libraries/home" + request.url.substring(base.length)
            val answer: HttpAnswer = inner.send(HttpRequest(request.ticket, request.home, request.method, local, request.headers, request.body))
            if (answer.status == 403u) refusals?.add(Json.obj(answer.body.toString(Charsets.UTF_8))?.string("result") ?: "-")
            answer
        }
    }
}
