package works.luff.colophon.testapp

import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.zip.Deflater
import java.util.zip.Inflater

/**
 * The two payloads the test apps pass between devices, the same bytes as the iPhone app (apps/test-ios/App/Pairing.swift):
 * an invite (`CTJ1.`: the home's prefix and slot, the account ID and its `authority/` history) and a request (`CTR1.`:
 * the joining device's signed member request). JSON (or the request's bytes), raw DEFLATE, base64url without padding.
 */
object PairingPayload {
    data class Invite(val homePrefix: String, val slot: String, val account: String, val history: Map<String, ByteArray>)
    class Failure(message: String) : Exception(message)

    const val INVITE = "CTJ1."
    const val REQUEST = "CTR1."
    private const val MAX_INFLATED = 32 * 1024 * 1024

    fun encode(invite: Invite): String {
        val history = JSONObject()
        for ((path, bytes) in invite.history.toSortedMap()) history.put(path, Base64.getEncoder().encodeToString(bytes))
        val json = JSONObject().put("v", 1).put("prefix", invite.homePrefix).put("slot", invite.slot)
            .put("account", invite.account).put("history", history).toString()
        return INVITE + b64url(deflate(json.toByteArray()))
    }
    fun encodeRequest(request: ByteArray): String = REQUEST + b64url(deflate(request))

    fun decodeInvite(text: String): Invite {
        val o = try { JSONObject(String(body(text, INVITE))) } catch (e: Failure) { throw e } catch (_: Exception) { throw notAPayload() }
        if (o.optInt("v") != 1) throw notAPayload()
        val account = o.optString("account")
        val history = o.optJSONObject("history") ?: throw notAPayload()
        val files = HashMap<String, ByteArray>()
        for (path in history.keys()) {
            if (!isHistoryPath(path)) throw Failure("The invite carries a path that is not account history: $path")
            files[path] = try { Base64.getDecoder().decode(history.getString(path)) } catch (_: Exception) { throw Failure("bad history entry $path") }
        }
        if (account.length != 64 || !account.all { it in '0'..'9' || it in 'a'..'f' } || files.isEmpty()) throw notAPayload()
        return Invite(o.optString("prefix"), o.optString("slot"), account, files)
    }
    fun decodeRequest(text: String): ByteArray = body(text, REQUEST)
    fun kind(text: String): String? = text.trim().let { if (it.startsWith(INVITE)) "invite" else if (it.startsWith(REQUEST)) "request" else null }

    /** `authority/` followed by 8 digits and `.json`: the only paths an invite may write. */
    fun isHistoryPath(path: String): Boolean {
        val parts = path.split("/")
        if (parts.size != 2 || parts[0] != "authority" || !parts[1].endsWith(".json")) return false
        val digits = parts[1].removeSuffix(".json")
        return digits.length == 8 && digits.all { it in '0'..'9' }
    }

    private fun notAPayload() = Failure("This is not a Colophon test invite or request.")
    private fun body(text: String, prefix: String): ByteArray {
        val t = text.trim()
        if (!t.startsWith(prefix)) throw notAPayload()
        val raw = try { Base64.getUrlDecoder().decode(t.removePrefix(prefix)) } catch (_: Exception) { throw notAPayload() }
        return inflate(raw)
    }
    private fun deflate(data: ByteArray): ByteArray {
        val deflater = Deflater(Deflater.BEST_COMPRESSION, true)
        try {
            deflater.setInput(data); deflater.finish()
            val out = ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            while (!deflater.finished()) out.write(buffer, 0, deflater.deflate(buffer))
            return out.toByteArray()
        } finally { deflater.end() }
    }
    private fun inflate(data: ByteArray): ByteArray {
        val inflater = Inflater(true)
        try {
            inflater.setInput(data)
            val out = ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            while (!inflater.finished()) {
                val n = inflater.inflate(buffer)
                if (n == 0 && (inflater.needsInput() || inflater.needsDictionary())) break
                out.write(buffer, 0, n)
                if (out.size() > MAX_INFLATED) throw Failure("payload too large")
            }
            if (!inflater.finished()) throw notAPayload()
            return out.toByteArray()
        } catch (e: java.util.zip.DataFormatException) { throw notAPayload() } finally { inflater.end() }
    }
    private fun b64url(data: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(data)
}
