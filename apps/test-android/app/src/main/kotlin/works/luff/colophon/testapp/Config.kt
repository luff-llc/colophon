package works.luff.colophon.testapp

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.SecureRandom

/** The build's defaults (BuildConfig, from Gradle properties). Nothing here is secret. */
object BuildDefaults {
    val homePrefix: String get() = BuildConfig.HOME_PREFIX
    val reachPrefix: String get() = BuildConfig.HOME_REACH
    val provisioner: String get() = BuildConfig.PROVISIONER
    val relyingParty: String get() = BuildConfig.RELYING_PARTY
    val stagingPrefix: String get() = BuildConfig.STAGING_PREFIX
    val stagingProvisioner: String get() = BuildConfig.STAGING_PROVISIONER
}

enum class OwnerChoice(val wire: String) {
    /** The person's passkey (Credential Manager, PRF): a real owner. */
    PASSKEY("passkey"),
    /** A P-256 owner key in Android Keystore, no passkey: for emulators that cannot do PRF. Test only. */
    DEVICE_KEY("software"),
    /** This device joined an account: a member key only; it cannot approve, revoke or veto. */
    NONE("none");
    companion object { fun of(wire: String?) = entries.firstOrNull { it.wire == wire } }
}

/** The person's settings, as JSON in app-private storage: URLs, the slot, the passkey's public descriptor. */
data class Settings(
    val homePrefix: String = BuildDefaults.homePrefix,
    val reachPrefix: String = BuildDefaults.reachPrefix,
    val provisioner: String = BuildDefaults.provisioner,
    val slot: String? = null,
    val owner: OwnerChoice? = null,
    /** The passkey's core-parsed descriptor (public). */
    val passkeyDescriptor: String? = null,
    /** The token the local home service printed at start-up (it refuses requests without it). */
    val provisionerToken: String = "",
    /** Invites that failed to read or verify, in ms (the last hour counts; see `AppModel.ATTEMPT_LIMIT`). Approving a device is bounded by the session's own pairing limiter (§7.3). */
    val failures: List<Long> = listOf(),
) {
    /** The home's base URL as the account names it (no trailing slash). */
    val homeBase: String? get() = slot?.let { (if (homePrefix.endsWith("/")) homePrefix else "$homePrefix/") + it }

    fun json(): String = JSONObject().apply {
        put("homePrefix", homePrefix); put("reachPrefix", reachPrefix); put("provisioner", provisioner)
        slot?.let { put("slot", it) }; owner?.let { put("owner", it.wire) }; passkeyDescriptor?.let { put("passkey", it) }
        put("provisionerToken", provisionerToken); put("failures", JSONArray(failures))
    }.toString()

    companion object {
        fun parse(text: String): Settings {
            val o = JSONObject(text)
            return Settings(o.optString("homePrefix", BuildDefaults.homePrefix), o.optString("reachPrefix", BuildDefaults.reachPrefix),
                o.optString("provisioner", BuildDefaults.provisioner), o.optString("slot").ifEmpty { null },
                OwnerChoice.of(o.optString("owner").ifEmpty { null }), o.optString("passkey").ifEmpty { null }, o.optString("provisionerToken"),
                o.optJSONArray("failures")?.let { a -> (0 until a.length()).map { a.getLong(it) } } ?: listOf())
        }
        fun newSlot(): String = "t" + ByteArray(5).also(SecureRandom()::nextBytes).joinToString("") { "%02x".format(it) }
    }
}

/** Where this app keeps things (one account per install), all in `noBackupFilesDir`. */
class Paths(context: Context) {
    val root = File(context.noBackupFilesDir, "colophon-test")
    val settings = File(root, "settings.json")
    val account = File(root, "account")
    val records = File(account, "records")
    val session = File(account, "session")
    val deviceKeys = File(account, "device-keys")
    /** Debug builds write the last pairing payload they showed and the log here, for scripted runs (public bytes only). */
    val outbox = File(context.filesDir, "outbox.txt")
    val logFile = File(context.filesDir, "log.txt")

    fun loadSettings(): Settings = try { if (settings.isFile) Settings.parse(settings.readText()) else Settings() } catch (_: Exception) { Settings() }
    fun save(value: Settings) {
        root.mkdirs()
        val tmp = File(root, ".settings.tmp")
        tmp.writeText(value.json())
        if (!tmp.renameTo(settings)) throw IllegalStateException("cannot save the settings")
    }
}
