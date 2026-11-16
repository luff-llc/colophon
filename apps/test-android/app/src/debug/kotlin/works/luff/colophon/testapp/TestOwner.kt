package works.luff.colophon.testapp

import android.content.Context
import com.luff.colophon.session.AsyncKeyProvider
import org.luff.colophon.session.AndroidSession

/**
 * Debug builds only (src/debug): an owner key in Android Keystore with no passkey, for emulators that cannot do PRF.
 * It bypasses the person's passkey ceremony, so release builds (src/release) have no such key at all.
 */
object TestOwner {
    const val AVAILABLE = true
    fun keys(context: Context, alias: String): AsyncKeyProvider? = AndroidSession.memberKeys(context, alias)
}
