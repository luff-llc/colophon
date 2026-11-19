package works.luff.colophon.testapp

import android.content.Context
import com.luff.colophon.session.AsyncKeyProvider

/** Release builds have no test owner key: the person's passkey is the only owner (see src/debug for the test one). */
object TestOwner {
    const val AVAILABLE = false
    @Suppress("UNUSED_PARAMETER") fun keys(context: Context, alias: String): AsyncKeyProvider? = null
}
