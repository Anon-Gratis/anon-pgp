package gratis.anon.pgp

import android.content.Context
import android.content.SharedPreferences

/**
 * Adapts Android [SharedPreferences] to the [KeyValuePrefs] interface that
 * :core's [KeyVault] needs. Same on-disk format as before — the SharedPreferences
 * file name and key are unchanged so existing installs keep their active-key
 * pointer.
 */
class AndroidPrefs(context: Context, name: String) : KeyValuePrefs {

    private val sp: SharedPreferences =
        context.getSharedPreferences(name, Context.MODE_PRIVATE)

    override fun getString(key: String): String? = sp.getString(key, null)

    override fun putString(key: String, value: String) {
        sp.edit().putString(key, value).apply()
    }

    override fun remove(key: String) {
        sp.edit().remove(key).apply()
    }

    override fun clear() {
        sp.edit().clear().apply()
    }
}
