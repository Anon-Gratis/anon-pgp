package gratis.anon.pgp

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Stores the user's app-lock PIN as a PBKDF2-HMAC-SHA256 hash (100k iterations,
 * 32-byte salt, 32-byte digest) inside an [EncryptedSharedPreferences] file
 * (which itself is AES-encrypted with an Android Keystore-bound master key).
 *
 * Two layers of protection:
 *   1. PIN is never stored in plaintext — only hash + salt.
 *   2. The hash + salt are stored in an encrypted prefs file whose key lives
 *      in Keystore (hardware-backed where available).
 *
 * There is no PIN recovery. Forgetting the PIN means clearing app data and
 * re-importing your PGP keys.
 */
class PinStore(context: Context) {

    private val prefs: SharedPreferences by lazy {
        val masterKey = MasterKey.Builder(context, MasterKey.DEFAULT_MASTER_KEY_ALIAS)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            "anon_pgp_lock",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    fun hasPin(): Boolean = prefs.contains(KEY_HASH) && prefs.contains(KEY_SALT)

    fun isBiometricEnabled(): Boolean = prefs.getBoolean(KEY_BIO, false)

    fun setBiometricEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_BIO, enabled).apply()
    }

    fun setPin(pin: CharArray) {
        val salt = ByteArray(SALT_BYTES).also { SecureRandom().nextBytes(it) }
        val hash = pbkdf2(pin, salt)
        prefs.edit()
            .putString(KEY_HASH, Base64.encodeToString(hash, Base64.NO_WRAP))
            .putString(KEY_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
            .apply()
    }

    fun verifyPin(pin: CharArray): Boolean {
        val storedHash = prefs.getString(KEY_HASH, null) ?: return false
        val storedSalt = prefs.getString(KEY_SALT, null) ?: return false
        val expected = Base64.decode(storedHash, Base64.NO_WRAP)
        val salt = Base64.decode(storedSalt, Base64.NO_WRAP)
        val actual = pbkdf2(pin, salt)
        // Constant-time compare to avoid timing oracle.
        return constantTimeEquals(expected, actual)
    }

    /** Clear PIN + biometric flag. Used when disabling the lock. */
    fun clearPin() {
        prefs.edit()
            .remove(KEY_HASH)
            .remove(KEY_SALT)
            .remove(KEY_BIO)
            .apply()
    }

    private fun pbkdf2(pin: CharArray, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(pin, salt, ITERATIONS, DIGEST_BITS)
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }

    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }

    companion object {
        private const val KEY_HASH = "pin_hash"
        private const val KEY_SALT = "pin_salt"
        private const val KEY_BIO = "bio_enabled"
        private const val SALT_BYTES = 32
        private const val ITERATIONS = 100_000
        private const val DIGEST_BITS = 256
    }
}
