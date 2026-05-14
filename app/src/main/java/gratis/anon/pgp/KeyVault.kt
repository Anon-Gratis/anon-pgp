package gratis.anon.pgp

import android.content.Context
import org.bouncycastle.openpgp.PGPSecretKeyRing
import java.io.File

/**
 * Multi-keyring vault. Each secret keyring is stored as ASCII-armored
 * (passphrase-protected at the OpenPGP layer) under
 * `filesDir/keys/<compact-fingerprint>.asc`. Importing the same key twice is a
 * no-op overwrite, keyed by fingerprint.
 *
 * One key is marked "active" via SharedPreferences; all crypto ops in the rest
 * of the app use the active key. The active selection is plain-text but
 * harmless (it doesn't leak the key material).
 *
 * Backwards compat: if the legacy single-key file `anon-pgp-secret.asc` exists
 * from a v0.2.x install, it's migrated into the vault on construction.
 */
class KeyVault(private val context: Context) {

    private val dir: File
        get() = File(context.filesDir, DIR).also { if (!it.exists()) it.mkdirs() }

    private val prefs by lazy {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    }

    init {
        migrateLegacyIfPresent()
    }

    data class Entry(
        val fingerprint: String,
        val displayName: String,
        val ring: PGPSecretKeyRing
    ) {
        val prettyFingerprint: String
            get() = fingerprint.chunked(4).joinToString(" ")
    }

    fun list(): List<Entry> {
        val files = dir.listFiles { f -> f.isFile && f.name.endsWith(".asc") }
            ?: return emptyList()
        return files.mapNotNull { f ->
            try {
                val ring = PgpHelper.loadSecretKeyRing(f.readBytes())
                Entry(
                    fingerprint = PgpHelper.fingerprintCompact(ring.publicKey),
                    displayName = PgpHelper.firstUserId(ring.publicKey) ?: "<unknown>",
                    ring = ring
                )
            } catch (_: Throwable) {
                null
            }
        }.sortedBy { it.displayName.lowercase() }
    }

    /** Adds or replaces (by fingerprint) a secret keyring. */
    fun add(armored: ByteArray): Entry {
        val ring = PgpHelper.loadSecretKeyRing(armored)
        val fp = PgpHelper.fingerprintCompact(ring.publicKey)
        File(dir, "$fp.asc").writeBytes(armored)
        // First key added becomes active automatically.
        if (getActiveFingerprint() == null) setActiveFingerprint(fp)
        return Entry(
            fingerprint = fp,
            displayName = PgpHelper.firstUserId(ring.publicKey) ?: "<unknown>",
            ring = ring
        )
    }

    fun rawBytes(fingerprint: String): ByteArray? {
        val f = File(dir, "$fingerprint.asc")
        return if (f.exists()) f.readBytes() else null
    }

    fun delete(fingerprint: String) {
        val f = File(dir, "$fingerprint.asc")
        if (f.exists()) {
            f.writeBytes(ByteArray(f.length().toInt()))
            f.delete()
        }
        if (getActiveFingerprint() == fingerprint) {
            // Pick another key as active if any remain.
            val first = list().firstOrNull()
            if (first != null) setActiveFingerprint(first.fingerprint)
            else prefs.edit().remove(PREF_ACTIVE).apply()
        }
    }

    fun getActiveFingerprint(): String? = prefs.getString(PREF_ACTIVE, null)

    fun setActiveFingerprint(fingerprint: String) {
        prefs.edit().putString(PREF_ACTIVE, fingerprint).apply()
    }

    fun getActive(): Entry? {
        val fp = getActiveFingerprint() ?: return null
        return list().firstOrNull { it.fingerprint == fp }
            ?: list().firstOrNull()  // active fp went stale — pick anything
                ?.also { setActiveFingerprint(it.fingerprint) }
    }

    fun wipe() {
        dir.listFiles()?.forEach {
            it.writeBytes(ByteArray(it.length().toInt()))
            it.delete()
        }
        prefs.edit().clear().apply()
    }

    /**
     * If `filesDir/anon-pgp-secret.asc` from v0.2.x exists, import it into the
     * vault and delete the legacy file. The user's single key thus survives an
     * in-place upgrade.
     */
    private fun migrateLegacyIfPresent() {
        val legacy = File(context.filesDir, LEGACY_FILE)
        if (!legacy.exists() || legacy.length() == 0L) return
        try {
            val bytes = legacy.readBytes()
            add(bytes)
            legacy.writeBytes(ByteArray(legacy.length().toInt()))
            legacy.delete()
        } catch (_: Throwable) {
            // leave legacy file in place; user can still re-import manually
        }
    }

    companion object {
        private const val DIR = "keys"
        private const val PREFS = "key_vault"
        private const val PREF_ACTIVE = "active_fingerprint"
        private const val LEGACY_FILE = "anon-pgp-secret.asc"
    }
}
