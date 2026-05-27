package gratis.anon.pgp

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.Properties

/**
 * Tiny string-keyed string-value preference store. Lets [KeyVault] track its
 * "active fingerprint" pointer without depending on Android's SharedPreferences
 * or any other framework.
 *
 * On Android this is backed by SharedPreferences (see :app AndroidPrefs).
 * On desktop this is backed by [PropertiesPrefs], a plain java.util.Properties
 * file on disk.
 */
interface KeyValuePrefs {
    fun getString(key: String): String?
    fun putString(key: String, value: String)
    fun remove(key: String)
    fun clear()
}

/**
 * java.util.Properties-backed implementation. Writes the file on every mutation
 * — simple, correct, and fast enough for the handful of keys this app stores.
 */
class PropertiesPrefs(private val file: File) : KeyValuePrefs {

    private val props = Properties().also { p ->
        if (file.exists()) file.inputStream().use { p.load(it) }
    }

    override fun getString(key: String): String? = props.getProperty(key)

    override fun putString(key: String, value: String) {
        props.setProperty(key, value)
        save()
    }

    override fun remove(key: String) {
        props.remove(key)
        save()
    }

    override fun clear() {
        props.clear()
        save()
    }

    private fun save() {
        file.parentFile?.mkdirs()
        file.outputStream().use { props.store(it, null) }
    }
}

/**
 * Properties-backed prefs whose file is wrapped with AES-256-GCM under the
 * vault's [MasterKey]. The cleartext lives in `Properties` in memory; the
 * on-disk form is a single encrypted blob, replacing the equivalent
 * plaintext file.
 *
 * Misses on missing files: if the file doesn't exist, the prefs start empty.
 * Misses on decryption failure (e.g. wrong master, tampered blob) are
 * surfaced as exceptions from the ctor — callers should refuse to operate.
 */
class EncryptedPrefs(private val file: File, private val master: MasterKey) : KeyValuePrefs {

    private val props = Properties().also { p ->
        if (file.exists()) {
            val plain = master.decryptBytes(file.readBytes())
            ByteArrayInputStream(plain).use { p.load(it) }
        }
    }

    override fun getString(key: String): String? = props.getProperty(key)

    override fun putString(key: String, value: String) {
        props.setProperty(key, value)
        save()
    }

    override fun remove(key: String) {
        props.remove(key)
        save()
    }

    override fun clear() {
        props.clear()
        save()
    }

    private fun save() {
        val baos = ByteArrayOutputStream()
        props.store(baos, null)
        file.parentFile?.mkdirs()
        file.writeBytes(master.encryptBytes(baos.toByteArray()))
    }
}
