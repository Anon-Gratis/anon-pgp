package gratis.anon.pgp

import org.bouncycastle.openpgp.PGPSecretKeyRing
import java.io.File

/**
 * Multi-keyring vault. Each secret keyring is stored as ASCII-armored
 * (passphrase-protected at the OpenPGP layer) under
 * `baseDir/keys/<compact-fingerprint>.asc`. Importing the same key twice is a
 * no-op overwrite, keyed by fingerprint.
 *
 * One key is marked "active" via [KeyValuePrefs]; all crypto ops in the rest
 * of the app use the active key.
 *
 * Backwards compat: if the legacy single-key file `anon-pgp-secret.asc` exists
 * from a v0.2.x install at [baseDir]/anon-pgp-secret.asc, it's migrated into
 * the vault on construction.
 *
 * ## At-rest encryption
 *
 * When a non-null [master] is supplied the vault enters **encrypted-at-rest**
 * mode:
 *   - Every file is wrapped with AES-256-GCM under [master] and the original
 *     filename is prefixed inside the encrypted envelope so listings can
 *     still associate `.asc` keyrings with their `.pqc` sidecars.
 *   - On-disk filenames are HMAC-SHA256 outputs (via [MasterKey.obfuscateName])
 *     so anyone reading the directory listing sees neither fingerprints nor
 *     file extensions.
 *
 * Plaintext and encrypted modes are mutually exclusive on a given vault
 * directory — caller chooses by passing [master] or not. Migration between
 * modes is in [MasterKey.migrateToEncrypted] / [MasterKey.migrateToPlaintext].
 *
 * @param baseDir the application's private data directory. On Android this is
 *   `context.filesDir`; on desktop it's `~/.local/share/anon-pgp`.
 * @param prefs key-value store for the "active fingerprint" pointer. Should
 *   be an [EncryptedPrefs] when [master] is non-null.
 * @param master optional master key for at-rest encryption. `null` = plaintext.
 */
class KeyVault(
    private val baseDir: File,
    private val prefs: KeyValuePrefs,
    private val master: MasterKey? = null,
) {

    private val dir: File
        get() = File(baseDir, DIR).also { if (!it.exists()) it.mkdirs() }

    init {
        // Legacy migration only runs in plaintext mode — pre-v0.4 vaults
        // can't possibly be encrypted.
        if (master == null) migrateLegacyIfPresent()
    }

    /**
     * One identity in the vault. Carries the classical OpenPGP secret ring +
     * an optional [PqcSidecar] (its bytes live in `<fp>.pqc` on disk; we don't
     * decrypt eagerly because that needs the passphrase).
     */
    data class Entry(
        val fingerprint: String,
        val displayName: String,
        val ring: PGPSecretKeyRing,
        val hasPqc: Boolean
    ) {
        val prettyFingerprint: String
            get() = fingerprint.chunked(4).joinToString(" ")
    }

    fun list(): List<Entry> =
        if (master == null) listPlaintext() else listEncrypted()

    private fun listPlaintext(): List<Entry> {
        val files = dir.listFiles { f -> f.isFile && f.name.endsWith(".asc") }
            ?: return emptyList()
        return files.mapNotNull { f ->
            try {
                val ring = PgpHelper.loadSecretKeyRing(f.readBytes())
                val fp = PgpHelper.fingerprintCompact(ring.publicKey)
                Entry(
                    fingerprint = fp,
                    displayName = PgpHelper.firstUserId(ring.publicKey) ?: "<unknown>",
                    ring = ring,
                    hasPqc = File(dir, "$fp.pqc").exists(),
                )
            } catch (_: Throwable) { null }
        }.sortedBy { it.displayName.lowercase() }
    }

    private fun listEncrypted(): List<Entry> {
        val files = dir.listFiles { f -> f.isFile && f.name.endsWith(ENC_EXT) }
            ?: return emptyList()
        // Decrypt every blob once. Stash by ORIGINAL filename ("<fp>.asc" or
        // "<fp>.pqc") so we can associate sidecars with their primary rings.
        val byOriginalName = mutableMapOf<String, ByteArray>()
        for (f in files) {
            try {
                val envelope = master!!.decryptBytes(f.readBytes())
                val (name, content) = unpackEnvelope(envelope)
                byOriginalName[name] = content
            } catch (_: Throwable) {
                // skip — corrupt or wrong master would have failed at unlock
            }
        }
        return byOriginalName.entries
            .filter { (k, _) -> k.endsWith(".asc") }
            .mapNotNull { (k, content) ->
                val ring = try { PgpHelper.loadSecretKeyRing(content) } catch (_: Throwable) { return@mapNotNull null }
                val fp = PgpHelper.fingerprintCompact(ring.publicKey)
                Entry(
                    fingerprint = fp,
                    displayName = PgpHelper.firstUserId(ring.publicKey) ?: "<unknown>",
                    ring = ring,
                    hasPqc = byOriginalName.containsKey("$fp.pqc"),
                )
            }
            .sortedBy { it.displayName.lowercase() }
    }

    /**
     * Adds or replaces (by fingerprint) a secret keyring, optionally paired
     * with a PQC sidecar.
     */
    fun add(generated: PgpHelper.GeneratedKey): Entry =
        add(generated.classicalArmored, generated.pqcSidecar)

    fun add(armored: ByteArray): Entry = add(armored, pqcSidecar = null)

    fun add(armored: ByteArray, pqcSidecar: ByteArray?): Entry {
        val ring = PgpHelper.loadSecretKeyRing(armored)
        val fp = PgpHelper.fingerprintCompact(ring.publicKey)
        writeFile("$fp.asc", armored)
        if (pqcSidecar != null) {
            writeFile("$fp.pqc", pqcSidecar)
        } else {
            // Replacing an existing hybrid identity with a classical-only one
            // shouldn't leave a stale sidecar that no longer matches.
            val staleFile = onDisk("$fp.pqc")
            if (staleFile.exists()) {
                staleFile.writeBytes(ByteArray(staleFile.length().toInt()))
                staleFile.delete()
            }
        }
        if (getActiveFingerprint() == null) setActiveFingerprint(fp)
        return Entry(
            fingerprint = fp,
            displayName = PgpHelper.firstUserId(ring.publicKey) ?: "<unknown>",
            ring = ring,
            hasPqc = pqcSidecar != null,
        )
    }

    fun rawBytes(fingerprint: String): ByteArray? = readFile("$fingerprint.asc")

    fun rawPqcSidecar(fingerprint: String): ByteArray? = readFile("$fingerprint.pqc")

    fun loadPqcSidecar(fingerprint: String, passphrase: CharArray): PqcSidecar.PqcKeys {
        val bytes = rawPqcSidecar(fingerprint)
            ?: throw IllegalStateException("No PQC sidecar stored for $fingerprint")
        return PqcSidecar.load(bytes, passphrase)
    }

    fun delete(fingerprint: String) {
        for (name in listOf("$fingerprint.asc", "$fingerprint.pqc")) {
            val f = onDisk(name)
            if (f.exists()) {
                f.writeBytes(ByteArray(f.length().toInt()))
                f.delete()
            }
        }
        if (getActiveFingerprint() == fingerprint) {
            val first = list().firstOrNull()
            if (first != null) setActiveFingerprint(first.fingerprint)
            else prefs.remove(PREF_ACTIVE)
        }
    }

    fun getActiveFingerprint(): String? = prefs.getString(PREF_ACTIVE)

    fun setActiveFingerprint(fingerprint: String) {
        prefs.putString(PREF_ACTIVE, fingerprint)
    }

    fun getActive(): Entry? {
        val fp = getActiveFingerprint() ?: return null
        return list().firstOrNull { it.fingerprint == fp }
            ?: list().firstOrNull()?.also { setActiveFingerprint(it.fingerprint) }
    }

    fun wipe() {
        dir.listFiles()?.forEach {
            it.writeBytes(ByteArray(it.length().toInt()))
            it.delete()
        }
        prefs.clear()
    }

    // ─── Mode-aware filesystem helpers ────────────────────────────────────

    /** Compute the on-disk [File] for an "original" filename like "<fp>.asc". */
    internal fun onDisk(originalName: String): File =
        if (master == null) File(dir, originalName)
        else File(dir, master.obfuscateName("keys/$originalName") + ENC_EXT)

    private fun readFile(originalName: String): ByteArray? {
        val f = onDisk(originalName)
        if (!f.exists()) return null
        val raw = f.readBytes()
        return if (master == null) raw else {
            val envelope = master.decryptBytes(raw)
            unpackEnvelope(envelope).second
        }
    }

    private fun writeFile(originalName: String, content: ByteArray) {
        val f = onDisk(originalName)
        f.parentFile?.mkdirs()
        val bytes = if (master == null) content
                    else master.encryptBytes(packEnvelope(originalName, content))
        f.writeBytes(bytes)
    }

    private fun migrateLegacyIfPresent() {
        val legacy = File(baseDir, LEGACY_FILE)
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
        private const val PREF_ACTIVE = "active_fingerprint"
        private const val LEGACY_FILE = "anon-pgp-secret.asc"

        /** Suffix for encrypted-mode on-disk filenames. */
        internal const val ENC_EXT = ".enc"

        /**
         * Pack `(originalName, content)` into a single byte array. The first
         * UTF-8 line is the original filename so listings can re-associate
         * sidecars; the rest is the original content verbatim.
         */
        internal fun packEnvelope(originalName: String, content: ByteArray): ByteArray {
            val name = originalName.toByteArray(Charsets.UTF_8)
            val out = ByteArray(name.size + 1 + content.size)
            System.arraycopy(name, 0, out, 0, name.size)
            out[name.size] = '\n'.code.toByte()
            System.arraycopy(content, 0, out, name.size + 1, content.size)
            return out
        }

        /** Inverse of [packEnvelope]. Throws on malformed envelope. */
        internal fun unpackEnvelope(envelope: ByteArray): Pair<String, ByteArray> {
            val nl = envelope.indexOf('\n'.code.toByte())
            require(nl >= 0) { "envelope missing filename header" }
            val name = String(envelope, 0, nl, Charsets.UTF_8)
            val content = envelope.copyOfRange(nl + 1, envelope.size)
            return name to content
        }
    }
}
