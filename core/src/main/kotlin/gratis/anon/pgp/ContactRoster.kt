package gratis.anon.pgp

import org.bouncycastle.openpgp.PGPPublicKeyRing
import java.io.File

/**
 * Roster of imported public keys. Each contact is stored as an ASCII-armored
 * public keyring file under `baseDir/contacts/<compact-fingerprint>.asc`.
 *
 * Filename IS the fingerprint, which doubles as a deduplication key. The
 * label / display name is taken from the OpenPGP user-id baked into the key
 * itself — no parallel metadata.
 *
 * Honours the same encrypted-at-rest mode as [KeyVault]: when [master] is
 * supplied, contents are AES-256-GCM wrapped and filenames are HMAC-derived
 * so disk inspection reveals neither the fingerprint nor the contact count
 * patterns of the user.
 *
 * @param baseDir the application's private data directory.
 * @param master optional master key for at-rest encryption. `null` = plaintext.
 */
class ContactRoster(
    private val baseDir: File,
    private val master: MasterKey? = null,
) {

    private val dir: File
        get() = File(baseDir, DIR).also { if (!it.exists()) it.mkdirs() }

    data class Contact(
        val fingerprint: String,
        val displayName: String,
        val ring: PGPPublicKeyRing
    ) {
        val prettyFingerprint: String
            get() = fingerprint.chunked(4).joinToString(" ")
    }

    fun list(): List<Contact> =
        if (master == null) listPlaintext() else listEncrypted()

    private fun listPlaintext(): List<Contact> {
        val files = dir.listFiles { f -> f.isFile && f.name.endsWith(".asc") }
            ?: return emptyList()
        return files.mapNotNull { f -> parseContact(f.readBytes()) }
            .sortedBy { it.displayName.lowercase() }
    }

    private fun listEncrypted(): List<Contact> {
        val files = dir.listFiles { f -> f.isFile && f.name.endsWith(KeyVault.ENC_EXT) }
            ?: return emptyList()
        return files.mapNotNull { f ->
            try {
                val envelope = master!!.decryptBytes(f.readBytes())
                val (_, content) = KeyVault.unpackEnvelope(envelope)
                parseContact(content)
            } catch (_: Throwable) { null }
        }.sortedBy { it.displayName.lowercase() }
    }

    private fun parseContact(content: ByteArray): Contact? = try {
        val ring = PgpHelper.loadPublicKeyRing(content)
        Contact(
            fingerprint = PgpHelper.fingerprintCompact(ring.publicKey),
            displayName = PgpHelper.firstUserId(ring.publicKey) ?: "<unknown>",
            ring = ring,
        )
    } catch (_: Throwable) { null }

    fun import(armored: ByteArray): Contact {
        val ring = PgpHelper.loadPublicKeyRing(armored)
        val fp = PgpHelper.fingerprintCompact(ring.publicKey)
        writeFile("$fp.asc", armored)
        return Contact(
            fingerprint = fp,
            displayName = PgpHelper.firstUserId(ring.publicKey) ?: "<unknown>",
            ring = ring,
        )
    }

    fun delete(fingerprint: String) {
        val f = onDisk("$fingerprint.asc")
        if (f.exists()) {
            f.writeBytes(ByteArray(f.length().toInt()))
            f.delete()
        }
    }

    fun wipe() {
        dir.listFiles()?.forEach {
            it.writeBytes(ByteArray(it.length().toInt()))
            it.delete()
        }
    }

    internal fun onDisk(originalName: String): File =
        if (master == null) File(dir, originalName)
        else File(dir, master.obfuscateName("contacts/$originalName") + KeyVault.ENC_EXT)

    private fun writeFile(originalName: String, content: ByteArray) {
        val f = onDisk(originalName)
        f.parentFile?.mkdirs()
        val bytes = if (master == null) content
                    else master.encryptBytes(KeyVault.packEnvelope(originalName, content))
        f.writeBytes(bytes)
    }

    companion object {
        private const val DIR = "contacts"
    }
}
