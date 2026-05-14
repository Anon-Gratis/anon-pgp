package gratis.anon.pgp

import android.content.Context
import org.bouncycastle.openpgp.PGPPublicKeyRing
import java.io.File

/**
 * Roster of imported public keys. Each contact is stored as an ASCII-armored
 * public keyring file under `filesDir/contacts/<compact-fingerprint>.asc`.
 *
 * Filename IS the fingerprint, which doubles as a deduplication key (importing
 * the same key twice is a no-op overwrite). The label / display name is taken
 * from the OpenPGP user-id baked into the key itself — no parallel metadata.
 */
class ContactRoster(private val context: Context) {

    private val dir: File
        get() = File(context.filesDir, DIR).also { if (!it.exists()) it.mkdirs() }

    data class Contact(
        val fingerprint: String,      // 40 hex chars, no spaces
        val displayName: String,      // user-id or "<unknown>"
        val ring: PGPPublicKeyRing
    ) {
        /** Pretty fingerprint for UI ("ABCD 1234 ..."). */
        val prettyFingerprint: String
            get() = fingerprint.chunked(4).joinToString(" ")
    }

    /** Returns all stored contacts, sorted by display name (case-insensitive). */
    fun list(): List<Contact> {
        val files = dir.listFiles { f -> f.isFile && f.name.endsWith(".asc") } ?: return emptyList()
        return files.mapNotNull { f ->
            try {
                val ring = PgpHelper.loadPublicKeyRing(f.readBytes())
                Contact(
                    fingerprint = PgpHelper.fingerprintCompact(ring.publicKey),
                    displayName = PgpHelper.firstUserId(ring.publicKey) ?: "<unknown>",
                    ring = ring
                )
            } catch (_: Throwable) {
                null
            }
        }.sortedBy { it.displayName.lowercase() }
    }

    /** Parse, store, and return the imported contact. Overwrites by fingerprint. */
    fun import(armored: ByteArray): Contact {
        val ring = PgpHelper.loadPublicKeyRing(armored)
        val fp = PgpHelper.fingerprintCompact(ring.publicKey)
        File(dir, "$fp.asc").writeBytes(armored)
        return Contact(
            fingerprint = fp,
            displayName = PgpHelper.firstUserId(ring.publicKey) ?: "<unknown>",
            ring = ring
        )
    }

    fun delete(fingerprint: String) {
        val f = File(dir, "$fingerprint.asc")
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

    companion object {
        private const val DIR = "contacts"
    }
}
