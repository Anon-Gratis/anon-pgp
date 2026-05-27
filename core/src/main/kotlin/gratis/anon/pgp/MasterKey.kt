package gratis.anon.pgp

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * In-memory master key derived from the user's vault passphrase.
 *
 * When a vault is "encrypted at rest", every file inside the vault is wrapped
 * with AES-256-GCM under [encKey], and every filename is replaced with an
 * HMAC-SHA256 of the underlying identifier under [macKey] — so a disk image
 * leaks neither key fingerprints nor contact identities.
 *
 * Both halves are derived from one PBKDF2-HMAC-SHA256 pass over the user's
 * master passphrase + a per-vault salt, then split:
 *   bytes  0..31 → encKey (AES-256 content encryption)
 *   bytes 32..63 → macKey (HMAC filename obfuscation)
 *
 * The salt lives on disk at `<vault>/.salt`. Its presence is the canonical
 * "this vault is locked" marker — KeyVault refuses to operate without a
 * matching unlocked [MasterKey] when `.salt` exists.
 *
 * Wipe with [clear] when locking; the same instance must not be reused after.
 */
class MasterKey private constructor(
    private val encKey: ByteArray,
    private val macKey: ByteArray,
) {

    /** Encrypt `plain` with a fresh random IV. Returns IV ‖ ciphertext ‖ tag. */
    fun encryptBytes(plain: ByteArray): ByteArray {
        val iv = ByteArray(IV_LEN).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(encKey, "AES"), GCMParameterSpec(GCM_TAG_BITS, iv))
        val ct = cipher.doFinal(plain)
        val out = ByteArray(iv.size + ct.size)
        System.arraycopy(iv, 0, out, 0, iv.size)
        System.arraycopy(ct, 0, out, iv.size, ct.size)
        return out
    }

    /** Inverse of [encryptBytes]. Throws on GCM auth-tag mismatch (wrong key / tampered ct). */
    fun decryptBytes(blob: ByteArray): ByteArray {
        require(blob.size > IV_LEN) { "ciphertext too short" }
        val iv = blob.copyOfRange(0, IV_LEN)
        val ct = blob.copyOfRange(IV_LEN, blob.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(encKey, "AES"), GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(ct)
    }

    /**
     * Deterministic per-vault filename for `realName` (e.g. a fingerprint or a
     * relative file path). Same input → same output for the lifetime of this
     * [MasterKey]; reproducible across app restarts because [macKey] is
     * derived from the passphrase + on-disk salt.
     */
    fun obfuscateName(realName: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(macKey, "HmacSHA256"))
        val tag = mac.doFinal(realName.toByteArray(Charsets.UTF_8))
        // 16 raw bytes → 32 hex chars. That's enough namespace to avoid
        // collisions even with thousands of keys, and short enough to be
        // human-tolerable on the filesystem.
        return tag.copyOfRange(0, 16).joinToString("") { "%02x".format(it) }
    }

    /** Verify [other] derives to the same encryption key. Constant-time. */
    fun matchesEncKeyOf(other: MasterKey): Boolean {
        if (encKey.size != other.encKey.size) return false
        var diff = 0
        for (i in encKey.indices) diff = diff or (encKey[i].toInt() xor other.encKey[i].toInt())
        return diff == 0
    }

    /** Zero out key material. The instance must not be used after [clear]. */
    fun clear() {
        encKey.fill(0)
        macKey.fill(0)
    }

    companion object {
        private const val IV_LEN = 12
        private const val GCM_TAG_BITS = 128
        private const val KDF_ITERS = 600_000
        private const val SALT_LEN = 16

        /** Hardcoded verifier plaintext — its decrypt-success tells us the passphrase is right. */
        private val VERIFY_TAG = "anonpgp-vault-v1".toByteArray(Charsets.US_ASCII)

        const val SALT_FILE = ".salt"
        const val VERIFY_FILE = ".verify"

        /** Is `vaultDir` set up for at-rest encryption? */
        fun isLocked(vaultDir: File): Boolean = File(vaultDir, SALT_FILE).exists()

        /**
         * Initialize at-rest encryption for `vaultDir`. Writes the salt + a
         * verifier blob and returns a live [MasterKey]. Caller is responsible
         * for migrating existing plaintext files into the new encrypted layout.
         */
        fun create(vaultDir: File, passphrase: CharArray): MasterKey {
            vaultDir.mkdirs()
            val salt = ByteArray(SALT_LEN).also { SecureRandom().nextBytes(it) }
            File(vaultDir, SALT_FILE).writeBytes(salt)
            val key = derive(passphrase, salt)
            File(vaultDir, VERIFY_FILE).writeBytes(key.encryptBytes(VERIFY_TAG))
            return key
        }

        /**
         * Unlock an existing encrypted vault. Returns null if `vaultDir` isn't
         * encrypted (no `.salt`), throws on wrong passphrase or corrupted
         * verifier.
         */
        fun unlock(vaultDir: File, passphrase: CharArray): MasterKey? {
            val saltFile = File(vaultDir, SALT_FILE)
            if (!saltFile.exists()) return null
            val salt = saltFile.readBytes()
            val key = derive(passphrase, salt)
            val verifyFile = File(vaultDir, VERIFY_FILE)
            require(verifyFile.exists()) { "vault is partially set up — .salt without .verify" }
            val verified = try {
                key.decryptBytes(verifyFile.readBytes())
            } catch (t: Throwable) {
                key.clear()
                throw IllegalStateException("wrong master passphrase", t)
            }
            require(verified.contentEquals(VERIFY_TAG)) {
                key.clear()
                "verifier mismatch — vault may be corrupted"
            }
            return key
        }

        /**
         * Permanently turn OFF at-rest encryption on `vaultDir`. Deletes
         * `.salt` and `.verify`. Caller is responsible for decrypting existing
         * files back to plaintext layout BEFORE calling this.
         */
        fun teardown(vaultDir: File) {
            listOf(SALT_FILE, VERIFY_FILE).forEach { name ->
                val f = File(vaultDir, name)
                if (f.exists()) {
                    f.writeBytes(ByteArray(f.length().toInt()))
                    f.delete()
                }
            }
        }

        /**
         * Walk a plaintext vault directory and re-write every file in
         * `keys/` and `contacts/` as an encrypted envelope under `master`,
         * deleting the originals. Idempotent — files already named with the
         * `.enc` suffix are skipped.
         *
         * The prefs file is handled separately by callers (the prefs path is
         * outside this class's purview).
         */
        fun migrateToEncrypted(vaultDir: File, master: MasterKey) {
            for (sub in listOf("keys", "contacts")) {
                val subDir = File(vaultDir, sub)
                if (!subDir.isDirectory) continue
                subDir.listFiles()?.forEach { f ->
                    if (!f.isFile) return@forEach
                    if (f.name.endsWith(KeyVault.ENC_EXT)) return@forEach
                    try {
                        val plain = f.readBytes()
                        val envelope = KeyVault.packEnvelope(f.name, plain)
                        val ct = master.encryptBytes(envelope)
                        val newName = master.obfuscateName("$sub/${f.name}") + KeyVault.ENC_EXT
                        File(subDir, newName).writeBytes(ct)
                        // Securely overwrite + delete the original.
                        f.writeBytes(ByteArray(f.length().toInt()))
                        f.delete()
                    } catch (_: Throwable) {
                        // Skip unreadable files; user can retry.
                    }
                }
            }
        }

        /**
         * Reverse of [migrateToEncrypted]. Walks `keys/` and `contacts/`,
         * decrypts each `.enc` envelope, writes the original-named plaintext
         * file back, and deletes the encrypted version. Caller is expected
         * to invoke [teardown] afterwards to remove `.salt` + `.verify`.
         */
        fun migrateToPlaintext(vaultDir: File, master: MasterKey) {
            for (sub in listOf("keys", "contacts")) {
                val subDir = File(vaultDir, sub)
                if (!subDir.isDirectory) continue
                subDir.listFiles()?.forEach { f ->
                    if (!f.isFile || !f.name.endsWith(KeyVault.ENC_EXT)) return@forEach
                    try {
                        val envelope = master.decryptBytes(f.readBytes())
                        val (originalName, content) = KeyVault.unpackEnvelope(envelope)
                        File(subDir, originalName).writeBytes(content)
                        f.writeBytes(ByteArray(f.length().toInt()))
                        f.delete()
                    } catch (_: Throwable) {
                        // Leave the .enc file in place; manual recovery possible.
                    }
                }
            }
        }

        /**
         * Re-derive a [MasterKey] from a passphrase + an arbitrary salt.
         * Used for the verifier check; production callers should use [unlock].
         */
        internal fun derive(passphrase: CharArray, salt: ByteArray): MasterKey {
            val spec = PBEKeySpec(passphrase, salt, KDF_ITERS, 512)  // 64 bytes
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val full = factory.generateSecret(spec).encoded
            val enc = full.copyOfRange(0, 32)
            val mac = full.copyOfRange(32, 64)
            full.fill(0)
            return MasterKey(enc, mac)
        }
    }
}
