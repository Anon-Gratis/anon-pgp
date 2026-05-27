package gratis.anon.pgp

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

/**
 * Vault-at-rest encryption: filename obfuscation, content encryption,
 * migration between plaintext and encrypted modes, and the on-disk leak
 * guarantees (no plaintext fingerprints in filenames or contents).
 */
class EncryptedVaultTest {

    @TempDir lateinit var dir: File

    private val keyPass = "secret-key-pass".toCharArray()
    private val masterPass = "vault-master-pass".toCharArray()

    private fun plainVault() = KeyVault(
        dir,
        PropertiesPrefs(File(dir, "prefs.properties")),
    )

    private fun encryptedVault(master: MasterKey) = KeyVault(
        dir,
        EncryptedPrefs(File(dir, "prefs.enc"), master),
        master,
    )

    // ─── MasterKey primitives ────────────────────────────────────────────

    @Test
    fun `encryptBytes round-trip recovers plaintext`() {
        val master = MasterKey.create(dir, masterPass.copyOf())
        val plain = ByteArray(50_000) { (it and 0xFF).toByte() }
        val ct = master.encryptBytes(plain)
        assertNotEquals(plain.size, ct.size, "ciphertext should differ in size (IV + tag)")
        val pt = master.decryptBytes(ct)
        assertArrayEquals(plain, pt)
    }

    @Test
    fun `wrong passphrase fails unlock`() {
        MasterKey.create(dir, masterPass.copyOf()).clear()
        assertThrows(Throwable::class.java) {
            MasterKey.unlock(dir, "wrong-passphrase".toCharArray())
        }
    }

    @Test
    fun `unlock on a not-yet-encrypted vault returns null`() {
        assertFalse(MasterKey.isLocked(dir))
        assertNull(MasterKey.unlock(dir, masterPass.copyOf()))
    }

    @Test
    fun `obfuscated names are stable across MasterKey instances with same passphrase`() {
        val k1 = MasterKey.create(dir, masterPass.copyOf())
        val name1 = k1.obfuscateName("keys/ABCD1234.asc")
        k1.clear()
        // Unlock the existing vault — should produce same macKey
        val k2 = MasterKey.unlock(dir, masterPass.copyOf())!!
        val name2 = k2.obfuscateName("keys/ABCD1234.asc")
        assertEquals(name1, name2, "obfuscated names must be deterministic per-vault")
    }

    // ─── End-to-end: encrypted KeyVault ─────────────────────────────────

    @Test
    fun `encrypted vault stores key under obfuscated filename`() {
        val master = MasterKey.create(dir, masterPass.copyOf())
        val v = encryptedVault(master)
        val gen = PgpHelper.generateSecretKeyRing(
            "Test <t@example.com>", keyPass.copyOf(), PgpHelper.KeyAlgo.CLASSICAL_ED25519
        )
        val entry = v.add(gen)

        // No file in keys/ should contain the fingerprint as a substring.
        val keysDir = File(dir, "keys")
        val ascFile = File(keysDir, "${entry.fingerprint}.asc")
        assertFalse(ascFile.exists(), "no plaintext .asc named after the fingerprint")

        val files = keysDir.listFiles()!!.toList()
        assertEquals(1, files.size, "exactly one encrypted file")
        assertTrue(files[0].name.endsWith(".enc"), "file must use the encrypted suffix")
        // Filename must not contain the fingerprint anywhere.
        assertFalse(
            files[0].name.contains(entry.fingerprint, ignoreCase = true),
            "filename leaks the fingerprint"
        )

        // And the contents must not contain the fingerprint either.
        val rawBytes = files[0].readBytes()
        val rawString = rawBytes.joinToString("") { "%02x".format(it) }
        assertFalse(
            rawString.contains(entry.fingerprint, ignoreCase = true),
            "encrypted contents leak the fingerprint as hex"
        )
    }

    @Test
    fun `encrypted vault round-trips through close and reopen`() {
        val master1 = MasterKey.create(dir, masterPass.copyOf())
        val v1 = encryptedVault(master1)
        val gen = PgpHelper.generateSecretKeyRing(
            "Alice <a@example.com>", keyPass.copyOf(), PgpHelper.KeyAlgo.CLASSICAL_ED25519
        )
        val entry = v1.add(gen)
        master1.clear()

        // Reopen as a different process would — re-derive master from disk salt.
        val master2 = MasterKey.unlock(dir, masterPass.copyOf())!!
        val v2 = encryptedVault(master2)
        val reopened = v2.list()
        assertEquals(1, reopened.size)
        assertEquals(entry.fingerprint, reopened[0].fingerprint)
        assertEquals(entry.displayName, reopened[0].displayName)

        // Active-fingerprint pointer must survive too.
        assertEquals(entry.fingerprint, v2.getActiveFingerprint())
    }

    @Test
    fun `encrypted vault preserves PQC sidecar`() {
        val master = MasterKey.create(dir, masterPass.copyOf())
        val v = encryptedVault(master)
        val gen = PgpHelper.generateSecretKeyRing(
            "Bob <b@example.com>", keyPass.copyOf(), PgpHelper.KeyAlgo.HYBRID_PQC
        )
        val entry = v.add(gen)
        assertTrue(entry.hasPqc)

        master.clear()
        val master2 = MasterKey.unlock(dir, masterPass.copyOf())!!
        val v2 = encryptedVault(master2)
        val reopened = v2.list().single()
        assertTrue(reopened.hasPqc, ".pqc sidecar association must survive a vault reopen")

        // Sidecar bytes round-trip too.
        val sidecar = v2.loadPqcSidecar(reopened.fingerprint, keyPass.copyOf())
        assertEquals(1952, sidecar.mlDsaPublic.size)
        assertEquals(1184, sidecar.mlKemPublic.size)
    }

    // ─── Migration: plaintext ↔ encrypted ───────────────────────────────

    @Test
    fun `migrateToEncrypted converts an existing plaintext vault in place`() {
        val v1 = plainVault()
        val gen = PgpHelper.generateSecretKeyRing(
            "Plain <p@example.com>", keyPass.copyOf(), PgpHelper.KeyAlgo.CLASSICAL_ED25519
        )
        val entry = v1.add(gen)
        val plainFile = File(dir, "keys/${entry.fingerprint}.asc")
        assertTrue(plainFile.exists())

        val master = MasterKey.create(dir, masterPass.copyOf())
        MasterKey.migrateToEncrypted(dir, master)

        assertFalse(plainFile.exists(), "plaintext .asc must be gone")
        val keysDir = File(dir, "keys")
        assertEquals(
            1, keysDir.listFiles()?.size ?: 0,
            "exactly one file remains in keys/"
        )
        // Encrypted vault should see the migrated key.
        val v2 = encryptedVault(master)
        val reopened = v2.list().single()
        assertEquals(entry.fingerprint, reopened.fingerprint)
    }

    @Test
    fun `migrateToPlaintext is the inverse of migrateToEncrypted`() {
        val master = MasterKey.create(dir, masterPass.copyOf())
        val v1 = encryptedVault(master)
        val gen = PgpHelper.generateSecretKeyRing(
            "Round-Trip <rt@example.com>", keyPass.copyOf(), PgpHelper.KeyAlgo.CLASSICAL_ED25519
        )
        val entry = v1.add(gen)

        MasterKey.migrateToPlaintext(dir, master)
        MasterKey.teardown(dir)

        // .salt / .verify must be gone after teardown.
        assertFalse(File(dir, MasterKey.SALT_FILE).exists())
        assertFalse(File(dir, MasterKey.VERIFY_FILE).exists())

        // Plaintext .asc should be at the canonical name.
        assertTrue(File(dir, "keys/${entry.fingerprint}.asc").exists())

        // And a plaintext vault should pick it up.
        val v2 = plainVault()
        val reopened = v2.list().single()
        assertEquals(entry.fingerprint, reopened.fingerprint)
    }

    @Test
    fun `EncryptedPrefs survive close and reopen`() {
        val master1 = MasterKey.create(dir, masterPass.copyOf())
        val prefsFile = File(dir, "prefs.enc")
        val p1 = EncryptedPrefs(prefsFile, master1)
        p1.putString("active_fingerprint", "ABCDEF1234567890")
        p1.putString("theme", "dark")
        master1.clear()

        val master2 = MasterKey.unlock(dir, masterPass.copyOf())!!
        val p2 = EncryptedPrefs(prefsFile, master2)
        assertEquals("ABCDEF1234567890", p2.getString("active_fingerprint"))
        assertEquals("dark", p2.getString("theme"))
    }

    @Test
    fun `EncryptedPrefs file is not a readable Properties stream`() {
        val master = MasterKey.create(dir, masterPass.copyOf())
        val prefsFile = File(dir, "prefs.enc")
        EncryptedPrefs(prefsFile, master).putString("k", "v")

        // Attempting to read it as plain Properties must not succeed in
        // producing the original key — verifies we're actually encrypting.
        val raw = prefsFile.readBytes()
        val asText = String(raw, Charsets.US_ASCII)
        assertFalse(asText.contains("active_fingerprint"))
        assertFalse(asText.contains("k=v"))
    }
}
