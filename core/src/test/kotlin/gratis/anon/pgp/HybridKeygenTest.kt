package gratis.anon.pgp

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

/**
 * Round-trip exercise for the three Phase-2 keygen flavors. Builds a vault in
 * a temp dir, generates keys, persists them, re-opens the vault from disk,
 * and runs encrypt/decrypt + sign/verify against the recovered keys.
 *
 * What this catches:
 *   - PqcSidecar serialization bugs (encode → load round-trip)
 *   - KeyVault losing the .pqc file across reopens
 *   - Ed25519/X25519 keyring being unable to encrypt or sign through the
 *     existing PgpHelper code paths
 *   - Passphrase-wrong sidecar load throwing the right kind of error
 */
class HybridKeygenTest {

    @TempDir lateinit var tempDir: File

    private val passphrase = "round-trip-test-passphrase".toCharArray()

    private fun newVault() = KeyVault(
        tempDir,
        PropertiesPrefs(File(tempDir, "prefs.properties"))
    )

    @Test
    fun `classical RSA generation persists across vault reopen`() {
        val v1 = newVault()
        val generated = PgpHelper.generateSecretKeyRing(
            "Test User <test@example.com>",
            passphrase.copyOf(),
            PgpHelper.KeyAlgo.CLASSICAL_RSA
        )
        assertNull(generated.pqcSidecar, "classical RSA must NOT emit a PQC sidecar")
        val entry = v1.add(generated)
        assertFalse(entry.hasPqc)

        val v2 = newVault()
        val reopened = v2.list().single()
        assertEquals(entry.fingerprint, reopened.fingerprint)
        assertFalse(reopened.hasPqc, "no .pqc file should exist on disk")
        assertNull(v2.rawPqcSidecar(reopened.fingerprint))
    }

    @Test
    fun `Ed25519 X25519 keyring encrypts and decrypts a message`() {
        val v = newVault()
        val gen = PgpHelper.generateSecretKeyRing(
            "Alice <alice@example.com>",
            passphrase.copyOf(),
            PgpHelper.KeyAlgo.CLASSICAL_ED25519
        )
        val entry = v.add(gen)
        assertFalse(entry.hasPqc)

        val publicRing = PgpHelper.publicRingFrom(entry.ring)

        val plaintext = "hello quantum world".toByteArray()
        val ciphertext = PgpHelper.encryptToRecipient(plaintext, publicRing)
        val recovered = PgpHelper.decryptFromArmored(ciphertext, entry.ring, passphrase.copyOf())
        assertArrayEquals(plaintext, recovered)
    }

    @Test
    fun `Ed25519 keyring produces detached signatures that verify`() {
        val v = newVault()
        val gen = PgpHelper.generateSecretKeyRing(
            "Bob <bob@example.com>",
            passphrase.copyOf(),
            PgpHelper.KeyAlgo.CLASSICAL_ED25519
        )
        val entry = v.add(gen)
        val publicRing = PgpHelper.publicRingFrom(entry.ring)

        val message = "signed by quantum-curious bob".toByteArray()
        val sig = PgpHelper.signDetached(message, entry.ring, passphrase.copyOf())
        assertTrue(PgpHelper.verifyDetached(message, sig, publicRing))
        assertFalse(PgpHelper.verifyDetached("tampered".toByteArray(), sig, publicRing))
    }

    @Test
    fun `hybrid PQC identity persists both files and survives vault reopen`() {
        val v1 = newVault()
        val gen = PgpHelper.generateSecretKeyRing(
            "Charlie <charlie@example.com>",
            passphrase.copyOf(),
            PgpHelper.KeyAlgo.HYBRID_PQC
        )
        assertNotNull(gen.pqcSidecar, "hybrid keygen MUST emit a PQC sidecar")
        val entry = v1.add(gen)
        assertTrue(entry.hasPqc)

        val v2 = newVault()
        val reopened = v2.list().single()
        assertTrue(reopened.hasPqc, ".pqc file must survive vault reopen")
        val sidecar = v2.loadPqcSidecar(reopened.fingerprint, passphrase.copyOf())

        // ML-DSA-65 public key is 1952 bytes; ML-KEM-768 public key is 1184 bytes.
        // These are the FIPS-203/204 standardized sizes — if BC changes its
        // encoding, the test fails fast and the file-format version bumps.
        assertEquals(1952, sidecar.mlDsaPublic.size, "ML-DSA-65 public key length")
        assertEquals(1184, sidecar.mlKemPublic.size, "ML-KEM-768 public key length")
        assertTrue(sidecar.mlDsaPrivate.isNotEmpty())
        assertTrue(sidecar.mlKemPrivate.isNotEmpty())
    }

    @Test
    fun `loadPqcSidecar with wrong passphrase fails`() {
        val v = newVault()
        val gen = PgpHelper.generateSecretKeyRing(
            "Dana <dana@example.com>",
            passphrase.copyOf(),
            PgpHelper.KeyAlgo.HYBRID_PQC
        )
        val entry = v.add(gen)
        assertThrows(Throwable::class.java) {
            v.loadPqcSidecar(entry.fingerprint, "wrong-passphrase".toCharArray())
        }
    }

    @Test
    fun `loadPublicOnly works without the passphrase`() {
        val v = newVault()
        val gen = PgpHelper.generateSecretKeyRing(
            "Eve <eve@example.com>",
            passphrase.copyOf(),
            PgpHelper.KeyAlgo.HYBRID_PQC
        )
        val entry = v.add(gen)
        val pub = PqcSidecar.loadPublicOnly(v.rawPqcSidecar(entry.fingerprint)!!)
        assertEquals(1952, pub.mlDsaPublic.size)
        assertEquals(1184, pub.mlKemPublic.size)
    }

    @Test
    fun `delete wipes both classical and sidecar files`() {
        val v = newVault()
        val gen = PgpHelper.generateSecretKeyRing(
            "Frank <frank@example.com>",
            passphrase.copyOf(),
            PgpHelper.KeyAlgo.HYBRID_PQC
        )
        val entry = v.add(gen)
        assertTrue(v.list().isNotEmpty())

        v.delete(entry.fingerprint)
        assertTrue(v.list().isEmpty())
        assertNull(v.rawBytes(entry.fingerprint))
        assertNull(v.rawPqcSidecar(entry.fingerprint))
    }
}
