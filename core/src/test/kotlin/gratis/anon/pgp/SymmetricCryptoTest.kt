package gratis.anon.pgp

import org.bouncycastle.openpgp.PGPException
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Round-trip exercise for the new passphrase-only encrypt/decrypt path. Also
 * checks that wrong passphrases and bit-flipped ciphertext are rejected.
 */
class SymmetricCryptoTest {

    private val pass = "correct horse battery staple".toCharArray()

    @Test
    fun `round-trip empty, short, and large payloads`() {
        val payloads = listOf(
            ByteArray(0),
            "hi".toByteArray(),
            ByteArray(1_000_000) { (it and 0xFF).toByte() },  // 1 MB pattern
        )
        for (plain in payloads) {
            val ct = PgpHelper.encryptSymmetric(plain, pass.copyOf())
            assertTrue(ct.size > 0, "ciphertext non-empty for ${plain.size}B plain")
            val pt = PgpHelper.decryptSymmetric(ct, pass.copyOf())
            assertArrayEquals(plain, pt, "round-trip on ${plain.size}B")
        }
    }

    @Test
    fun `output is ASCII-armored`() {
        val ct = PgpHelper.encryptSymmetric("hello".toByteArray(), pass.copyOf())
        val header = String(ct.copyOfRange(0, minOf(64, ct.size)), Charsets.US_ASCII)
        assertTrue(
            header.startsWith("-----BEGIN PGP MESSAGE-----"),
            "expected PGP MESSAGE armor header, got: $header"
        )
    }

    @Test
    fun `wrong passphrase fails`() {
        val ct = PgpHelper.encryptSymmetric("secret".toByteArray(), pass.copyOf())
        // BC may throw PGPException or surface a corrupted literal packet; either
        // way, decryptSymmetric must not return success with the wrong passphrase.
        assertThrows(Throwable::class.java) {
            PgpHelper.decryptSymmetric(ct, "wrong passphrase".toCharArray())
        }
    }

    @Test
    fun `tampered ciphertext fails integrity check`() {
        val ct = PgpHelper.encryptSymmetric("secret".toByteArray(), pass.copyOf())
        // Flip a byte in the middle of the armored block — far enough past
        // the header to land in the actual packet bytes.
        val tampered = ct.copyOf()
        val mid = tampered.size / 2
        tampered[mid] = (tampered[mid].toInt() xor 0xFF).toByte()
        assertThrows(Throwable::class.java) {
            PgpHelper.decryptSymmetric(tampered, pass.copyOf())
        }
    }

    @Test
    fun `cannot decrypt symmetric ciphertext with decryptFromArmored`() {
        // Asymmetric decryptor must reject PBE-only ciphertexts (no public-key
        // session packet to match against any secret key).
        val ct = PgpHelper.encryptSymmetric("hi".toByteArray(), pass.copyOf())
        val ringBytes = PgpHelper.generateSecretKeyRing(
            "Test <t@example.com>", "ringpass".toCharArray(),
            PgpHelper.KeyAlgo.CLASSICAL_ED25519
        ).classicalArmored
        val ring = PgpHelper.loadSecretKeyRing(ringBytes)
        assertThrows(PGPException::class.java) {
            PgpHelper.decryptFromArmored(ct, ring, "ringpass".toCharArray())
        }
    }
}
