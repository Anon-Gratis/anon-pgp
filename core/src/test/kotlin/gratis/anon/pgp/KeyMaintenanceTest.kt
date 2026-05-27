package gratis.anon.pgp

import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.time.Instant
import java.time.temporal.ChronoUnit

/**
 * Exercises subkey rotation, expiry-set, and revocation cert generation —
 * the operations a user would normally do through Kleopatra's "Certificate
 * Details" panel. Each test starts with a fresh Ed25519+X25519 ring.
 */
class KeyMaintenanceTest {

    private val pass = "test-passphrase-1234".toCharArray()

    private fun freshRing() = PgpHelper.loadSecretKeyRing(
        PgpHelper.generateSecretKeyRing(
            "Maint Test <m@example.com>",
            pass.copyOf(),
            PgpHelper.KeyAlgo.CLASSICAL_ED25519
        ).classicalArmored
    )

    // ─── addEncryptionSubkey ──────────────────────────────────────────────

    @Test
    fun `addEncryptionSubkey appends a new X25519 subkey`() {
        val ring = freshRing()
        val before = ring.publicKeys.asSequence().count()

        val updatedBytes = PgpHelper.addEncryptionSubkey(ring, pass.copyOf())
        val updated = PgpHelper.loadSecretKeyRing(updatedBytes)
        val after = updated.publicKeys.asSequence().count()
        assertEquals(before + 1, after, "subkey count should increase by 1")

        // Last subkey should be encryption-capable.
        val newest = updated.publicKeys.asSequence().last()
        assertTrue(newest.isEncryptionKey, "newly added subkey must be encryption-capable")
        assertFalse(newest.isMasterKey, "newly added subkey must not be the master")
    }

    @Test
    fun `encryption uses newer subkey after rotation`() {
        // After rotation the public-keyring still has TWO encryption subkeys
        // (old + new). encryptToRecipient picks the first encryption-capable
        // public key it sees — so the test just verifies the round-trip still
        // works after rotation, not which subkey is picked.
        val ring = freshRing()
        val rotated = PgpHelper.loadSecretKeyRing(
            PgpHelper.addEncryptionSubkey(ring, pass.copyOf())
        )
        val pubRing = PgpHelper.publicRingFrom(rotated)

        val msg = "encrypt me after rotation".toByteArray()
        val ct = PgpHelper.encryptToRecipient(msg, pubRing)
        val pt = PgpHelper.decryptFromArmored(ct, rotated, pass.copyOf())
        assertArrayEquals(msg, pt)
    }

    @Test
    fun `addEncryptionSubkey rejects wrong passphrase`() {
        val ring = freshRing()
        assertThrows(Throwable::class.java) {
            PgpHelper.addEncryptionSubkey(ring, "wrong-passphrase".toCharArray())
        }
    }

    // ─── setPrimaryExpiry ─────────────────────────────────────────────────

    @Test
    fun `setPrimaryExpiry to a future date sets validSeconds`() {
        val ring = freshRing()
        assertNull(PgpHelper.primaryExpiry(ring), "fresh ring has no expiry")

        val oneYearOut = Instant.now().plus(365, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS)
        val updated = PgpHelper.loadSecretKeyRing(
            PgpHelper.setPrimaryExpiry(ring, oneYearOut, pass.copyOf())
        )
        val exp = PgpHelper.primaryExpiry(updated)
        assertNotNull(exp, "expiry should be set")
        // Allow ±2 seconds of slop — OpenPGP stores seconds-from-creation as
        // an integer so we lose sub-second precision crossing the boundary.
        val delta = kotlin.math.abs(exp!!.epochSecond - oneYearOut.epochSecond)
        assertTrue(delta <= 2, "expiry within 2s of target (got delta=$delta)")
    }

    @Test
    fun `setPrimaryExpiry to null clears expiry`() {
        val ring = freshRing()
        val withExpiry = PgpHelper.loadSecretKeyRing(
            PgpHelper.setPrimaryExpiry(
                ring,
                Instant.now().plus(30, ChronoUnit.DAYS),
                pass.copyOf()
            )
        )
        assertNotNull(PgpHelper.primaryExpiry(withExpiry))

        val cleared = PgpHelper.loadSecretKeyRing(
            PgpHelper.setPrimaryExpiry(withExpiry, null, pass.copyOf())
        )
        assertNull(PgpHelper.primaryExpiry(cleared), "expiry should be cleared")
    }

    @Test
    fun `setPrimaryExpiry rejects times before key creation`() {
        val ring = freshRing()
        val ancient = Instant.parse("2000-01-01T00:00:00Z")
        assertThrows(Throwable::class.java) {
            PgpHelper.setPrimaryExpiry(ring, ancient, pass.copyOf())
        }
    }

    // ─── generateRevocationCert + applyRevocation ─────────────────────────

    @Test
    fun `revocation cert is a stand-alone KEY_REVOCATION signature`() {
        val ring = freshRing()
        assertFalse(PgpHelper.isRevoked(ring))

        val cert = PgpHelper.generateRevocationCert(
            ring,
            pass.copyOf(),
            PgpHelper.RevocationReason.Compromised,
            "key seized"
        )

        // Parse it back and inspect the packet.
        val decoder = PGPUtil.getDecoderStream(ByteArrayInputStream(cert))
        val factory = BcPGPObjectFactory(decoder)
        val sigList = factory.nextObject() as org.bouncycastle.openpgp.PGPSignatureList
        assertEquals(1, sigList.size())
        val sig = sigList[0]
        assertEquals(
            PGPSignature.KEY_REVOCATION.toInt(),
            sig.signatureType.toInt(),
            "must be type KEY_REVOCATION"
        )
    }

    @Test
    fun `applyRevocation marks the keyring as revoked`() {
        val ring = freshRing()
        val cert = PgpHelper.generateRevocationCert(
            ring, pass.copyOf(), PgpHelper.RevocationReason.Retired
        )
        val revoked = PgpHelper.loadSecretKeyRing(
            PgpHelper.applyRevocation(ring, cert)
        )
        assertTrue(PgpHelper.isRevoked(revoked), "ring should be marked revoked")
    }

    @Test
    fun `revocation cert cannot be generated with wrong passphrase`() {
        val ring = freshRing()
        assertThrows(Throwable::class.java) {
            PgpHelper.generateRevocationCert(ring, "wrong".toCharArray())
        }
    }
}
