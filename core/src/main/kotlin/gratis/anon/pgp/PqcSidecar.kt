package gratis.anon.pgp

import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters
import org.bouncycastle.crypto.params.MLDSAParameters
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters
import org.bouncycastle.crypto.params.MLKEMParameters
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Post-quantum sidecar carried alongside an AnonPGP classical OpenPGP key.
 *
 * Contains an ML-DSA-65 signing keypair and an ML-KEM-768 KEM keypair.
 * Secret keys are passphrase-protected with PBKDF2-HMAC-SHA256 → AES-256-GCM.
 * Public keys are stored in the clear.
 *
 * Why a sidecar instead of native OpenPGP packets: BouncyCastle bcpg 1.84
 * doesn't yet ship draft-ietf-openpgp-pqc packet wrappers. Once it does, this
 * can migrate to in-band packets without changing the file-pair pattern.
 *
 * Wire format (binary, "APGP-PQC v1"):
 *   magic         4    "APGP"
 *   version       1    = 1
 *   kdf salt     16
 *   kdf iters     4    big-endian
 *   ml-dsa-pub-len 4 + bytes
 *   ml-dsa-iv    12
 *   ml-dsa-ct-len 4 + bytes      // AES-256-GCM(ml-dsa-priv)
 *   ml-kem-pub-len 4 + bytes
 *   ml-kem-iv    12
 *   ml-kem-ct-len 4 + bytes      // AES-256-GCM(ml-kem-priv)
 */
object PqcSidecar {

    private const val MAGIC = "APGP"
    private const val VERSION: Byte = 1
    private const val PBKDF2_ITERS = 600_000
    private const val SALT_LEN = 16
    private const val GCM_IV_LEN = 12
    private const val GCM_TAG_BITS = 128
    private const val AES_KEY_BITS = 256

    /** Public PQC material — fingerprint-friendly, never encrypted. */
    data class PqcPublic(
        val mlDsaPublic: ByteArray,
        val mlKemPublic: ByteArray
    )

    /** Full PQC keypairs after passphrase unlock. */
    data class PqcKeys(
        val mlDsaPublic: ByteArray,
        val mlDsaPrivate: ByteArray,
        val mlKemPublic: ByteArray,
        val mlKemPrivate: ByteArray
    )

    /** Generates a fresh PQC sidecar (ML-DSA-65 + ML-KEM-768) and serializes it. */
    fun generate(passphrase: CharArray): ByteArray {
        val random = SecureRandom()

        val mlDsaKp = MLDSAKeyPairGenerator().apply {
            init(MLDSAKeyGenerationParameters(random, MLDSAParameters.ml_dsa_65))
        }.generateKeyPair()
        val mlDsaPub = (mlDsaKp.public as MLDSAPublicKeyParameters).encoded
        val mlDsaPriv = (mlDsaKp.private as MLDSAPrivateKeyParameters).encoded

        val mlKemKp = MLKEMKeyPairGenerator().apply {
            init(MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_768))
        }.generateKeyPair()
        val mlKemPub = (mlKemKp.public as MLKEMPublicKeyParameters).encoded
        val mlKemPriv = (mlKemKp.private as MLKEMPrivateKeyParameters).encoded

        return encode(passphrase, mlDsaPub, mlDsaPriv, mlKemPub, mlKemPriv, random)
    }

    /** Decrypts a sidecar with the user passphrase, returning all four key blobs. */
    fun load(bytes: ByteArray, passphrase: CharArray): PqcKeys {
        val input = DataInputStream(ByteArrayInputStream(bytes))
        val magic = ByteArray(4).also { input.readFully(it) }
        require(String(magic, Charsets.US_ASCII) == MAGIC) {
            "Not an AnonPGP PQC sidecar (bad magic)"
        }
        val version = input.readByte()
        require(version == VERSION) { "Unsupported sidecar version: $version" }
        val salt = ByteArray(SALT_LEN).also { input.readFully(it) }
        val iters = input.readInt()

        val key = derive(passphrase, salt, iters)
        try {
            val mlDsaPub = readBlob(input)
            val mlDsaPriv = readEncrypted(input, key)
            val mlKemPub = readBlob(input)
            val mlKemPriv = readEncrypted(input, key)
            return PqcKeys(mlDsaPub, mlDsaPriv, mlKemPub, mlKemPriv)
        } finally {
            key.fill(0)
        }
    }

    /** Reads ONLY the public-key blobs — no passphrase needed. */
    fun loadPublicOnly(bytes: ByteArray): PqcPublic {
        val input = DataInputStream(ByteArrayInputStream(bytes))
        val magic = ByteArray(4).also { input.readFully(it) }
        require(String(magic, Charsets.US_ASCII) == MAGIC) {
            "Not an AnonPGP PQC sidecar (bad magic)"
        }
        val version = input.readByte()
        require(version == VERSION) { "Unsupported sidecar version: $version" }
        input.skipBytes(SALT_LEN + Int.SIZE_BYTES)  // skip salt + iters

        val mlDsaPub = readBlob(input)
        skipEncrypted(input)
        val mlKemPub = readBlob(input)
        return PqcPublic(mlDsaPub, mlKemPub)
    }

    private fun encode(
        passphrase: CharArray,
        mlDsaPub: ByteArray, mlDsaPriv: ByteArray,
        mlKemPub: ByteArray, mlKemPriv: ByteArray,
        random: SecureRandom
    ): ByteArray {
        val salt = ByteArray(SALT_LEN).also { random.nextBytes(it) }
        val key = derive(passphrase, salt, PBKDF2_ITERS)
        try {
            val out = ByteArrayOutputStream()
            DataOutputStream(out).use { d ->
                d.write(MAGIC.toByteArray(Charsets.US_ASCII))
                d.writeByte(VERSION.toInt())
                d.write(salt)
                d.writeInt(PBKDF2_ITERS)
                writeBlob(d, mlDsaPub)
                writeEncrypted(d, mlDsaPriv, key, random)
                writeBlob(d, mlKemPub)
                writeEncrypted(d, mlKemPriv, key, random)
            }
            return out.toByteArray()
        } finally {
            key.fill(0)
            mlDsaPriv.fill(0)
            mlKemPriv.fill(0)
        }
    }

    private fun derive(passphrase: CharArray, salt: ByteArray, iters: Int): ByteArray {
        val spec = PBEKeySpec(passphrase, salt, iters, AES_KEY_BITS)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        return factory.generateSecret(spec).encoded
    }

    private fun writeBlob(d: DataOutputStream, bytes: ByteArray) {
        d.writeInt(bytes.size)
        d.write(bytes)
    }

    private fun readBlob(d: DataInputStream): ByteArray {
        val len = d.readInt()
        return ByteArray(len).also { d.readFully(it) }
    }

    private fun writeEncrypted(
        d: DataOutputStream,
        plain: ByteArray,
        key: ByteArray,
        random: SecureRandom
    ) {
        val iv = ByteArray(GCM_IV_LEN).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, iv))
        val ct = cipher.doFinal(plain)
        d.write(iv)
        writeBlob(d, ct)
    }

    private fun readEncrypted(d: DataInputStream, key: ByteArray): ByteArray {
        val iv = ByteArray(GCM_IV_LEN).also { d.readFully(it) }
        val ct = readBlob(d)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(ct)
    }

    private fun skipEncrypted(d: DataInputStream) {
        d.skipBytes(GCM_IV_LEN)
        val len = d.readInt()
        d.skipBytes(len)
    }
}
