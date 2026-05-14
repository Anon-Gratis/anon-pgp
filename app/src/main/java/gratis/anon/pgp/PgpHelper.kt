package gratis.anon.pgp

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPCompressedDataGenerator
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import java.util.Date

/**
 * Stateless OpenPGP operations on top of Bouncy Castle. Defaults:
 *   - RSA-3072 / SHA-256 / AES-256 / ZLIB
 *   - Passphrase-protected private key, AES-256 wrapping
 */
object PgpHelper {

    private const val KEY_BITS = 3072
    private const val BUFFER_SIZE = 1 shl 16  // 64KB stream buffer

    // ─── Key generation / parsing ─────────────────────────────────────────

    fun generateSecretKeyRing(identity: String, passphrase: CharArray): ByteArray {
        val kpg = java.security.KeyPairGenerator.getInstance("RSA")
        kpg.initialize(KEY_BITS, SecureRandom())
        val javaPair = kpg.generateKeyPair()

        val pgpPair: PGPKeyPair = JcaPGPKeyPair(
            org.bouncycastle.bcpg.PublicKeyAlgorithmTags.RSA_GENERAL,
            javaPair,
            Date()
        )

        val sha1Calc = BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1)
        val secretKeyEncryptor = BcPBESecretKeyEncryptorBuilder(
            SymmetricKeyAlgorithmTags.AES_256, sha1Calc
        ).build(passphrase)

        val ringGen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            pgpPair,
            identity,
            sha1Calc,
            null,
            null,
            BcPGPContentSignerBuilder(pgpPair.publicKey.algorithm, HashAlgorithmTags.SHA256),
            secretKeyEncryptor
        )

        val secretRing = ringGen.generateSecretKeyRing()
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).use { armor -> secretRing.encode(armor) }
        return out.toByteArray()
    }

    fun loadSecretKeyRing(armoredBytes: ByteArray): PGPSecretKeyRing {
        val input = PGPUtil.getDecoderStream(ByteArrayInputStream(armoredBytes))
        val factory = BcPGPObjectFactory(input)
        var obj = factory.nextObject()
        while (obj != null) {
            if (obj is PGPSecretKeyRing) return obj
            obj = factory.nextObject()
        }
        throw PGPException("No secret keyring found in armored input")
    }

    fun loadPublicKeyRing(armoredBytes: ByteArray): PGPPublicKeyRing {
        val input = PGPUtil.getDecoderStream(ByteArrayInputStream(armoredBytes))
        val factory = BcPGPObjectFactory(input)
        var obj = factory.nextObject()
        while (obj != null) {
            if (obj is PGPPublicKeyRing) return obj
            obj = factory.nextObject()
        }
        throw PGPException("No public keyring found in armored input")
    }

    fun exportPublicKey(secretRing: PGPSecretKeyRing): ByteArray {
        val publicRing = PGPPublicKeyRing(secretRing.publicKey.encoded, BcKeyFingerprintCalculator())
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).use { armor -> publicRing.encode(armor) }
        return out.toByteArray()
    }

    /** Hex-formatted fingerprint of a public key (e.g. "ABCD 1234 EF56..."). */
    fun fingerprint(publicKey: PGPPublicKey): String {
        val bytes = publicKey.fingerprint
        val hex = bytes.joinToString("") { "%02X".format(it) }
        return hex.chunked(4).joinToString(" ")
    }

    /** Fingerprint with no separators — used for filenames. */
    fun fingerprintCompact(publicKey: PGPPublicKey): String =
        publicKey.fingerprint.joinToString("") { "%02X".format(it) }

    /** First user-id baked into the public key, or null if absent. */
    fun firstUserId(publicKey: PGPPublicKey): String? {
        val iter = publicKey.userIDs
        return if (iter.hasNext()) iter.next() else null
    }

    // ─── Text (in-memory) encrypt / decrypt ───────────────────────────────

    fun encryptToRecipient(plaintext: ByteArray, recipientPublicRing: PGPPublicKeyRing): ByteArray {
        val out = ByteArrayOutputStream()
        encryptStreamToRecipient(
            ByteArrayInputStream(plaintext),
            plaintext.size.toLong(),
            "msg",
            recipientPublicRing,
            out
        )
        return out.toByteArray()
    }

    fun decryptFromArmored(
        armoredCiphertext: ByteArray,
        secretRing: PGPSecretKeyRing,
        passphrase: CharArray
    ): ByteArray {
        val out = ByteArrayOutputStream()
        decryptStream(ByteArrayInputStream(armoredCiphertext), secretRing, passphrase, out)
        return out.toByteArray()
    }

    // ─── Streaming encrypt / decrypt (for files) ──────────────────────────

    /**
     * Stream-encrypt {@code plain} → ASCII-armored ciphertext to {@code armoredOut}.
     * Does NOT close armoredOut. {@code plainSize} is used for the literal-data
     * length hint; pass -1 if unknown.
     */
    fun encryptStreamToRecipient(
        plain: InputStream,
        plainSize: Long,
        nameHint: String,
        recipientPublicRing: PGPPublicKeyRing,
        armoredOut: OutputStream
    ) {
        val encryptionKey = recipientPublicRing.publicKeys.asSequence()
            .firstOrNull { it.isEncryptionKey }
            ?: throw PGPException("Recipient public keyring has no encryption-capable key")

        val armor = ArmoredOutputStream(armoredOut)
        val encGen = PGPEncryptedDataGenerator(
            org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder(
                SymmetricKeyAlgorithmTags.AES_256
            ).setWithIntegrityPacket(true).setSecureRandom(SecureRandom())
        )
        encGen.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(encryptionKey))

        // ZLIB stream wrapped in encryption stream wrapped in literal stream.
        val encStream = encGen.open(armor, ByteArray(BUFFER_SIZE))
        val compGen = PGPCompressedDataGenerator(PGPCompressedData.ZLIB)
        val compStream = compGen.open(encStream)
        val litGen = PGPLiteralDataGenerator()
        val litStream = litGen.open(
            compStream,
            PGPLiteralData.BINARY,
            nameHint,
            if (plainSize >= 0) plainSize else PGPLiteralData.NOW.time,
            Date()
        )

        val buf = ByteArray(BUFFER_SIZE)
        while (true) {
            val n = plain.read(buf)
            if (n <= 0) break
            litStream.write(buf, 0, n)
        }
        litStream.close()
        compStream.close()
        encStream.close()
        armor.close()
    }

    /**
     * Stream-decrypt {@code armoredIn} → {@code plainOut}. Does NOT close
     * plainOut. Throws PGPException on integrity / passphrase / no-matching-key.
     */
    fun decryptStream(
        armoredIn: InputStream,
        secretRing: PGPSecretKeyRing,
        passphrase: CharArray,
        plainOut: OutputStream
    ) {
        val decoder = PGPUtil.getDecoderStream(armoredIn)
        val factory: PGPObjectFactory = BcPGPObjectFactory(decoder)
        var obj = factory.nextObject()
        if (obj !is PGPEncryptedDataList) obj = factory.nextObject()
        val encList = obj as? PGPEncryptedDataList
            ?: throw PGPException("No encrypted data block found in input")

        var picked: PGPPublicKeyEncryptedData? = null
        var secretKey: PGPSecretKey? = null
        for (encDataObj in encList.encryptedDataObjects) {
            val pked = encDataObj as? PGPPublicKeyEncryptedData ?: continue
            val candidate = secretRing.getSecretKey(pked.keyID)
            if (candidate != null) { picked = pked; secretKey = candidate; break }
        }
        if (picked == null || secretKey == null) {
            throw PGPException("Ciphertext is not encrypted to this key")
        }

        val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider())
            .build(passphrase)
        val privateKey = secretKey.extractPrivateKey(decryptor)
        val clearStream: InputStream =
            picked.getDataStream(BcPublicKeyDataDecryptorFactory(privateKey))

        var inner: PGPObjectFactory = BcPGPObjectFactory(clearStream)
        var messageObj = inner.nextObject()
        if (messageObj is PGPCompressedData) {
            inner = BcPGPObjectFactory(messageObj.dataStream)
            messageObj = inner.nextObject()
        }
        val literal = messageObj as? PGPLiteralData
            ?: throw PGPException("Decryption succeeded but the inner data isn't a literal packet")

        val src = literal.inputStream
        val buf = ByteArray(BUFFER_SIZE)
        while (true) {
            val n = src.read(buf)
            if (n <= 0) break
            plainOut.write(buf, 0, n)
        }
        plainOut.flush()
        if (picked.isIntegrityProtected && !picked.verify()) {
            throw PGPException("Ciphertext integrity check failed — message may have been tampered with")
        }
    }

    // ─── Detached signatures ─────────────────────────────────────────────

    fun signDetached(
        plaintext: ByteArray,
        secretRing: PGPSecretKeyRing,
        passphrase: CharArray
    ): ByteArray {
        val out = ByteArrayOutputStream()
        signDetachedStream(ByteArrayInputStream(plaintext), secretRing, passphrase, out)
        return out.toByteArray()
    }

    fun signDetachedStream(
        data: InputStream,
        secretRing: PGPSecretKeyRing,
        passphrase: CharArray,
        armoredSigOut: OutputStream
    ) {
        val signingKey = secretRing.secretKey
        val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider())
            .build(passphrase)
        val privateKey = signingKey.extractPrivateKey(decryptor)
        val sigGen = PGPSignatureGenerator(
            BcPGPContentSignerBuilder(signingKey.publicKey.algorithm, HashAlgorithmTags.SHA256)
        )
        sigGen.init(PGPSignature.BINARY_DOCUMENT, privateKey)
        val buf = ByteArray(BUFFER_SIZE)
        while (true) {
            val n = data.read(buf)
            if (n <= 0) break
            sigGen.update(buf, 0, n)
        }
        ArmoredOutputStream(armoredSigOut).use { armor -> sigGen.generate().encode(armor) }
    }

    fun verifyDetached(
        plaintext: ByteArray,
        armoredSignature: ByteArray,
        signerPublicRing: PGPPublicKeyRing
    ): Boolean = verifyDetachedStream(
        ByteArrayInputStream(plaintext),
        ByteArrayInputStream(armoredSignature),
        signerPublicRing
    )

    fun verifyDetachedStream(
        data: InputStream,
        armoredSignature: InputStream,
        signerPublicRing: PGPPublicKeyRing
    ): Boolean {
        val decoder = PGPUtil.getDecoderStream(armoredSignature)
        val factory = BcPGPObjectFactory(decoder)
        val sigListObj = factory.nextObject()
        val signatures = sigListObj as? org.bouncycastle.openpgp.PGPSignatureList ?: return false
        val sig = signatures[0]
        val pubKey = signerPublicRing.getPublicKey(sig.keyID) ?: return false
        sig.init(BcPGPContentVerifierBuilderProvider(), pubKey)
        val buf = ByteArray(BUFFER_SIZE)
        while (true) {
            val n = data.read(buf)
            if (n <= 0) break
            sig.update(buf, 0, n)
        }
        return sig.verify()
    }

    /**
     * Try {@code armoredSignature} against every public ring in {@code candidates}.
     * Returns the matching ring (and pretty-fingerprint) if one verifies, else null.
     * Useful when the signer is unknown and we have a roster of candidates.
     */
    data class VerifyResult(val ring: PGPPublicKeyRing, val signerKeyId: Long)

    fun verifyDetachedAgainstAny(
        plaintext: ByteArray,
        armoredSignature: ByteArray,
        candidates: List<PGPPublicKeyRing>
    ): VerifyResult? {
        // Parse signature once to find keyID, then try matching candidates.
        val decoder = PGPUtil.getDecoderStream(ByteArrayInputStream(armoredSignature))
        val factory = BcPGPObjectFactory(decoder)
        val sigListObj = factory.nextObject() as? org.bouncycastle.openpgp.PGPSignatureList ?: return null
        val sig = sigListObj[0]
        val signerId = sig.keyID

        for (ring in candidates) {
            val pubKey = ring.getPublicKey(signerId) ?: continue
            sig.init(BcPGPContentVerifierBuilderProvider(), pubKey)
            sig.update(plaintext)
            if (sig.verify()) return VerifyResult(ring, signerId)
        }
        return null
    }
}
