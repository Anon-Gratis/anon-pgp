package gratis.anon.pgp

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
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
import org.bouncycastle.openpgp.PGPPBEEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPBEDataDecryptorFactory
import org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
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
 * Stateless OpenPGP operations on top of Bouncy Castle.
 *
 * Three key-generation flavors:
 *   - [KeyAlgo.CLASSICAL_RSA]     — RSA-3072 (legacy, broadest interop)
 *   - [KeyAlgo.CLASSICAL_ED25519] — Ed25519 signing + X25519 encryption (modern OpenPGP)
 *   - [KeyAlgo.HYBRID_PQC]        — modern OpenPGP key + [PqcSidecar]
 *                                   (ML-DSA-65 + ML-KEM-768) for AnonPGP↔AnonPGP traffic
 *
 * Defaults for all three: SHA-256 certifications, AES-256 secret-key wrapping,
 * AES-256 + integrity for message encryption, ZLIB compression.
 */
object PgpHelper {

    private const val KEY_BITS = 3072
    private const val BUFFER_SIZE = 1 shl 16  // 64KB stream buffer

    /**
     * Key flavor used at generation time. Existing keyrings keep working
     * regardless of which flavor produced them — this enum only affects
     * `generateSecretKeyRing(...)` dispatch.
     */
    enum class KeyAlgo {
        /** RSA-3072. Broadest interop with old PGP installs. */
        CLASSICAL_RSA,

        /** Ed25519 sign + X25519 encrypt. Modern OpenPGP (crypto-refresh). */
        CLASSICAL_ED25519,

        /**
         * Modern OpenPGP (Ed25519 + X25519) bundled with an [PqcSidecar]
         * carrying ML-DSA-65 + ML-KEM-768. Quantum-safe when both parties
         * have AnonPGP; degrades to classical Ed25519/X25519 with non-PQC
         * peers.
         */
        HYBRID_PQC,
    }

    /**
     * Result of generating a hybrid identity. The classical part is a normal
     * OpenPGP armored secret keyring; the optional [pqcSidecar] is the
     * AnonPGP-specific binary blob produced by [PqcSidecar.generate]. Persist
     * them as a pair (KeyVault handles this automatically).
     */
    data class GeneratedKey(
        val classicalArmored: ByteArray,
        val pqcSidecar: ByteArray?
    )

    // ─── Key generation / parsing ─────────────────────────────────────────

    /**
     * Generate a fresh secret keyring + (optional) PQC sidecar.
     *
     * Default [algo] is [KeyAlgo.HYBRID_PQC] — quantum-safe by default,
     * classical fallback retained for non-AnonPGP peers.
     */
    fun generateSecretKeyRing(
        identity: String,
        passphrase: CharArray,
        algo: KeyAlgo = KeyAlgo.HYBRID_PQC
    ): GeneratedKey = when (algo) {
        KeyAlgo.CLASSICAL_RSA     -> GeneratedKey(generateRsa3072Ring(identity, passphrase), null)
        KeyAlgo.CLASSICAL_ED25519 -> GeneratedKey(generateEd25519Ring(identity, passphrase), null)
        KeyAlgo.HYBRID_PQC        -> GeneratedKey(
            generateEd25519Ring(identity, passphrase),
            PqcSidecar.generate(passphrase)
        )
    }

    private fun generateRsa3072Ring(identity: String, passphrase: CharArray): ByteArray {
        val kpg = java.security.KeyPairGenerator.getInstance("RSA")
        kpg.initialize(KEY_BITS, SecureRandom())
        val javaPair = kpg.generateKeyPair()

        val pgpPair: PGPKeyPair = JcaPGPKeyPair(
            PublicKeyAlgorithmTags.RSA_GENERAL,
            javaPair,
            Date()
        )
        return buildRing(identity, passphrase, pgpPair, encSubKey = null)
    }

    /**
     * Ed25519 primary signing key + X25519 encryption subkey. These are the
     * modern OpenPGP (crypto-refresh) algorithm tags — smaller, faster, and
     * unlike RSA-3072 widely deployed in fresh PGP installs from 2024+.
     */
    private fun generateEd25519Ring(identity: String, passphrase: CharArray): ByteArray {
        val random = SecureRandom()

        val edKp = Ed25519KeyPairGenerator().apply {
            init(Ed25519KeyGenerationParameters(random))
        }.generateKeyPair()
        val edPgp = BcPGPKeyPair(PublicKeyAlgorithmTags.Ed25519, edKp, Date())

        val xKp = X25519KeyPairGenerator().apply {
            init(X25519KeyGenerationParameters(random))
        }.generateKeyPair()
        val xPgp = BcPGPKeyPair(PublicKeyAlgorithmTags.X25519, xKp, Date())

        return buildRing(identity, passphrase, edPgp, encSubKey = xPgp)
    }

    /** Shared keyring construction: primary signing key + optional encryption subkey. */
    private fun buildRing(
        identity: String,
        passphrase: CharArray,
        primary: PGPKeyPair,
        encSubKey: PGPKeyPair?
    ): ByteArray {
        // BC requires SHA-1 specifically for the S2K key-checksum calculator on
        // OpenPGP v4 secret keys ("only SHA1 supported for key checksum
        // calculations"). The actual content-signer hash uses SHA-256.
        val sha1Calc = BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1)
        val secretKeyEncryptor = BcPBESecretKeyEncryptorBuilder(
            SymmetricKeyAlgorithmTags.AES_256, sha1Calc
        ).build(passphrase)

        // When the ring has a split signing/encryption layout, the self-cert
        // on the primary must declare SIGN+CERTIFY (otherwise default flags
        // attach the encryption role to the primary too), and the subkey
        // binding signature must declare ENCRYPT_COMMS+ENCRYPT_STORAGE so
        // `PGPPublicKey.isEncryptionKey` returns true on the subkey.
        val primaryHashedPcks = if (encSubKey != null) {
            PGPSignatureSubpacketGenerator().apply {
                setKeyFlags(false, KeyFlags.SIGN_DATA or KeyFlags.CERTIFY_OTHER)
            }.generate()
        } else null

        val ringGen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            primary,
            identity,
            sha1Calc,
            primaryHashedPcks,
            null,
            BcPGPContentSignerBuilder(primary.publicKey.algorithm, HashAlgorithmTags.SHA256),
            secretKeyEncryptor
        )
        if (encSubKey != null) {
            val subkeyHashedPcks = PGPSignatureSubpacketGenerator().apply {
                setKeyFlags(false, KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE)
            }.generate()
            ringGen.addSubKey(encSubKey, subkeyHashedPcks, null)
        }

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
        // Encoding `secretRing.publicKey` alone drops any subkeys — fine for
        // single-key RSA rings, but on Ed25519+X25519 the encryption subkey
        // would disappear and the exported public key would be useless for
        // encrypting to. Serialize every public key in the ring.
        val publicRing = publicRingFrom(secretRing)
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).use { armor -> publicRing.encode(armor) }
        return out.toByteArray()
    }

    /** Construct a PGPPublicKeyRing carrying every public key in [secretRing]. */
    fun publicRingFrom(secretRing: PGPSecretKeyRing): PGPPublicKeyRing {
        val baos = ByteArrayOutputStream()
        secretRing.publicKeys.forEach { pk -> pk.encode(baos) }
        return PGPPublicKeyRing(baos.toByteArray(), BcKeyFingerprintCalculator())
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

    /** Whether the primary key carries a verified revocation signature. */
    fun isRevoked(secretRing: PGPSecretKeyRing): Boolean = secretRing.publicKey.hasRevocation()

    /**
     * Expiry timestamp of the primary key as a Java [java.time.Instant], or
     * `null` if the key has no expiry set. Reads `validSeconds` off the
     * primary public key (which BC computes from the self-cert subpacket).
     */
    fun primaryExpiry(secretRing: PGPSecretKeyRing): java.time.Instant? {
        val pk = secretRing.publicKey
        val seconds = pk.validSeconds
        if (seconds <= 0L) return null
        return pk.creationTime.toInstant().plusSeconds(seconds)
    }

    // ─── Subkey management ────────────────────────────────────────────────
    //
    // Adding a fresh encryption subkey lets users rotate the keys that
    // ciphertext is encrypted to without throwing away their identity
    // (the primary key + user-ids stay the same, so existing trust relations
    // remain valid).

    /** Algorithms supported for adding an encryption subkey. */
    enum class SubkeyAlgo {
        /** X25519 (modern OpenPGP, fast, small). */
        X25519,
        /** RSA-3072 (legacy interop). */
        RSA_3072,
    }

    /**
     * Generate a fresh encryption subkey and append it to [secretRing].
     * Returns an updated armored secret-keyring that supersedes the old one
     * — the vault's `.asc` should be replaced with the result. The new
     * subkey is bound by a subkey-binding signature from the primary, with
     * KeyFlags = ENCRYPT_COMMS | ENCRYPT_STORAGE.
     */
    fun addEncryptionSubkey(
        secretRing: PGPSecretKeyRing,
        passphrase: CharArray,
        algo: SubkeyAlgo = SubkeyAlgo.X25519
    ): ByteArray {
        val primarySecret = secretRing.secretKey
        val primaryPub = secretRing.publicKey
        val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider())
            .build(passphrase)
        val primaryPriv = primarySecret.extractPrivateKey(decryptor)

        val random = SecureRandom()
        val subPgpKp: PGPKeyPair = when (algo) {
            SubkeyAlgo.X25519 -> {
                val kp = X25519KeyPairGenerator().apply {
                    init(X25519KeyGenerationParameters(random))
                }.generateKeyPair()
                BcPGPKeyPair(PublicKeyAlgorithmTags.X25519, kp, Date())
            }
            SubkeyAlgo.RSA_3072 -> {
                val rsa = java.security.KeyPairGenerator.getInstance("RSA")
                rsa.initialize(3072, random)
                JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, rsa.generateKeyPair(), Date())
            }
        }

        // Build the subkey-binding signature. Modern OpenPGP convention puts
        // ENCRYPT flags here even though they're "subkey-only" because the
        // primary signature already establishes signing capability.
        val bindingSigGen = PGPSignatureGenerator(
            BcPGPContentSignerBuilder(primaryPub.algorithm, HashAlgorithmTags.SHA256)
        )
        bindingSigGen.init(PGPSignature.SUBKEY_BINDING, primaryPriv)
        val hashedPcks = PGPSignatureSubpacketGenerator().apply {
            setKeyFlags(false, KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE)
        }.generate()
        bindingSigGen.setHashedSubpackets(hashedPcks)
        val bindingSig = bindingSigGen.generateCertification(primaryPub, subPgpKp.publicKey)
        val subPubBound = PGPPublicKey.addCertification(subPgpKp.publicKey, bindingSig)

        // Wrap as PGPSecretKey. We re-use the same passphrase encryptor as
        // the existing primary so the user has one passphrase across the ring.
        val sha1Calc = BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1)
        val secretKeyEncryptor = BcPBESecretKeyEncryptorBuilder(
            SymmetricKeyAlgorithmTags.AES_256, sha1Calc
        ).build(passphrase)

        val subSecretKey = PGPSecretKey(
            subPgpKp.privateKey,
            subPubBound,
            sha1Calc,
            false,                  // not the master
            secretKeyEncryptor
        )

        val updated = PGPSecretKeyRing.insertSecretKey(secretRing, subSecretKey)
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).use { armor -> updated.encode(armor) }
        return out.toByteArray()
    }

    // ─── Key expiry ───────────────────────────────────────────────────────
    //
    // OpenPGP keys can carry an expiry timestamp in their user-id self-cert.
    // Setting (or extending) expiry is done by generating a fresh self-cert
    // with a new KeyExpirationTime subpacket and replacing the old one.

    /**
     * Set or clear the expiry on the primary key. Pass [expiry] = `null` to
     * make the key non-expiring. Returns an updated armored secret-keyring.
     */
    fun setPrimaryExpiry(
        secretRing: PGPSecretKeyRing,
        expiry: java.time.Instant?,
        passphrase: CharArray
    ): ByteArray {
        val primarySecret = secretRing.secretKey
        val primaryPub = secretRing.publicKey
        val userId = firstUserId(primaryPub)
            ?: throw PGPException("No user-id on primary key — can't anchor expiry")

        val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider())
            .build(passphrase)
        val primaryPriv = primarySecret.extractPrivateKey(decryptor)

        val sigGen = PGPSignatureGenerator(
            BcPGPContentSignerBuilder(primaryPub.algorithm, HashAlgorithmTags.SHA256)
        )
        sigGen.init(PGPSignature.POSITIVE_CERTIFICATION, primaryPriv)
        val subpkts = PGPSignatureSubpacketGenerator().apply {
            // OpenPGP encodes expiry as seconds-from-creation, not absolute.
            // A value of 0 means "never expires" (we just omit the subpacket).
            if (expiry != null) {
                val secondsFromCreation =
                    expiry.epochSecond - (primaryPub.creationTime.time / 1000)
                require(secondsFromCreation > 0) {
                    "Expiry must be after the key's creation time"
                }
                setKeyExpirationTime(false, secondsFromCreation)
            }
            // Preserve the standard primary-key capability flags so the key
            // remains usable for signing + certifying after the self-cert is
            // replaced. If the user has split sign/encrypt onto a subkey, the
            // subkey's binding sig still carries ENCRYPT_* flags untouched.
            setKeyFlags(false, KeyFlags.SIGN_DATA or KeyFlags.CERTIFY_OTHER)
        }.generate()
        sigGen.setHashedSubpackets(subpkts)
        val newSig = sigGen.generateCertification(userId, primaryPub)

        // Find the *latest* existing positive self-cert (the one currently
        // authoritative) and replace it. Older sigs left in place are
        // harmless — verifiers always pick the newest by creation time.
        var newPub = primaryPub
        val existing = primaryPub.getSignaturesForID(userId).asSequence()
            .filter { it.signatureType == PGPSignature.POSITIVE_CERTIFICATION }
            .toList()
        val toReplace = existing.maxByOrNull { it.creationTime.time }
        if (toReplace != null) {
            newPub = PGPPublicKey.removeCertification(newPub, userId, toReplace)
        }
        newPub = PGPPublicKey.addCertification(newPub, userId, newSig)

        val pubRing = PGPPublicKeyRing.insertPublicKey(publicRingFrom(secretRing), newPub)
        val updated = PGPSecretKeyRing.replacePublicKeys(secretRing, pubRing)

        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).use { armor -> updated.encode(armor) }
        return out.toByteArray()
    }

    // ─── Revocation certificates ──────────────────────────────────────────
    //
    // A revocation cert is a standalone OpenPGP signature (type KEY_REVOCATION)
    // signed by the primary's private key. It says "this key is revoked, here's
    // why". Once produced, anyone can import it (`gpg --import revcert.asc`)
    // to mark the key as revoked in their keyring. Best practice: generate one
    // at keygen time, print it on paper, and lock it in a drawer — so if you
    // lose the key passphrase you can still tell the world to stop trusting it.

    /** OpenPGP revocation reason codes (RFC 4880 §5.2.3.23). */
    enum class RevocationReason(val code: Byte) {
        /** No reason given — generic revocation. */
        NoReason(0),
        /** Key has been superseded by a newer one. */
        Superseded(1),
        /** Key has been compromised (passphrase leaked, device seized, etc.). */
        Compromised(2),
        /** Key is no longer used; not necessarily compromised. */
        Retired(3),
    }

    /**
     * Build a stand-alone revocation certificate for [secretRing]'s primary
     * key, signed using [passphrase]. The returned bytes are ASCII-armored and
     * can be imported by any OpenPGP client.
     */
    fun generateRevocationCert(
        secretRing: PGPSecretKeyRing,
        passphrase: CharArray,
        reason: RevocationReason = RevocationReason.NoReason,
        comment: String = ""
    ): ByteArray {
        val primarySecret = secretRing.secretKey
        val primaryPub = secretRing.publicKey
        val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider())
            .build(passphrase)
        val primaryPriv = primarySecret.extractPrivateKey(decryptor)

        val sigGen = PGPSignatureGenerator(
            BcPGPContentSignerBuilder(primaryPub.algorithm, HashAlgorithmTags.SHA256)
        )
        sigGen.init(PGPSignature.KEY_REVOCATION, primaryPriv)
        val subpkts = PGPSignatureSubpacketGenerator().apply {
            setRevocationReason(false, reason.code, comment)
        }.generate()
        sigGen.setHashedSubpackets(subpkts)

        val revSig = sigGen.generateCertification(primaryPub)
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).use { armor ->
            armor.setHeader("Comment", "AnonPGP revocation certificate — import to revoke this key")
            revSig.encode(armor)
        }
        return out.toByteArray()
    }

    /**
     * Apply a previously-generated revocation certificate to [secretRing]'s
     * public key. Returns an updated armored secret-keyring. The classical
     * `.asc` file should be replaced with the result so future encryptors
     * see the revocation.
     */
    fun applyRevocation(secretRing: PGPSecretKeyRing, armoredRevCert: ByteArray): ByteArray {
        val decoder = PGPUtil.getDecoderStream(ByteArrayInputStream(armoredRevCert))
        val factory = BcPGPObjectFactory(decoder)
        val sigList = factory.nextObject() as? org.bouncycastle.openpgp.PGPSignatureList
            ?: throw PGPException("Not a signature block")
        val sig = sigList[0]
        require(sig.signatureType == PGPSignature.KEY_REVOCATION) {
            "Not a KEY_REVOCATION signature (type=${sig.signatureType})"
        }
        val revoked = PGPPublicKey.addCertification(secretRing.publicKey, sig)
        val updated = PGPSecretKeyRing.replacePublicKeys(
            secretRing,
            PgpHelper.publicRingFrom(secretRing).run {
                // Replace just the primary; subkeys keep their existing certs.
                PGPPublicKeyRing.insertPublicKey(this, revoked)
            }
        )
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).use { armor -> updated.encode(armor) }
        return out.toByteArray()
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

    // ─── Symmetric (passphrase-only) encrypt / decrypt ───────────────────
    //
    // Equivalent to `gpg --symmetric`. No recipient key, no metadata to
    // anyone — just AES-256 with a key derived from the passphrase via S2K.
    // Privacy story: the ciphertext leaks nothing about who can read it,
    // because the answer is "anyone with the passphrase".
    //
    // Interoperable with GnuPG: `gpg -d ciphertext.asc` will prompt for the
    // passphrase and decrypt.

    fun encryptSymmetric(plaintext: ByteArray, passphrase: CharArray): ByteArray {
        val out = ByteArrayOutputStream()
        encryptSymmetricStream(
            ByteArrayInputStream(plaintext),
            plaintext.size.toLong(),
            "msg",
            passphrase,
            out
        )
        return out.toByteArray()
    }

    fun decryptSymmetric(armoredCiphertext: ByteArray, passphrase: CharArray): ByteArray {
        val out = ByteArrayOutputStream()
        decryptSymmetricStream(ByteArrayInputStream(armoredCiphertext), passphrase, out)
        return out.toByteArray()
    }

    /** What kind of encryption an OpenPGP ciphertext uses. */
    enum class CiphertextKind {
        /** Encrypted to one or more public keys. Needs a matching secret key + its passphrase. */
        PublicKey,

        /** Encrypted with a passphrase only (`gpg --symmetric`). */
        Symmetric,

        /** Has BOTH public-key and PBE session-key packets — rare but allowed. */
        Mixed,

        /** Couldn't be parsed as an OpenPGP encrypted message. */
        Unknown,
    }

    /**
     * Look at the head of an armored ciphertext without decrypting it, to
     * decide which path (asymmetric / symmetric) to drive. Lets the Decrypt
     * UI pick a passphrase prompt vs. a key passphrase prompt automatically.
     */
    fun classifyCiphertext(armoredCiphertext: ByteArray): CiphertextKind {
        return try {
            val decoder = PGPUtil.getDecoderStream(ByteArrayInputStream(armoredCiphertext))
            val factory = BcPGPObjectFactory(decoder)
            var obj = factory.nextObject()
            if (obj !is PGPEncryptedDataList) obj = factory.nextObject()
            val list = obj as? PGPEncryptedDataList ?: return CiphertextKind.Unknown

            var hasPbe = false
            var hasPke = false
            for (d in list.encryptedDataObjects) {
                when (d) {
                    is PGPPBEEncryptedData -> hasPbe = true
                    is PGPPublicKeyEncryptedData -> hasPke = true
                }
            }
            when {
                hasPbe && hasPke -> CiphertextKind.Mixed
                hasPbe          -> CiphertextKind.Symmetric
                hasPke          -> CiphertextKind.PublicKey
                else            -> CiphertextKind.Unknown
            }
        } catch (_: Throwable) {
            CiphertextKind.Unknown
        }
    }

    /**
     * Stream-encrypt with a passphrase-derived AES-256 key. Output is
     * ASCII-armored OpenPGP, integrity-protected (MDC packet), ZLIB-compressed.
     */
    fun encryptSymmetricStream(
        plain: InputStream,
        plainSize: Long,
        nameHint: String,
        passphrase: CharArray,
        armoredOut: OutputStream
    ) {
        val armor = ArmoredOutputStream(armoredOut)
        val encGen = PGPEncryptedDataGenerator(
            org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder(
                SymmetricKeyAlgorithmTags.AES_256
            ).setWithIntegrityPacket(true).setSecureRandom(SecureRandom())
        )
        // BcPBEKeyEncryptionMethodGenerator uses S2K iterated+salted by
        // default, with SHA-256 digest — that's the standard OpenPGP
        // passphrase-to-key mechanism.
        encGen.addMethod(BcPBEKeyEncryptionMethodGenerator(passphrase))

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
     * Stream-decrypt passphrase-encrypted ciphertext. Throws PGPException on
     * bad passphrase, missing PBE packet, or integrity-check failure.
     */
    fun decryptSymmetricStream(
        armoredIn: InputStream,
        passphrase: CharArray,
        plainOut: OutputStream
    ) {
        val decoder = PGPUtil.getDecoderStream(armoredIn)
        val factory: PGPObjectFactory = BcPGPObjectFactory(decoder)
        var obj = factory.nextObject()
        if (obj !is PGPEncryptedDataList) obj = factory.nextObject()
        val encList = obj as? PGPEncryptedDataList
            ?: throw PGPException("No encrypted data block found in input")

        // Find the first PBE-encrypted session-key packet.
        val pbe = encList.encryptedDataObjects.asSequence()
            .filterIsInstance<PGPPBEEncryptedData>()
            .firstOrNull()
            ?: throw PGPException("Ciphertext is not passphrase-encrypted (no PBE packet)")

        val clearStream: InputStream = pbe.getDataStream(
            BcPBEDataDecryptorFactory(passphrase, BcPGPDigestCalculatorProvider())
        )

        var inner: PGPObjectFactory = BcPGPObjectFactory(clearStream)
        var messageObj = inner.nextObject()
        if (messageObj is PGPCompressedData) {
            inner = BcPGPObjectFactory(messageObj.dataStream)
            messageObj = inner.nextObject()
        }
        val literal = messageObj as? PGPLiteralData
            ?: throw PGPException("Decryption succeeded but inner data is not a literal packet")

        val src = literal.inputStream
        val buf = ByteArray(BUFFER_SIZE)
        while (true) {
            val n = src.read(buf)
            if (n <= 0) break
            plainOut.write(buf, 0, n)
        }
        plainOut.flush()
        if (pbe.isIntegrityProtected && !pbe.verify()) {
            throw PGPException("Ciphertext integrity check failed — message may have been tampered with")
        }
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
