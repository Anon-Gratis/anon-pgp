package gratis.anon.pgp

import org.bouncycastle.openpgp.PGPSecretKeyRing

/**
 * Process-scoped state shared between UI screens. Holds the active keyring +
 * per-key cached passphrases (keyed by fingerprint, so switching keys doesn't
 * leak passphrases between identities).
 *
 * Nuked on process exit. The keys themselves persist on disk via KeyVault.
 */
object Session {
    /** The keyring all crypto ops currently use. */
    var activeRing: PGPSecretKeyRing? = null

    private val passphrases = mutableMapOf<String, CharArray>()

    fun passphraseFor(fingerprint: String): CharArray? = passphrases[fingerprint]

    fun setPassphrase(fingerprint: String, pass: CharArray) {
        passphrases[fingerprint] = pass
    }

    fun clearPassphrase(fingerprint: String) {
        passphrases.remove(fingerprint)?.fill(' ')
    }

    fun reset() {
        activeRing = null
        passphrases.values.forEach { it.fill(' ') }
        passphrases.clear()
    }
}
