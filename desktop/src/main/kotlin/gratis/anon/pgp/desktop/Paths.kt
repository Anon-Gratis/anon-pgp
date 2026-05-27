package gratis.anon.pgp.desktop

import java.io.File

/**
 * Resolves the AnonPGP data directory on Linux. Follows the XDG Base Directory
 * spec: `$XDG_DATA_HOME/anon-pgp` if set, else `~/.local/share/anon-pgp`.
 *
 * Created on first access — the rest of the app assumes the directory exists.
 */
object Paths {
    val dataDir: File by lazy {
        val xdg = System.getenv("XDG_DATA_HOME")?.takeIf { it.isNotBlank() }
        val base = if (xdg != null) File(xdg) else File(System.getProperty("user.home"), ".local/share")
        File(base, "anon-pgp").also { it.mkdirs() }
    }

    /** Plaintext .properties prefs (used when the vault is NOT encrypted at rest). */
    val prefsFile: File get() = File(dataDir, "prefs.properties")

    /** Encrypted prefs blob (used when at-rest encryption is enabled). */
    val encPrefsFile: File get() = File(dataDir, "prefs.enc")
}
