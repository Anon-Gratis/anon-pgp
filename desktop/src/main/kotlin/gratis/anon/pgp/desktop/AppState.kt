package gratis.anon.pgp.desktop

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import gratis.anon.pgp.ContactRoster
import gratis.anon.pgp.EncryptedPrefs
import gratis.anon.pgp.KeyValuePrefs
import gratis.anon.pgp.KeyVault
import gratis.anon.pgp.MasterKey
import gratis.anon.pgp.PropertiesPrefs
import gratis.anon.pgp.Session
import org.bouncycastle.openpgp.PGPSecretKeyRing

/**
 * Process-wide state for the desktop app. One instance is created in
 * [main] and passed into the composable tree.
 *
 * Mutations to the observable lists ([keys] / [contacts]) drive Compose
 * recomposition; mutations to the underlying disk happen via [vault] / [roster].
 * Call [refreshKeys] / [refreshContacts] after any disk write to keep the
 * observables in sync.
 */
class AppState(val master: MasterKey? = null) {

    private val prefs: KeyValuePrefs = if (master == null) {
        PropertiesPrefs(Paths.prefsFile)
    } else {
        EncryptedPrefs(Paths.encPrefsFile, master)
    }

    val vault: KeyVault = KeyVault(Paths.dataDir, prefs, master)
    val roster: ContactRoster = ContactRoster(Paths.dataDir, master)

    /** Whether the vault directory is set up for at-rest encryption. */
    val isEncryptedVault: Boolean get() = master != null

    /**
     * Set by [AppRoot] in Main.kt — call to nuke this AppState and rebuild it
     * (e.g. after enabling/disabling encryption, since the vault layout
     * changes on disk and the in-memory state needs to follow).
     */
    var onReloadRequested: () -> Unit = {}

    /** Observable mirror of [vault]; refreshed via [refreshKeys]. */
    val keys = mutableStateListOf<KeyVault.Entry>()

    /** Observable mirror of [roster]; refreshed via [refreshContacts]. */
    val contacts = mutableStateListOf<ContactRoster.Contact>()

    /** Footer status line — shown at the bottom of every screen. */
    var status: String by mutableStateOf("ready")

    /** Currently-selected nav rail destination. */
    var currentScreen: Screen by mutableStateOf(Screen.Identity)

    init {
        refreshKeys()
        refreshContacts()
        Session.activeRing = vault.getActive()?.ring
    }

    fun refreshKeys() {
        keys.clear()
        keys.addAll(vault.list())
    }

    fun refreshContacts() {
        contacts.clear()
        contacts.addAll(roster.list())
    }

    fun activeRing(): PGPSecretKeyRing? = Session.activeRing

    /** Update the bottom status line. Renamed away from `setStatus` to avoid
     *  clashing with the auto-generated JVM setter for [status]. */
    fun say(msg: String) {
        status = if (msg.startsWith(">") || msg.startsWith("ERROR")) msg else "> $msg"
    }
}

enum class Screen(val title: String) {
    Identity("Identity"),
    Contacts("Contacts"),
    Encrypt("Encrypt"),
    Decrypt("Decrypt"),
    SignVerify("Sign / Verify"),
    Settings("Settings"),
}
