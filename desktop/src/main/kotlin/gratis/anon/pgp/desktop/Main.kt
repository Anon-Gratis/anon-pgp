package gratis.anon.pgp.desktop

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.People
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.Divider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import gratis.anon.pgp.desktop.screens.ContactsScreen
import gratis.anon.pgp.desktop.screens.DecryptScreen
import gratis.anon.pgp.desktop.screens.EncryptScreen
import gratis.anon.pgp.desktop.screens.IdentityScreen
import gratis.anon.pgp.desktop.screens.SettingsScreen
import gratis.anon.pgp.desktop.screens.SignVerifyScreen

// Brand palette sampled from desktop/icons/anon-pgp.png — the desaturated teal
// of the mask and binary backdrop. Replaces Material3's default purple primary
// while keeping the surface/background tones dark to match the existing look.
private val AnonPgpColors = darkColorScheme(
    primary              = Color(0xFF7FC0CF),
    onPrimary            = Color(0xFF003640),
    primaryContainer     = Color(0xFF274B53),
    onPrimaryContainer   = Color(0xFFB5E9F2),
    secondary            = Color(0xFFB0CBD0),
    onSecondary          = Color(0xFF1B343A),
    secondaryContainer   = Color(0xFF324A50),
    onSecondaryContainer = Color(0xFFCCE7EC),
    tertiary             = Color(0xFF8FB8C2),
    onTertiary           = Color(0xFF0F2A30),
)

fun main() {
    // Make X11/Wayland WM_CLASS match the .desktop filename so GNOME, KDE,
    // and other shells can pair the running window with /usr/share/applications/
    // anon-pgp-anon-pgp.desktop and show our launcher icon in the dock.
    // The field lives on sun.awt.X11.XToolkit; reflection because the JDK
    // doesn't expose it publicly. Silently skipped on non-X toolkits.
    runCatching {
        val toolkit = java.awt.Toolkit.getDefaultToolkit()
        val field = toolkit.javaClass.getDeclaredField("awtAppClassName")
        field.isAccessible = true
        field.set(toolkit, "anon-pgp")
    }
    application {
        Window(
            onCloseRequest = ::exitApplication,
            title = "Anon PGP",
            icon = painterResource("anon-pgp.png"),
            state = rememberWindowState(width = 1100.dp, height = 760.dp),
        ) {
            MaterialTheme(colorScheme = AnonPgpColors) {
                Surface(modifier = Modifier.fillMaxSize()) {
                    AppRoot()
                }
            }
        }
    }
}

/**
 * Two-phase startup. If the vault has at-rest encryption enabled we render
 * [UnlockScreen] first; otherwise [AppState] is instantiated immediately
 * with no master key. The `appKey` lets a reload nuke the AppState (used
 * when the user enables / disables encryption from Settings).
 */
@Composable
private fun AppRoot() {
    var appKey by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf(0) }
    var master by androidx.compose.runtime.remember(appKey) {
        androidx.compose.runtime.mutableStateOf<gratis.anon.pgp.MasterKey?>(null)
    }
    val isLocked = androidx.compose.runtime.remember(appKey) {
        gratis.anon.pgp.MasterKey.isLocked(Paths.dataDir)
    }

    if (isLocked && master == null) {
        UnlockScreen(onUnlocked = { master = it })
    } else {
        val state = androidx.compose.runtime.remember(master, appKey) {
            AppState(master).also { it.onReloadRequested = { appKey++ } }
        }
        AppShell(state)
    }
}

@Composable
private fun AppShell(state: AppState) {
    Column(modifier = Modifier.fillMaxSize()) {
        Row(modifier = Modifier.fillMaxWidth().padding(0.dp).run { fillMaxHeight(1f) }.weight(1f)) {
            NavRail(state)
            Divider(modifier = Modifier.fillMaxHeight().width(1.dp))
            Box(modifier = Modifier.fillMaxSize().padding(16.dp)) {
                when (state.currentScreen) {
                    Screen.Identity   -> IdentityScreen(state)
                    Screen.Contacts   -> ContactsScreen(state)
                    Screen.Encrypt    -> EncryptScreen(state)
                    Screen.Decrypt    -> DecryptScreen(state)
                    Screen.SignVerify -> SignVerifyScreen(state)
                    Screen.Settings   -> SettingsScreen(state)
                }
            }
        }
        StatusBar(state)
    }
}

@Composable
private fun NavRail(state: AppState) {
    NavigationRail(modifier = Modifier.fillMaxHeight()) {
        Image(
            painter = painterResource("anon-pgp.png"),
            contentDescription = "Anon PGP",
            modifier = Modifier.padding(vertical = 16.dp).size(40.dp),
        )
        for (screen in Screen.values()) {
            NavigationRailItem(
                selected = state.currentScreen == screen,
                onClick = { state.currentScreen = screen },
                icon = { /* set below */ iconFor(screen).let { ic -> androidx.compose.material3.Icon(ic, screen.title) } },
                label = { Text(screen.title) },
                alwaysShowLabel = true,
            )
        }
    }
}

private fun iconFor(screen: Screen): ImageVector = when (screen) {
    Screen.Identity   -> Icons.Filled.Key
    Screen.Contacts   -> Icons.Filled.People
    Screen.Encrypt    -> Icons.Filled.Lock
    Screen.Decrypt    -> Icons.Filled.LockOpen
    Screen.SignVerify -> Icons.Filled.VerifiedUser
    Screen.Settings   -> Icons.Filled.Settings
}

@Composable
private fun StatusBar(state: AppState) {
    val status by androidx.compose.runtime.rememberUpdatedState(state.status)
    Divider()
    Box(modifier = Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surfaceVariant).padding(8.dp)) {
        Text(
            text = status,
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodySmall,
        )
    }
}
