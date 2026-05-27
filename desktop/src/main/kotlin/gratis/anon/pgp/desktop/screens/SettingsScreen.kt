package gratis.anon.pgp.desktop.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import gratis.anon.pgp.MasterKey
import gratis.anon.pgp.PropertiesPrefs
import gratis.anon.pgp.Session
import gratis.anon.pgp.EncryptedPrefs
import gratis.anon.pgp.desktop.AppState
import gratis.anon.pgp.desktop.Paths
import gratis.anon.pgp.desktop.smartcard.SmartCardOpenPgp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun SettingsScreen(state: AppState) {
    var confirmWipe by remember { mutableStateOf(false) }
    var showEnableEnc by remember { mutableStateOf(false) }
    var showDisableEnc by remember { mutableStateOf(false) }

    Column(modifier = Modifier.fillMaxSize()) {
        Text("Settings", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(16.dp))

        Text("Anon PGP — Linux desktop", style = MaterialTheme.typography.titleMedium)
        Text("Version 0.3.6", style = MaterialTheme.typography.bodyMedium)
        Spacer(Modifier.height(8.dp))
        Text(
            "Local-only OpenPGP suite with quantum-safe key generation. Keys are " +
                "stored under:",
            style = MaterialTheme.typography.bodyMedium,
        )
        Text(
            Paths.dataDir.absolutePath,
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodySmall,
        )
        Spacer(Modifier.height(24.dp))

        // ─── Vault encryption ─────────────────────────────────────────
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Vault encryption at rest", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.width(8.dp))
            AssistChip(
                onClick = {},
                label = { Text(if (state.isEncryptedVault) "ENABLED" else "OFF") },
            )
        }
        Spacer(Modifier.height(4.dp))
        Text(
            if (state.isEncryptedVault)
                "Your keys and contacts are AES-256-GCM encrypted on disk. Filenames are HMAC-obfuscated so disk inspection doesn't reveal fingerprints or contact identities."
            else
                "Keys + contacts are stored plaintext on disk (still passphrase-protected at the OpenPGP layer). Enable to wrap the whole vault under a single master passphrase.",
            style = MaterialTheme.typography.bodySmall,
        )
        Spacer(Modifier.height(8.dp))
        if (state.isEncryptedVault) {
            OutlinedButton(onClick = { showDisableEnc = true }) {
                Text("Disable vault encryption")
            }
        } else {
            OutlinedButton(onClick = { showEnableEnc = true }) {
                Text("Enable vault encryption…")
            }
        }
        Spacer(Modifier.height(24.dp))

        SmartcardSection(state)
        Spacer(Modifier.height(24.dp))

        Text("Danger zone", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(8.dp))
        Button(
            onClick = { confirmWipe = true },
            colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
        ) { Text("Wipe vault") }
    }

    if (confirmWipe) WipeConfirmDialog(state, onDismiss = { confirmWipe = false })
    if (showEnableEnc) EnableEncryptionDialog(state, onDismiss = { showEnableEnc = false })
    if (showDisableEnc) DisableEncryptionDialog(state, onDismiss = { showDisableEnc = false })
}

/**
 * Smartcard detection panel — Phase 4d MVP. Lists PCSC readers and, on
 * demand, attempts to open the OpenPGP applet and read the cardholder /
 * fingerprint info. Read-only: nothing is written to the card. Full
 * card-backed signing isn't wired into the Identity flow yet.
 */
@Composable
private fun SmartcardSection(state: AppState) {
    var readers by remember { mutableStateOf<List<String>>(emptyList()) }
    var identity by remember { mutableStateOf<SmartCardOpenPgp.Identity?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var working by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Text("Hardware smartcards (experimental)", style = MaterialTheme.typography.titleMedium)
    Spacer(Modifier.height(4.dp))
    Text(
        "Detection-only MVP. Lists PCSC readers and reads the OpenPGP applet's " +
            "public metadata if a YubiKey / Nitrokey / Gnuk is plugged in. Sign + " +
            "decrypt routing through the card is a follow-up.",
        style = MaterialTheme.typography.bodySmall,
    )
    Spacer(Modifier.height(8.dp))
    Row(verticalAlignment = Alignment.CenterVertically) {
        OutlinedButton(
            enabled = !working,
            onClick = {
                working = true
                error = null
                identity = null
                scope.launch {
                    try {
                        val (rs, id) = withContext(Dispatchers.Default) {
                            val rs = SmartCardOpenPgp.listReaders()
                            val id = SmartCardOpenPgp.openFirst()?.use { it.readIdentity() }
                            rs to id
                        }
                        readers = rs
                        identity = id
                        state.say(
                            when {
                                id != null -> "> detected OpenPGP card (${id.cardholderName ?: "unnamed"})"
                                rs.isEmpty() -> "no readers found — is pcscd running?"
                                else -> "no OpenPGP card in any reader"
                            }
                        )
                    } catch (t: Throwable) {
                        error = t.message
                        state.say("ERROR: ${t.message}")
                    } finally {
                        working = false
                    }
                }
            },
        ) { Text(if (working) "Detecting…" else "Detect card") }
    }
    if (readers.isNotEmpty()) {
        Spacer(Modifier.height(8.dp))
        Text("Readers:", style = MaterialTheme.typography.bodySmall)
        for (r in readers) {
            Text("  · $r", fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
        }
    }
    val id = identity
    if (id != null) {
        Spacer(Modifier.height(8.dp))
        Text("Detected card:", style = MaterialTheme.typography.bodySmall)
        Text(
            "  cardholder    ${id.cardholderName ?: "(unnamed)"}",
            fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall,
        )
        Text(
            "  AID           ${id.aidHex}",
            fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall,
        )
        Text(
            "  sign fp       ${id.signingFingerprint ?: "(slot empty)"}",
            fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall,
        )
        Text(
            "  encrypt fp    ${id.encryptionFingerprint ?: "(slot empty)"}",
            fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall,
        )
        Text(
            "  auth fp       ${id.authFingerprint ?: "(slot empty)"}",
            fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall,
        )
    }
    error?.let {
        Spacer(Modifier.height(8.dp))
        Text("Error: $it", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun WipeConfirmDialog(state: AppState, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Wipe vault?") },
        text = { Text("This deletes every secret key, contact, and PQC sidecar. There is no undo. Export anything you want to keep first.") },
        confirmButton = {
            Button(
                onClick = {
                    state.vault.wipe()
                    state.roster.wipe()
                    Session.reset()
                    state.refreshKeys()
                    state.refreshContacts()
                    state.say("> vault wiped")
                    onDismiss()
                },
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
            ) { Text("Wipe everything") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun EnableEncryptionDialog(state: AppState, onDismiss: () -> Unit) {
    var pass1 by remember { mutableStateOf("") }
    var pass2 by remember { mutableStateOf("") }
    var working by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val matches = pass1.isNotEmpty() && pass1 == pass2
    val tooShort = pass1.isNotEmpty() && pass1.length < 12

    AlertDialog(
        onDismissRequest = { if (!working) onDismiss() },
        title = { Text("Enable vault encryption") },
        text = {
            Column {
                Text(
                    "Set a master passphrase. The app will prompt for it on every launch " +
                        "to unlock the vault. Forget it and your keys are unrecoverable — " +
                        "export anything important first."
                )
                OutlinedTextField(
                    value = pass1,
                    onValueChange = { pass1 = it },
                    label = { Text("Master passphrase (12+ chars)") },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    isError = tooShort,
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                )
                OutlinedTextField(
                    value = pass2,
                    onValueChange = { pass2 = it },
                    label = { Text("Confirm") },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    isError = pass2.isNotEmpty() && !matches,
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                )
            }
        },
        confirmButton = {
            Button(
                enabled = matches && !tooShort && !working,
                onClick = {
                    working = true
                    val pass = pass1
                    scope.launch {
                        try {
                            withContext(Dispatchers.Default) {
                                // 1. Set up at-rest encryption — writes .salt + .verify.
                                val master = MasterKey.create(Paths.dataDir, pass.toCharArray())
                                // 2. Encrypt every existing file under keys/ + contacts/.
                                MasterKey.migrateToEncrypted(Paths.dataDir, master)
                                // 3. Move plaintext prefs into the encrypted prefs file,
                                //    then securely delete the plaintext one.
                                val plain = Paths.prefsFile
                                if (plain.exists()) {
                                    val src = PropertiesPrefs(plain)
                                    val dst = EncryptedPrefs(Paths.encPrefsFile, master)
                                    src.getString("active_fingerprint")?.let {
                                        dst.putString("active_fingerprint", it)
                                    }
                                    plain.writeBytes(ByteArray(plain.length().toInt()))
                                    plain.delete()
                                }
                                master.clear()
                            }
                            // Trigger a reload from disk — the next AppState will
                            // see the .salt and prompt for the passphrase.
                            Session.reset()
                            state.say("> vault encryption enabled — relock on next launch")
                            onDismiss()
                            state.onReloadRequested()
                        } catch (t: Throwable) {
                            state.say("ERROR: ${t.message}")
                            working = false
                        }
                    }
                },
            ) { Text(if (working) "Working…" else "Enable") }
        },
        dismissButton = { TextButton(enabled = !working, onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun DisableEncryptionDialog(state: AppState, onDismiss: () -> Unit) {
    var pass by remember { mutableStateOf("") }
    var working by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    AlertDialog(
        onDismissRequest = { if (!working) onDismiss() },
        title = { Text("Disable vault encryption?") },
        text = {
            Column {
                Text(
                    "This decrypts every file back to plaintext on disk. Your keys will still be " +
                        "OpenPGP-passphrase-protected, but fingerprints and contact identities " +
                        "will be readable to anyone with disk access. Continue only if you trust " +
                        "your disk's other protections."
                )
                OutlinedTextField(
                    value = pass,
                    onValueChange = { pass = it },
                    label = { Text("Master passphrase") },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                )
            }
        },
        confirmButton = {
            Button(
                enabled = pass.isNotEmpty() && !working,
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
                onClick = {
                    working = true
                    val attempt = pass
                    scope.launch {
                        try {
                            withContext(Dispatchers.Default) {
                                val master = MasterKey.unlock(Paths.dataDir, attempt.toCharArray())
                                    ?: throw IllegalStateException("vault is not encrypted")
                                // Reverse-migrate every file back to plaintext name + content.
                                MasterKey.migrateToPlaintext(Paths.dataDir, master)
                                // Move active-fingerprint pointer back to plaintext prefs.
                                if (Paths.encPrefsFile.exists()) {
                                    val src = EncryptedPrefs(Paths.encPrefsFile, master)
                                    val dst = PropertiesPrefs(Paths.prefsFile)
                                    src.getString("active_fingerprint")?.let {
                                        dst.putString("active_fingerprint", it)
                                    }
                                    val enc = Paths.encPrefsFile
                                    enc.writeBytes(ByteArray(enc.length().toInt()))
                                    enc.delete()
                                }
                                // Drop .salt + .verify last so a crash mid-migration
                                // still leaves a re-unlockable vault.
                                MasterKey.teardown(Paths.dataDir)
                                master.clear()
                            }
                            Session.reset()
                            state.say("> vault encryption disabled")
                            onDismiss()
                            state.onReloadRequested()
                        } catch (t: Throwable) {
                            state.say("ERROR: ${t.message}")
                            working = false
                        }
                    }
                },
            ) { Text(if (working) "Working…" else "Disable") }
        },
        dismissButton = { TextButton(enabled = !working, onClick = onDismiss) { Text("Cancel") } },
    )
}
