package gratis.anon.pgp.desktop.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import gratis.anon.pgp.KeyVault
import gratis.anon.pgp.PgpHelper
import gratis.anon.pgp.Session
import gratis.anon.pgp.desktop.AppState
import gratis.anon.pgp.desktop.PassphraseDialog
import gratis.anon.pgp.desktop.copyToClipboard
import gratis.anon.pgp.desktop.pickFileToOpen
import gratis.anon.pgp.desktop.pickFileToSave
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun IdentityScreen(state: AppState) {
    val scope = rememberCoroutineScope()
    var showGenerateWizard by remember { mutableStateOf(false) }

    Column(modifier = Modifier.fillMaxSize()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Identities", style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.width(16.dp))
            Button(onClick = { showGenerateWizard = true }) { Text("Generate") }
            Spacer(Modifier.width(8.dp))
            OutlinedButton(onClick = {
                val f = pickFileToOpen("Import secret key (.asc)") ?: return@OutlinedButton
                try {
                    val entry = state.vault.add(f.readBytes())
                    state.refreshKeys()
                    state.say("imported ${entry.displayName} (${entry.prettyFingerprint})")
                } catch (t: Throwable) {
                    state.say("ERROR: ${t.message}")
                }
            }) { Text("Import secret key") }
        }
        Spacer(Modifier.height(12.dp))
        if (state.keys.isEmpty()) {
            EmptyHint("No keys yet. Click Generate to create your first quantum-safe keypair.")
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(state.keys) { entry ->
                    KeyRow(state, entry, scope)
                }
            }
        }
    }

    if (showGenerateWizard) {
        GenerateWizard(
            state = state,
            onDismiss = { showGenerateWizard = false },
        )
    }
}

@Composable
private fun KeyRow(state: AppState, entry: KeyVault.Entry, scope: kotlinx.coroutines.CoroutineScope) {
    val isActive = state.activeRing()?.publicKey?.let { PgpHelper.fingerprintCompact(it) } == entry.fingerprint
    val isRevoked = PgpHelper.isRevoked(entry.ring)
    val expiry = PgpHelper.primaryExpiry(entry.ring)
    var pendingAction by remember(entry.fingerprint) { mutableStateOf<MaintenanceAction?>(null) }

    Card(elevation = CardDefaults.cardElevation(2.dp), modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(entry.displayName, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.width(8.dp))
                if (isActive) AssistChip(onClick = {}, label = { Text("active") })
                if (entry.hasPqc) {
                    Spacer(Modifier.width(8.dp))
                    AssistChip(onClick = {}, label = { Text("PQC") })
                }
                if (isRevoked) {
                    Spacer(Modifier.width(8.dp))
                    AssistChip(onClick = {}, label = { Text("revoked") })
                }
            }
            Text(
                entry.prettyFingerprint,
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodySmall,
            )
            if (expiry != null) {
                Text(
                    "expires: ${java.time.format.DateTimeFormatter.ISO_LOCAL_DATE.format(expiry.atZone(java.time.ZoneId.systemDefault()))}",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            Spacer(Modifier.height(8.dp))
            // First row: identity actions.
            Row {
                if (!isActive) {
                    OutlinedButton(onClick = {
                        state.vault.setActiveFingerprint(entry.fingerprint)
                        Session.activeRing = entry.ring
                        state.refreshKeys()
                        state.say("active: ${entry.displayName}")
                    }) { Text("Make active") }
                    Spacer(Modifier.width(8.dp))
                }
                OutlinedButton(onClick = {
                    val armored = PgpHelper.exportPublicKey(entry.ring)
                    copyToClipboard(String(armored, Charsets.UTF_8))
                    state.say("copied public key to clipboard")
                }) { Text("Copy public key") }
                Spacer(Modifier.width(8.dp))
                OutlinedButton(onClick = {
                    val f = pickFileToSave("Export public key", "${entry.fingerprint}.pub.asc") ?: return@OutlinedButton
                    f.writeBytes(PgpHelper.exportPublicKey(entry.ring))
                    state.say("exported public key to ${f.name}")
                }) { Text("Export public") }
                Spacer(Modifier.width(8.dp))
                OutlinedButton(onClick = {
                    val f = pickFileToSave("Export secret key", "${entry.fingerprint}.sec.asc") ?: return@OutlinedButton
                    val raw = state.vault.rawBytes(entry.fingerprint) ?: return@OutlinedButton
                    f.writeBytes(raw)
                    state.say("exported secret key to ${f.name}")
                }) { Text("Export secret") }
                Spacer(Modifier.width(8.dp))
                OutlinedButton(onClick = {
                    state.vault.delete(entry.fingerprint)
                    if (state.activeRing()?.publicKey?.let { PgpHelper.fingerprintCompact(it) } == entry.fingerprint) {
                        Session.activeRing = state.vault.getActive()?.ring
                    }
                    state.refreshKeys()
                    state.say("deleted ${entry.displayName}")
                }) { Text("Delete") }
            }
            Spacer(Modifier.height(6.dp))
            // Second row: key-maintenance actions (Kleopatra parity).
            Row {
                OutlinedButton(onClick = { pendingAction = MaintenanceAction.AddSubkey }) {
                    Text("Add subkey")
                }
                Spacer(Modifier.width(8.dp))
                OutlinedButton(onClick = { pendingAction = MaintenanceAction.SetExpiry }) {
                    Text("Set expiry")
                }
                Spacer(Modifier.width(8.dp))
                OutlinedButton(onClick = { pendingAction = MaintenanceAction.RevocationCert }) {
                    Text("Revocation cert")
                }
            }
        }
    }

    when (pendingAction) {
        MaintenanceAction.AddSubkey -> AddSubkeyDialog(
            state, entry,
            onDone = { pendingAction = null },
            onDismiss = { pendingAction = null },
        )
        MaintenanceAction.SetExpiry -> SetExpiryDialog(
            state, entry,
            onDone = { pendingAction = null },
            onDismiss = { pendingAction = null },
        )
        MaintenanceAction.RevocationCert -> RevocationCertDialog(
            state, entry,
            onDone = { pendingAction = null },
            onDismiss = { pendingAction = null },
        )
        null -> Unit
    }
}

private enum class MaintenanceAction { AddSubkey, SetExpiry, RevocationCert }

@Composable
private fun AddSubkeyDialog(
    state: AppState,
    entry: KeyVault.Entry,
    onDone: () -> Unit,
    onDismiss: () -> Unit,
) {
    var passphrase by remember { mutableStateOf("") }
    var algo by remember { mutableStateOf(PgpHelper.SubkeyAlgo.X25519) }
    var working by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    AlertDialog(
        onDismissRequest = { if (!working) onDismiss() },
        title = { Text("Add encryption subkey") },
        text = {
            Column {
                Text("Adds a fresh encryption-only subkey to ${entry.displayName}. The primary stays the same; old ciphertexts can still be decrypted with the previous subkey.")
                Spacer(Modifier.height(8.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(selected = algo == PgpHelper.SubkeyAlgo.X25519, onClick = { algo = PgpHelper.SubkeyAlgo.X25519 })
                    Text("X25519 (modern)")
                    Spacer(Modifier.width(16.dp))
                    RadioButton(selected = algo == PgpHelper.SubkeyAlgo.RSA_3072, onClick = { algo = PgpHelper.SubkeyAlgo.RSA_3072 })
                    Text("RSA-3072 (legacy)")
                }
                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it },
                    label = { Text("Key passphrase") },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                )
            }
        },
        confirmButton = {
            Button(enabled = !working && passphrase.isNotEmpty(), onClick = {
                working = true
                scope.launch {
                    try {
                        val updated = withContext(Dispatchers.Default) {
                            PgpHelper.addEncryptionSubkey(entry.ring, passphrase.toCharArray(), algo)
                        }
                        // Re-add to vault (preserving any existing PQC sidecar).
                        val sidecar = state.vault.rawPqcSidecar(entry.fingerprint)
                        state.vault.add(updated, sidecar)
                        state.refreshKeys()
                        Session.activeRing = state.vault.getActive()?.ring
                        state.say("added ${algo.name} subkey to ${entry.displayName}")
                        onDone()
                    } catch (t: Throwable) {
                        state.say("ERROR: ${t.message}")
                        working = false
                    }
                }
            }) { Text(if (working) "working…" else "Add") }
        },
        dismissButton = { TextButton(enabled = !working, onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun SetExpiryDialog(
    state: AppState,
    entry: KeyVault.Entry,
    onDone: () -> Unit,
    onDismiss: () -> Unit,
) {
    var daysText by remember { mutableStateOf("365") }
    var passphrase by remember { mutableStateOf("") }
    var clearExpiry by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Set primary-key expiry") },
        text = {
            Column {
                Text("Sets when the primary key will be treated as expired by other OpenPGP clients. Existing signatures stay valid; just new operations stop.")
                Spacer(Modifier.height(8.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(selected = !clearExpiry, onClick = { clearExpiry = false })
                    Text("Expire in")
                    Spacer(Modifier.width(8.dp))
                    OutlinedTextField(
                        value = daysText,
                        onValueChange = { daysText = it.filter { ch -> ch.isDigit() }.take(5) },
                        singleLine = true,
                        modifier = Modifier.width(100.dp),
                        enabled = !clearExpiry,
                    )
                    Spacer(Modifier.width(8.dp))
                    Text("days")
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(selected = clearExpiry, onClick = { clearExpiry = true })
                    Text("Never expire")
                }
                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it },
                    label = { Text("Key passphrase") },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                )
            }
        },
        confirmButton = {
            Button(
                enabled = passphrase.isNotEmpty() && (clearExpiry || daysText.toIntOrNull() != null),
                onClick = {
                    scope.launch {
                        try {
                            val expiry = if (clearExpiry) null else
                                java.time.Instant.now().plus(daysText.toLong(), java.time.temporal.ChronoUnit.DAYS)
                            val updated = withContext(Dispatchers.Default) {
                                PgpHelper.setPrimaryExpiry(entry.ring, expiry, passphrase.toCharArray())
                            }
                            val sidecar = state.vault.rawPqcSidecar(entry.fingerprint)
                            state.vault.add(updated, sidecar)
                            state.refreshKeys()
                            Session.activeRing = state.vault.getActive()?.ring
                            state.say(
                                if (expiry == null) "cleared expiry on ${entry.displayName}"
                                else "expires in $daysText day(s)"
                            )
                            onDone()
                        } catch (t: Throwable) {
                            state.say("ERROR: ${t.message}")
                        }
                    }
                }
            ) { Text("Apply") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun RevocationCertDialog(
    state: AppState,
    entry: KeyVault.Entry,
    onDone: () -> Unit,
    onDismiss: () -> Unit,
) {
    var passphrase by remember { mutableStateOf("") }
    var reason by remember { mutableStateOf(PgpHelper.RevocationReason.NoReason) }
    var reasonMenu by remember { mutableStateOf(false) }
    var comment by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Generate revocation certificate") },
        text = {
            Column {
                Text("Saves a stand-alone signature that, when imported, marks this key as revoked. Best practice: generate one now, store it offline (paper / USB), and use it if the key is ever compromised.")
                Spacer(Modifier.height(8.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Reason:")
                    Spacer(Modifier.width(8.dp))
                    OutlinedButton(onClick = { reasonMenu = true }) { Text(reason.name) }
                    DropdownMenu(expanded = reasonMenu, onDismissRequest = { reasonMenu = false }) {
                        PgpHelper.RevocationReason.values().forEach { r ->
                            DropdownMenuItem(
                                text = { Text(r.name) },
                                onClick = { reason = r; reasonMenu = false },
                            )
                        }
                    }
                }
                OutlinedTextField(
                    value = comment,
                    onValueChange = { comment = it },
                    label = { Text("Comment (optional)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                )
                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it },
                    label = { Text("Key passphrase") },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                )
            }
        },
        confirmButton = {
            Button(enabled = passphrase.isNotEmpty(), onClick = {
                scope.launch {
                    try {
                        val cert = withContext(Dispatchers.Default) {
                            PgpHelper.generateRevocationCert(
                                entry.ring, passphrase.toCharArray(), reason, comment
                            )
                        }
                        val f = pickFileToSave(
                            "Save revocation certificate",
                            "${entry.fingerprint}.rev.asc",
                        )
                        if (f != null) {
                            f.writeBytes(cert)
                            state.say("saved revocation cert to ${f.name}")
                        } else {
                            copyToClipboard(String(cert, Charsets.UTF_8))
                            state.say("revocation cert copied to clipboard")
                        }
                        onDone()
                    } catch (t: Throwable) {
                        state.say("ERROR: ${t.message}")
                    }
                }
            }) { Text("Generate") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun GenerateWizard(state: AppState, onDismiss: () -> Unit) {
    val scope = rememberCoroutineScope()
    var step by remember { mutableStateOf(0) }   // 0=identity, 1=algo, 2=passphrase, 3=in progress
    var identity by remember { mutableStateOf("anon@anon.gratis") }
    var algo by remember { mutableStateOf(PgpHelper.KeyAlgo.HYBRID_PQC) }
    var passphrase by remember { mutableStateOf("") }
    var generating by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = { if (!generating) onDismiss() },
        title = { Text(when (step) {
            0 -> "New key — identity"
            1 -> "New key — algorithm"
            else -> "New key — passphrase"
        }) },
        text = {
            when (step) {
                0 -> Column {
                    Text("User-id baked into the public key. Free-form; convention is \"Name <email>\".")
                    OutlinedTextField(
                        value = identity,
                        onValueChange = { identity = it },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                    )
                }
                1 -> Column {
                    AlgoChoice("Quantum-safe  (Ed25519 + ML-DSA + ML-KEM)", PgpHelper.KeyAlgo.HYBRID_PQC, algo) { algo = it }
                    AlgoChoice("Classical Ed25519  (modern, fast)", PgpHelper.KeyAlgo.CLASSICAL_ED25519, algo) { algo = it }
                    AlgoChoice("Classical RSA-3072  (broadest interop)", PgpHelper.KeyAlgo.CLASSICAL_RSA, algo) { algo = it }
                }
                else -> Column {
                    Text("Your private key will be encrypted with this passphrase. Forget it and the key is unrecoverable.")
                    OutlinedTextField(
                        value = passphrase,
                        onValueChange = { passphrase = it },
                        label = { Text("Passphrase (8+ chars)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                        visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation(),
                    )
                    if (generating) {
                        Spacer(Modifier.height(8.dp))
                        Text("generating…", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        },
        confirmButton = {
            Button(
                enabled = !generating,
                onClick = {
                    when (step) {
                        0 -> step = 1
                        1 -> step = 2
                        else -> {
                            if (passphrase.length < 8) {
                                state.say("ERROR: passphrase must be at least 8 chars")
                                return@Button
                            }
                            generating = true
                            val pass = passphrase.toCharArray()
                            val id = identity
                            val a = algo
                            scope.launch {
                                try {
                                    val gen = withContext(Dispatchers.Default) {
                                        PgpHelper.generateSecretKeyRing(id, pass, a)
                                    }
                                    val entry = state.vault.add(gen)
                                    state.vault.setActiveFingerprint(entry.fingerprint)
                                    Session.activeRing = entry.ring
                                    Session.setPassphrase(entry.fingerprint, pass)
                                    state.refreshKeys()
                                    val flavor = if (entry.hasPqc) "hybrid PQC" else "classical"
                                    state.say("> generated $flavor '${entry.displayName}' (${entry.prettyFingerprint})")
                                    onDismiss()
                                } catch (t: Throwable) {
                                    state.say("ERROR: ${t.message}")
                                    generating = false
                                }
                            }
                        }
                    }
                }
            ) { Text(if (step < 2) "Next" else "Generate") }
        },
        dismissButton = {
            TextButton(enabled = !generating, onClick = onDismiss) { Text("Cancel") }
        },
    )
}

@Composable
private fun AlgoChoice(
    label: String,
    value: PgpHelper.KeyAlgo,
    current: PgpHelper.KeyAlgo,
    onPick: (PgpHelper.KeyAlgo) -> Unit,
) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        RadioButton(selected = current == value, onClick = { onPick(value) })
        Text(label)
    }
}

@Composable
internal fun EmptyHint(text: String) {
    Box(
        modifier = Modifier.fillMaxSize().padding(32.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(text, style = MaterialTheme.typography.bodyMedium)
    }
}
