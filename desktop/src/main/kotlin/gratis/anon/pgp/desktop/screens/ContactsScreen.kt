package gratis.anon.pgp.desktop.screens

import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import gratis.anon.pgp.desktop.AppState
import gratis.anon.pgp.desktop.pickFileToOpen

@Composable
fun ContactsScreen(state: AppState) {
    var showPaste by remember { mutableStateOf(false) }

    Column(modifier = Modifier.fillMaxSize()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Contacts", style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.width(16.dp))
            OutlinedButton(onClick = {
                val f = pickFileToOpen("Import public key (.asc)") ?: return@OutlinedButton
                try {
                    val c = state.roster.import(f.readBytes())
                    state.refreshContacts()
                    state.say("imported ${c.displayName}")
                } catch (t: Throwable) {
                    state.say("ERROR: ${t.message}")
                }
            }) { Text("Import from file") }
            Spacer(Modifier.width(8.dp))
            OutlinedButton(onClick = { showPaste = true }) { Text("Paste armored key") }
        }
        Spacer(Modifier.height(12.dp))
        if (state.contacts.isEmpty()) {
            EmptyHint("No contacts yet. Import a public .asc file or paste one to get started.")
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(state.contacts) { c ->
                    Card(elevation = CardDefaults.cardElevation(2.dp), modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Text(c.displayName, fontWeight = FontWeight.SemiBold)
                            Text(
                                c.prettyFingerprint,
                                fontFamily = FontFamily.Monospace,
                                style = MaterialTheme.typography.bodySmall,
                            )
                            Spacer(Modifier.height(8.dp))
                            OutlinedButton(onClick = {
                                state.roster.delete(c.fingerprint)
                                state.refreshContacts()
                                state.say("deleted contact ${c.displayName}")
                            }) { Text("Delete") }
                        }
                    }
                }
            }
        }
    }

    if (showPaste) {
        var pasted by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { showPaste = false },
            title = { Text("Paste armored public key") },
            text = {
                OutlinedTextField(
                    value = pasted,
                    onValueChange = { pasted = it },
                    modifier = Modifier.fillMaxWidth().height(280.dp),
                    placeholder = { Text("-----BEGIN PGP PUBLIC KEY BLOCK-----\n...") },
                )
            },
            confirmButton = {
                Button(onClick = {
                    try {
                        val c = state.roster.import(pasted.toByteArray())
                        state.refreshContacts()
                        state.say("imported ${c.displayName}")
                        showPaste = false
                    } catch (t: Throwable) {
                        state.say("ERROR: ${t.message}")
                    }
                }) { Text("Import") }
            },
            dismissButton = { TextButton(onClick = { showPaste = false }) { Text("Cancel") } },
        )
    }
}
