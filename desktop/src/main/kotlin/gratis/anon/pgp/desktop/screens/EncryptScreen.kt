package gratis.anon.pgp.desktop.screens

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
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import gratis.anon.pgp.ContactRoster
import gratis.anon.pgp.PgpHelper
import gratis.anon.pgp.desktop.AppState
import gratis.anon.pgp.desktop.copyToClipboard

private enum class EncryptMode { ToRecipient, Symmetric }

@Composable
fun EncryptScreen(state: AppState) {
    var mode by remember { mutableStateOf(EncryptMode.ToRecipient) }
    var recipient by remember { mutableStateOf<ContactRoster.Contact?>(null) }
    var passphrase by remember { mutableStateOf("") }
    var plaintext by remember { mutableStateOf("") }
    var ciphertext by remember { mutableStateOf("") }
    var menuOpen by remember { mutableStateOf(false) }

    Column(modifier = Modifier.fillMaxSize()) {
        Text("Encrypt", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(12.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            RadioButton(selected = mode == EncryptMode.ToRecipient, onClick = { mode = EncryptMode.ToRecipient })
            Text("To recipient (asymmetric)")
            Spacer(Modifier.width(16.dp))
            RadioButton(selected = mode == EncryptMode.Symmetric, onClick = { mode = EncryptMode.Symmetric })
            Text("Passphrase only (symmetric)")
        }
        Spacer(Modifier.height(8.dp))

        when (mode) {
            EncryptMode.ToRecipient -> Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Recipient:")
                Spacer(Modifier.width(8.dp))
                Box {
                    OutlinedButton(onClick = { menuOpen = true }) {
                        Text(recipient?.displayName ?: "Pick a contact…")
                    }
                    DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                        if (state.contacts.isEmpty()) {
                            DropdownMenuItem(
                                text = { Text("(no contacts — import on the Contacts tab)") },
                                onClick = { menuOpen = false },
                            )
                        }
                        state.contacts.forEach { c ->
                            DropdownMenuItem(
                                text = { Text("${c.displayName}  ·  ${c.prettyFingerprint}") },
                                onClick = { recipient = c; menuOpen = false },
                            )
                        }
                    }
                }
            }
            EncryptMode.Symmetric -> OutlinedTextField(
                value = passphrase,
                onValueChange = { passphrase = it },
                label = { Text("Passphrase") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
            )
        }
        Spacer(Modifier.height(8.dp))

        OutlinedTextField(
            value = plaintext,
            onValueChange = { plaintext = it },
            label = { Text("Plaintext") },
            modifier = Modifier.fillMaxWidth().height(220.dp),
        )
        Spacer(Modifier.height(8.dp))

        Row {
            val canEncrypt = plaintext.isNotEmpty() && when (mode) {
                EncryptMode.ToRecipient -> recipient != null
                EncryptMode.Symmetric -> passphrase.isNotEmpty()
            }
            Button(
                enabled = canEncrypt,
                onClick = {
                    try {
                        val ct = when (mode) {
                            EncryptMode.ToRecipient ->
                                PgpHelper.encryptToRecipient(plaintext.toByteArray(), recipient!!.ring)
                            EncryptMode.Symmetric ->
                                PgpHelper.encryptSymmetric(plaintext.toByteArray(), passphrase.toCharArray())
                        }
                        ciphertext = String(ct, Charsets.UTF_8)
                        val to = when (mode) {
                            EncryptMode.ToRecipient -> recipient!!.displayName
                            EncryptMode.Symmetric -> "passphrase"
                        }
                        state.say("encrypted ${plaintext.length} bytes to $to")
                    } catch (t: Throwable) {
                        state.say("ERROR: ${t.message}")
                    }
                }
            ) { Text("Encrypt") }
            Spacer(Modifier.width(8.dp))
            OutlinedButton(
                enabled = ciphertext.isNotEmpty(),
                onClick = {
                    copyToClipboard(ciphertext)
                    state.say("copied ciphertext to clipboard")
                }
            ) { Text("Copy ciphertext") }
        }
        Spacer(Modifier.height(8.dp))

        OutlinedTextField(
            value = ciphertext,
            onValueChange = { ciphertext = it },
            label = { Text("Ciphertext (armored)") },
            modifier = Modifier.fillMaxWidth().height(260.dp),
            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
        )
    }
}
