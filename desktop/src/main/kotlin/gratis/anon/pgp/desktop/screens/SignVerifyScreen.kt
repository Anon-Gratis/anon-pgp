package gratis.anon.pgp.desktop.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import gratis.anon.pgp.PgpHelper
import gratis.anon.pgp.Session
import gratis.anon.pgp.desktop.AppState
import gratis.anon.pgp.desktop.PassphraseDialog
import gratis.anon.pgp.desktop.copyToClipboard

private enum class Mode { Sign, Verify }

@Composable
fun SignVerifyScreen(state: AppState) {
    var mode by remember { mutableStateOf(Mode.Sign) }
    var message by remember { mutableStateOf("") }
    var signature by remember { mutableStateOf("") }
    var promptPass by remember { mutableStateOf(false) }

    Column(modifier = Modifier.fillMaxSize()) {
        Text("Sign / Verify", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(12.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            RadioButton(selected = mode == Mode.Sign, onClick = { mode = Mode.Sign })
            Text("Sign")
            Spacer(Modifier.width(16.dp))
            RadioButton(selected = mode == Mode.Verify, onClick = { mode = Mode.Verify })
            Text("Verify (against roster)")
        }
        Spacer(Modifier.height(8.dp))

        OutlinedTextField(
            value = message,
            onValueChange = { message = it },
            label = { Text("Message") },
            modifier = Modifier.fillMaxWidth().height(220.dp),
        )
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = signature,
            onValueChange = { signature = it },
            label = { Text("Detached signature (armored)") },
            modifier = Modifier.fillMaxWidth().height(220.dp),
            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
        )
        Spacer(Modifier.height(8.dp))

        Row {
            when (mode) {
                Mode.Sign -> Button(
                    enabled = message.isNotEmpty() && state.activeRing() != null,
                    onClick = { promptPass = true },
                ) { Text("Sign") }
                Mode.Verify -> Button(
                    enabled = message.isNotEmpty() && signature.isNotEmpty(),
                    onClick = {
                        val rings = state.contacts.map { it.ring }
                        val result = PgpHelper.verifyDetachedAgainstAny(
                            message.toByteArray(), signature.toByteArray(), rings
                        )
                        if (result == null) {
                            state.say("ERROR: signature does not verify against any contact")
                        } else {
                            val name = state.contacts.first { it.ring === result.ring }.displayName
                            state.say("> verified signature by $name")
                        }
                    },
                ) { Text("Verify") }
            }
            Spacer(Modifier.width(8.dp))
            OutlinedButton(
                enabled = signature.isNotEmpty(),
                onClick = {
                    copyToClipboard(signature)
                    state.say("copied signature to clipboard")
                }
            ) { Text("Copy signature") }
        }
    }

    if (promptPass && mode == Mode.Sign) {
        val ring = state.activeRing()!!
        val fp = PgpHelper.fingerprintCompact(ring.publicKey)
        val cached = Session.passphraseFor(fp)
        if (cached != null) {
            doSign(state, ring, message, cached) { signature = it }
            promptPass = false
        } else {
            PassphraseDialog(
                title = "Unlock key to sign",
                onDismiss = { promptPass = false },
                onConfirm = { pass ->
                    try {
                        doSign(state, ring, message, pass) { signature = it }
                        Session.setPassphrase(fp, pass)
                    } catch (t: Throwable) {
                        state.say("ERROR: ${t.message}")
                    }
                    promptPass = false
                },
            )
        }
    }
}

private fun doSign(
    state: AppState,
    ring: org.bouncycastle.openpgp.PGPSecretKeyRing,
    message: String,
    pass: CharArray,
    setSig: (String) -> Unit,
) {
    try {
        val sig = PgpHelper.signDetached(message.toByteArray(), ring, pass)
        setSig(String(sig, Charsets.UTF_8))
        state.say("signed ${message.length} bytes")
    } catch (t: Throwable) {
        state.say("ERROR: ${t.message}")
    }
}
