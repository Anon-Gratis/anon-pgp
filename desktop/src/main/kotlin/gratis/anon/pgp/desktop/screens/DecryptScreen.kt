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
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.derivedStateOf
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

@Composable
fun DecryptScreen(state: AppState) {
    var ciphertext by remember { mutableStateOf("") }
    var plaintext by remember { mutableStateOf("") }
    var promptPass by remember { mutableStateOf(false) }

    // Re-classify whenever the ciphertext changes so the button + prompt
    // can reflect whether this is a symmetric or asymmetric message.
    val kind by remember(ciphertext) {
        derivedStateOf {
            if (ciphertext.isBlank()) PgpHelper.CiphertextKind.Unknown
            else PgpHelper.classifyCiphertext(ciphertext.toByteArray())
        }
    }

    Column(modifier = Modifier.fillMaxSize()) {
        Text("Decrypt", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(12.dp))

        OutlinedTextField(
            value = ciphertext,
            onValueChange = { ciphertext = it },
            label = { Text("Ciphertext (armored)") },
            modifier = Modifier.fillMaxWidth().height(260.dp),
            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
        )
        Spacer(Modifier.height(8.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            val (label, canDecrypt) = when (kind) {
                PgpHelper.CiphertextKind.Symmetric  -> "Decrypt (passphrase)" to true
                PgpHelper.CiphertextKind.PublicKey  -> "Decrypt (active key)" to (state.activeRing() != null)
                PgpHelper.CiphertextKind.Mixed      -> "Decrypt (active key)" to (state.activeRing() != null)
                PgpHelper.CiphertextKind.Unknown    -> "Decrypt" to false
            }
            Button(
                enabled = ciphertext.isNotEmpty() && canDecrypt,
                onClick = { promptPass = true },
            ) { Text(label) }
            Spacer(Modifier.width(8.dp))
            OutlinedButton(
                enabled = plaintext.isNotEmpty(),
                onClick = {
                    copyToClipboard(plaintext)
                    state.say("copied plaintext to clipboard")
                }
            ) { Text("Copy plaintext") }
            Spacer(Modifier.width(12.dp))
            // Small status hint about what we detected in the ciphertext.
            val hint = when (kind) {
                PgpHelper.CiphertextKind.Symmetric -> "detected: passphrase-encrypted"
                PgpHelper.CiphertextKind.PublicKey -> "detected: encrypted to public key"
                PgpHelper.CiphertextKind.Mixed     -> "detected: hybrid (using public key)"
                PgpHelper.CiphertextKind.Unknown   ->
                    if (ciphertext.isBlank()) "" else "couldn't parse — not an OpenPGP message?"
            }
            Text(hint, style = MaterialTheme.typography.bodySmall)
        }
        Spacer(Modifier.height(8.dp))

        OutlinedTextField(
            value = plaintext,
            onValueChange = { plaintext = it },
            label = { Text("Plaintext") },
            modifier = Modifier.fillMaxWidth().height(220.dp),
        )
    }

    if (promptPass) {
        when (kind) {
            PgpHelper.CiphertextKind.Symmetric -> SymmetricPrompt(
                state, ciphertext,
                onDone = { plaintext = it; promptPass = false },
                onDismiss = { promptPass = false },
            )
            PgpHelper.CiphertextKind.PublicKey,
            PgpHelper.CiphertextKind.Mixed -> AsymmetricPrompt(
                state, ciphertext,
                onDone = { plaintext = it; promptPass = false },
                onDismiss = { promptPass = false },
            )
            PgpHelper.CiphertextKind.Unknown -> { promptPass = false }
        }
    }
}

@Composable
private fun AsymmetricPrompt(
    state: AppState,
    ciphertext: String,
    onDone: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    val ring = state.activeRing() ?: run { onDismiss(); return }
    val fp = PgpHelper.fingerprintCompact(ring.publicKey)
    val cached = Session.passphraseFor(fp)
    if (cached != null) {
        runDecryptAsymmetric(state, ring, ciphertext, cached, onDone)
        return
    }
    PassphraseDialog(
        title = "Unlock key to decrypt",
        onDismiss = onDismiss,
        onConfirm = { pass ->
            runDecryptAsymmetric(state, ring, ciphertext, pass) { result ->
                Session.setPassphrase(fp, pass)
                onDone(result)
            }
        },
    )
}

@Composable
private fun SymmetricPrompt(
    state: AppState,
    ciphertext: String,
    onDone: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    PassphraseDialog(
        title = "Decryption passphrase",
        message = "This ciphertext is encrypted with a passphrase — no key is needed.",
        onDismiss = onDismiss,
        onConfirm = { pass ->
            try {
                val pt = PgpHelper.decryptSymmetric(ciphertext.toByteArray(), pass)
                state.say("decrypted ${pt.size} bytes (symmetric)")
                onDone(String(pt, Charsets.UTF_8))
            } catch (t: Throwable) {
                state.say("ERROR: ${t.message}")
                onDismiss()
            }
        },
    )
}

private fun runDecryptAsymmetric(
    state: AppState,
    ring: org.bouncycastle.openpgp.PGPSecretKeyRing,
    ciphertext: String,
    pass: CharArray,
    onResult: (String) -> Unit,
) {
    try {
        val pt = PgpHelper.decryptFromArmored(ciphertext.toByteArray(), ring, pass)
        state.say("decrypted ${pt.size} bytes")
        onResult(String(pt, Charsets.UTF_8))
    } catch (t: Throwable) {
        state.say("ERROR: ${t.message}")
    }
}
