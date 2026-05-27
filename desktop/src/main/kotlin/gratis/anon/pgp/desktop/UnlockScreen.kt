package gratis.anon.pgp.desktop

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import gratis.anon.pgp.MasterKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Centered passphrase prompt shown at startup when the vault is encrypted at
 * rest. PBKDF2 is intentionally slow (600k iters) so the unlock happens off
 * the UI thread; the button shows a working indicator while we wait.
 *
 * Calls [onUnlocked] with the live [MasterKey] on success — callers should
 * pass that key into [AppState] to construct an unlocked-mode vault.
 */
@Composable
fun UnlockScreen(onUnlocked: (MasterKey) -> Unit) {
    var passphrase by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var working by remember { mutableStateOf(false) }
    val focus = remember { FocusRequester() }
    val scope = rememberCoroutineScope()

    LaunchedEffect(Unit) { focus.requestFocus() }

    fun attempt() {
        if (passphrase.isEmpty() || working) return
        working = true
        error = null
        val attempt = passphrase
        scope.launch {
            try {
                val key = withContext(Dispatchers.Default) {
                    MasterKey.unlock(Paths.dataDir, attempt.toCharArray())
                        ?: throw IllegalStateException("vault is not encrypted")
                }
                onUnlocked(key)
            } catch (t: Throwable) {
                error = "wrong passphrase"
                working = false
                passphrase = ""
            }
        }
    }

    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Card(
            elevation = CardDefaults.cardElevation(4.dp),
            modifier = Modifier.width(420.dp).padding(24.dp),
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Image(
                    painter = painterResource("anon-pgp.png"),
                    contentDescription = "Anon PGP",
                    modifier = Modifier.size(96.dp),
                )
                Text("Anon PGP — vault locked", style = MaterialTheme.typography.titleLarge)
                Text(
                    "This vault is encrypted at rest. Enter the master passphrase to unlock " +
                        "your keys and contacts.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it; error = null },
                    label = { Text("Master passphrase") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                    keyboardActions = KeyboardActions(onDone = { attempt() }),
                    isError = error != null,
                    supportingText = { error?.let { Text(it, color = MaterialTheme.colorScheme.error) } },
                    enabled = !working,
                    modifier = Modifier.focusRequester(focus),
                )
                Button(
                    enabled = passphrase.isNotEmpty() && !working,
                    onClick = ::attempt,
                ) {
                    Text(if (working) "Unlocking…" else "Unlock")
                }
            }
        }
    }
}
