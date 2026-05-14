package gratis.anon.pgp

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

/**
 * Full-screen unlock gate. Shown whenever [AppLock.isLocked] is true and the
 * user has a PIN configured. Routes back to [MainActivity] on successful
 * unlock; otherwise can't be dismissed.
 *
 * Singleton task in the manifest so that re-entering the app while locked
 * doesn't spawn duplicates.
 */
class LockActivity : AppCompatActivity() {

    private lateinit var pinField: EditText
    private lateinit var unlockBtn: Button
    private lateinit var biometricBtn: Button
    private lateinit var errorText: TextView
    private lateinit var pinStore: PinStore

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // FLAG_SECURE blocks screenshots + the Recent Apps preview.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContentView(R.layout.activity_lock)

        pinStore = PinStore(applicationContext)

        pinField = findViewById(R.id.pinField)
        unlockBtn = findViewById(R.id.unlockBtn)
        biometricBtn = findViewById(R.id.biometricBtn)
        errorText = findViewById(R.id.errorText)

        unlockBtn.setOnClickListener { attemptPinUnlock() }
        pinField.setOnEditorActionListener { _, _, _ -> attemptPinUnlock(); true }

        if (pinStore.isBiometricEnabled() && BiometricHelper.isAvailable(applicationContext)) {
            biometricBtn.visibility = android.view.View.VISIBLE
            biometricBtn.setOnClickListener { promptBiometric() }
            // Auto-prompt on launch so the user doesn't have to tap.
            biometricBtn.post { promptBiometric() }
        }
    }

    override fun onBackPressed() {
        // Don't let the user dismiss the lock screen — moveTaskToBack pushes
        // the app to background instead of bypassing the unlock.
        moveTaskToBack(true)
    }

    private fun attemptPinUnlock() {
        val pin = pinField.text.toString().toCharArray()
        if (pin.isEmpty()) return
        val ok = pinStore.verifyPin(pin)
        pin.fill('0')
        pinField.text.clear()
        if (ok) {
            unlock()
        } else {
            errorText.text = "incorrect PIN"
            errorText.visibility = android.view.View.VISIBLE
        }
    }

    private fun promptBiometric() {
        BiometricHelper.prompt(
            this,
            title = "Unlock Anon PGP",
            subtitle = "Use your biometric to unlock",
            onSuccess = { unlock() },
            onFail = { _, _ ->
                // Either the user cancelled or biometric failed; leave the
                // PIN path available. Don't shout — the prompt already
                // communicated the failure.
            },
        )
    }

    private fun unlock() {
        AppLock.markUnlocked()
        // Just finish — MainActivity (already in the back stack with content
        // inflated) will resume underneath, see AppLock.isLocked()==false in
        // its onResume's gateOnLock check, and render normally.
        finish()
    }
}
