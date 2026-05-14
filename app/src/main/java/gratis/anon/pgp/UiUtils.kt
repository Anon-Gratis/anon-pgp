package gratis.anon.pgp

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Color
import android.text.InputType
import android.view.WindowManager
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AlertDialog

object UiUtils {

    fun toast(context: Context, msg: String) {
        Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
    }

    fun copyToClipboard(context: Context, label: String, text: String) {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText(label, text))
    }

    /**
     * EditText for use inside AlertDialogs. The dialog body comes from the
     * Material3 dialog theme, which on many devices renders an input with a
     * light/white background — black text on it keeps it readable regardless
     * of which device theme the dialog ends up using.
     */
    fun dialogEditText(
        context: Context,
        hint: String,
        inputType: Int = InputType.TYPE_CLASS_TEXT,
        initial: String? = null
    ): EditText = EditText(context).apply {
        this.inputType = inputType
        this.hint = hint
        setTextColor(Color.BLACK)
        setHintTextColor(Color.DKGRAY)
        if (!initial.isNullOrEmpty()) setText(initial)
    }

    fun pasteFromClipboard(context: Context): String? {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = cm.primaryClip ?: return null
        if (clip.itemCount == 0) return null
        return clip.getItemAt(0).coerceToText(context)?.toString()
    }

    /**
     * Prompt for the passphrase that unlocks key {@code fingerprint}, caching
     * the result in Session per-fingerprint so the user is only prompted once
     * per process per key. {@code force} clears the cache for that fingerprint.
     */
    fun ensurePassphrase(
        context: Context,
        fingerprint: String,
        force: Boolean = false,
        title: String = "Unlock key",
        onResult: (CharArray) -> Unit
    ) {
        if (!force) Session.passphraseFor(fingerprint)?.let { onResult(it); return }

        val pwField = dialogEditText(
            context,
            hint = "Key passphrase",
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        )
        val dialog = AlertDialog.Builder(context)
            .setTitle(title)
            .setMessage(fingerprint.chunked(4).joinToString(" "))
            .setView(pwField)
            .setNegativeButton("CANCEL", null)
            .setPositiveButton("UNLOCK") { _, _ ->
                val pass = pwField.text.toString().toCharArray()
                Session.setPassphrase(fingerprint, pass)
                onResult(pass)
            }
            .create()
        dialog.window?.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        dialog.show()
    }
}
