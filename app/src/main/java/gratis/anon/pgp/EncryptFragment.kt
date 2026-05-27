package gratis.anon.pgp

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.RadioGroup
import android.widget.TextView
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class EncryptFragment : Fragment() {

    private var selectedContact: ContactRoster.Contact? = null
    private var pickedFileUri: Uri? = null
    private var pickedFileName: String? = null
    private var pickedFileSize: Long = -1L

    private lateinit var recipientPicker: TextView
    private lateinit var recipientPanel: LinearLayout
    private lateinit var encryptionTypeGroup: RadioGroup
    private lateinit var modeGroup: RadioGroup
    private lateinit var textPanel: LinearLayout
    private lateinit var filePanel: LinearLayout
    private lateinit var plaintextIn: EditText
    private lateinit var ciphertextOut: EditText
    private lateinit var btnCopyCipher: Button
    private lateinit var pickedFile: TextView
    private lateinit var btnEncryptFile: Button

    private val scope = CoroutineScope(Dispatchers.Main)

    private lateinit var pickInputLauncher: ActivityResultLauncher<Intent>
    private lateinit var saveOutputLauncher: ActivityResultLauncher<Intent>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        pickInputLauncher = registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { res ->
            if (res.resultCode != Activity.RESULT_OK) return@registerForActivityResult
            res.data?.data?.let { onInputPicked(it) }
        }
        saveOutputLauncher = registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { res ->
            if (res.resultCode != Activity.RESULT_OK) return@registerForActivityResult
            res.data?.data?.let { doFileEncrypt(it) }
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, saved: Bundle?
    ): View = inflater.inflate(R.layout.fragment_encrypt, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        recipientPicker = view.findViewById(R.id.recipientPicker)
        recipientPanel = view.findViewById(R.id.recipientPanel)
        encryptionTypeGroup = view.findViewById(R.id.encryptionTypeGroup)
        modeGroup = view.findViewById(R.id.modeGroup)
        textPanel = view.findViewById(R.id.textPanel)
        filePanel = view.findViewById(R.id.filePanel)
        plaintextIn = view.findViewById(R.id.plaintextIn)
        ciphertextOut = view.findViewById(R.id.ciphertextOut)
        btnCopyCipher = view.findViewById(R.id.btnCopyCipher)
        pickedFile = view.findViewById(R.id.pickedFile)
        btnEncryptFile = view.findViewById(R.id.btnEncryptFile)

        recipientPicker.setOnClickListener { showRecipientPicker() }
        encryptionTypeGroup.setOnCheckedChangeListener { _, id ->
            // Hide the recipient picker when the user opts for a symmetric
            // passphrase — there's no recipient in that flow.
            recipientPanel.visibility = if (id == R.id.typeSymmetric) View.GONE else View.VISIBLE
        }
        modeGroup.setOnCheckedChangeListener { _, id ->
            val isText = id == R.id.modeText
            textPanel.visibility = if (isText) View.VISIBLE else View.GONE
            filePanel.visibility = if (isText) View.GONE else View.VISIBLE
        }

        view.findViewById<Button>(R.id.btnEncryptText).setOnClickListener { onEncryptText() }
        btnCopyCipher.setOnClickListener {
            val txt = ciphertextOut.text.toString()
            if (txt.isEmpty()) return@setOnClickListener
            UiUtils.copyToClipboard(requireContext(), "ciphertext", txt)
            UiUtils.toast(requireContext(), "ciphertext copied")
        }
        view.findViewById<Button>(R.id.btnPickFile).setOnClickListener {
            val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "*/*"
            }
            pickInputLauncher.launch(intent)
        }
        btnEncryptFile.setOnClickListener { onSaveAndEncrypt() }
    }

    private fun showRecipientPicker() {
        val contacts = (requireActivity() as MainActivity).roster.list()
        if (contacts.isEmpty()) {
            UiUtils.toast(requireContext(), "no contacts — go to CONTACTS tab to import one")
            return
        }
        val labels = contacts.map { "${it.displayName}\n${it.prettyFingerprint}" }.toTypedArray()
        AlertDialog.Builder(requireContext())
            .setTitle("Pick recipient")
            .setItems(labels) { _, which ->
                selectedContact = contacts[which]
                recipientPicker.text = contacts[which].displayName
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    private fun onEncryptText() {
        val plain = plaintextIn.text.toString()
        if (plain.isEmpty()) return UiUtils.toast(requireContext(), "nothing to encrypt")
        if (encryptionTypeGroup.checkedRadioButtonId == R.id.typeSymmetric) {
            promptForSymmetricPassphraseAndEncrypt(plain)
        } else {
            val contact = selectedContact ?: return UiUtils.toast(requireContext(), "pick a recipient first")
            encryptToContact(plain, contact)
        }
    }

    private fun encryptToContact(plain: String, contact: ContactRoster.Contact) {
        status("encrypting…")
        scope.launch {
            try {
                val ct = withContext(Dispatchers.Default) {
                    PgpHelper.encryptToRecipient(plain.toByteArray(), contact.ring)
                }
                ciphertextOut.setText(String(ct))
                status("> encrypted ${plain.length} chars → ${ct.size} bytes armored")
            } catch (t: Throwable) {
                status("ENCRYPT FAILED: ${t.message}")
            }
        }
    }

    private fun promptForSymmetricPassphraseAndEncrypt(plain: String) {
        val pwField = UiUtils.dialogEditText(
            requireContext(),
            hint = "Passphrase (8+ chars)",
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD,
        )
        AlertDialog.Builder(requireContext())
            .setTitle("Symmetric encryption passphrase")
            .setMessage("Anyone with this passphrase can decrypt. No key is used.")
            .setView(pwField)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton("ENCRYPT") { _, _ ->
                val pass = pwField.text.toString()
                if (pass.length < 8) {
                    UiUtils.toast(requireContext(), "passphrase must be at least 8 chars")
                    return@setPositiveButton
                }
                status("encrypting (symmetric)…")
                scope.launch {
                    try {
                        val ct = withContext(Dispatchers.Default) {
                            PgpHelper.encryptSymmetric(plain.toByteArray(), pass.toCharArray())
                        }
                        ciphertextOut.setText(String(ct))
                        status("> encrypted ${plain.length} chars → ${ct.size} bytes (symmetric)")
                    } catch (t: Throwable) {
                        status("ENCRYPT FAILED: ${t.message}")
                    }
                }
            }
            .show()
    }

    private fun onInputPicked(uri: Uri) {
        pickedFileUri = uri
        val (name, size) = queryFileMeta(uri)
        pickedFileName = name
        pickedFileSize = size
        pickedFile.text = "$name  (${humanSize(size)})"
        btnEncryptFile.isEnabled = true
    }

    private fun onSaveAndEncrypt() {
        if (selectedContact == null) return UiUtils.toast(requireContext(), "pick a recipient first")
        if (pickedFileUri == null) return UiUtils.toast(requireContext(), "pick a file first")
        val suggested = (pickedFileName ?: "file") + ".asc"
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/pgp-encrypted"
            putExtra(Intent.EXTRA_TITLE, suggested)
        }
        saveOutputLauncher.launch(intent)
    }

    private fun doFileEncrypt(outputUri: Uri) {
        val contact = selectedContact ?: return
        val inputUri = pickedFileUri ?: return
        val ctx = requireContext()
        status("encrypting file…")
        btnEncryptFile.isEnabled = false
        scope.launch {
            try {
                withContext(Dispatchers.Default) {
                    ctx.contentResolver.openInputStream(inputUri)!!.use { inp ->
                        ctx.contentResolver.openOutputStream(outputUri)!!.use { out ->
                            PgpHelper.encryptStreamToRecipient(
                                inp,
                                pickedFileSize,
                                pickedFileName ?: "data",
                                contact.ring,
                                out
                            )
                        }
                    }
                }
                status("> encrypted ${pickedFileName} → saved")
            } catch (t: Throwable) {
                status("ENCRYPT FAILED: ${t.message}")
            } finally {
                btnEncryptFile.isEnabled = true
            }
        }
    }

    private fun queryFileMeta(uri: Uri): Pair<String, Long> {
        var name = "file"
        var size = -1L
        requireContext().contentResolver.query(uri, null, null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                val nameIdx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                val sizeIdx = c.getColumnIndex(OpenableColumns.SIZE)
                if (nameIdx >= 0) name = c.getString(nameIdx) ?: name
                if (sizeIdx >= 0) size = c.getLong(sizeIdx)
            }
        }
        return name to size
    }

    private fun humanSize(bytes: Long): String {
        if (bytes < 0) return "?"
        if (bytes < 1024) return "${bytes}B"
        if (bytes < 1024 * 1024) return "${bytes / 1024}K"
        return "${bytes / (1024 * 1024)}M"
    }

    private fun status(msg: String) = (requireActivity() as MainActivity).setStatus(msg)
}
