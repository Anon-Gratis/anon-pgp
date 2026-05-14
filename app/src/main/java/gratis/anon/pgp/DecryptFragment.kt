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
import androidx.fragment.app.Fragment
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class DecryptFragment : Fragment() {

    private var pickedFileUri: Uri? = null
    private var pickedFileName: String? = null

    private lateinit var modeGroup: RadioGroup
    private lateinit var textPanel: LinearLayout
    private lateinit var filePanel: LinearLayout
    private lateinit var ciphertextIn: EditText
    private lateinit var plaintextOut: EditText
    private lateinit var pickedFile: TextView
    private lateinit var btnDecryptFile: Button

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
            res.data?.data?.let { doFileDecrypt(it) }
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, saved: Bundle?
    ): View = inflater.inflate(R.layout.fragment_decrypt, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        modeGroup = view.findViewById(R.id.modeGroup)
        textPanel = view.findViewById(R.id.textPanel)
        filePanel = view.findViewById(R.id.filePanel)
        ciphertextIn = view.findViewById(R.id.ciphertextIn)
        plaintextOut = view.findViewById(R.id.plaintextOut)
        pickedFile = view.findViewById(R.id.pickedFile)
        btnDecryptFile = view.findViewById(R.id.btnDecryptFile)

        modeGroup.setOnCheckedChangeListener { _, id ->
            val isText = id == R.id.modeText
            textPanel.visibility = if (isText) View.VISIBLE else View.GONE
            filePanel.visibility = if (isText) View.GONE else View.VISIBLE
        }
        view.findViewById<Button>(R.id.btnDecryptText).setOnClickListener { onDecryptText() }
        view.findViewById<Button>(R.id.btnPickFile).setOnClickListener {
            val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "*/*"
            }
            pickInputLauncher.launch(intent)
        }
        btnDecryptFile.setOnClickListener { onSaveAndDecrypt() }
    }

    private fun onDecryptText() {
        val ring = Session.activeRing
            ?: return UiUtils.toast(requireContext(), "no active key — go to IDENTITY tab")
        val fp = PgpHelper.fingerprintCompact(ring.publicKey)
        val ct = ciphertextIn.text.toString().trim()
        if (ct.isEmpty()) return UiUtils.toast(requireContext(), "nothing to decrypt")
        UiUtils.ensurePassphrase(requireContext(), fp) { pass ->
            status("decrypting…")
            scope.launch {
                try {
                    val plain = withContext(Dispatchers.Default) {
                        PgpHelper.decryptFromArmored(ct.toByteArray(), ring, pass)
                    }
                    plaintextOut.setText(String(plain))
                    status("> decrypted ${ct.length} bytes → ${plain.size} chars")
                } catch (t: Throwable) {
                    status("DECRYPT FAILED: ${t.message}")
                    Session.clearPassphrase(fp)
                }
            }
        }
    }

    private fun onInputPicked(uri: Uri) {
        pickedFileUri = uri
        val name = queryDisplayName(uri)
        pickedFileName = name
        pickedFile.text = name
        btnDecryptFile.isEnabled = true
    }

    private fun onSaveAndDecrypt() {
        if (Session.activeRing == null)
            return UiUtils.toast(requireContext(), "no active key — go to IDENTITY tab")
        if (pickedFileUri == null)
            return UiUtils.toast(requireContext(), "pick a file first")
        val suggested = (pickedFileName ?: "file")
            .removeSuffix(".asc").removeSuffix(".pgp").removeSuffix(".gpg")
            .ifEmpty { "decrypted" }
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/octet-stream"
            putExtra(Intent.EXTRA_TITLE, suggested)
        }
        saveOutputLauncher.launch(intent)
    }

    private fun doFileDecrypt(outputUri: Uri) {
        val ring = Session.activeRing ?: return
        val fp = PgpHelper.fingerprintCompact(ring.publicKey)
        val inputUri = pickedFileUri ?: return
        val ctx = requireContext()
        UiUtils.ensurePassphrase(requireContext(), fp) { pass ->
            status("decrypting file…")
            btnDecryptFile.isEnabled = false
            scope.launch {
                try {
                    withContext(Dispatchers.Default) {
                        ctx.contentResolver.openInputStream(inputUri)!!.use { inp ->
                            ctx.contentResolver.openOutputStream(outputUri)!!.use { out ->
                                PgpHelper.decryptStream(inp, ring, pass, out)
                            }
                        }
                    }
                    status("> decrypted ${pickedFileName} → saved")
                } catch (t: Throwable) {
                    status("DECRYPT FAILED: ${t.message}")
                    Session.clearPassphrase(fp)
                } finally {
                    btnDecryptFile.isEnabled = true
                }
            }
        }
    }

    private fun queryDisplayName(uri: Uri): String {
        var name = "file"
        requireContext().contentResolver.query(uri, null, null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                val nameIdx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (nameIdx >= 0) name = c.getString(nameIdx) ?: name
            }
        }
        return name
    }

    private fun status(msg: String) = (requireActivity() as MainActivity).setStatus(msg)
}
