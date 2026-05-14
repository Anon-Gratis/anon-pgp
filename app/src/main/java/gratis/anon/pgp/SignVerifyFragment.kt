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

class SignVerifyFragment : Fragment() {

    // panels
    private lateinit var panelSignText: LinearLayout
    private lateinit var panelSignFile: LinearLayout
    private lateinit var panelVerifyText: LinearLayout
    private lateinit var panelVerifyFile: LinearLayout

    // sign-text widgets
    private lateinit var signTextInput: EditText
    private lateinit var signTextOutput: EditText

    // verify-text widgets
    private lateinit var verifyTextInput: EditText
    private lateinit var verifySigInput: EditText

    // sign-file widgets
    private lateinit var signFilePicked: TextView
    private lateinit var btnSignFile: Button
    private var signFileUri: Uri? = null
    private var signFileName: String? = null

    // verify-file widgets
    private lateinit var verifyFilePicked: TextView
    private lateinit var verifySigFilePicked: TextView
    private lateinit var btnVerifyFile: Button
    private var verifyDataUri: Uri? = null
    private var verifySigUri: Uri? = null

    private lateinit var verifyResult: TextView

    private val scope = CoroutineScope(Dispatchers.Main)

    private lateinit var pickSignFileLauncher: ActivityResultLauncher<Intent>
    private lateinit var saveSigLauncher: ActivityResultLauncher<Intent>
    private lateinit var pickVerifyDataLauncher: ActivityResultLauncher<Intent>
    private lateinit var pickVerifySigLauncher: ActivityResultLauncher<Intent>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        pickSignFileLauncher = registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { res ->
            if (res.resultCode != Activity.RESULT_OK) return@registerForActivityResult
            res.data?.data?.let {
                signFileUri = it
                signFileName = queryDisplayName(it)
                signFilePicked.text = signFileName
                btnSignFile.isEnabled = true
            }
        }
        saveSigLauncher = registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { res ->
            if (res.resultCode != Activity.RESULT_OK) return@registerForActivityResult
            res.data?.data?.let { doFileSign(it) }
        }
        pickVerifyDataLauncher = registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { res ->
            if (res.resultCode != Activity.RESULT_OK) return@registerForActivityResult
            res.data?.data?.let {
                verifyDataUri = it
                verifyFilePicked.text = queryDisplayName(it)
                refreshVerifyFileButton()
            }
        }
        pickVerifySigLauncher = registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { res ->
            if (res.resultCode != Activity.RESULT_OK) return@registerForActivityResult
            res.data?.data?.let {
                verifySigUri = it
                verifySigFilePicked.text = queryDisplayName(it)
                refreshVerifyFileButton()
            }
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, saved: Bundle?
    ): View = inflater.inflate(R.layout.fragment_signverify, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        panelSignText = view.findViewById(R.id.panelSignText)
        panelSignFile = view.findViewById(R.id.panelSignFile)
        panelVerifyText = view.findViewById(R.id.panelVerifyText)
        panelVerifyFile = view.findViewById(R.id.panelVerifyFile)

        signTextInput = view.findViewById(R.id.signTextInput)
        signTextOutput = view.findViewById(R.id.signTextOutput)
        verifyTextInput = view.findViewById(R.id.verifyTextInput)
        verifySigInput = view.findViewById(R.id.verifySigInput)

        signFilePicked = view.findViewById(R.id.signFilePicked)
        btnSignFile = view.findViewById(R.id.btnSignFile)

        verifyFilePicked = view.findViewById(R.id.verifyFilePicked)
        verifySigFilePicked = view.findViewById(R.id.verifySigFilePicked)
        btnVerifyFile = view.findViewById(R.id.btnVerifyFile)

        verifyResult = view.findViewById(R.id.verifyResult)

        val actionGroup = view.findViewById<RadioGroup>(R.id.actionGroup)
        val modeGroup = view.findViewById<RadioGroup>(R.id.modeGroup)

        fun updatePanels() {
            val sign = actionGroup.checkedRadioButtonId == R.id.actionSign
            val text = modeGroup.checkedRadioButtonId == R.id.modeText
            panelSignText.visibility = if (sign && text) View.VISIBLE else View.GONE
            panelSignFile.visibility = if (sign && !text) View.VISIBLE else View.GONE
            panelVerifyText.visibility = if (!sign && text) View.VISIBLE else View.GONE
            panelVerifyFile.visibility = if (!sign && !text) View.VISIBLE else View.GONE
            verifyResult.visibility = View.GONE
        }
        actionGroup.setOnCheckedChangeListener { _, _ -> updatePanels() }
        modeGroup.setOnCheckedChangeListener { _, _ -> updatePanels() }

        view.findViewById<Button>(R.id.btnSignText).setOnClickListener { onSignText() }
        view.findViewById<Button>(R.id.btnCopySig).setOnClickListener {
            val sig = signTextOutput.text.toString()
            if (sig.isEmpty()) return@setOnClickListener
            UiUtils.copyToClipboard(requireContext(), "signature", sig)
            UiUtils.toast(requireContext(), "signature copied")
        }
        view.findViewById<Button>(R.id.btnVerifyText).setOnClickListener { onVerifyText() }

        view.findViewById<Button>(R.id.btnPickSignFile).setOnClickListener {
            pickSignFileLauncher.launch(openDocumentIntent("*/*"))
        }
        btnSignFile.setOnClickListener {
            if (Session.activeRing == null)
                return@setOnClickListener UiUtils.toast(requireContext(), "no active key — go to IDENTITY tab")
            if (signFileUri == null) return@setOnClickListener
            val sigName = (signFileName ?: "file") + ".sig"
            val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "application/pgp-signature"
                putExtra(Intent.EXTRA_TITLE, sigName)
            }
            saveSigLauncher.launch(intent)
        }
        view.findViewById<Button>(R.id.btnPickVerifyFile).setOnClickListener {
            pickVerifyDataLauncher.launch(openDocumentIntent("*/*"))
        }
        view.findViewById<Button>(R.id.btnPickVerifySigFile).setOnClickListener {
            pickVerifySigLauncher.launch(openDocumentIntent("*/*"))
        }
        btnVerifyFile.setOnClickListener { onVerifyFile() }
    }

    private fun refreshVerifyFileButton() {
        btnVerifyFile.isEnabled = verifyDataUri != null && verifySigUri != null
    }

    // ─── SIGN / TEXT ─────────────────────────────────────────────────────

    private fun onSignText() {
        val ring = Session.activeRing
            ?: return UiUtils.toast(requireContext(), "no active key — go to IDENTITY tab")
        val fp = PgpHelper.fingerprintCompact(ring.publicKey)
        val text = signTextInput.text.toString()
        if (text.isEmpty()) return UiUtils.toast(requireContext(), "nothing to sign")
        UiUtils.ensurePassphrase(requireContext(), fp) { pass ->
            status("signing…")
            scope.launch {
                try {
                    val sig = withContext(Dispatchers.Default) {
                        PgpHelper.signDetached(text.toByteArray(), ring, pass)
                    }
                    signTextOutput.setText(String(sig))
                    status("> signed ${text.length} chars → ${sig.size} bytes")
                } catch (t: Throwable) {
                    status("SIGN FAILED: ${t.message}")
                    Session.clearPassphrase(fp)
                }
            }
        }
    }

    // ─── VERIFY / TEXT ───────────────────────────────────────────────────

    private fun onVerifyText() {
        val text = verifyTextInput.text.toString()
        val sig = verifySigInput.text.toString().trim()
        if (text.isEmpty() || sig.isEmpty())
            return UiUtils.toast(requireContext(), "fill both text and signature")
        val candidates = (requireActivity() as MainActivity).roster.list()
        if (candidates.isEmpty())
            return UiUtils.toast(requireContext(), "no contacts to verify against — import a key")

        status("verifying…")
        scope.launch {
            try {
                val result = withContext(Dispatchers.Default) {
                    PgpHelper.verifyDetachedAgainstAny(
                        text.toByteArray(), sig.toByteArray(),
                        candidates.map { it.ring }
                    )
                }
                showVerifyResult(result, candidates)
            } catch (t: Throwable) {
                showVerifyFailed("error: ${t.message}")
            }
        }
    }

    // ─── SIGN / FILE ─────────────────────────────────────────────────────

    private fun doFileSign(outputUri: Uri) {
        val ring = Session.activeRing ?: return
        val fp = PgpHelper.fingerprintCompact(ring.publicKey)
        val dataUri = signFileUri ?: return
        UiUtils.ensurePassphrase(requireContext(), fp) { pass ->
            status("signing file…")
            btnSignFile.isEnabled = false
            val ctx = requireContext()
            scope.launch {
                try {
                    withContext(Dispatchers.Default) {
                        ctx.contentResolver.openInputStream(dataUri)!!.use { inp ->
                            ctx.contentResolver.openOutputStream(outputUri)!!.use { out ->
                                PgpHelper.signDetachedStream(inp, ring, pass, out)
                            }
                        }
                    }
                    status("> signed ${signFileName} → .sig saved")
                } catch (t: Throwable) {
                    status("SIGN FAILED: ${t.message}")
                    Session.clearPassphrase(fp)
                } finally {
                    btnSignFile.isEnabled = true
                }
            }
        }
    }

    // ─── VERIFY / FILE ───────────────────────────────────────────────────

    private fun onVerifyFile() {
        val dataUri = verifyDataUri ?: return
        val sigUri = verifySigUri ?: return
        val candidates = (requireActivity() as MainActivity).roster.list()
        if (candidates.isEmpty())
            return UiUtils.toast(requireContext(), "no contacts to verify against — import a key")
        val ctx = requireContext()
        status("verifying file…")
        btnVerifyFile.isEnabled = false
        scope.launch {
            try {
                // Read sig + data into memory only enough to use existing API.
                // The signature is small. We stream the data once per candidate.
                val sigBytes = withContext(Dispatchers.IO) {
                    ctx.contentResolver.openInputStream(sigUri)!!.use { it.readBytes() }
                }

                // Parse sig once to find key id
                val keyId = withContext(Dispatchers.Default) {
                    val decoder = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(
                        java.io.ByteArrayInputStream(sigBytes)
                    )
                    val factory = org.bouncycastle.openpgp.bc.BcPGPObjectFactory(decoder)
                    val sigList = factory.nextObject() as? org.bouncycastle.openpgp.PGPSignatureList
                    sigList?.get(0)?.keyID
                } ?: run {
                    showVerifyFailed("signature file has no signature packet")
                    btnVerifyFile.isEnabled = true
                    return@launch
                }

                val matchingRing = candidates.firstOrNull { it.ring.getPublicKey(keyId) != null }
                if (matchingRing == null) {
                    showVerifyFailed("signature is by an unknown key (id ${"%X".format(keyId)})")
                    btnVerifyFile.isEnabled = true
                    return@launch
                }

                val ok = withContext(Dispatchers.IO) {
                    ctx.contentResolver.openInputStream(dataUri)!!.use { dataStream ->
                        PgpHelper.verifyDetachedStream(
                            dataStream,
                            java.io.ByteArrayInputStream(sigBytes),
                            matchingRing.ring
                        )
                    }
                }
                if (ok) showVerifyResult(
                    PgpHelper.VerifyResult(matchingRing.ring, keyId),
                    candidates
                ) else showVerifyFailed("signature is INVALID for this data")
            } catch (t: Throwable) {
                showVerifyFailed("error: ${t.message}")
            } finally {
                btnVerifyFile.isEnabled = true
            }
        }
    }

    private fun showVerifyResult(
        result: PgpHelper.VerifyResult?,
        candidates: List<ContactRoster.Contact>
    ) {
        verifyResult.visibility = View.VISIBLE
        if (result == null) {
            verifyResult.setTextColor(resources.getColor(R.color.anon_red, null))
            verifyResult.text = "✗ INVALID — signature does not match any imported key"
            status("VERIFY: invalid")
            return
        }
        val match = candidates.firstOrNull { it.ring === result.ring }
        verifyResult.setTextColor(resources.getColor(R.color.anon_green, null))
        verifyResult.text =
            "✓ VALID — signed by ${match?.displayName ?: "<unknown>"}\n${match?.prettyFingerprint ?: ""}"
        status("VERIFY: ok — ${match?.displayName}")
    }

    private fun showVerifyFailed(msg: String) {
        verifyResult.visibility = View.VISIBLE
        verifyResult.setTextColor(resources.getColor(R.color.anon_red, null))
        verifyResult.text = "✗ $msg"
        status("VERIFY FAILED: $msg")
    }

    // ─── helpers ─────────────────────────────────────────────────────────

    private fun openDocumentIntent(mime: String) = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
        addCategory(Intent.CATEGORY_OPENABLE)
        type = mime
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
