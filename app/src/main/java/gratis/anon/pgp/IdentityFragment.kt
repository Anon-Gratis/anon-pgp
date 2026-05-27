package gratis.anon.pgp

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.text.InputType
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.TextView
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.zxing.BarcodeFormat
import com.journeyapps.barcodescanner.BarcodeEncoder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class IdentityFragment : Fragment() {

    private lateinit var emptyState: TextView
    private lateinit var recyclerKeys: RecyclerView
    private lateinit var btnGenerate: Button
    private lateinit var btnImportSecret: Button
    private lateinit var btnCopyPub: Button
    private lateinit var btnShowQr: Button
    private lateinit var btnSavePubFile: Button
    private lateinit var btnExportSecret: Button
    private lateinit var btnMaintenance: Button
    private lateinit var btnDeleteActive: Button

    private val adapter = KeyAdapter(::onKeyClicked)
    private val scope = CoroutineScope(Dispatchers.Main)

    private lateinit var exportPubLauncher: ActivityResultLauncher<Intent>
    private lateinit var exportSecretLauncher: ActivityResultLauncher<Intent>
    private lateinit var importSecretLauncher: ActivityResultLauncher<Intent>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        exportPubLauncher = registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { res ->
            if (res.resultCode != Activity.RESULT_OK) return@registerForActivityResult
            res.data?.data?.let { writePublicKeyTo(it) }
        }
        exportSecretLauncher = registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { res ->
            if (res.resultCode != Activity.RESULT_OK) return@registerForActivityResult
            res.data?.data?.let { writeSecretKeyTo(it) }
        }
        importSecretLauncher = registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { res ->
            if (res.resultCode != Activity.RESULT_OK) return@registerForActivityResult
            res.data?.data?.let { readSecretKeyFrom(it) }
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, saved: Bundle?
    ): View = inflater.inflate(R.layout.fragment_identity, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        emptyState = view.findViewById(R.id.emptyState)
        recyclerKeys = view.findViewById(R.id.recyclerKeys)
        btnGenerate = view.findViewById(R.id.btnGenerate)
        btnImportSecret = view.findViewById(R.id.btnImportSecret)
        btnCopyPub = view.findViewById(R.id.btnCopyPub)
        btnShowQr = view.findViewById(R.id.btnShowQr)
        btnSavePubFile = view.findViewById(R.id.btnSavePubFile)
        btnExportSecret = view.findViewById(R.id.btnExportSecret)
        btnMaintenance = view.findViewById(R.id.btnMaintenance)
        btnDeleteActive = view.findViewById(R.id.btnDeleteActive)

        recyclerKeys.layoutManager = LinearLayoutManager(requireContext())
        recyclerKeys.adapter = adapter

        btnGenerate.setOnClickListener { onGenerate() }
        btnImportSecret.setOnClickListener { onImportSecret() }
        btnCopyPub.setOnClickListener { onCopyPublic() }
        btnShowQr.setOnClickListener { onShowQr() }
        btnSavePubFile.setOnClickListener { onExportPub() }
        btnExportSecret.setOnClickListener { onExportSecret() }
        btnMaintenance.setOnClickListener { onMaintenanceMenu() }
        btnDeleteActive.setOnClickListener { onDeleteActive() }

        refresh()
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    private fun refresh() {
        val keys = vault().list()
        val activeFp = vault().getActiveFingerprint()
        adapter.submit(keys, activeFp)

        if (keys.isEmpty()) {
            emptyState.visibility = View.VISIBLE
            recyclerKeys.visibility = View.GONE
            setActiveActionsEnabled(false)
        } else {
            emptyState.visibility = View.GONE
            recyclerKeys.visibility = View.VISIBLE
            setActiveActionsEnabled(Session.activeRing != null)
        }
    }

    private fun setActiveActionsEnabled(enabled: Boolean) {
        btnCopyPub.isEnabled = enabled
        btnShowQr.isEnabled = enabled
        btnSavePubFile.isEnabled = enabled
        btnExportSecret.isEnabled = enabled
        btnMaintenance.isEnabled = enabled
        btnDeleteActive.isEnabled = enabled
    }

    // ─── Key MAINTENANCE actions (subkey / expiry / revocation cert) ────

    private fun onMaintenanceMenu() {
        val ring = Session.activeRing ?: return
        val active = vault().getActive() ?: return
        val expiryLine = PgpHelper.primaryExpiry(ring)
            ?.let { java.text.SimpleDateFormat("yyyy-MM-dd").format(java.util.Date(it.epochSecond * 1000)) }
            ?: "never"
        val revokedLine = if (PgpHelper.isRevoked(ring)) "  (REVOKED)" else ""
        AlertDialog.Builder(requireContext())
            .setTitle("Key maintenance$revokedLine")
            .setMessage("${active.displayName}\nExpires: $expiryLine")
            .setItems(arrayOf(
                "Add encryption subkey",
                "Set primary expiry",
                "Generate revocation certificate",
            )) { _, which ->
                when (which) {
                    0 -> onAddSubkey(active)
                    1 -> onSetExpiry(active)
                    2 -> onGenerateRevocation(active)
                }
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    private fun onAddSubkey(active: KeyVault.Entry) {
        // Algorithm picker first.
        val labels = arrayOf(
            "X25519  (modern)",
            "RSA-3072  (legacy)",
        )
        val algos = arrayOf(PgpHelper.SubkeyAlgo.X25519, PgpHelper.SubkeyAlgo.RSA_3072)
        var picked = 0
        AlertDialog.Builder(requireContext())
            .setTitle("Add encryption subkey")
            .setSingleChoiceItems(labels, picked) { _, w -> picked = w }
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton("NEXT") { _, _ ->
                UiUtils.ensurePassphrase(requireContext(), active.fingerprint) { pass ->
                    status("adding subkey…")
                    scope.launch {
                        try {
                            val updated = withContext(Dispatchers.Default) {
                                PgpHelper.addEncryptionSubkey(active.ring, pass, algos[picked])
                            }
                            val sidecar = vault().rawPqcSidecar(active.fingerprint)
                            vault().add(updated, sidecar)
                            Session.activeRing = vault().getActive()?.ring
                            refresh()
                            status("> added ${algos[picked].name} subkey")
                        } catch (t: Throwable) {
                            status("ERROR: ${t.message}")
                            Session.clearPassphrase(active.fingerprint)
                        }
                    }
                }
            }
            .show()
    }

    private fun onSetExpiry(active: KeyVault.Entry) {
        val daysField = UiUtils.dialogEditText(
            requireContext(),
            hint = "Days from today (0 = never expire)",
            inputType = InputType.TYPE_CLASS_NUMBER,
            initial = "365",
        )
        AlertDialog.Builder(requireContext())
            .setTitle("Set primary-key expiry")
            .setMessage("Enter the number of days from today. 0 = never expire.")
            .setView(daysField)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton("APPLY") { _, _ ->
                val days = daysField.text.toString().toLongOrNull() ?: return@setPositiveButton
                UiUtils.ensurePassphrase(requireContext(), active.fingerprint) { pass ->
                    status("updating expiry…")
                    scope.launch {
                        try {
                            val expiry = if (days <= 0L) null else
                                java.time.Instant.now().plus(days, java.time.temporal.ChronoUnit.DAYS)
                            val updated = withContext(Dispatchers.Default) {
                                PgpHelper.setPrimaryExpiry(active.ring, expiry, pass)
                            }
                            val sidecar = vault().rawPqcSidecar(active.fingerprint)
                            vault().add(updated, sidecar)
                            Session.activeRing = vault().getActive()?.ring
                            refresh()
                            status(
                                if (expiry == null) "> expiry cleared"
                                else "> expires in $days day(s)"
                            )
                        } catch (t: Throwable) {
                            status("ERROR: ${t.message}")
                            Session.clearPassphrase(active.fingerprint)
                        }
                    }
                }
            }
            .show()
    }

    private fun onGenerateRevocation(active: KeyVault.Entry) {
        val reasons = PgpHelper.RevocationReason.values()
        var picked = 0
        AlertDialog.Builder(requireContext())
            .setTitle("Reason for revocation")
            .setSingleChoiceItems(reasons.map { it.name }.toTypedArray(), picked) { _, w -> picked = w }
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton("NEXT") { _, _ ->
                UiUtils.ensurePassphrase(requireContext(), active.fingerprint) { pass ->
                    scope.launch {
                        try {
                            val cert = withContext(Dispatchers.Default) {
                                PgpHelper.generateRevocationCert(active.ring, pass, reasons[picked])
                            }
                            UiUtils.copyToClipboard(
                                requireContext(),
                                "Anon PGP revocation cert",
                                String(cert)
                            )
                            status("> revocation cert copied to clipboard — save it offline")
                            AlertDialog.Builder(requireContext())
                                .setTitle("Revocation certificate")
                                .setMessage(
                                    "Cert copied to clipboard. Paste it somewhere safe — " +
                                        "ideally printed and stored offline. Importing it " +
                                        "anywhere later will revoke this key."
                                )
                                .setPositiveButton("DONE", null)
                                .show()
                        } catch (t: Throwable) {
                            status("ERROR: ${t.message}")
                            Session.clearPassphrase(active.fingerprint)
                        }
                    }
                }
            }
            .show()
    }

    // ─── Adapter callback ────────────────────────────────────────────────

    private fun onKeyClicked(entry: KeyVault.Entry) {
        vault().setActiveFingerprint(entry.fingerprint)
        Session.activeRing = entry.ring
        refresh()
        status("> active: ${entry.displayName}")
    }

    // ─── GENERATE ────────────────────────────────────────────────────────

    private fun onGenerate() {
        val idField = UiUtils.dialogEditText(
            requireContext(),
            hint = "name@example  (any string)",
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS,
            initial = "anon@anon.gratis"
        )
        AlertDialog.Builder(requireContext())
            .setTitle("New key — identity")
            .setMessage(
                "User-id baked into the public key. Free-form; convention is " +
                    "\"Name <email>\"."
            )
            .setView(idField)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton("NEXT") { _, _ ->
                val identity = idField.text.toString().ifBlank { "anon@anon.gratis" }
                promptAlgoForGenerate(identity)
            }
            .show()
    }

    /**
     * Three key flavors, presented in order of recommendation. Quantum-safe is
     * default for new keys. Classical options remain available because PQC
     * messages only work AnonPGP↔AnonPGP — to talk to GnuPG/Sequoia/etc. peers
     * the classical key flavor is what they'll consume.
     */
    private fun promptAlgoForGenerate(identity: String) {
        val labels = arrayOf(
            "Quantum-safe  (Ed25519 + ML-DSA + ML-KEM)",
            "Classical Ed25519  (modern, fast)",
            "Classical RSA-3072  (broadest interop)"
        )
        val algos = arrayOf(
            PgpHelper.KeyAlgo.HYBRID_PQC,
            PgpHelper.KeyAlgo.CLASSICAL_ED25519,
            PgpHelper.KeyAlgo.CLASSICAL_RSA
        )
        var picked = 0
        AlertDialog.Builder(requireContext())
            .setTitle("New key — algorithm")
            .setSingleChoiceItems(labels, picked) { _, which -> picked = which }
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton("NEXT") { _, _ ->
                promptPassphraseForGenerate(identity, algos[picked])
            }
            .show()
    }

    private fun promptPassphraseForGenerate(identity: String, algo: PgpHelper.KeyAlgo) {
        val pwField = UiUtils.dialogEditText(
            requireContext(),
            hint = "Choose a passphrase (8+ chars)",
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        )
        AlertDialog.Builder(requireContext())
            .setTitle("New key — passphrase")
            .setMessage(
                "Your private key will be encrypted with this passphrase. " +
                    "Forget it and the key is unrecoverable."
            )
            .setView(pwField)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton("GENERATE") { _, _ ->
                val pass = pwField.text.toString()
                if (pass.length < 8) {
                    UiUtils.toast(requireContext(), "passphrase must be at least 8 chars")
                    return@setPositiveButton
                }
                doGenerate(identity, algo, pass.toCharArray())
            }
            .show()
    }

    private fun doGenerate(identity: String, algo: PgpHelper.KeyAlgo, passphrase: CharArray) {
        val label = when (algo) {
            PgpHelper.KeyAlgo.HYBRID_PQC        -> "quantum-safe hybrid"
            PgpHelper.KeyAlgo.CLASSICAL_ED25519 -> "Ed25519/X25519"
            PgpHelper.KeyAlgo.CLASSICAL_RSA     -> "RSA-3072 (slow — ~10-30s)"
        }
        status("generating $label keypair…")
        btnGenerate.isEnabled = false
        scope.launch {
            try {
                val generated = withContext(Dispatchers.Default) {
                    PgpHelper.generateSecretKeyRing(identity, passphrase, algo)
                }
                val entry = vault().add(generated)
                vault().setActiveFingerprint(entry.fingerprint)
                Session.activeRing = entry.ring
                Session.setPassphrase(entry.fingerprint, passphrase)
                refresh()
                val flavor = if (entry.hasPqc) "hybrid PQC" else "classical"
                status("> generated $flavor '${entry.displayName}' (${entry.prettyFingerprint})")
            } catch (t: Throwable) {
                status("ERROR: ${t.message}")
            } finally {
                btnGenerate.isEnabled = true
            }
        }
    }

    // ─── IMPORT SECRET KEY ──────────────────────────────────────────────

    private fun onImportSecret() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
        importSecretLauncher.launch(intent)
    }

    private fun readSecretKeyFrom(uri: Uri) {
        try {
            val bytes = requireContext().contentResolver.openInputStream(uri)
                ?.use { it.readBytes() }
                ?: return run { status("ERROR: could not read file") }

            val entry = try {
                vault().add(bytes)
            } catch (t: Throwable) {
                status("ERROR: not a valid secret keyring — ${t.message}")
                return
            }

            // Make the imported key the active one — that's almost always what
            // the user wants right after import.
            vault().setActiveFingerprint(entry.fingerprint)
            Session.activeRing = entry.ring
            // Clear any stale cached passphrase for that fingerprint.
            Session.clearPassphrase(entry.fingerprint)
            refresh()
            status("> imported '${entry.displayName}' (${entry.prettyFingerprint})")
        } catch (t: Throwable) {
            status("ERROR: ${t.message}")
        }
    }

    // ─── PUBLIC KEY actions ─────────────────────────────────────────────

    private fun onCopyPublic() {
        val ring = Session.activeRing ?: return
        val pubArmored = PgpHelper.exportPublicKey(ring)
        UiUtils.copyToClipboard(requireContext(), "Anon PGP public key", String(pubArmored))
        UiUtils.toast(requireContext(), "public key copied to clipboard")
        status("> ${pubArmored.size} bytes of public key on clipboard")
    }

    private fun onShowQr() {
        val ring = Session.activeRing ?: return
        val pubArmored = PgpHelper.exportPublicKey(ring)
        val payload = String(pubArmored)
        try {
            val matrix = com.google.zxing.MultiFormatWriter().encode(
                payload, BarcodeFormat.QR_CODE, 1024, 1024
            )
            val bitmap = BarcodeEncoder().createBitmap(matrix)
            val image = ImageView(requireContext()).apply {
                setImageBitmap(bitmap)
                adjustViewBounds = true
                setBackgroundColor(Color.WHITE)
                setPadding(24, 24, 24, 24)
            }
            val wrap = LinearLayout(requireContext()).apply {
                orientation = LinearLayout.VERTICAL
                gravity = android.view.Gravity.CENTER
                addView(image)
            }
            AlertDialog.Builder(requireContext())
                .setTitle("Public-key QR")
                .setMessage(
                    "Have the other device open ANON PGP → CONTACTS → SCAN QR.\n" +
                        "Fingerprint: ${PgpHelper.fingerprint(ring.publicKey)}"
                )
                .setView(wrap)
                .setPositiveButton("DONE", null)
                .show()
        } catch (t: Throwable) {
            status("ERROR: QR encode failed — ${t.message} (key too large?)")
        }
    }

    private fun onExportPub() {
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/pgp-keys"
            putExtra(Intent.EXTRA_TITLE, "anon-pgp-public.asc")
        }
        exportPubLauncher.launch(intent)
    }

    private fun writePublicKeyTo(uri: Uri) {
        val ring = Session.activeRing ?: return
        try {
            val pubArmored = PgpHelper.exportPublicKey(ring)
            requireContext().contentResolver.openOutputStream(uri)?.use { it.write(pubArmored) }
            status("> exported public key (${pubArmored.size} bytes)")
        } catch (t: Throwable) {
            status("ERROR: ${t.message}")
        }
    }

    // ─── SECRET KEY EXPORT ──────────────────────────────────────────────

    private fun onExportSecret() {
        val active = vault().getActive() ?: return
        AlertDialog.Builder(requireContext())
            .setTitle("Export secret key?")
            .setMessage(
                "The .asc file contains your PASSPHRASE-PROTECTED private key. " +
                    "Anyone with both the file AND the passphrase has your identity."
            )
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton("I UNDERSTAND") { _, _ ->
                val sanitized = active.displayName
                    .replace(Regex("[^A-Za-z0-9._-]"), "_")
                    .ifEmpty { "anon-pgp" }
                val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE)
                    type = "application/pgp-keys"
                    putExtra(Intent.EXTRA_TITLE, "$sanitized-secret.asc")
                }
                exportSecretLauncher.launch(intent)
            }
            .show()
    }

    private fun writeSecretKeyTo(uri: Uri) {
        val active = vault().getActive() ?: return
        try {
            val raw = vault().rawBytes(active.fingerprint)
                ?: return run { status("ERROR: key file missing") }
            requireContext().contentResolver.openOutputStream(uri)?.use { it.write(raw) }
            status("> exported secret key (${raw.size} bytes, still passphrase-protected)")
        } catch (t: Throwable) {
            status("ERROR: ${t.message}")
        }
    }

    // ─── DELETE ─────────────────────────────────────────────────────────

    private fun onDeleteActive() {
        val active = vault().getActive() ?: return
        AlertDialog.Builder(requireContext())
            .setTitle("Delete '${active.displayName}'?")
            .setMessage(
                "This permanently removes the key from this device. Anything " +
                    "encrypted to its public key becomes undecryptable unless " +
                    "you have a backup."
            )
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.delete) { _, _ ->
                vault().delete(active.fingerprint)
                Session.clearPassphrase(active.fingerprint)
                Session.activeRing = vault().getActive()?.ring
                refresh()
                status("> deleted '${active.displayName}'")
            }
            .show()
    }

    private fun vault() = (requireActivity() as MainActivity).vault
    private fun status(msg: String) = (requireActivity() as MainActivity).setStatus(msg)
}

private class KeyAdapter(
    private val onClick: (KeyVault.Entry) -> Unit
) : RecyclerView.Adapter<KeyAdapter.VH>() {

    private val items = mutableListOf<KeyVault.Entry>()
    private var activeFp: String? = null

    fun submit(list: List<KeyVault.Entry>, activeFingerprint: String?) {
        items.clear()
        items.addAll(list)
        activeFp = activeFingerprint
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val v = LayoutInflater.from(parent.context).inflate(R.layout.item_key, parent, false)
        return VH(v)
    }

    override fun onBindViewHolder(holder: VH, position: Int) {
        val e = items[position]
        holder.name.text = e.displayName
        holder.fp.text = e.prettyFingerprint
        holder.radio.isChecked = (e.fingerprint == activeFp)
        holder.itemView.setOnClickListener { onClick(e) }
    }

    override fun getItemCount(): Int = items.size

    class VH(v: View) : RecyclerView.ViewHolder(v) {
        val radio: RadioButton = v.findViewById(R.id.keyActive)
        val name: TextView = v.findViewById(R.id.keyName)
        val fp: TextView = v.findViewById(R.id.keyFp)
    }
}
