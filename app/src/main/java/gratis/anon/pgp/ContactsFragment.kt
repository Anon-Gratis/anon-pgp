package gratis.anon.pgp

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.zxing.integration.android.IntentIntegrator

class ContactsFragment : Fragment() {

    private lateinit var inputPubKey: EditText
    private lateinit var emptyState: TextView
    private lateinit var recycler: RecyclerView
    private val adapter = ContactAdapter(::onDelete)

    private lateinit var fileImportLauncher: ActivityResultLauncher<Intent>
    private lateinit var qrScanLauncher: ActivityResultLauncher<Intent>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        fileImportLauncher = registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { res ->
            if (res.resultCode != Activity.RESULT_OK) return@registerForActivityResult
            res.data?.data?.let { importFromUri(it) }
        }
        qrScanLauncher = registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { res ->
            val result = IntentIntegrator.parseActivityResult(res.resultCode, res.data)
                ?: return@registerForActivityResult
            if (result.contents == null) return@registerForActivityResult
            importArmored(result.contents.toByteArray())
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, saved: Bundle?
    ): View = inflater.inflate(R.layout.fragment_contacts, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        inputPubKey = view.findViewById(R.id.inputPubKey)
        emptyState = view.findViewById(R.id.emptyState)
        recycler = view.findViewById(R.id.recyclerContacts)
        recycler.layoutManager = LinearLayoutManager(requireContext())
        recycler.adapter = adapter

        view.findViewById<Button>(R.id.btnPasteImport).setOnClickListener { onPasteImport() }
        view.findViewById<Button>(R.id.btnScanQr).setOnClickListener { onScanQr() }
        view.findViewById<Button>(R.id.btnImportFile).setOnClickListener { onImportFile() }
        refresh()
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    fun refresh() {
        val contacts = roster().list()
        adapter.submit(contacts)
        emptyState.visibility = if (contacts.isEmpty()) View.VISIBLE else View.GONE
        recycler.visibility = if (contacts.isEmpty()) View.GONE else View.VISIBLE
    }

    private fun onPasteImport() {
        val txt = inputPubKey.text.toString().trim()
        if (txt.isEmpty()) return UiUtils.toast(requireContext(), "paste a public key first")
        importArmored(txt.toByteArray())
        inputPubKey.text.clear()
    }

    private fun onScanQr() {
        val integrator = IntentIntegrator.forSupportFragment(this).apply {
            setPrompt("Aim at the public-key QR code")
            setOrientationLocked(true)
            setBeepEnabled(false)
            setDesiredBarcodeFormats(IntentIntegrator.QR_CODE)
        }
        // forSupportFragment's createScanIntent gives us an Intent we can launch
        qrScanLauncher.launch(integrator.createScanIntent())
    }

    private fun onImportFile() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
        fileImportLauncher.launch(intent)
    }

    private fun importFromUri(uri: Uri) {
        try {
            val bytes = requireContext().contentResolver.openInputStream(uri)
                ?.use { it.readBytes() }
                ?: return UiUtils.toast(requireContext(), "could not read file")
            importArmored(bytes)
        } catch (t: Throwable) {
            status("ERROR: ${t.message}")
        }
    }

    private fun importArmored(armored: ByteArray) {
        try {
            val contact = roster().import(armored)
            status("> imported '${contact.displayName}' (${contact.prettyFingerprint})")
            refresh()
        } catch (t: Throwable) {
            status("ERROR: not a valid public key — ${t.message}")
        }
    }

    private fun onDelete(contact: ContactRoster.Contact) {
        AlertDialog.Builder(requireContext())
            .setTitle("Delete contact?")
            .setMessage("Remove ${contact.displayName}?")
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.delete) { _, _ ->
                roster().delete(contact.fingerprint)
                status("> deleted ${contact.displayName}")
                refresh()
            }
            .show()
    }

    private fun roster() = (requireActivity() as MainActivity).roster
    private fun status(msg: String) = (requireActivity() as MainActivity).setStatus(msg)
}

private class ContactAdapter(
    private val onDelete: (ContactRoster.Contact) -> Unit
) : RecyclerView.Adapter<ContactAdapter.VH>() {

    private val items = mutableListOf<ContactRoster.Contact>()

    fun submit(list: List<ContactRoster.Contact>) {
        items.clear()
        items.addAll(list)
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val v = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_contact, parent, false)
        return VH(v)
    }

    override fun onBindViewHolder(holder: VH, position: Int) {
        val c = items[position]
        holder.name.text = c.displayName
        holder.fp.text = c.prettyFingerprint
        holder.del.setOnClickListener { onDelete(c) }
    }

    override fun getItemCount(): Int = items.size

    class VH(v: View) : RecyclerView.ViewHolder(v) {
        val name: TextView = v.findViewById(R.id.contactName)
        val fp: TextView = v.findViewById(R.id.contactFp)
        val del: Button = v.findViewById(R.id.contactDelete)
    }
}
