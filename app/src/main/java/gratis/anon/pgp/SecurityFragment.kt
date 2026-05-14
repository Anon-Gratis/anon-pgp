package gratis.anon.pgp

import android.app.AlertDialog
import android.content.DialogInterface
import android.os.Bundle
import android.text.InputType
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.fragment.app.Fragment
import com.google.android.material.button.MaterialButton
import com.google.android.material.materialswitch.MaterialSwitch

/**
 * The "// LOCK" tab. Exposes:
 *   - Enable / disable app lock (prompts for a new PIN when enabling, asks for
 *     the existing PIN when disabling).
 *   - Change PIN.
 *   - Toggle biometric unlock (only if the device has Class 3 biometric enrolled).
 */
class SecurityFragment : Fragment() {

    private lateinit var pinStore: PinStore
    private lateinit var enableSwitch: MaterialSwitch
    private lateinit var changePinBtn: MaterialButton
    private lateinit var biometricSwitch: MaterialSwitch
    private lateinit var biometricHint: TextView

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_security, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        pinStore = PinStore(requireContext().applicationContext)
        enableSwitch = view.findViewById(R.id.enableLockSwitch)
        changePinBtn = view.findViewById(R.id.changePinBtn)
        biometricSwitch = view.findViewById(R.id.biometricSwitch)
        biometricHint = view.findViewById(R.id.biometricHint)

        refresh()

        enableSwitch.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked && !pinStore.hasPin()) {
                promptNewPin(onCancel = { refresh() })
            } else if (!isChecked && pinStore.hasPin()) {
                promptDisable()
            }
        }
        changePinBtn.setOnClickListener { promptChangePin() }
        biometricSwitch.setOnCheckedChangeListener { _, isChecked ->
            pinStore.setBiometricEnabled(isChecked)
        }
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    /** Reflect current state in the toggles + button visibility. */
    private fun refresh() {
        val hasPin = pinStore.hasPin()
        enableSwitch.setOnCheckedChangeListener(null)
        enableSwitch.isChecked = hasPin
        enableSwitch.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked && !pinStore.hasPin()) {
                promptNewPin(onCancel = { refresh() })
            } else if (!isChecked && pinStore.hasPin()) {
                promptDisable()
            }
        }
        changePinBtn.visibility = if (hasPin) View.VISIBLE else View.GONE

        val bioReason = BiometricHelper.unavailableReason(requireContext())
        if (hasPin && bioReason == null) {
            biometricSwitch.visibility = View.VISIBLE
            biometricSwitch.setOnCheckedChangeListener(null)
            biometricSwitch.isChecked = pinStore.isBiometricEnabled()
            biometricSwitch.setOnCheckedChangeListener { _, isChecked ->
                pinStore.setBiometricEnabled(isChecked)
            }
            biometricHint.visibility = View.GONE
        } else if (hasPin) {
            biometricSwitch.visibility = View.GONE
            biometricHint.text = bioReason ?: ""
            biometricHint.visibility = View.VISIBLE
        } else {
            biometricSwitch.visibility = View.GONE
            biometricHint.visibility = View.GONE
        }
    }

    private fun promptNewPin(onCancel: () -> Unit) {
        val (pinField, container) = buildPinDialogView("new PIN (4-12 digits)")
        AlertDialog.Builder(requireContext())
            .setTitle("Set app PIN")
            .setView(container)
            .setCancelable(false)
            .setPositiveButton("SET") { _, _ ->
                val pin = pinField.text.toString().toCharArray()
                if (pin.size < 4) {
                    UiUtils.toast(requireContext(), "PIN must be at least 4 digits")
                    pin.fill('0')
                    onCancel()
                    return@setPositiveButton
                }
                pinStore.setPin(pin)
                pin.fill('0')
                AppLock.markUnlocked()
                UiUtils.toast(requireContext(), "PIN set")
                refresh()
            }
            .setNegativeButton(android.R.string.cancel) { d: DialogInterface, _ -> d.cancel(); onCancel() }
            .show()
    }

    private fun promptChangePin() {
        val (oldField, oldContainer) = buildPinDialogView("current PIN")
        AlertDialog.Builder(requireContext())
            .setTitle("Change PIN")
            .setView(oldContainer)
            .setPositiveButton("NEXT") { _, _ ->
                val old = oldField.text.toString().toCharArray()
                val ok = pinStore.verifyPin(old)
                old.fill('0')
                if (!ok) {
                    UiUtils.toast(requireContext(), "incorrect PIN")
                    return@setPositiveButton
                }
                promptNewPin(onCancel = {})
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun promptDisable() {
        val (field, container) = buildPinDialogView("current PIN")
        AlertDialog.Builder(requireContext())
            .setTitle("Disable app lock")
            .setMessage("Enter current PIN to disable.")
            .setView(container)
            .setCancelable(false)
            .setPositiveButton("DISABLE") { _, _ ->
                val pin = field.text.toString().toCharArray()
                val ok = pinStore.verifyPin(pin)
                pin.fill('0')
                if (!ok) {
                    UiUtils.toast(requireContext(), "incorrect PIN")
                    refresh()
                    return@setPositiveButton
                }
                pinStore.clearPin()
                AppLock.markUnlocked()
                UiUtils.toast(requireContext(), "App lock disabled")
                refresh()
            }
            .setNegativeButton(android.R.string.cancel) { _, _ -> refresh() }
            .show()
    }

    private fun buildPinDialogView(hint: String): Pair<EditText, LinearLayout> {
        val field = EditText(requireContext()).apply {
            this.hint = hint
            inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
            filters = arrayOf(android.text.InputFilter.LengthFilter(12))
            setTextColor(resources.getColor(R.color.anon_black, null))
            setHintTextColor(resources.getColor(R.color.anon_mid, null))
        }
        val pad = (resources.displayMetrics.density * 16).toInt()
        val container = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, 0)
            addView(field)
        }
        return field to container
    }
}
