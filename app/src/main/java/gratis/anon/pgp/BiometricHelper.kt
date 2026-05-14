package gratis.anon.pgp

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.Executor
import java.util.concurrent.Executors

/**
 * Thin wrapper around [BiometricPrompt] gated on Class 3 (strong) biometrics
 * only. Class 2 (weak) is rejected — strong biometric is the bar Android lets
 * us bind to a hardware-backed Keystore key, and we don't want a weaker
 * fallback masquerading as the same trust level.
 */
object BiometricHelper {

    /** True iff the device has enrolled Class 3 biometric and we can prompt. */
    fun isAvailable(context: Context): Boolean {
        val mgr = BiometricManager.from(context)
        return mgr.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS
    }

    /** Returns a stable reason code for why biometric isn't usable, or
     *  null if it is. Used in SecurityFragment to render a hint. */
    fun unavailableReason(context: Context): String? {
        val mgr = BiometricManager.from(context)
        return when (mgr.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> null
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "No biometric hardware"
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "Biometric hardware unavailable"
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "No biometric enrolled in system settings"
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> "Biometric requires security update"
            else -> "Biometric unavailable"
        }
    }

    /**
     * Shows the system biometric prompt. [onSuccess] runs on the main thread,
     * [onFail] runs on every authentication failure or user cancel (caller can
     * distinguish via `errCode`).
     */
    fun prompt(
        activity: FragmentActivity,
        title: String,
        subtitle: String,
        onSuccess: () -> Unit,
        onFail: (errCode: Int, errMessage: CharSequence) -> Unit,
    ) {
        val executor: Executor = Executors.newSingleThreadExecutor()
        val prompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    activity.runOnUiThread { onSuccess() }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    activity.runOnUiThread { onFail(errorCode, errString) }
                }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText("Use PIN")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setConfirmationRequired(false)
            .build()
        prompt.authenticate(info)
    }
}
