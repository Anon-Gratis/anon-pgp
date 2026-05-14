package gratis.anon.pgp

import android.app.ActivityManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Listens for the Guardian Project Panic API trigger and wipes every byte of
 * app-private data (including the private key) via
 * ActivityManager.clearApplicationUserData().
 *
 * Bind a trigger app like Ripple (F-Droid) to actually fire this.
 */
class PanicReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != ACTION_TRIGGER) return
        Log.w(AnonPgpApp.TAG, "PANIC TRIGGER — wiping all data and exiting")
        try {
            val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
            if (am?.clearApplicationUserData() == true) return
        } catch (t: Throwable) {
            Log.e(AnonPgpApp.TAG, "panic wipe failed; exiting anyway", t)
        }
        kotlin.system.exitProcess(0)
    }

    companion object {
        const val ACTION_TRIGGER = "info.guardianproject.panic.action.TRIGGER"
    }
}
