package gratis.anon.pgp

import android.app.Activity
import android.app.Application
import android.os.Bundle
import android.util.Log
import android.view.WindowManager
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

class AnonPgpApp : Application() {

    override fun onCreate() {
        super.onCreate()
        installCrashLogger()
        // Bouncy Castle is bundled. Insert as a JCA provider so OpenPGP
        // operations can resolve the right algorithm implementations.
        try {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        } catch (t: Throwable) {
            Log.e(TAG, "could not install BouncyCastle provider", t)
        }
        installAppLockHooks()
        installFlagSecure()
    }

    private fun installAppLockHooks() {
        // If a PIN is configured, start the process locked so the first
        // activity has to go through LockActivity before reaching content.
        if (PinStore(this).hasPin()) {
            AppLock.lockOnProcessStart()
        }
        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStop(owner: LifecycleOwner) {
                AppLock.onAppBackgrounded()
            }
            override fun onStart(owner: LifecycleOwner) {
                AppLock.onAppForegrounded(PinStore(this@AnonPgpApp).hasPin())
            }
        })
    }

    /** FLAG_SECURE on every activity: blocks screenshots and blanks the
     *  Recent Apps preview. */
    private fun installFlagSecure() {
        registerActivityLifecycleCallbacks(object : ActivityLifecycleCallbacks {
            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
                activity.window.setFlags(
                    WindowManager.LayoutParams.FLAG_SECURE,
                    WindowManager.LayoutParams.FLAG_SECURE,
                )
            }
            override fun onActivityStarted(activity: Activity) {}
            override fun onActivityResumed(activity: Activity) {}
            override fun onActivityPaused(activity: Activity) {}
            override fun onActivityStopped(activity: Activity) {}
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
            override fun onActivityDestroyed(activity: Activity) {}
        })
    }

    private fun installCrashLogger() {
        // Same pattern as Anon XMPP — writes uncaught exceptions to
        // /sdcard/Android/data/gratis.anon.pgp/files/anon-crash.log
        val prior = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { t, e ->
            try {
                val dir = getExternalFilesDir(null)
                if (dir != null) {
                    val log = java.io.File(dir, "anon-crash.log")
                    log.appendText(
                        "===== ${java.util.Date()} thread=${t.name} =====\n" +
                            android.util.Log.getStackTraceString(e) + "\n\n"
                    )
                }
            } catch (_: Throwable) {
            }
            prior?.uncaughtException(t, e)
        }
    }

    companion object {
        const val TAG = "AnonPGP"
    }
}
