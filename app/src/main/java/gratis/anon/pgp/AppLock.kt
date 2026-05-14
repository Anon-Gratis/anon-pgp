package gratis.anon.pgp

/**
 * Process-wide app lock state. Tracks when the app was last backgrounded so
 * MainActivity can decide whether to gate `onResume` with [LockActivity].
 *
 * Locked == true means the next foregrounded activity must redirect to
 * [LockActivity] before showing real content. Locked is set on process start
 * (if a PIN is configured) and after the grace period elapses while in
 * background.
 */
object AppLock {

    /** Grace window after backgrounding during which we DON'T re-lock. */
    const val GRACE_MS: Long = 60_000L

    @Volatile private var locked: Boolean = false
    @Volatile private var backgroundedAt: Long = 0L

    fun isLocked(): Boolean = locked

    /** Called from LockActivity after correct PIN / biometric. */
    fun markUnlocked() {
        locked = false
        backgroundedAt = 0L
    }

    /** Force lock — used by SecurityFragment when the user disables and re-enables,
     *  or after a "lock now" action. */
    fun markLocked() {
        locked = true
    }

    /** Called when the app moves to background (last activity stopped). */
    fun onAppBackgrounded() {
        backgroundedAt = System.currentTimeMillis()
    }

    /** Called when any activity comes to foreground; returns true if the
     *  caller should redirect to LockActivity. */
    fun onAppForegrounded(pinConfigured: Boolean): Boolean {
        if (!pinConfigured) {
            locked = false
            return false
        }
        if (locked) return true
        val bg = backgroundedAt
        if (bg > 0L && System.currentTimeMillis() - bg > GRACE_MS) {
            locked = true
        }
        backgroundedAt = 0L
        return locked
    }

    /** Called from Application.onCreate when a PIN is configured. The first
     *  activity to start MUST go through LockActivity. */
    fun lockOnProcessStart() {
        locked = true
    }
}
