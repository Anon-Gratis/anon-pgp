package gratis.anon.pgp

import android.content.Intent
import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentActivity
import androidx.viewpager2.adapter.FragmentStateAdapter
import androidx.viewpager2.widget.ViewPager2
import com.google.android.material.tabs.TabLayout
import com.google.android.material.tabs.TabLayoutMediator

class MainActivity : AppCompatActivity() {

    /** Set by fragments to update the footer status line. */
    lateinit var statusLine: TextView
        private set

    lateinit var vault: KeyVault
        private set
    lateinit var roster: ContactRoster
        private set

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No gateOnLock() in onCreate — onResume handles it. Calling here AND
        // in onResume on cold start fired two LockActivity instances back-to-back
        // (onCreate → onStart → onResume runs synchronously, and AppLock.isLocked()
        // is still true at both points). User had to enter the PIN twice.
        // (PGP 0.3.5 bug.)
        setContentView(R.layout.activity_main)

        vault = KeyVault(filesDir, AndroidPrefs(this, "key_vault"))
        roster = ContactRoster(filesDir)

        // Restore active key on launch (vault.migrateLegacyIfPresent() in init
        // has already imported any v0.2.x single-key file).
        if (Session.activeRing == null) {
            Session.activeRing = vault.getActive()?.ring
        }

        statusLine = findViewById(R.id.statusLine)
        val tabs = findViewById<TabLayout>(R.id.tabs)
        val pager = findViewById<ViewPager2>(R.id.pager)
        pager.adapter = TabAdapter(this)
        pager.offscreenPageLimit = 5
        TabLayoutMediator(tabs, pager) { tab, pos ->
            tab.text = when (pos) {
                0 -> getString(R.string.tab_identity)
                1 -> getString(R.string.tab_contacts)
                2 -> getString(R.string.tab_encrypt)
                3 -> getString(R.string.tab_decrypt)
                4 -> getString(R.string.tab_sign_verify)
                5 -> getString(R.string.tab_security)
                else -> ""
            }
        }.attach()
    }

    override fun onResume() {
        super.onResume()
        gateOnLock()
    }

    /** If a PIN is configured and AppLock is locked, overlay LockActivity. */
    private fun gateOnLock() {
        if (PinStore(applicationContext).hasPin() && AppLock.isLocked()) {
            startActivity(Intent(this, LockActivity::class.java))
        }
    }

    fun setStatus(msg: String) {
        statusLine.text = if (msg.startsWith(">") || msg.startsWith("ERROR")) msg else "> $msg"
    }

    private class TabAdapter(activity: FragmentActivity) : FragmentStateAdapter(activity) {
        override fun getItemCount(): Int = 6
        override fun createFragment(position: Int): Fragment = when (position) {
            0 -> IdentityFragment()
            1 -> ContactsFragment()
            2 -> EncryptFragment()
            3 -> DecryptFragment()
            4 -> SignVerifyFragment()
            5 -> SecurityFragment()
            else -> error("bad position $position")
        }
    }
}
