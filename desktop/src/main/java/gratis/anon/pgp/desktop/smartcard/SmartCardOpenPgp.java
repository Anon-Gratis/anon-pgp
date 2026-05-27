package gratis.anon.pgp.desktop.smartcard;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Minimal OpenPGP smartcard driver — enough to detect a YubiKey / Nitrokey /
 * Gnuk via PCSC, read its cardholder name + key fingerprints, verify the
 * user PIN, and produce on-card RSA signatures.
 *
 * <p>Cannot yet:
 * <ul>
 *   <li>decrypt session keys on the card (cryptogram parsing not implemented)
 *   <li>work with EC keys (Ed25519 / X25519 / NIST P-256)
 *   <li>change PINs or manage admin functions
 *   <li>generate keys on the card
 * </ul>
 *
 * <p>Threading: synchronous and not thread-safe.
 */
public final class SmartCardOpenPgp implements AutoCloseable {

    /** OpenPGP applet AID prefix (RID + PIX) per the OpenPGP card spec. */
    private static final byte[] OPENPGP_AID = {
        (byte) 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01
    };

    private final Card card;
    private final CardChannel channel;

    private SmartCardOpenPgp(Card card, CardChannel channel) {
        this.card = card;
        this.channel = channel;
    }

    /** Cardholder + key metadata parsed from the application-related data DO. */
    public static final class Identity {
        public final String cardholderName;   // nullable
        public final String aidHex;
        public final String signingFingerprint;     // nullable
        public final String encryptionFingerprint;  // nullable
        public final String authFingerprint;        // nullable

        public Identity(String cardholderName, String aidHex,
                        String sig, String enc, String auth) {
            this.cardholderName = cardholderName;
            this.aidHex = aidHex;
            this.signingFingerprint = sig;
            this.encryptionFingerprint = enc;
            this.authFingerprint = auth;
        }

        public boolean isProvisioned() {
            return signingFingerprint != null
                || encryptionFingerprint != null
                || authFingerprint != null;
        }

        @Override public String toString() {
            return "Identity{name=" + cardholderName
                + ", aid=" + aidHex
                + ", sigFp=" + signingFingerprint
                + ", encFp=" + encryptionFingerprint
                + ", authFp=" + authFingerprint + "}";
        }
    }

    /** Read the card's identity blob. Safe without PIN — only public data. */
    public Identity readIdentity() {
        // 0x6E = "Application Related Data": AID, UIF, key info, fingerprints.
        byte[] appData = sendAndRequire(Apdu.getData(0x6E), "GET DATA 6E");
        Map<Integer, byte[]> tlv = Apdu.parseTlv(appData);

        byte[] aidBytes = tlv.getOrDefault(0x4F, new byte[0]);
        StringBuilder aidHex = new StringBuilder(aidBytes.length * 2);
        for (byte b : aidBytes) aidHex.append(String.format("%02x", b));

        // Cardholder name lives in DO 0x65 → 0x5B (ISO-8859-1, '<' separator).
        byte[] cardholderData = sendAndRequire(Apdu.getData(0x65), "GET DATA 65");
        Map<Integer, byte[]> cardholderTlv = Apdu.parseTlv(cardholderData);
        byte[] nameRaw = cardholderTlv.getOrDefault(0x5B, tlv.get(0x5B));
        String cardholderName = null;
        if (nameRaw != null && nameRaw.length > 0) {
            String s = new String(nameRaw, StandardCharsets.ISO_8859_1)
                .replace('<', ' ').trim();
            if (!s.isEmpty()) cardholderName = s;
        }

        // 0xC5 = "fingerprints of all three keys, 20 bytes each".
        byte[] fingerprints = tlv.get(0xC5);
        return new Identity(
            cardholderName,
            aidHex.toString(),
            slot(fingerprints, 0),
            slot(fingerprints, 20),
            slot(fingerprints, 40)
        );
    }

    private static String slot(byte[] fingerprints, int off) {
        if (fingerprints == null || fingerprints.length < off + 20) return null;
        // Empty (un-provisioned) slot is all zeros.
        boolean allZero = true;
        for (int i = off; i < off + 20; i++) {
            if (fingerprints[i] != 0) { allZero = false; break; }
        }
        if (allZero) return null;
        StringBuilder hex = new StringBuilder(40);
        for (int i = off; i < off + 20; i++) hex.append(String.format("%02X", fingerprints[i]));
        return hex.toString();
    }

    /**
     * Verify PW1 (user PIN, reference 0x81 = signature only). Throws
     * {@link CardException} on wrong PIN; the message tells you how many
     * attempts remain.
     */
    public void verifyUserPin(char[] pin) {
        sendAndRequire(Apdu.verifyPin(0x81, pin), "VERIFY PW1");
    }

    /**
     * Produce a digital signature on {@code digestInfo} using the on-card
     * signing key. Caller is responsible for wrapping the message hash in a
     * PKCS#1 v1.5 DigestInfo if the on-card key is RSA.
     */
    public byte[] signWithSigningKey(byte[] digestInfo) {
        return sendAndRequire(Apdu.psoSign(digestInfo), "PSO COMPUTE SIGNATURE");
    }

    private byte[] sendAndRequire(CommandAPDU cmd, String ctx) {
        try {
            ResponseAPDU resp = channel.transmit(cmd);
            return Apdu.require(resp, ctx);
        } catch (javax.smartcardio.CardException e) {
            throw new CardException(ctx + ": transmit failed", e);
        }
    }

    @Override
    public void close() {
        try { card.disconnect(false); } catch (Throwable ignored) {}
    }

    // ─── Static factory / discovery ────────────────────────────────────

    /**
     * Names of all readers visible to PCSC. Empty if pcscd isn't running or
     * no readers are plugged in.
     */
    public static List<String> listReaders() {
        try {
            List<CardTerminal> ts = TerminalFactory.getDefault().terminals().list();
            List<String> out = new ArrayList<>(ts.size());
            for (CardTerminal t : ts) out.add(t.getName());
            return out;
        } catch (javax.smartcardio.CardException e) {
            return new ArrayList<>();
        }
    }

    /**
     * Connect to the first reader that holds a card with the OpenPGP applet.
     * Returns null if no such reader exists. Caller MUST close the returned
     * instance when done — it holds an exclusive lock on the card.
     */
    public static SmartCardOpenPgp openFirst() {
        try {
            List<CardTerminal> ts = TerminalFactory.getDefault().terminals().list();
            for (CardTerminal terminal : ts) {
                SmartCardOpenPgp opened = tryOpen(terminal);
                if (opened != null) return opened;
            }
        } catch (javax.smartcardio.CardException ignored) {}
        return null;
    }

    private static SmartCardOpenPgp tryOpen(CardTerminal terminal) {
        try {
            if (!terminal.isCardPresent()) return null;
            Card card = terminal.connect("*");
            CardChannel channel = card.getBasicChannel();
            ResponseAPDU sel = channel.transmit(Apdu.select(OPENPGP_AID));
            if (sel.getSW() != Apdu.SW_OK) {
                try { card.disconnect(false); } catch (Throwable ignored) {}
                return null;
            }
            return new SmartCardOpenPgp(card, channel);
        } catch (Throwable ignored) {
            return null;
        }
    }
}
