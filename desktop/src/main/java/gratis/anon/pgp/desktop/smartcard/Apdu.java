package gratis.anon.pgp.desktop.smartcard;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Helpers for ISO 7816-4 APDU construction and BER-TLV parsing — both needed
 * to talk to OpenPGP smartcards. Written in Java rather than Kotlin because
 * the Kotlin compile doesn't pick up the non-default {@code java.smartcardio}
 * JDK module (it's outside the {@code java.se} aggregate); javac does, via
 * {@code --add-modules}.
 */
public final class Apdu {

    /** CLA byte for an OpenPGP card command in default mode. */
    public static final int CLA = 0x00;

    /** SW1SW2 = 0x9000 means "operation completed successfully". */
    public static final int SW_OK = 0x9000;

    private Apdu() {}

    /** Wrap {@link ResponseAPDU#getSW()} into a typed exception when not 0x9000. */
    public static byte[] require(ResponseAPDU resp, String ctx) {
        if (resp.getSW() != SW_OK) {
            throw new CardException(
                String.format("%s failed: SW=%04X (%s)", ctx, resp.getSW(), sw(resp.getSW()))
            );
        }
        return resp.getData();
    }

    /** Human-readable label for a few SW values we care about. */
    public static String sw(int value) {
        switch (value) {
            case 0x9000: return "OK";
            case 0x6700: return "wrong length";
            case 0x6982: return "security status not satisfied (PIN not verified?)";
            case 0x6983: return "authentication blocked";
            case 0x6984: return "data invalid";
            case 0x6985: return "conditions of use not satisfied";
            case 0x6A82: return "file not found (wrong AID?)";
            case 0x6A86: return "incorrect P1/P2";
            case 0x6A88: return "referenced data not found";
            case 0x6D00: return "instruction not supported";
            default:
                if ((value & 0xFF00) == 0x6300) {
                    return "PIN attempts remaining: " + (value & 0x0F);
                }
                return "unknown";
        }
    }

    /** SELECT APPLICATION by AID. */
    public static CommandAPDU select(byte[] aid) {
        return new CommandAPDU(CLA, 0xA4, 0x04, 0x00, aid);
    }

    /** GET DATA by 2-byte tag. */
    public static CommandAPDU getData(int tag) {
        return new CommandAPDU(CLA, 0xCA, (tag >>> 8) & 0xFF, tag & 0xFF, 256);
    }

    /** VERIFY (PIN) for the given PW reference (0x81 = PW1, 0x83 = PW3). */
    public static CommandAPDU verifyPin(int pwRef, char[] pin) {
        // UTF-8 encode the PIN. ASCII-safe for digit PINs.
        StringBuilder sb = new StringBuilder(pin.length);
        for (char c : pin) sb.append(c);
        byte[] pinBytes = sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        return new CommandAPDU(CLA, 0x20, 0x00, pwRef, pinBytes);
    }

    /**
     * PSO COMPUTE DIGITAL SIGNATURE. Caller is responsible for any
     * algorithm-specific framing (e.g. DigestInfo prefix for RSA).
     */
    public static CommandAPDU psoSign(byte[] data) {
        return new CommandAPDU(CLA, 0x2A, 0x9E, 0x9A, data, 256);
    }

    /**
     * Parse a BER-TLV stream into a flat (tag → value) map. Constructed
     * (compound) tags are recursed into; primitive tags map to their raw
     * value bytes. Two-byte tags (0x5F..., 0x7F...) are stored as ints
     * (0x5F50 etc.) so callers can look up OpenPGP-card-spec tags directly.
     *
     * Defensive minimal parser: assumes well-formed input from a card and
     * ignores indefinite-length encodings (which OpenPGP cards don't use).
     */
    public static Map<Integer, byte[]> parseTlv(byte[] data) {
        Map<Integer, byte[]> out = new LinkedHashMap<>();
        int i = 0;
        while (i < data.length) {
            int firstTagByte = data[i] & 0xFF;
            i++;
            int tag;
            if ((firstTagByte & 0x1F) == 0x1F) {
                // Multi-byte tag: low 5 bits all set in the first byte.
                tag = (firstTagByte << 8) | (data[i] & 0xFF);
                i++;
            } else {
                tag = firstTagByte;
            }
            int firstLenByte = data[i] & 0xFF;
            i++;
            int len;
            if (firstLenByte < 0x80) {
                len = firstLenByte;
            } else if (firstLenByte == 0x81) {
                len = data[i] & 0xFF;
                i++;
            } else if (firstLenByte == 0x82) {
                int hi = data[i] & 0xFF;
                int lo = data[i + 1] & 0xFF;
                i += 2;
                len = (hi << 8) | lo;
            } else {
                throw new IllegalArgumentException(
                    String.format("unsupported TLV length form 0x%02X", firstLenByte)
                );
            }
            if (i + len > data.length) {
                // Malformed — bail out instead of throwing so partial parse
                // is still useful for debugging.
                break;
            }
            byte[] value = new byte[len];
            System.arraycopy(data, i, value, 0, len);
            i += len;
            // Tag is "constructed" if bit 6 of the first byte is set. Recurse.
            boolean constructed = ((firstTagByte >> 5) & 0x01) == 1;
            if (constructed) {
                out.putAll(parseTlv(value));
            } else {
                out.put(tag, value);
            }
        }
        return out;
    }

    /** Build a ResponseAPDU from data + SW — used by tests. */
    public static ResponseAPDU mockResponse(byte[] data, int sw) {
        byte[] full = new byte[data.length + 2];
        System.arraycopy(data, 0, full, 0, data.length);
        full[data.length]     = (byte) ((sw >> 8) & 0xFF);
        full[data.length + 1] = (byte) (sw & 0xFF);
        return new ResponseAPDU(full);
    }
}
