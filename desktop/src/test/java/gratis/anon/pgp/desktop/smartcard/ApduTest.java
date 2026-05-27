package gratis.anon.pgp.desktop.smartcard;

import org.junit.jupiter.api.Test;

import javax.smartcardio.CommandAPDU;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Pure-Java unit tests for APDU construction + BER-TLV parsing. Runs without
 * any PCSC daemon, card reader, or YubiKey — these are the bugs that would
 * be most painful to catch against real hardware.
 */
class ApduTest {

    @Test
    void selectCarriesTheAidInTheDataField() {
        byte[] aid = {(byte) 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01};
        CommandAPDU cmd = Apdu.select(aid);
        byte[] expected = {
            0x00, (byte) 0xA4, 0x04, 0x00, 0x06,
            (byte) 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01
        };
        assertArrayEquals(expected, cmd.getBytes());
    }

    @Test
    void getDataEncodesTwoByteTagInP1P2() {
        CommandAPDU cmd = Apdu.getData(0x5F50);
        assertEquals(0x00, cmd.getCLA());
        assertEquals(0xCA, cmd.getINS());
        assertEquals(0x5F, cmd.getP1());
        assertEquals(0x50, cmd.getP2());
    }

    @Test
    void verifyEncodesPinAsUtf8Bytes() {
        CommandAPDU cmd = Apdu.verifyPin(0x81, "123456".toCharArray());
        assertEquals(0x20, cmd.getINS());
        assertEquals(0x81, cmd.getP2());
        assertArrayEquals("123456".getBytes(java.nio.charset.StandardCharsets.UTF_8), cmd.getData());
    }

    @Test
    void parseTlvHandlesShortFormLength() {
        byte[] input = {0x5B, 0x03, 'a', 'b', 'c'};
        Map<Integer, byte[]> parsed = Apdu.parseTlv(input);
        assertArrayEquals("abc".getBytes(), parsed.get(0x5B));
    }

    @Test
    void parseTlvHandlesTwoByteTag() {
        // 0x5F has low-5-bits all set → multi-byte tag.
        byte[] input = {0x5F, 0x50, 0x02, (byte) 0xCA, (byte) 0xFE};
        Map<Integer, byte[]> parsed = Apdu.parseTlv(input);
        assertArrayEquals(new byte[]{(byte) 0xCA, (byte) 0xFE}, parsed.get(0x5F50));
    }

    @Test
    void parseTlvHandlesLongFormLength0x81() {
        byte[] payload = new byte[130];
        for (int i = 0; i < payload.length; i++) payload[i] = (byte) i;
        byte[] input = new byte[3 + payload.length];
        input[0] = 0x5B;
        input[1] = (byte) 0x81;
        input[2] = (byte) 0x82;  // length = 130
        System.arraycopy(payload, 0, input, 3, payload.length);
        Map<Integer, byte[]> parsed = Apdu.parseTlv(input);
        assertArrayEquals(payload, parsed.get(0x5B));
    }

    @Test
    void parseTlvHandlesLongFormLength0x82() {
        byte[] payload = new byte[256];
        for (int i = 0; i < payload.length; i++) payload[i] = (byte) (i & 0xFF);
        byte[] input = new byte[4 + payload.length];
        input[0] = 0x5B;
        input[1] = (byte) 0x82;
        input[2] = 0x01;
        input[3] = 0x00;  // length = 256
        System.arraycopy(payload, 0, input, 4, payload.length);
        Map<Integer, byte[]> parsed = Apdu.parseTlv(input);
        assertArrayEquals(payload, parsed.get(0x5B));
    }

    @Test
    void parseTlvRecursesIntoConstructedTags() {
        // Outer 0x6E (constructed) wraps inner 0x4F (primitive).
        byte[] input = {
            0x6E, 0x06,
            0x4F, 0x04, (byte) 0xD2, 0x76, 0x00, 0x01
        };
        Map<Integer, byte[]> parsed = Apdu.parseTlv(input);
        assertArrayEquals(new byte[]{(byte) 0xD2, 0x76, 0x00, 0x01}, parsed.get(0x4F));
        assertFalse(parsed.containsKey(0x6E), "constructed tags must be recursed, not stored");
    }

    @Test
    void parseTlvToleratesTrailingTruncation() {
        // Claims length 100 but only gives 2 bytes — parser should bail
        // gracefully rather than throwing.
        byte[] input = {0x5B, 0x64, 0x00, 0x00};
        Map<Integer, byte[]> parsed = Apdu.parseTlv(input);
        // Either empty or contains the truncated key; just must not throw.
        assertTrue(parsed.isEmpty() || parsed.containsKey(0x5B));
    }

    @Test
    void requireThrowsOnNonOkSw() {
        CardException ex = assertThrows(CardException.class, () -> {
            Apdu.require(Apdu.mockResponse(new byte[0], 0x6982), "test");
        });
        assertTrue(ex.getMessage().contains("security status"));
    }

    @Test
    void requireReturnsDataOnOkSw() {
        byte[] data = Apdu.require(Apdu.mockResponse("hello".getBytes(), 0x9000), "test");
        assertArrayEquals("hello".getBytes(), data);
    }

    @Test
    void swLabelsPinAttemptsRemaining() {
        assertEquals("PIN attempts remaining: 3", Apdu.sw(0x63C3));
        assertEquals("PIN attempts remaining: 0", Apdu.sw(0x63C0));
    }
}
