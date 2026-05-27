package gratis.anon.pgp.desktop.smartcard;

/** Thrown when the card reports a non-OK SW or APDU framing is wrong. */
public class CardException extends RuntimeException {
    public CardException(String msg) { super(msg); }
    public CardException(String msg, Throwable cause) { super(msg, cause); }
}
