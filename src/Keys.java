import java.math.BigInteger;
import java.util.Random;

class Keys {

    public final static int PRIV_KEY_BITS_LENGTH = 256;
    public final static BigInteger ELLIPTIC_CURVE_ORDER = new BigInteger
            ("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    public final static BigInteger ELLIPTIC_CURVE_ORDER_MINUS_ONE = ELLIPTIC_CURVE_ORDER.
            subtract(new BigInteger("1"));


    public static BigInteger privKey()
    {
        Random randPrivateKey = new Random();
        BigInteger privateKey;
        do {
            privateKey = new BigInteger(PRIV_KEY_BITS_LENGTH, randPrivateKey);
        } while (privateKey.compareTo(ELLIPTIC_CURVE_ORDER_MINUS_ONE) > 0);
        return privateKey;
    }
}
