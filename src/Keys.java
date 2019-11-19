import java.math.BigInteger;
import java.util.Random;

class Keys {
    public final static int PRIV_KEY_BITS_LENGTH = 256;
    public final static BigInteger ELIPTIC_CURVE_ORDER = Keys.elipticCurveOrder();

    // Constructor
    public Keys() {

    }

    public static BigInteger elipticCurveOrder()
    {
        BigInteger twoPower256 = new BigInteger("2").pow(256);
        BigInteger twoPower32 = new BigInteger("2").pow(32);
        BigInteger twoPower9 = new BigInteger("2").pow(9);
        BigInteger twoPower8 = new BigInteger("2").pow(8);
        BigInteger twoPower7 = new BigInteger("2").pow(7);
        BigInteger twoPower6 = new BigInteger("2").pow(6);
        BigInteger twoPower4 = new BigInteger("2").pow(4);
        BigInteger twoPower0 = new BigInteger("2").pow(0);
        return twoPower256.subtract(twoPower32).subtract(twoPower9).subtract(twoPower8).subtract(twoPower7).
                subtract(twoPower6).subtract(twoPower4).subtract(twoPower0);
    }


    public static BigInteger privKey()
    {
        Random randPrivateKey = new Random();
        BigInteger privateKey = new BigInteger(PRIV_KEY_BITS_LENGTH, randPrivateKey);
        System.out.println(privateKey);
        return privateKey;
    }

    public static void main(String[] args)
    {
        System.out.print(ELIPTIC_CURVE_ORDER);
    }
}
