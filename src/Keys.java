import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Random;
import java.security.spec.ECGenParameterSpec;

class Keys {

    public final static int PRIV_KEY_BITS_LENGTH = 256;
    public final static BigInteger ELLIPTIC_CURVE_ORDER = new BigInteger
            ("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    public final static BigInteger G = new BigInteger
            ("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798" +
                    "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
    public final static BigInteger ELLIPTIC_CURVE_ORDER_MINUS_ONE = ELLIPTIC_CURVE_ORDER.
            subtract(BigInteger.ZERO);


    /**
     * static method for generating a private key in size of 2 ^ 256, but less than the elliptic curve order, so it can
     * be a private key for the java_coin blockchain (as in the bitcoin blockchain)
     * @return the generated private key as a BigInteger
     */
    public static BigInteger[] getPrivAndPubKeys() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
    {
        // Generate both privateKey and publicKey, Using an existing library
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(ecSpec, new SecureRandom());
        KeyPair keypair = g.generateKeyPair();
        PublicKey publicKey = keypair.getPublic();
        PrivateKey privateKey = keypair.getPrivate();

        // Convert privateKey and PublicKey to BigIntegers:
        // Get keys as array of bytes: publicKey (88 bytes, first 24 useless), privateKey (64 bytes, first 32 useless)
        byte[] bPrivateKey, bPublicKey;
        bPrivateKey = privateKey.getEncoded();
        bPublicKey = publicKey.getEncoded();

        // Change byte arrays to hex strings
        StringBuilder stringPubKey = new StringBuilder();
        for (byte b : bPublicKey) {
            stringPubKey.append(String.format("%02X", b));
        }
        StringBuilder stringPrivKey = new StringBuilder();
        for (byte b : bPrivateKey) {
            stringPrivKey.append(String.format("%02X", b));
        }

        // Cut the useless bytes
        String substringPubKey = stringPubKey.substring(48);
        String substringPrivKey = stringPrivKey.substring(64);

        // Convert the substrings to BigInteger
        // Init BigInteger array, index 0: privateKey. index 1: publicKey
        BigInteger[] arrayOfPrivPubKeys = new BigInteger[2];
        arrayOfPrivPubKeys[0] = new BigInteger(substringPrivKey, 16);
        arrayOfPrivPubKeys[1] = new BigInteger(substringPubKey, 16);
        return arrayOfPrivPubKeys;
    }

    public static void main(String[] args)
    {
        try {
            BigInteger[] arreeee = new BigInteger[2];
            arreeee = Keys.getPrivAndPubKeys();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("No Such Algorithm");
        } catch (InvalidAlgorithmParameterException e) {
            System.out.println("Invalid Algorithm Parameter");
        }

    }
}
