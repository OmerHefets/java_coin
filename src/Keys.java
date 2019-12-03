import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bitcoinj.core.Base58;

class Keys {
    public final static int PRIV_KEY_BITS_LENGTH = 256;
    public final static BigInteger ELLIPTIC_CURVE_ORDER = new BigInteger
            ("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    public final static BigInteger G = new BigInteger
            ("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798" +
                    "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
    public final static BigInteger ELLIPTIC_CURVE_ORDER_MINUS_ONE = ELLIPTIC_CURVE_ORDER.
            subtract(BigInteger.ZERO);
    public final static int RIPEMD160_HASH_LENGTH = 20;
    public final static byte[] BITCOIN_ADDRESS_PREFIX_IN_ARR = {0};
    public final static int FIRST_4_BYTES_OF_CHECKSUM = 4;
    public final static int HEX_BASE = 16;

    /**
     * static method for generating a private key in size of 2 ^ 256, but less than the elliptic curve order, so it can
     * be a private key for the java_coin blockchain (as in the bitcoin blockchain)
     * @return the generated private key as a BigInteger
     * @throws NoSuchAlgorithmException first exception of the ECDSA library
     * @throws InvalidAlgorithmParameterException second exception of the ECDSA library
     */
    public static BigInteger[] getPrivAndPubKeys() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
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
        arrayOfPrivPubKeys[0] = new BigInteger(substringPrivKey, HEX_BASE);
        arrayOfPrivPubKeys[1] = new BigInteger(substringPubKey, HEX_BASE);
        return arrayOfPrivPubKeys;
    }

    /**
     * returns a key (private key or public key) as a hex string
     * @param key the required key
     * @return the key as a string
     */
    public static String getKeysAsHexString(BigInteger key)
    {
        return key.toString(HEX_BASE);
    }

    /**
     * A method that gets a public key and return the address of that public key
     * @param publicKey the public key
     * @return the address as a String
     * @throws NoSuchAlgorithmException for the MessageDigest class
     */
    public static String getAddress(BigInteger publicKey) throws NoSuchAlgorithmException {
        // Convert to byte array for the SHA256, RIPEMD160
        String stringPublicKey = publicKey.toString(HEX_BASE);

        // Apply first SHA256
        MessageDigest d256 = MessageDigest.getInstance("SHA-256");
        byte[] hashedSHA256PublicKey_byteArr = d256.digest(stringPublicKey.getBytes(StandardCharsets.UTF_8));

        // Apply RIPEMD160
        RIPEMD160Digest d160 = new RIPEMD160Digest();
        d160.update(hashedSHA256PublicKey_byteArr, 0, hashedSHA256PublicKey_byteArr.length);
        byte[] hashedRIPEMD160PublicKey_byteArr = new byte[RIPEMD160_HASH_LENGTH];
        d160.doFinal(hashedRIPEMD160PublicKey_byteArr, 0);

        // Concat prefix 0x00 (Bitcoin Adress) to the RIPEMD160 byte array
        byte[] hashedRIPEMD160_withPrefix = new byte[hashedRIPEMD160PublicKey_byteArr.length + 1];
        System.arraycopy(BITCOIN_ADDRESS_PREFIX_IN_ARR, 0, hashedRIPEMD160_withPrefix, 0,
                BITCOIN_ADDRESS_PREFIX_IN_ARR.length);
        System.arraycopy(hashedRIPEMD160PublicKey_byteArr, 0, hashedRIPEMD160_withPrefix, 1,
                hashedRIPEMD160PublicKey_byteArr.length);

        // Double SHA-256 on the (Version + RIPEMD160(SHA256(PAYLOAD))) == checksum
        byte[] firstSHA256onRIPEMD160withPrefix = d256.digest(hashedRIPEMD160_withPrefix);
        byte[] secondSHA256onRIPEMD160withPrefix = d256.digest(firstSHA256onRIPEMD160withPrefix);

        // Concat 4 first bytes of the checksum to the payload
        byte[] fourFirstBytesChecksum = Arrays.copyOfRange(secondSHA256onRIPEMD160withPrefix, 0, FIRST_4_BYTES_OF_CHECKSUM);
        byte[] addressInBytesArray = new byte[hashedRIPEMD160_withPrefix.length + fourFirstBytesChecksum.length];
        System.arraycopy(hashedRIPEMD160_withPrefix, 0, addressInBytesArray,0,
                hashedRIPEMD160_withPrefix.length);
        System.arraycopy(fourFirstBytesChecksum, 0, addressInBytesArray, hashedRIPEMD160_withPrefix.length,
                fourFirstBytesChecksum.length);

        // Convert the bitcoin address from bytes array to String with Base58 class in bitcoinj, and return the address
        return Base58.encode(addressInBytesArray);

    }
}
