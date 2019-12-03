import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

public class Main {
    public static void main(String[] args)
    {
        try {
            BigInteger[] privateAndPublicArr = new BigInteger[2];
            privateAndPublicArr = Keys.getPrivAndPubKeys();
            String address = Keys.getAddress(privateAndPublicArr[1]);
            System.out.println("The private key (in hex) is: " + Keys.getKeysAsHexString(privateAndPublicArr[0]));
            System.out.println("The public key (in hex) is: " + Keys.getKeysAsHexString(privateAndPublicArr[1]));
            System.out.println("The address (String, base 58) is: " + address);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("No Such Algorithm");
        } catch (InvalidAlgorithmParameterException e) {
            System.out.println("Invalid Algorithm Parameter");
        }
    }
}
