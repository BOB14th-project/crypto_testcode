import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;

public class JavaRSAKeyDemo {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair pair = kpg.generateKeyPair();

        RSAPublicKey pub = (RSAPublicKey) pair.getPublic();
        System.out.println("RSA modulus length: " + pub.getModulus().bitLength());
        System.out.println("RSA public exponent: " + pub.getPublicExponent());
    }
}
