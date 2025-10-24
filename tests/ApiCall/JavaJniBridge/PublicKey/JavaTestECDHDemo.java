import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.crypto.KeyAgreement;

public class JavaTestECDHDemo {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair alice = kpg.generateKeyPair();
        KeyPair bob = kpg.generateKeyPair();

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(alice.getPrivate());
        ka.doPhase(bob.getPublic(), true);
        byte[] secret = ka.generateSecret();

        System.out.println("ECDH shared secret length: " + secret.length);
        System.out.println("Shared secret first 8 bytes:");
        for (int i = 0; i < Math.min(8, secret.length); i++) {
            System.out.printf("%02x", secret[i]);
        }
        System.out.println();
    }
}
