import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Arrays;

public class JavaSignatureDemo {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair pair = kpg.generateKeyPair();

        byte[] message = "java-signature-demo".getBytes();

        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(pair.getPrivate());
        signer.update(message);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(pair.getPublic());
        verifier.update(message);
        boolean ok = verifier.verify(sig);

        System.out.println("Signature length: " + sig.length);
        System.out.println("Verification result: " + ok);
        System.out.println("Signature (first 16 bytes): " +
                Arrays.toString(Arrays.copyOf(sig, Math.min(16, sig.length))));
    }
}
