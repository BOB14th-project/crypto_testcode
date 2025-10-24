import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

public class JavaTestEdDSASignature {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        KeyPair pair = kpg.generateKeyPair();

        byte[] message = "java-test-eddsa".getBytes();

        Signature sig = Signature.getInstance("Ed25519");
        sig.initSign(pair.getPrivate());
        sig.update(message);
        byte[] signature = sig.sign();

        Signature verify = Signature.getInstance("Ed25519");
        verify.initVerify(pair.getPublic());
        verify.update(message);
        boolean ok = verify.verify(signature);

        System.out.println("Ed25519 signature length: " + signature.length);
        System.out.println("Verification result: " + ok);
    }
}
