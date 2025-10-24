import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.spec.KeySpec;
import java.util.Base64;

public class JavaPBKDF2Demo {
    public static void main(String[] args) throws Exception {
        char[] password = "classical-password".toCharArray();
        byte[] salt = "salt".getBytes();
        KeySpec spec = new PBEKeySpec(password, salt, 10000, 256);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] key = factory.generateSecret(spec).getEncoded();

        System.out.println("PBKDF2 output (Base64): " + Base64.getEncoder().encodeToString(key));
    }
}
