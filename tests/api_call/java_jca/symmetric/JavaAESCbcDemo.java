import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

public class JavaAESCbcDemo {
    public static void main(String[] args) throws Exception {
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        Arrays.fill(key, (byte) 0x11);
        Arrays.fill(iv, (byte) 0x22);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

        byte[] ciphertext = cipher.doFinal("classical-java-crypto".getBytes());
        System.out.println("AES-CBC ciphertext hex: " + bytesToHex(ciphertext));
    }

    private static String bytesToHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
