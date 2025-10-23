import java.security.SecureRandom;

public class JavaSecureRandomDemo {
    public static void main(String[] args) throws Exception {
        SecureRandom rng = SecureRandom.getInstanceStrong();
        byte[] sample = new byte[32];
        rng.nextBytes(sample);

        System.out.println("SecureRandom provider: " + rng.getProvider().getName());
        System.out.println("Random sample: " + bytesToHex(sample));
    }

    private static String bytesToHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
