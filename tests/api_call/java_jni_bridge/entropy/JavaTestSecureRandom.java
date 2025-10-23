import java.security.SecureRandom;

public class JavaTestSecureRandom {
    public static void main(String[] args) throws Exception {
        SecureRandom rng = SecureRandom.getInstance("NativePRNG");
        byte[] buf = new byte[16];
        rng.nextBytes(buf);
        System.out.println("Java test SecureRandom provider: " + rng.getProvider().getName());
        System.out.println("Sample: " + bytesToHex(buf));
    }

    private static String bytesToHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
