import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class JavaTestHKDF {
    private static byte[] hmacSha256(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }

    public static void main(String[] args) throws Exception {
        byte[] ikm = "hkdf-input".getBytes();
        byte[] salt = "salt".getBytes();
        byte[] info = "info".getBytes();

        byte[] prk = hmacSha256(salt, ikm);
        byte[] t = new byte[0];
        ByteBuffer okm = ByteBuffer.allocate(32);
        byte counter = 1;
        while (okm.position() < okm.capacity()) {
            byte[] input = new byte[t.length + info.length + 1];
            System.arraycopy(t, 0, input, 0, t.length);
            System.arraycopy(info, 0, input, t.length, info.length);
            input[input.length - 1] = counter++;
            t = hmacSha256(prk, input);
            okm.put(t, 0, Math.min(t.length, okm.remaining()));
        }
        System.out.println("HKDF output (first 16 bytes): " +
                Arrays.toString(Arrays.copyOf(okm.array(), 16)));
    }
}
