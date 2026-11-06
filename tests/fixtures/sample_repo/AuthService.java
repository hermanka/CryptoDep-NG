import java.security.KeyPairGenerator;
import javax.crypto.Cipher;
import javax.net.ssl.SSLContext;

public class AuthService {
    public void generateRSAKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
    }

    public void encryptAES(byte[] key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    }

    public void configureSSL() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
    }
}
