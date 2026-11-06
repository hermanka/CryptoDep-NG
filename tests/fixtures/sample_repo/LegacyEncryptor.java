import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import java.security.KeyPairGenerator;

public class LegacyEncryptor {
    public void generateDHKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(2048);
    }
}
