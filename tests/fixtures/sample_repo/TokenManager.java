import java.security.MessageDigest;

public class TokenManager {
    private static final String JWT_ALG = "RS256";

    public byte[] hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(password.getBytes("UTF-8"));
    }
}
