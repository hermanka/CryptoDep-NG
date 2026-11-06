import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PostMapping;

@RestController
public class LoginController {

    private AuthService authService = new AuthService();

    @PostMapping("/login")
    public String login(String username, String password) throws Exception {
        authService.generateRSAKey();
        return "ok";
    }

    @PostMapping("/encrypt")
    public String encrypt(String data) throws Exception {
        authService.encryptAES(new byte[16], data.getBytes());
        return "encrypted";
    }
}
