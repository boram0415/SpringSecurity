package OAuthJWT.controller;


import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {

    @GetMapping()
    public String index() {
        return "loginSuccess";
    }

//    @GetMapping("/loginForm")
//    public String login(HttpServletResponse response) {
//        return "loginForm";
//    }

    @GetMapping("/loginError")
    public String loginError() {
        return "loginError";
    }

    @GetMapping("/user")
    public String user() {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal();
        System.out.println("authentication = " + authentication);
        System.out.println("principal = " + principal);
        System.out.println("Principal class: " + principal.getClass().getName());
//        OAuth2User user = (OAuth2User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return "user test";
    }

    @GetMapping("/expire")
    public String accessTokeExpire() {
        return "expire";
    }

    @GetMapping("/refreshToken")
    public String refreshToken() {

        return "d";
    }

    @GetMapping("/loginSuccess")
    public ResponseEntity<String> loginSuccess() {
        return ResponseEntity.ok("loginSuccess");
    }
}
