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
    public ResponseEntity<?> user() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal();
        System.out.println("authentication = " + authentication.getName());
        System.out.println("authentication = " + authentication.getAuthorities());
        System.out.println("principal = " + principal);
//        System.out.println("Principal class: " + principal.getClass().getName());

        // 권한 확인
        boolean hasAdminRole = authentication.getAuthorities().stream()
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_ADMIN"));
        boolean hasUserRole = authentication.getAuthorities().stream()
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_USER"));

        System.out.println("Has ROLE_ADMIN: " + hasAdminRole);
        System.out.println("Has ROLE_USER: " + hasUserRole);
        return ResponseEntity.ok(200);

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

    @GetMapping("/logoutSuccess")
    public ResponseEntity<String> logoutSuccess() {
        return ResponseEntity.ok("logoutSuccess");
    }
}
