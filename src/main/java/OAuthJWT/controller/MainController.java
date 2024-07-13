package OAuthJWT.controller;


import OAuthJWT.oauth2.CustomUserDetails;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;
import java.util.Iterator;

@RestController
@Slf4j
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


        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            String userName = authentication.getName();
            CustomUserDetails UserDetails = (CustomUserDetails) authentication.getPrincipal();
            Collection<? extends GrantedAuthority> authorities = UserDetails.getAuthorities();
            // 권한 확인
            boolean hasAdminRole = authorities.stream()
                    .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_ADMIN"));
            boolean hasUserRole = authorities.stream()
                    .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_USER"));

            System.out.println("Has ROLE_ADMIN: " + hasAdminRole);
            System.out.println("Has ROLE_USER: " + hasUserRole);
            log.info("userName: {}", userName);
        } catch (NullPointerException e) {
            log.info("userName is null");
        }


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
