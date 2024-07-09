package OAuthJWT.controller;


import OAuthJWT.dto.UserDTO;
import OAuthJWT.entity.UserEntity;
import OAuthJWT.repository.UserRepository;
import OAuthJWT.response.ErrorResponse;
import OAuthJWT.servicr.JoinService;
import com.nimbusds.oauth2.sdk.Response;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequiredArgsConstructor
@Slf4j
public class LoginController {

    private final JoinService joinService;


    @GetMapping("/loginForm")
    public String loginFrom() {
        System.out.println("");
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String join() {
        return "joinForm";
    }

    @PostMapping("/userLogin")
    public ResponseEntity<?> login() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal();
        System.out.println("authentication = " + authentication);
        System.out.println("principal = " + principal);
        System.out.println("Principal class: " + principal.getClass().getName());
        return ResponseEntity.ok(200);
    }

    @PostMapping("/join")
    @ResponseBody
    public ResponseEntity<?> join(@ModelAttribute UserDTO userDTO) {
        joinService.joinProcess(userDTO);
        return ResponseEntity.ok("회원가입완료");
    }



}
