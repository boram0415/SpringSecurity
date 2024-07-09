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
    public String login() {
        System.out.println("");
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String join() {
        return "joinForm";
    }

    @GetMapping("/userLogin")
    public ResponseEntity<?> login(@ModelAttribute("user") UserEntity user) {
        System.out.println("user.getUsername() = " + user.getUserid());
        log.info("user.getUserId() = {}", user.getUserid());
//        UserEntity byUsername = userRepository.findByUsername(user.getUsername());

//        if(byUsername == null) {
//            ErrorResponse errorResponse = new ErrorResponse("아이디 없음", 401);
//            return ResponseEntity.badRequest().body(errorResponse);
//        }

        return ResponseEntity.ok(200);
    }

    @PostMapping("/join")
    @ResponseBody
    public ResponseEntity<?> join(@ModelAttribute UserDTO userDTO) {
        joinService.joinProcess(userDTO);
        return ResponseEntity.ok("회원가입완료");
    }



}
