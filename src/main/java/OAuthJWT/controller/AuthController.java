package OAuthJWT.controller;

import OAuthJWT.entity.RefreshEntity;
import OAuthJWT.jwt.JWTUtil;
import OAuthJWT.repository.RefreshTokenRepository;
import OAuthJWT.repository.UserRepository;
import OAuthJWT.servicr.AuthService;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
@Slf4j
public class AuthController {

    private final AuthService authService;

    @Operation(summary = "액세스 토큰 재발급")
    @PostMapping("/refresh")
    public ResponseEntity<?> reissue(@CookieValue("refreshToken") String refreshToken , @RequestBody RefreshEntity refreshEntity) {

        // 리스레시 토큰 유효성 체크
        if(refreshToken == null || refreshToken.isEmpty()
                || JWTUtil.validateRefreshToken(refreshToken)) {
            log.error("refreshToken is null or empty");
            return ResponseEntity.status(HttpServletResponse.SC_UNAUTHORIZED).body("refreshToken is null or empty");
        }

        // 액세스,리프레시 토큰 재발급
        log.info("refreshToken: " + refreshToken);
        log.info("userEmail: " + refreshEntity.getUserEmail());
        authService.refreshTokenRotate(refreshToken, refreshEntity.getUserEmail());
        return ResponseEntity.ok("ok");

    }
}