package OAuthJWT.controller;

import OAuthJWT.dto.TokenDTO;
import OAuthJWT.entity.RefreshEntity;
import OAuthJWT.jwt.JWTUtil;
import OAuthJWT.repository.RefreshTokenRepository;
import OAuthJWT.repository.UserRepository;
import OAuthJWT.servicr.AuthService;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import io.jsonwebtoken.ExpiredJwtException;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.Null;
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

    @Operation(summary = "access 토큰 재발급")
    @PostMapping("/refresh")
    public ResponseEntity<?> reissue(@CookieValue("refreshToken") String refreshToken , @RequestBody RefreshEntity refreshEntity
    ,HttpServletResponse resp) {

        // 토큰 유효성 체크
//        if(refreshToken == null || refreshToken.isEmpty()
//                || JWTUtil.validateRefreshToken(refreshToken)) {
//            log.error("refreshToken is null or empty");
//            return ResponseEntity.status(HttpServletResponse.SC_UNAUTHORIZED).body("refreshToken is null or empty");
//        }

        // 토큰 재발급
        TokenDTO tokenDTO = authService.refreshTokenRotate(refreshToken, refreshEntity.getUserEmail());
        resp.addHeader("Authorization" ,"Bearer "+ tokenDTO.getAccessToken());
        resp.addCookie(JWTUtil.createCookie(tokenDTO.getRefreshToken()));
        return ResponseEntity.ok("ok");

    }

    @GetMapping("/test")
    public ResponseEntity<?> getUser() {
        throw new NullPointerException();
    }
}