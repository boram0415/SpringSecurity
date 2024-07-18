package OAuthJWT.controller;

import OAuthJWT.dto.TokenDTO;
import OAuthJWT.entity.RefreshTokenEntity;
import OAuthJWT.jwt.JWTUtil;
import OAuthJWT.repository.RefreshTokenRepository;
import OAuthJWT.repository.UserRepository;
import OAuthJWT.response.ErrorResponse;
import io.swagger.v3.oas.annotations.Operation;
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

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    @Operation(summary = "리프레시 토큰 유효성 체크 및 액세스 토큰 재발급")
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody TokenDTO tokenDTO, HttpServletResponse response) {
        try {
            String refreshToken = tokenDTO.getRefreshToken();
            if (refreshToken == null) {
                log.info("refreshToken is null");
                return ResponseEntity.status(400).body(ErrorResponse.builder().errorMessage("Refresh token is missing").build());
            }

            JWTUtil.validateRefreshToken(refreshToken);

            String username = JWTUtil.getUsernameFromRefreshToken(refreshToken);
            RefreshTokenEntity storedToken = refreshTokenRepository.findByRefreshToken(refreshToken);

            if (storedToken != null && storedToken.getRefreshToken().equals(refreshToken)) {
                String newAccessToken = JWTUtil.generateAccessToken(username, storedToken.getRole());
                String newRefreshToken = JWTUtil.generateRefreshToken(username, storedToken.getRole());
                storedToken.setRefreshToken(newRefreshToken);
                refreshTokenRepository.save(storedToken);

                // 토큰 재발급
                response.addCookie(JWTUtil.createCookie(newRefreshToken));
                response.addHeader("Authorization", "Bearer " + newAccessToken);
                return ResponseEntity.ok("ok");
            } else {
                return ResponseEntity.status(403).body(ErrorResponse.builder().errorMessage("Invalid refresh token").build());
            }
        } catch (NullPointerException e) {
            log.error("Null pointer exception: {}", e.getMessage());
            return ResponseEntity.status(500).body(ErrorResponse.builder().errorMessage("Server error occurred").build());
        } catch (Exception e) {
            log.error("Exception: {}", e.getMessage());
            return ResponseEntity.status(500).body(ErrorResponse.builder().errorMessage("Server error occurred").build());
        }
    }
}