package OAuthJWT.controller;


import OAuthJWT.dto.TokenDTO;
import OAuthJWT.entity.RefreshTokenEntity;
import OAuthJWT.jwt.JWTUtil;
import OAuthJWT.repository.RefreshTokenRepository;
import OAuthJWT.repository.UserRepository;
import OAuthJWT.response.ErrorResponse;
import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    public final UserRepository userRepository;
    public final RefreshTokenRepository refreshTokenRepository;

    @Operation(summary = "리프레쉬 토큰 유효성 체크 및 액세스 토큰 재발급")
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody TokenDTO tokenDTO) {

        String refreshToken = tokenDTO.getRefreshToken();

        System.out.println("refreshToken = " + refreshToken);

        if (JWTUtil.validateRefreshToken(refreshToken)) {
            String username = JWTUtil.getUsernameFromRefreshToken(refreshToken);
            RefreshTokenEntity storedToken = refreshTokenRepository.findByRefreshToken(refreshToken);

            if (storedToken != null && storedToken.getRefreshToken().equals(refreshToken)) {
                String newAccessToken = JWTUtil.generateAccessToken(username, storedToken.getRole());
                String newRefreshToken = JWTUtil.generateRefreshToken(username, storedToken.getRole());
                storedToken.setRefreshToken(newRefreshToken);
                refreshTokenRepository.save(storedToken);
                return ResponseEntity.ok(TokenDTO.builder()
                        .accessToken(newAccessToken)
                        .refreshToken(newRefreshToken)
                        .build());
            }
        }
        return ResponseEntity.status(403).
                body(ErrorResponse.builder().errorMessage("재로그인 ㄱㄱ"));

    }

}
