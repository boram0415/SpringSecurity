package OAuthJWT.servicr;

import OAuthJWT.entity.UserEntity;
import OAuthJWT.jwt.JWTUtil;
import OAuthJWT.repository.RefreshTokenRepository;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AuthService {

    private final RefreshTokenRepository refreshTokenRepository;


    public void refreshTokenRotate(String refreshToken, String userEmail){

        // DB에 유저정보 + refreshToken 정보 확인
        if(refreshTokenRepository.existsByRefresh(refreshToken) || refreshTokenRepository.existsByUserEmail(userEmail)){
            refreshTokenRepository.deleteAllByRefresh(refreshToken);
            log.info("Refresh token has been deleted");
        }

        // 액세스 토큰 재발급 및 리프레시 토큰 rotate
        String newAccessToken = JWTUtil.generateAccessToken(refreshToken, userEmail);
        String newRefreshToken = JWTUtil.generateRefreshToken(refreshToken, userEmail);

        // 새로운 리프레시 토큰 db 업데이트
//        refreshTokenRepository.invalidateOldTokens(username);
//        RefreshToken token = new RefreshToken(username, refreshToken, LocalDateTime.now().plusDays(30));
//        refreshTokenRepository.save(token);


    }

}
