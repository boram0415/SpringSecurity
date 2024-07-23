package OAuthJWT.jwt;

import OAuthJWT.entity.RefreshEntity;
import OAuthJWT.repository.RefreshTokenRepository;
import io.jsonwebtoken.*;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Date;

/**
 * JWT
 * 발행
 * 유효성 검증
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class JWTUtil {

    @Value("${jwt.secret}")
    private String accessSecretKey;
    @Value("${jwt.refresh-secret}")
    private String refreshSecretKey;
    private static final long expirationTime = 1800; // 30분;
//    public static final long expirationTime = 60; // 1분
    public static final long refreshExpirationTime = 604800; // 7일
    public static final int COOKIE =60 * 60 * 24 * 30; // 30일

    private static SecretKey accessEncKey;
    private static SecretKey refreshEncKey;

    private final RefreshTokenRepository refreshRepository;

    @PostConstruct
    public void init() {
        accessEncKey = new SecretKeySpec(accessSecretKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        refreshEncKey = new SecretKeySpec(refreshSecretKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        log.info("accessEncKey initialized: {}", Arrays.toString(accessEncKey.getEncoded()));
        log.info("refreshEncKey initialized: {}", Arrays.toString(accessEncKey.getEncoded()));
    }

    public static String generateAccessToken(String username, String role) {
        return generateToken(username, role, accessEncKey, expirationTime);
    }

    public static String generateRefreshToken(String username, String role) {
        return generateToken(username, role, refreshEncKey, refreshExpirationTime);
    }

    private static String generateToken(String username, String role, Key key, long expirationTime) {
        log.debug("key = {} " ,key);
        log.debug("username = {} " ,username);
        log.debug("expirationTime = {} " ,expirationTime);
        return Jwts.builder()
                .claim("username", username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis()))  // 토큰 발급 시간
                .expiration(new Date(System.currentTimeMillis() + expirationTime)) // 만료 시
                .signWith(key)
                .compact();
    }

    public static String getUsernameFromAccessToken(String token) {
        return extractClaim(token, accessEncKey, "username");
    }

    public static String getUsernameFromRefreshToken(String token) {
        return extractClaim(token, refreshEncKey, "username");
    }

    public static String getRoleFromAccessToken(String token) {
        return extractClaim(token, accessEncKey, "role");
    }

    public static String getRoleFromRefreshToken(String token) {
        return extractClaim(token, refreshEncKey, "role");
    }

    public static boolean validateAccessToken(String token) {
        return validateToken(token, accessEncKey);
    }

    public static boolean validateRefreshToken(String token){
        return validateToken(token, refreshEncKey);
    }

    private static String extractClaim(String token, Object keyValue, String claim) {
        if (keyValue instanceof SecretKey key) {
            return Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .get(claim, String.class);
        }
        throw new NullPointerException("Invalid claim");
    }

    private static boolean validateToken(String token, SecretKey key) {
        try {
            Date expiration = Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getExpiration();
            return expiration.before(new Date());
        } catch (JwtException e) {
            log.error("만료되었거나 유효하지 않은 토큰", e);
            return true; // 만료되었거나 유효하지 않은 토큰으로 간주
        }
    }

    public static Cookie createCookie(String refreshToken) {
        Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);
        refreshTokenCookie.setHttpOnly(true); // JavaScript 에서 접근하지 못하도록 설정
        refreshTokenCookie.setSecure(true); // HTTPS 를 통해서만 전송되도록 설정
        refreshTokenCookie.setPath("/"); // 하위 모든 경로 쿠키 유효
        refreshTokenCookie.setMaxAge(COOKIE); // 쿠키의 유효기간 설정 (30일)
        return refreshTokenCookie;
    }


    public void addRefreshToken(String userEmail, String refresh ) {

        // 현재 시간에 만료 시간을 더하여 LocalDateTime 생성
        LocalDateTime expirationTime = LocalDateTime.now().plusSeconds(refreshExpirationTime);
        log.info("expirationTime = {}", expirationTime);
        refreshRepository.save(RefreshEntity.builder()
                .refresh(refresh)
                .userEmail(userEmail)
                .expiration(expirationTime)
                .build());
    }


    // 정기적으로 만료된 토큰 삭제
    @Scheduled(cron = "0 0 0 * * ?") // 매일 자정에 실행
    public void removeExpiredTokens() {
        refreshRepository.deleteByExpirationBefore(LocalDateTime.now());
    }

}