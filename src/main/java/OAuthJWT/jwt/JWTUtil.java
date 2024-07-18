package OAuthJWT.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.Cookie;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Arrays;
import java.util.Date;

/**
 * JWT
 * 발행
 * 유효성 검증
 */
@Component
@Slf4j
public class JWTUtil {

    @Value("${jwt.secret}")
    private String accessSecretKey;
    @Value("${jwt.refresh-secret}")
    private String refreshSecretKey;
//    private static final long expirationTime = 30 * 30 * 1000; // 30분;
    private static final long expirationTime = 60000; // 1분
    private static final long refreshExpirationTime = 7 * 24 * 60 * 60 * 1000; // 7일
    private static final int COOKIE =60 * 60 * 24 * 30;

    private static SecretKey accessEncKey;
    private static SecretKey refreshEncKey;

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

    public static void validateAccessToken(String token) {
        validateToken(token, accessEncKey);
    }

    public static void validateRefreshToken(String token) throws Exception{
        validateToken(token, refreshEncKey);
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

    private static void validateToken(String token, SecretKey key) {
        try {
            // JWT 토큰에서 만료 날짜를 추출
            Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getExpiration()
                    .before(new Date());

        } catch (ExpiredJwtException e) {
            log.error("JWT Token is expired", e);
            throw new NullPointerException("JWT Token is expired");
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT Token", e);
            throw new NullPointerException("Invalid JWT Token");
        } catch (SignatureException e) {
            log.error("Invalid JWT signature", e);
            throw new NullPointerException("Invalid JWT signature");
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported", e);
            throw new NullPointerException("JWT token is unsupported");
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty", e);
            throw new NullPointerException("JWT claims string is empty");
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

}