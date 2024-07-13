package OAuthJWT.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;

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
    private static final long expirationTime = 30 * 60 * 1000; // 30분;
    private static final long refreshExpirationTime = 7 * 24 * 60 * 60 * 1000; // 7일

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

    public static boolean validateAccessToken(String token) {
        return validateToken(token, accessEncKey);
    }

    public static boolean validateRefreshToken(String token) {
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
            // JWT 토큰에서 만료 날짜를 추출
            Date expirationDate = Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getExpiration();

            // 만료 날짜가 현재 날짜보다 이전인 경우, 만료된 토큰으로 간주
            if (expirationDate.before(new Date())) {
                log.error("JWT Token is expired");
                return false;
            }
            return true; // 토큰이 유효한 경우
        } catch (ExpiredJwtException e) {
            log.error("JWT Token is expired", e);
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT Token", e);
        } catch (SignatureException e) {
            log.error("Invalid JWT signature", e);
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported", e);
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty", e);
        }
        return false; // 예외가 발생한 경우, 토큰이 유효하지 않음
    }
}