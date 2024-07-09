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

/**
 * JWT 토큰 발행 클래스
 * */
@Component
@Slf4j
public class JWTUtil {

    @Value("${jwt.secret}")
    private String accessSecretKey;
    @Value("${jwt.refresh-secret}")
    private String refreshSecretKey;
    @Value("${jwt.expiration}")
    private static long expirationTime;
    @Value("${jwt.refresh-expiration}")
    private static long refreshExpirationTime;

    private static Key accessEncKey;
    private static Key refreshEncKey;


    @PostConstruct
    public void init(){
        accessEncKey = new SecretKeySpec(accessSecretKey.getBytes(StandardCharsets.UTF_8), SignatureAlgorithm.HS256.getJcaName());
        refreshEncKey = new SecretKeySpec(refreshSecretKey.getBytes(StandardCharsets.UTF_8), SignatureAlgorithm.HS256.getJcaName());
        log.info("accessEncKey initialized: {}", Arrays.toString(accessEncKey.getEncoded()));
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
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expirationTime))
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

    private static String extractClaim(String token, Key key, String claim) {
        return Jwts.parser()
                .setSigningKey(key)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get(claim, String.class);
    }

    private static boolean validateToken(String token, Key key) {
        try {

            System.out.println("token = " + token);
            System.out.println("key = " + key);

            Jwts.parser().setSigningKey(key).build().parseClaimsJws(token);
            return true;
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
        return false;
    }
}