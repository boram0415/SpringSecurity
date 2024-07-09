package OAuthJWT.jwt;

import OAuthJWT.oauth2.CustomOAuth2User;
import OAuthJWT.dto.UserDTO;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.print.attribute.standard.PresentationDirection;
import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;

/**
 * 1. OncePerRequestFilter 를 활용하는 이유
 * Servlet이 다른 Servler을 dispatch하는 경우 FilterChain을 여러번 거치게 되는데
 * OnceOErRequestFilter를 사용하는 경우 무조건 한번만 거치게 된다.
 * https://stackoverflow.com/questions/13152946/what-is-onceperrequestfilter
 */

/**
 * JWT 유효성 체크 클래스
 */

@Slf4j
@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    public final JWTUtil jaJwtUtil;

    @Override
    public void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {

        //cookie 들을 불러온 뒤 Authorization Key 에 담긴 쿠키를 찾음
        Cookie[] cookies = request.getCookies();

        Optional<String> accessTokenOpt = Optional.ofNullable(cookies) // 쿠키가 null 인지 체크해서
                .flatMap(cs -> Arrays.stream(cs) // 배열 돌리기
                        .filter(cookie -> "access_token".equals(cookie.getName())) // access_token 키 값을 찾으면
                        .map(Cookie::getValue) // 그 value 를 가져와
                        .findFirst()); // 일치 하는 값 반환

        String accessToken = accessTokenOpt.orElse(null); // 값이 비어있을 경우 인자값을 반환 (null)

        if ("null".equals(accessToken) || accessToken == null) {
            log.debug("access_token is null or 'null'");
            filterChain.doFilter(request, response);
            return;
        }

        //토큰 유효성 검증
        try {
            if (!JWTUtil.validateAccessToken(accessToken)) {
                log.warn("expired Token : {}", accessToken);
                response.sendRedirect("localhost:8080/auth/refresh");
                return;
            }
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            log.error("토큰 유효성 검증 실패", e); // 스택 트레이스를 포함하여 로그에 에러를 남김
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal server Error");
        }

        // 토큰에서 username , role 획득
        String username = JWTUtil.getUsernameFromAccessToken(accessToken);
        String role = JWTUtil.getRoleFromAccessToken(accessToken);

        //userDTO 를 생성하여 값 set
        UserDTO userDTO = UserDTO.builder()
                .username(username)
                .role(role)
                .build();

        //UserDetails 에 회원 정보 객체 담기
        CustomOAuth2User customOAuth2User = new CustomOAuth2User(userDTO);
        //스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(customOAuth2User, null, customOAuth2User.getAuthorities());
        //세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);
        filterChain.doFilter(request, response);
    }
}
