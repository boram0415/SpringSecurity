package OAuthJWT.jwt;

import OAuthJWT.oauth2.CustomUserDetails;
import OAuthJWT.repository.RefreshTokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;

/* UsernamePasswordAuthenticationFilter
사용자의 사용자명(username)과 비밀번호(password)를 통해 인증(authentication) 과정을 처리합니다.
이 필터는 일반적으로 사용자가 로그인 요청을 보낼 때 실행되며, 다음과 같은 역할을 수행합니다:
1.	로그인 요청 처리: 로그인 폼에서 전송된 사용자명과 비밀번호를 수신합니다.
2.	인증 토큰 생성: 사용자의 입력을 기반으로 UsernamePasswordAuthenticationToken을 생성합니다.
3.	인증 관리: 생성된 토큰을 AuthenticationManager에 전달하여 사용자가 유효한지 확인합니다.
4.	인증 성공 처리: 인증이 성공하면, 사용자를 인증된 상태로 설정하고, 성공 핸들러를 호출하여 적절한 페이지로 리다이렉션합니다.
5.	인증 실패 처리: 인증이 실패하면, 실패 핸들러를 호출하여 에러 메시지를 보여주거나 로그인 페이지로 다시 리다이렉션합니다

간략한 예시 흐름
1.	사용자가 로그인 폼을 통해 사용자명과 비밀번호를 제출합니다.
2.	UsernamePasswordAuthenticationFilter가 요청을 가로채서 사용자명과 비밀번호를 추출합니다.
3.	추출된 정보로 UsernamePasswordAuthenticationToken을 생성합니다.
4.	생성된 토큰을 AuthenticationManager에 전달하여 인증을 시도합니다.
5.	인증이 성공하면, 성공 핸들러를 통해 사용자를 환영하는 페이지로 리다이렉션합니다.
6.	인증이 실패하면, 실패 핸들러를 통해 에러 메시지를 표시합니다..*/
@RequiredArgsConstructor
@Slf4j
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;

    @Override
    // 실제로 인증을 시도하는 핵심 메서드로, 인증이 성공하면 Authentication 객체를 반환하고, 실패하면 AuthenticationException 을 던집니다.
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // 아이디, 비밀번호 추출
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        // 사용자명과 비밀번호로 AuthenticationToken 생성
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);

        // AuthenticationManager 에 토큰을 전달하여 인증 시도
        // 인증이 성공하면 Authentication 객체를 반환, 실패하면 예외를 던짐
        // CustomUserDetailsService 의 loadUserByUsername() 메서드와 상호작용하여 DB 에서 사용자 정보를 조회하고 검증
        // attemptAuthentication() -> authenticationManager.authenticate(authToken) -> CustomUserDetailsService.loadUserByUsername()
        return authenticationManager.authenticate(authToken);
    }
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        log.debug("로그인 성공 !!");
        CustomUserDetails UserDetails = (CustomUserDetails) authResult.getPrincipal();
        Collection<? extends GrantedAuthority> authorities = UserDetails.getAuthorities();

        // 사용자 이름과 권한으로 토큰 생성
        String usernama = UserDetails.getUsername();
        log.info("successfulAuthentication() username : {}", usernama);

        GrantedAuthority auth = authorities.stream().findFirst()
                .orElseThrow(() -> new RuntimeException("No authorities found"));

        // access , refresh 토큰 생성
        String accessToken = JWTUtil.generateAccessToken(usernama, auth.getAuthority());
        String refreshToken = JWTUtil.generateRefreshToken(usernama, auth.getAuthority());

        // Refresh 토큰 저장
        jwtUtil.addRefreshToken(usernama,refreshToken);

        // 쿠키에 refreshToken 토큰 저장
        response.addCookie(JWTUtil.createCookie(refreshToken));
        response.addHeader("Authorization", "Bearer " + accessToken);
        response.setStatus(HttpServletResponse.SC_OK);

    }


    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

}
