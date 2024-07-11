package OAuthJWT.oauth2;

import OAuthJWT.dto.UserDTO;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;


@RequiredArgsConstructor
public class CustomUserDetails implements UserDetails , OAuth2User {

    private final UserDTO userDTO;

    @Override
    // 각 소셜 로그인 인증 서버가 응답하는 속성값이 달라 획일화가 어려워 사용하지 않음
    public Map<String, Object> getAttributes() {
        return null;
    }

    // 권한 리턴 메소드
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList((GrantedAuthority) userDTO::getRole);
    }

    // userDetails override method
    @Override
    public String getPassword() {
        return userDTO.getPassword();
    }

    @Override
    public String getUsername() {
        return userDTO.getUsername();
    }


    @Override
    public String getName() {
        return userDTO.getUsername();
    }





}
