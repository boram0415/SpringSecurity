package OAuthJWT.oauth2;

import OAuthJWT.dto.*;
import OAuthJWT.entity.UserEntity;
import OAuthJWT.repository.UserRepository;
import OAuthJWT.response.GoogleResponse;
import OAuthJWT.response.NaverResponse;
import OAuthJWT.response.OAuth2Response;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

/* 생성된 OAuth2User 객체가 Spring Security 의 인증 컨텍스트에 설정되어 애플리케이션 내에서 인증된 사용자로 사용됩니다.*/
@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2Response oAuth2Response;

        try {
            oAuth2Response = getOAuth2Response(oAuth2User, registrationId);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Unsupported registration id: " + registrationId);
        }

        String username = oAuth2Response.getProvider() + " " + oAuth2Response.getProviderId();
        return saveOrUpdateUser(username, oAuth2Response);
    }

    private OAuth2Response getOAuth2Response(OAuth2User oAuth2User, String registrationId) {
        if (registrationId.equals("naver")) {
            log.debug("네이버 로 로그인");
            return new NaverResponse(oAuth2User.getAttributes());
        } else if (registrationId.equals("google")) {
            log.debug("구글 로 로그인");
            return new GoogleResponse(oAuth2User.getAttributes());
        } else {
            throw new IllegalArgumentException("Unsupported registration id: " + registrationId);
        }
    }

    private OAuth2User saveOrUpdateUser(String username, OAuth2Response oAuth2Response) {

        UserEntity existData = userRepository.findByUsername(username);

        if (existData == null) {
            UserEntity userEntity = new UserEntity();
            userEntity.setUsername(username);
            userEntity.setEmail(oAuth2Response.getEmail());
            userEntity.setRole("ROLE_USER");
            userRepository.save(userEntity);

            return new CustomUserDetails(UserDTO.builder().username(username).email(oAuth2Response.getEmail()).role("ROLE_USER").build());
        } else {
            existData.setEmail(oAuth2Response.getEmail());
            existData.setUsername(oAuth2Response.getName());
            userRepository.save(existData);
            return new CustomUserDetails(UserDTO.builder().username(oAuth2Response.getName()).email(oAuth2Response.getEmail()).build());
        }

    }
}

