package OAuthJWT.formLoginHandler;

import OAuthJWT.dto.UserDTO;
import OAuthJWT.entity.UserEntity;
import OAuthJWT.oauth2.CustomUserDetails;
import OAuthJWT.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
@Slf4j
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity user = userRepository.findByUsername(username);
        log.debug("username: {}", user);
        if (user != null) {
            return new CustomUserDetails(UserDTO.builder()
                    .username(user.getUsername())
                    .role(user.getRole())
                    .userid(user.getUserid())
                    .password(user.getPassword())
                    .build());
        }
        throw new UsernameNotFoundException("user not found with username : " + username);
    }
}
