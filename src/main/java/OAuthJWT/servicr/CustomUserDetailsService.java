package OAuthJWT.servicr;

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
@Slf4j
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity user = userRepository.findByUsername(username);
        log.debug("username: {}", user.getUsername());
        log.debug("role: {}", user.getRole());
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
