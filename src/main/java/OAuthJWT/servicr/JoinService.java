package OAuthJWT.servicr;

import OAuthJWT.dto.UserDTO;
import OAuthJWT.entity.UserEntity;
import OAuthJWT.repository.UserRepository;
import ch.qos.logback.classic.Logger;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;


    public void joinProcess(UserDTO userDTO) {
        boolean isExist = userRepository.existsByUsername(userDTO.getUsername());
        if (isExist) {
            log.debug("아이디가 중복임 = {}",userDTO.getUsername());
            return;
        }
        //테스트
        UserEntity user = UserEntity.builder()
                .userid(userDTO.getUserid())
                .username(userDTO.getUsername())
                .role("ROLE_USER")
                .password(bCryptPasswordEncoder.encode(userDTO.getPassword()))
                .email(userDTO.getEmail())
                .build();

        userRepository.save(user);
        log.debug("회원가입 완료");
    }
}
