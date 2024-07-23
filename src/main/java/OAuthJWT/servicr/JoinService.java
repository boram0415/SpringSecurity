package OAuthJWT.servicr;

import OAuthJWT.dto.UserDTO;
import OAuthJWT.entity.UserEntity;
import OAuthJWT.repository.RefreshTokenRepository;
import OAuthJWT.repository.UserRepository;
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
    private final RefreshTokenRepository refreshTokenRepository;

    public void joinProcess(UserDTO userDTO) {
        boolean isExist = userRepository.existsByUserid(userDTO.getUserid());
        if (isExist) {
            log.info("아이디가 중복임 = {}",userDTO.getUserid());
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
//
//        RefreshTokenEntity refreshTokenEntity = RefreshTokenEntity.builder()
//                .userEmail(userDTO.getEmail())
//                .refreshToken(JWTUtil.generateRefreshToken(userDTO.getUsername(), userDTO.getRole())
//
//
//        refreshTokenRepository.save(userDTO.getEmail());
        userRepository.save(user);
        log.info("회원가입 완료");
    }
}
