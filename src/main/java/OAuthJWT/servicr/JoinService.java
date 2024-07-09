package OAuthJWT.servicr;

import OAuthJWT.dto.UserDTO;
import OAuthJWT.entity.UserEntity;
import OAuthJWT.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;


    public void joinProcess(UserDTO userDTO) {

        boolean isExist = userRepository.existsByUsername(userDTO.getUsername());

        if (isExist) return;
        //테스트
        UserEntity user = UserEntity.builder()
                .userid(userDTO.getUserid())
                .username(userDTO.getUsername())
                .role(userDTO.getRole())
                .password(bCryptPasswordEncoder.encode(userDTO.getPassword()))
                .email(userDTO.getEmail())
                .build();

        userRepository.save(user);


    }
}
