package OAuthJWT.repository;

import OAuthJWT.entity.RefreshEntity;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.LocalDateTime;

@Transactional
public interface RefreshTokenRepository extends JpaRepository<RefreshEntity,Long> {

//    RefreshTokenEntity findByRefreshToken(String userEmail);
    boolean existsByRefresh(String refresh);
    void deleteAllByRefresh(String refresh);
    boolean existsByUserEmail(String userEmil);

    void deleteByExpirationBefore(LocalDateTime expiration);
    void deleteByUserEmail(String userEmil);

}
