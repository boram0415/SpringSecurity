package OAuthJWT.repository;

import OAuthJWT.entity.RefreshTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity,Long> {

    RefreshTokenEntity findByRefreshToken(String refreshToken);

}
