package OAuthJWT.repository;

import OAuthJWT.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


public interface UserRepository extends JpaRepository<UserEntity,Long> {

    UserEntity findByUsername(String username);
    boolean existsByUserid(String userid);

    UserEntity findByUserid(String userid);



}
