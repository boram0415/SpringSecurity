package OAuthJWT.entity;


import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Getter @Setter
@RequiredArgsConstructor
@Entity
@Table(name="refreshToken")
public class RefreshEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String userEmail;
    private String refresh;
    private LocalDateTime expiration;

    @Builder
    public RefreshEntity(String userEmail, String refresh, LocalDateTime expiration) {
        this.userEmail = userEmail;
        this.refresh = refresh;
        this.expiration = expiration;
    }
}


