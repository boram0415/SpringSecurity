package OAuthJWT.scheduler;


import OAuthJWT.repository.RefreshTokenRepository;
import io.swagger.v3.oas.annotations.Operation;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
public class TokenCleanupScheduler {

    private final RefreshTokenRepository refreshTokenRepository;

    public TokenCleanupScheduler(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Scheduled(cron = "0 0 0 * * ?") // 매일 자정에 실행
    public void removeExpiredTokens() {
        refreshTokenRepository.deleteByExpirationBefore(LocalDateTime.now());
    }

}
