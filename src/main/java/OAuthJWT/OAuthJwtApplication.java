package OAuthJWT;

import lombok.NonNull;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

import java.time.LocalDateTime;

@SpringBootApplication
@EnableAspectJAutoProxy
public class OAuthJwtApplication {

	public static void main(String[] args) {
		LocalDateTime localDateTime =LocalDateTime.now();
		LocalDateTime localDateTime2 = localDateTime.plusSeconds(60);

		System.out.println(localDateTime2);

		SpringApplication.run(OAuthJwtApplication.class, args);
	}

}
