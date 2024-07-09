package OAuthJWT;

import lombok.NonNull;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

@SpringBootApplication
@EnableAspectJAutoProxy
public class OAuthJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(OAuthJwtApplication.class, args);
	}

}
