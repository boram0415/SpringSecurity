package OAuthJWT.dto;


import lombok.*;

@Getter @Setter
@Builder
public class TokenDTO {

    private String grantType;
    private String accessToken;
    private String refreshToken;
    private String key;

}
