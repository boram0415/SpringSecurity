package OAuthJWT.response;


import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

@Setter @Getter
@Builder
@AllArgsConstructor
public class ErrorResponse {
    @JsonProperty
    private String errorMessage;
    @JsonProperty
    private int errorCode;

}
