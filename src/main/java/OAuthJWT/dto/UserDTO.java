package OAuthJWT.dto;


import lombok.*;

@Getter @Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserDTO {
    private Long id;
    private String userid;
    private String username;
    private String password;
    private String confirmPassword;
    private String email;
    private String role;

    public UserDTO(String role, String password, String username) {
        this.role = role;
        this.password = password;
        this.username = username;
    }

}
