package OAuthJWT.oauth2;

import OAuthJWT.dto.UserDTO;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CustomUserDetailsTest {

    @Test
    public void testUserRoles() {

        // given
        UserDTO userDTO = new UserDTO("ROLE_USER", "password", "boram");
        CustomUserDetails userDetails = new CustomUserDetails(userDTO);
        Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
        authorities.forEach(grantedAuthority -> System.out.println("grantedAuthority = " + grantedAuthority.getAuthority()));
        // when
        boolean hasUserRole = authorities.stream()
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_USER"));
        // then
        assertTrue(hasUserRole);
    }



}