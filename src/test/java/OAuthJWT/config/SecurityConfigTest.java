package OAuthJWT.config;

import OAuthJWT.jwt.JWTUtil;
import OAuthJWT.oauth2.CustomOAuth2UserService;
import OAuthJWT.oauth2.CustomOAuthSuccessHandler;
import OAuthJWT.formLoginHandler.CustomSuccessHandler;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(SecurityConfig.class)
public class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private CustomOAuth2UserService customOAuth2UserService;

    @MockBean
    private CustomOAuthSuccessHandler customOAuthSuccessHandler;

    @MockBean
    private CustomSuccessHandler customSuccessHandler;

    @MockBean
    private JWTUtil jwtUtil;

    @Test
    @WithMockUser(roles = "USER")
    public void testSecuredEndpoint() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/admin"))
                .andExpect(status().isForbidden());
    }

    @Test
    public void testUnsecuredEndpoint() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/joinForm"))
                .andExpect(status().isOk());
    }

    @Test
    public void testSwaggerEndpoint() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/swagger-ui/**"))
                .andExpect(status().isOk());
    }

    @Test
    public void testCorsConfiguration() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/any-endpoint")
                        .header("Origin", "http://localhost:8080"))
                .andExpect(MockMvcResultMatchers.header().string("Access-Control-Allow-Origin", "*"));
    }

    // 추가 테스트 케이스 작성
}