package dev.nidhi.oauthimplementation.configs;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.MacAlgorithm;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.SecretKey;

@Configuration
@EnableWebSecurity
public class AuthConfig {

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // to disable the default security configuration provided by Spring Security and
    // allow unauthenticated access to the /api/auth/** endpoints, while requiring
    // authentication for all other endpoints. Additionally, it enables HTTP Basic
    // authentication for the application.

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
             http
                .csrf(csrfConfig -> csrfConfig.disable())
                .authorizeHttpRequests(authorize ->
                        authorize.anyRequest()
                                .permitAll());
        return http.build();
    }

    @Bean
    public SecretKey secretKey() {
        // Generate a secret key for signing JWT tokens
        // In a real application, you should store this key securely and not hard-code it
        MacAlgorithm macAlgorithm = Jwts.SIG.HS256;
        SecretKey secretKey = macAlgorithm.key().build();
        return  secretKey;
    }
}
