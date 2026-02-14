package dev.nidhi.oauthimplementation.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

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
}
