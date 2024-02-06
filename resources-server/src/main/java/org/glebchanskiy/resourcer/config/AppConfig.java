package org.glebchanskiy.resourcer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class AppConfig {

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
    return httpSecurity
        .authorizeHttpRequests(request -> request
            .requestMatchers(HttpMethod.POST).hasAuthority("SCOPE_first")
            .requestMatchers(HttpMethod.GET).hasAuthority("SCOPE_second"))
        .oauth2ResourceServer(outh -> outh.jwt(Customizer.withDefaults()))
        .build();
  }
}
