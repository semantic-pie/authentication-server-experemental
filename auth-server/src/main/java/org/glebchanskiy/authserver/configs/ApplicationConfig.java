package org.glebchanskiy.authserver.configs;

import org.glebchanskiy.authserver.repositories.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Configuration
@EnableConfigurationProperties
public class ApplicationConfig {
  @Bean
  CommandLineRunner fillUsers(UserRepository userRepository, PasswordEncoder encoder,
      RegisteredClientListProperties clientListProperties) {
    return args -> {
      log.info("CLIENTS PROPERTIES:");
      clientListProperties.getRegisteredClients().forEach((name, client) -> {
        log.info("[name]: {}", name);
        log.info("[id]: {}", client.getClientId());
        log.info("[secret]: {}", client.getClientSecret());
        log.info("[redirect url]: {}", client.getRedirectUri());
        log.info("[scopes]: {}\n", client.getScopes());
      });
    };

  }
}
