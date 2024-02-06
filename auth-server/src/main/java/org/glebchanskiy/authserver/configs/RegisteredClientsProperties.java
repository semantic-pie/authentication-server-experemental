package org.glebchanskiy.authserver.configs;

import java.util.List;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Component
@AllArgsConstructor
@ConfigurationProperties(prefix = "authserver")
class RegisteredClientListProperties {

 @Getter
 private final Map<String, RegisteredClientProperties> registeredClients;

 @Getter
 @Setter
 public static class RegisteredClientProperties {
  private String clientId;
  private String clientSecret;
  private String redirectUri;
  private List<String> scopes;
 }
}
