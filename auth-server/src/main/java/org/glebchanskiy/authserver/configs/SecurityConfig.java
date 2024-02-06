package org.glebchanskiy.authserver.configs;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.UUID;

import org.glebchanskiy.authserver.configs.RegisteredClientListProperties.RegisteredClientProperties;
import org.glebchanskiy.authserver.models.User;
import org.glebchanskiy.authserver.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

  private PasswordEncoder passwordEncoder = passwordEncoder();

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
    return http.formLogin(Customizer.withDefaults()).build();
  }

  @Bean
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    return http
        .authorizeHttpRequests(request -> request.anyRequest().authenticated())
        .formLogin(Customizer.withDefaults())
        .build();
  }

  @Bean
  RegisteredClientRepository registeredClientRepository(RegisteredClientListProperties clientListProperties,
      PasswordEncoder encoder) {
    return new InMemoryRegisteredClientRepository(clientListProperties.getRegisteredClients().entrySet().stream()
        .map(Map.Entry::getValue)
        .map(this::regist)
        .toList());
  }

  RegisteredClient regist(RegisteredClientProperties properties) {
    return RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId(properties.getClientId())
        .clientSecret(passwordEncoder.encode(properties.getClientSecret()))
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .redirectUri(properties.getRedirectUri())
        .scopes((scopes) -> scopes.addAll(properties.getScopes()))
        .scope(OidcScopes.OPENID)
        .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
        .build();
  }

  @Bean
  JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
    RSAKey rsaKey = generateRsa();
    JWKSet jwkSet = new JWKSet(rsaKey);
    return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
  }

  private static RSAKey generateRsa() throws NoSuchAlgorithmException {
    KeyPair keyPair = generateRsaKey();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    return new RSAKey.Builder(publicKey)
        .privateKey(privateKey)
        .keyID(UUID.randomUUID().toString())
        .build();
  }

  private static KeyPair generateRsaKey() throws NoSuchAlgorithmException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(4096);
    return keyPairGenerator.generateKeyPair();
  }

  @Bean
  JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  @Bean
  UserDetailsService userDetailsService(UserRepository userRepo) {
    return username -> userRepo.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException(username));
  }

  @Bean
  PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  CommandLineRunner createAdminUser(UserRepository userRepository,
      @Value("${authserver.useradmin.username:admin}") String username,
      @Value("${authserver.useradmin.password:admin}") String password) {
    return args -> {
      User user = new User();
      user.setUsername(username);
      user.setPassword(passwordEncoder.encode(password));
      userRepository.save(user);
    };
  }
}
