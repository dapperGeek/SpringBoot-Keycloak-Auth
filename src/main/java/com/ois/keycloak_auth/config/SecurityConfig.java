package com.ois.keycloak_auth.config;

import org.keycloak.adapters.authorization.integration.jakarta.ServletPolicyEnforcerFilter;
import org.keycloak.representations.adapters.config.PolicyEnforcerConfig;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@EnableWebSecurity
@Configuration
public class SecurityConfig {
    @Value("${app.keycloak.realm}")
    private String keycloakRealm;

    @Value("${app.keycloak.auth-server-url}")
    private String keycloakAuthUrl;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String keycloakClientId;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-secret}")
    private String keycloakClientSecret;

    @Bean
    protected SecurityFilterChain filterChain (HttpSecurity http) throws Exception {
        http.addFilterAfter(createPolicyEnforcer(),
                BearerTokenAuthenticationFilter.class);

        http.sessionManagement(
                t ->t.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );

        return http.build();
    }

    /**
     * creates a policy enforcer with auth-server and enforcement rules
     * @return ServletPolicyEnforcerFilter
     */
    private ServletPolicyEnforcerFilter createPolicyEnforcer () {
        return new ServletPolicyEnforcerFilter(httpRequest -> {
            PolicyEnforcerConfig policyEnforcerConfig = new PolicyEnforcerConfig();
            policyEnforcerConfig.setRealm(keycloakRealm);
            policyEnforcerConfig.setAuthServerUrl(keycloakAuthUrl);
            policyEnforcerConfig.setResource(keycloakClientId);
            policyEnforcerConfig.setCredentials(createCredentials());

            List<PolicyEnforcerConfig.PathConfig> paths = new ArrayList<>();
            paths.add(createPathConfig("/swagger-ui/*"));
            paths.add(createPathConfig("/demo"));
            policyEnforcerConfig.setPaths(paths);

            return policyEnforcerConfig;
        });
    }

    /**
     * Creates the password map
     * @return Map<String, Object>
     */
    private Map<String, Object> createCredentials() {
        Map<String , Object> credentials = new HashMap<>();
        credentials.put("secret", keycloakClientSecret);
        return credentials;
    }

    private PolicyEnforcerConfig.PathConfig createPathConfig(String path) {
        PolicyEnforcerConfig.PathConfig pathConfig = new PolicyEnforcerConfig.PathConfig();
        pathConfig.setPath(path);
        pathConfig.setEnforcementMode(PolicyEnforcerConfig.EnforcementMode.DISABLED);
        return pathConfig;
    }
}
