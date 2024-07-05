package com.ois.keycloak_auth.service;

import com.ois.keycloak_auth.model.User;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.representations.idm.RoleRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.client.RestTemplate;


import java.util.*;
import java.util.stream.Collectors;

@Service
@Slf4j
public class KeycloakAuthService {
    private static final String CLAIM_FIRST_NAME = "first_name";
    private static final String CLAIM_SURNAME = "last_name";
    private static final String CLAIM_EMAIL = "email";
    private static final String CLAIM_USERNAME = "preferred_username";
    private static final String CLAIM_ROLES = "roles";
    private static final String CLAIM_REALM_ACCESS = "realm_access";

    @Value("${app.keycloak.realm}")
    protected String keycloakRealm;

    @Value("${app.keycloak.auth-server-url}")
    private String keycloakAuthUrl;

    @Value("${app.keycloak.credentials.secret}")
    private String keycloakCredentialSecret;

    @Value("${app.keycloak.admin-client-id}")
    private String keycloakAdminClientId;

    @Value("${app.keycloak.master.realm}")
    private String keycloakMasterRealm;

    @Value("${app.keycloak.master.realm-username}")
    private String keycloakMasterRealmUsername;

    @Value("${app.keycloak.master.realm-password}")
    private String keycloakMasterRealmPassword;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String keycloakClientId;

    @Value("${spring.security.keycloak.token-exchange.client-id}")
    private String keycloakTokenExchangeClientId;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-secret}")
    private String keycloakClientSecret;

    protected Keycloak getKeycloak() {
        return KeycloakBuilder.builder()
                .serverUrl(keycloakAuthUrl)
                .realm(keycloakMasterRealm)
                .clientId(keycloakAdminClientId)
                .clientSecret(keycloakCredentialSecret)
                .grantType(OAuth2Constants.PASSWORD)
                .username(keycloakMasterRealmUsername)
                .password(keycloakMasterRealmPassword)
                .build();
    }

    public User getAuthenticatedUser(Authentication authentication) {
        try {
            Jwt jwt = getJwt(authentication, findUserRoles());
            if (jwt == null) {
                return null;
            }

            //build user
            User user = new User();

            user.setId(UUID.fromString(jwt.getSubject()));
            user.setUsername(jwt.getClaimAsString(CLAIM_USERNAME));
            user.setFirstName(jwt.getClaimAsString(CLAIM_FIRST_NAME));
            user.setLastName(jwt.getClaimAsString(CLAIM_SURNAME));
            user.setActive(true);
            user.setEmail(jwt.getClaimAsString(CLAIM_EMAIL));
            

            //validate id
            if (user.getId() == null) {
                log.info(String.format("id was not found for %s", (Object) new String[]{user.getUsername()}));
                throw new HttpClientErrorException(HttpStatus.UNAUTHORIZED, "user id is missing");
            }

            //get role
            List<RoleRepresentation> roles = getRoles(jwt);
            if (roles.isEmpty()) {
                log.info(String.format("no valid role was found for %s}", user.getUsername()));
                throw new HttpClientErrorException(HttpStatus.UNAUTHORIZED, "user role is missing");
            }

            //set role
            return user.roles(roles.stream().filter(r -> !authServerDefaultRoles().contains(r.getName())).map(r -> new RoleRepresentation()).collect(Collectors.toList()));
        }
        catch (Exception e) {
//            LOG.log(Level.WARNING, e.getMessage());
            return null;
        }
    }
    
    private Jwt getJwt(Authentication authentication, RoleRepresentation... requiredRoles) {
        Jwt jwt = (Jwt) authentication.getPrincipal();
        if (requiredRoles == null || requiredRoles.length == 0) {
            return jwt;
        }

        Map<String, Object> rolesMap = jwt.getClaimAsMap(CLAIM_REALM_ACCESS);
        if (rolesMap == null || rolesMap.isEmpty()) {
            log.error(String.format("role not found for %s", jwt.getSubject()));
            throw new HttpClientErrorException(HttpStatus.UNAUTHORIZED, "user not found");
        }

        //find role
        List<String> roles = (List<String>) rolesMap.get(CLAIM_ROLES);
        if (roles == null || roles.isEmpty()) {
            log.info(String.format("role not found for %s", jwt.getSubject()));
            throw new HttpClientErrorException(HttpStatus.UNAUTHORIZED, "user not found");
        }

        //validate role
        boolean validate = Arrays.stream(requiredRoles)
                .anyMatch(r -> roles.contains(r.getName().toLowerCase()));

        if (!validate) {
            log.info(Arrays.toString(requiredRoles) + ":" + roles, new Object[]{jwt.getSubject(), roles});
            throw new HttpClientErrorException(HttpStatus.UNAUTHORIZED, "user not found");
        }

        return jwt;
    }

    /**
     * Filters keycloak default roles from roles list
     * @return List<RoleRepresentation>
     */
    public List<RoleRepresentation> realmEffectiveRoles() {
        try {
            Keycloak keycloak = getKeycloak();

            //get realm
            RealmResource realmResource = keycloak.realm(keycloakRealm);
            RolesResource roles = realmResource.roles();

            return roles.list().stream().filter(role -> !authServerDefaultRoles().contains(role.getName())).toList();
        }
        catch (Exception e) {
            log.warn(e.getMessage());
            return null;
        }
    }

    public List<RoleRepresentation> getRoles(Jwt jwt) {
        Map<String, Object> rolesMap = jwt.getClaimAsMap(CLAIM_REALM_ACCESS);
        if (rolesMap == null || rolesMap.isEmpty()) {
            return Collections.EMPTY_LIST;
        }

        List<String> roles = (List<String>) rolesMap.get(CLAIM_ROLES);
        if (roles == null || roles.isEmpty()) {
            return Collections.EMPTY_LIST;
        }

        return roles.stream().map(r -> new RoleRepresentation()).collect(Collectors.toList());
    }

    public RoleRepresentation[] findUserRoles() {
        List<RoleRepresentation> roleRepresentationList = realmEffectiveRoles();
        RoleRepresentation[] roles = new RoleRepresentation[roleRepresentationList.size()];
        int start = 0;
        for (RoleRepresentation ignored : roleRepresentationList) {
            roles[start] = new RoleRepresentation();
            start++;
        }
        return roles;
    }


    public ResponseEntity<String> doTokenExchange(String existingToken, Authentication authentication) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        if (existingToken == null) {
            return ResponseEntity.notFound().build();
        }

        try {
            User user = getAuthenticatedUser(authentication);

            // Set the request body
            HttpEntity<String> entity = getStringHttpEntity(existingToken, headers);

            //  Create the RestTemplate
            RestTemplate restTemplate = new RestTemplate();

            //Make HTTP request
            return restTemplate.exchange(
                    keycloakAuthUrl + "/realms/" + keycloakRealm + "/protocol/openid-connect/token",
                    HttpMethod.POST,
                    entity,
                    String.class
            );
        }
        catch (Exception e) {
            return ResponseEntity.notFound().build();
        }
    }

    private HttpEntity<String> getStringHttpEntity(String existingToken, HttpHeaders headers) {
        String requestBody = "client_id=" + keycloakTokenExchangeClientId
                + "&client_secret=" + keycloakClientSecret
                + "&grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=" + existingToken
                + "&requested_token_type=urn:ietf:params:oauth:token-type:refresh_token"
                + "&audience=" + keycloakClientId;

        // Create HTTP Entity
        return new HttpEntity<>(requestBody, headers);
    }

    private List<String> authServerDefaultRoles() {
        return List.of("default-roles-nmcn22", "uma_authorization", "offline_access");
    }
}
