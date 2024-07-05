package com.ois.keycloak_auth.service;

import com.ois.keycloak_auth.model.User;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@Service
@Slf4j
public class KeycloakService extends KeycloakAuthService{

    public ResponseEntity createUser(User user) {
        ResponseEntity<?> appResponse = findUserByUsernameAndRole(user);

        //IF user not found
        if (appResponse.getStatusCode() != HttpStatusCode.valueOf(404)) {
            return appResponse;
        }

        try {
            //get keycloak object
            Keycloak keycloak = getKeycloak();

            //get realm
            RealmResource realmResource = keycloak.realm(keycloakRealm);
            UsersResource usersResource = realmResource.users();

            //create user representation
            UserRepresentation userRepresentation = getUserRepresentation(user);

            //create user
            Response response = usersResource.create(userRepresentation);
            if (response.getLocation() == null) {
                return ResponseEntity.internalServerError().body("We are unable to complete your registration at the moment. Try again soon.");
            }

            //extract userId
            String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
            if (userId.isEmpty()) {
                return ResponseEntity.internalServerError().body("We are unable to create your account at the moment. Try again soon.");
            }

            validateRoles(user, realmResource, usersResource.get(userId));

            CredentialRepresentation credentialRepresentation = new CredentialRepresentation();
            credentialRepresentation.setTemporary(Boolean.TRUE);
            credentialRepresentation.setType(CredentialRepresentation.PASSWORD);
            credentialRepresentation.setValue(user.getPassword());

            //set password
            usersResource.get(userId).resetPassword(credentialRepresentation);

            return ResponseEntity.ok().body(userId);
        } catch (Exception e) {

        }

        return ResponseEntity.internalServerError().build();
    }

    private ResponseEntity findUserByUsernameAndRole(User user) {
        UsersResource usersResource = getKeycloak()
                .realm(keycloakRealm)
                .users();

        //find by username
        List<UserRepresentation> representations = usersResource.searchByUsername(user.getEmail(), Boolean.TRUE);
        List<RoleRepresentation> userRoles = user.getRoles();

        //if not exist
        if (representations == null || representations.isEmpty()) {
            return ResponseEntity.status(HttpStatusCode.valueOf(404)).body("No matching user found");
        }

        UserRepresentation representation = representations.get(0);
        for (RoleRepresentation ar : userRoles) {
            boolean userHasRole = userHasRole(ar, representation, usersResource);
            if (userHasRole) {
                return ResponseEntity.badRequest().body("A user with this email and role exist");
            }
        }
        return ResponseEntity.badRequest().body("A user with this email address exist");
    }


    private UserRepresentation getUserRepresentation(User user) {
        UserRepresentation representation = new UserRepresentation();

        representation.setEmail(String.valueOf(user.getEmail()));
        representation.setUsername(String.valueOf(user.getEmail()));
        representation.setEmailVerified(true);

        representation.setFirstName(String.valueOf(user.getFirstName()));
        representation.setLastName(String.valueOf(user.getLastName()));
        representation.setEnabled(Boolean.TRUE);

        return representation;
    }

    // Validate and assign/update user roles
    public void validateRoles(User user, RealmResource realmResource, UserResource userResource) {
        List<RoleRepresentation> userRoles = user.getRoles();
        List<RoleRepresentation> representations = new ArrayList<>();
        for (RoleRepresentation ar : userRoles) {
            //get role resource
            RoleResource roleResource = realmResource.roles().get(ar.getName());
            if (roleResource == null) {
                ResponseEntity.internalServerError().body("Keycloak role for " + ar.getName() + " was not found. Unable to proceed with your registration at the moment. Try again soon.");
                return;
            }
            //role representation
            RoleRepresentation roleRepresentation = roleResource.toRepresentation();
            representations.add(roleRepresentation);
        }

        //assign realm roles to user
        userResource.roles().realmLevel().add(representations);
    }

    private boolean userHasRole(RoleRepresentation role, UserRepresentation representation, UsersResource usersResource) {
        List<RoleRepresentation> representations = usersResource.get(representation.getId()).roles().realmLevel().listEffective();
        if (representations != null && !representations.isEmpty()) {
            return representations.stream().anyMatch((RoleRepresentation t) -> Objects.equals(t.getName(), role.getName()));
        }
        return false;
    }
}
