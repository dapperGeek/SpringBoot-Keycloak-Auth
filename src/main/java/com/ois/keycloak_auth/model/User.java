package com.ois.keycloak_auth.model;

import lombok.Getter;
import lombok.Setter;
import org.keycloak.representations.idm.RoleRepresentation;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Getter
@Setter
public class User {
    private UUID id;
    private String username;
    private String firstName;
    private String lastName;
    private String email;
    private String password;
    private boolean active;
    private List<RoleRepresentation> roles = new ArrayList<>();

    public User roles(List<RoleRepresentation> roles) {
        this.roles = roles;
        return this;
    }
}
