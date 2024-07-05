package com.ois.keycloak_auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

@SpringBootApplication(exclude = {SecurityAutoConfiguration.class})
public class KeycloakAuthApplication {

	public static void main(String[] args) {
		SpringApplication.run(KeycloakAuthApplication.class, args);
	}

}
