package com.ois.keycloak_auth.util;

public class Utils {
    public static String KCFormatRoleName(String name) {
        return name.replace(" ", "_").toLowerCase().trim();
    }
}
