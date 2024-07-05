package com.ois.keycloak_auth.controller;

import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/demo")
@ControllerAdvice
@RestController
public class DemoController {

    @GetMapping
    public String getPublicGreeting() {
        return "Hello World!!! this is a public endpoint";
    }

    @GetMapping("/user")
    public String getProtectedGreeting() {
        return "Hello World!!! this is a protected endpoint";
    }
}
