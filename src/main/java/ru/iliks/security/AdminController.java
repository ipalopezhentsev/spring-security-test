package ru.iliks.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("admin")
public class AdminController {
    private static final Logger log = LoggerFactory.getLogger(AdminController.class);
    @GetMapping("test")
    //instead we secure it in HttpSecurity by antmatcher with pattern /admin/**
//    @PreAuthorize("hasRole('admin')")
    public String testAdmin(Authentication auth) {
        log.info("/admin/test, auth: " + auth);
        return "admin";
    }
}
