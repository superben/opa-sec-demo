package com.example.opasecdemo;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class TestController {

    @RequestMapping(value = "/public/anonymous", method = RequestMethod.GET)
    public ResponseEntity<String> getAnonymous() {
        return ResponseEntity.ok("Hello Anonymous");
    }

    @RequestMapping(value = "/user/hello", method = RequestMethod.GET)
    public ResponseEntity<String> getUser(HttpServletRequest request) {
        System.out.println(request.getServletPath());

        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication;
        if (context != null) {
            authentication = context.getAuthentication();

            if (authentication != null) {
                Object detail = authentication.getDetails();
            }
        }

        return ResponseEntity.ok("Hello User");
    }

    @RequestMapping(value = "/admin/hello", method = RequestMethod.GET)
    public ResponseEntity<String> getAdmin() {
        return ResponseEntity.ok("Hello Admin");
    }

    @RequestMapping(value = "/all-user/hello", method = RequestMethod.GET)
    public ResponseEntity<String> getAllUser() {
        return ResponseEntity.ok("Hello All User");
    }
}
