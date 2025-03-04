package com.java.insecure_deserialization.controller;

import com.java.insecure_deserialization.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.Base64;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    public String serializeToBase64(Serializable obj) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(output);
        oos.writeObject(obj);
        oos.close();
        return Base64.getEncoder().encodeToString(output.toByteArray());
    }

    private static Object deserializeFromBase64(String s) throws IOException, ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(s);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object obj = ois.readObject();
        ois.close();
        return obj;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(
            @RequestParam String username,
            @RequestParam String password) {
        boolean success = userService.register(username, password);
        if (success) {
            return ResponseEntity.ok("Success");
        }
        return ResponseEntity.badRequest().body("Not exist");
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(
            @RequestParam String username,
            @RequestParam String password,
            HttpServletResponse response) {
        try {
            boolean success = userService.login(username, password);
            if (success) {
                String serializedUsername = serializeToBase64(username);
                Cookie cookie = new Cookie("user_session", serializedUsername);
                cookie.setHttpOnly(true);
                cookie.setPath("/");
                response.addCookie(cookie);
                return ResponseEntity.ok("Success");
            }
            return ResponseEntity.badRequest().body("Incorrect");
        } catch (Exception e) {
            logger.error("Login error for user {}: {}", username, e.getMessage(), e);
            return ResponseEntity.status(500).body("Error");
        }
    }

    @GetMapping("/home")
    public ResponseEntity<String> home(
            @CookieValue(value = "user_session", defaultValue = "") String userSession) {
        if (userSession.isEmpty()) {
            return ResponseEntity.status(403).body("Forbidden");
        }
        try {
            String username = (String) deserializeFromBase64(userSession);
            return ResponseEntity.ok("Hello " + username + "!");
        } catch (Exception e) {
            logger.error("Error processing user session: {}", e.getMessage(), e);
            return ResponseEntity.status(400).body("Invalid Cookie");
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletResponse response) {
        Cookie cookie = new Cookie("user_session", null);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
        return ResponseEntity.ok().build();
    }
}