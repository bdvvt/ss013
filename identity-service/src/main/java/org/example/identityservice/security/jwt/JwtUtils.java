package org.example.identityservice.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.example.identityservice.models.entities.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtils {

    @Value("${jwt.secret-key}")
    private String secretKey;

    @Value("${jwt.expired}")
    private Long expiredAccessToken;

    // Hàm băm key
    public Key getSignKey() {
        byte[] bytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(bytes);
    }

    // Hàm tạo ra token
    public String generateToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        ObjectMapper objectMapper = new ObjectMapper();

        // Trong khi muốn truyển gì vào thì lúc giải mã sẽ có cái đó (userId và roles)
        claims.put("userId", user.getId());
        claims.put("roles", objectMapper.writeValueAsString(user.getRoles()));
        return createToken(claims, user.getUsername());
    }

    public String createToken(Map<String, Object> claims, String username) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiredAccessToken))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

}