package com.sprk.jwt_database.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.util.Date;
@Component
public class JwtUtil {
    private final String secret="mysupersecuresecretkeymysupersecuresecretkey123";
    public String generateToken(String username,String role){
        return Jwts.builder().setSubject(username)
                .claim("role",role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*60))
                .signWith(Keys.hmacShaKeyFor(secret.getBytes()), SignatureAlgorithm.HS256)
                .compact();
    }

    public String extractUserName(String  token){
        return Jwts.parserBuilder().setSigningKey(secret.getBytes())
                .build().parseClaimsJws(token).getBody().getSubject();
    }


    public String extractRole(String token){
        return extractAllClaims(token).get("role",String.class);
    }
    private Claims extractAllClaims(String token){
        return Jwts.parser().setSigningKey(secret.getBytes()).parseClaimsJws(token).getBody();
    }
}
