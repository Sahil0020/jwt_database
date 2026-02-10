package com.sprk.jwt_database.service;

import com.sprk.jwt_database.model.Roles;
import com.sprk.jwt_database.model.User;
import com.sprk.jwt_database.repository.UserRepository;
import com.sprk.jwt_database.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

@Service
@RequiredArgsConstructor
public class UserServiceImpl {
    private final UserRepository repository;
    private final JwtUtil jwtUtil;

    @Autowired
    private final PasswordEncoder passwordEncoder;
    public User register(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        if (user.getRole().equals("ADMIN")||user.getRole().equals("admin")||user.getRole().equals("Admin")){
            user.setRole(Roles.ADMIN);
        } else if (user.getRole().equals("USER")||user.getRole().equals("user")||user.getRole().equals("User")) {
            user.setRole(Roles.USER);
        }else{
            throw new RuntimeException("Invalid Role");
        }
        return repository.save(user);
    }

    public List<User> getallUser() {
        return repository.findAll();
    }

    public User login(String name, String password) {
       User user= repository.findByName(name).orElseThrow(()-> new RuntimeException("User not found"));
       if (!passwordEncoder.matches(password,user.getPassword())){
           throw new RuntimeException("Invalid user");
       }
       return user;
    }

    public User showdetails(HttpServletRequest request, HttpServletResponse response) {
        String authHeader = request.getHeader("Authorization");

        String token = authHeader.substring(7);

        String username = jwtUtil.extractUserName(token);
        User user= repository.findByName(username).orElseThrow(()-> new RuntimeException("User not found"));
        return user;
    }
}
