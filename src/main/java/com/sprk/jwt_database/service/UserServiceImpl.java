package com.sprk.jwt_database.service;

import com.sprk.jwt_database.dto.UserDto;
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
    public User register(UserDto userDto) {
        User user=new User();
        user.setPassword(passwordEncoder.encode(userDto.getPassword()));
        user.setName(userDto.getName());
        if (userDto.getRole().equals("ADMIN")||userDto.getRole().equals("admin")||userDto.getRole().equals("Admin")){

        user.setRole((Roles.ADMIN));
        } else if (userDto.getRole().equals("USER")||userDto.getRole().equals("user")||userDto.getRole().equals("User")) {
        user.setRole((Roles.USER));

        }else {
            throw new RuntimeException("Invalid User");
        }
        return user;
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
