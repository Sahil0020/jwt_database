package com.sprk.jwt_database.controller;

import com.sprk.jwt_database.model.User;
import com.sprk.jwt_database.service.UserServiceImpl;
import com.sprk.jwt_database.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

@RestController
//@RequestMapping("/api/v1")
@AllArgsConstructor
public class UserController {
    private final UserServiceImpl service;
    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/register")
    public String register(@RequestBody User user){
       User user1= service.register(user);
       return "user register successfully";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/user")
    public List<User> getUser(){
        List<User> user=service.getallUser();
        return user;
    }
    @PostMapping("/login")
    public String login(@RequestParam String name,@RequestParam String password){
        User user=service.login(name,password);
        return jwtUtil.generateToken(user.getName(), String.valueOf(user.getRole()));
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user/showdetails")
    public User getbyId(HttpServletRequest request, HttpServletResponse response){
        User user=service.showdetails(request,response);
        return user;
    }
}
