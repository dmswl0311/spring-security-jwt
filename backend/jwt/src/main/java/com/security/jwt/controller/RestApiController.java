package com.security.jwt.controller;

import com.security.jwt.config.auth.PrincipalDetails;
import com.security.jwt.domain.User;
import com.security.jwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RestApiController {
    @Autowired
    UserRepository repo;
    
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/home")
    public String home(){
        return "<h1>Home</h1>";
    }

    @PostMapping("/join")
    public String join(@RequestBody User user){
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRole("ROLE_USER");
        repo.save(user);
        return "회원가입 완료";
    }

    @GetMapping("/api/v1/user")
    public String user(Authentication authentication){
        PrincipalDetails principle= (PrincipalDetails) authentication.getPrincipal();
        System.out.println("authentication ::"+principle.getUser());
        return "<h1>user</h1>";
    }
    @GetMapping("/api/v1/owner")
    public String owner(Authentication authentication){
        PrincipalDetails principle= (PrincipalDetails) authentication.getPrincipal();
        System.out.println("authentication ::"+principle.getUser());
        return "<h1>owner</h1>";
    }
    @GetMapping("/api/v1/admin")
    public String admin(Authentication authentication){
        PrincipalDetails principle= (PrincipalDetails) authentication.getPrincipal();
        System.out.println("authentication ::"+principle.getUser());
        return "<h1>admin</h1>";
    }
}
