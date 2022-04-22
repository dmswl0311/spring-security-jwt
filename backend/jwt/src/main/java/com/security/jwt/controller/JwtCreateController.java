package com.security.jwt.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.security.jwt.domain.User;
import com.security.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;

@RestController
@RequiredArgsConstructor
public class JwtCreateController {
    private final UserRepository repo;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @PostMapping("/api/oauth/jwt/google")
    public List<String> jwtCreate(@RequestBody Map<String,Object> data){
        List<String> tokens=new ArrayList<>();
        System.out.println("jwtCreateController 실행");
        System.out.println("유저 정보 data :: "+data.get("profileObj"));
        Map<String,Object> map= (Map<String, Object>) data.get("profileObj");
//        기존에 가입한 회원인지 확인
        User userEntity =repo.findByUsername("google_"+String.valueOf(map.get("googleId")));
//        회원 가입 진행
        if(userEntity==null){
            User userRequest = new User();
            userRequest.setUsername("google_"+String.valueOf(map.get("googleId")));
            userRequest.setRole("ROLE_USER");
            userRequest.setEmail(String.valueOf(map.get("email")));
            userRequest.setImg_url(String.valueOf(map.get("imageUrl")));
            userRequest.setNickname(String.valueOf(map.get("name")));
            userRequest.setPassword(bCryptPasswordEncoder.encode(UUID.randomUUID().toString())); //임의의 비밀번호
            userEntity=repo.save(userRequest);
        }
//        토큰 발급
        String jwtToken = JWT.create()
                .withSubject(userEntity.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+(60000)*1)) //1분
                .withClaim("id", userEntity.getId())
                .withClaim("username", userEntity.getUsername())
                .sign(Algorithm.HMAC512("cos"));
        String refreshToken = JWT.create()
                .withExpiresAt(new Date(System.currentTimeMillis()+(60000)*20160)) //2주
                .withClaim("uuid", UUID.randomUUID().toString()) //중복 방지
                .sign(Algorithm.HMAC512("cos"));
        System.out.println("refreshToken :: "+refreshToken);
        tokens.add(jwtToken);
        tokens.add(refreshToken);
        return tokens;
    }
}
