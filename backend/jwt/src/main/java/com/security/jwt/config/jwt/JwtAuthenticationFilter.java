package com.security.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.jwt.config.auth.PrincipalDetails;
import com.security.jwt.config.auth.PrincipalDetailsService;
import com.security.jwt.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음.
// /login 요청해서 username,password 전송하면 (post)
// UsernamePasswordAuthenticationFilter가 동작함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAutenticationFilter : 로그인 시도중..");

        /**
         * 1. username, password 받아서
         * 2. 정상인지 로그인 시도 해봄 -> authenticationManager로 로그인 시도를 하면 PrincipalDetailsService가 호출 -> loadUserByUsername 실행됨
         * 3. PrincipalDetails를 session에 담고 (session에 담지 않으면 권한 관리가 안됨)
         * 4. JWT 토큰을 만들어서 응답해주면 됨.
         */
        try {
            ObjectMapper om=new ObjectMapper(); //json data parsing
            User user=om.readValue(request.getInputStream(),User.class); //user object에 담아줌
//            System.out.println(user);
            UsernamePasswordAuthenticationToken authenticationToken=new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword());
//            PrincipalDetailsService의 loadUserByUsername() 함수가 실행됨
            Authentication authentication=authenticationManager.authenticate(authenticationToken);
            PrincipalDetails principalDetails= (PrincipalDetails) authentication.getPrincipal();
            System.out.println("login 유저 확인 :: "+principalDetails.getUser().getUsername()); //로그인이 정상적으로 되었음
//            autentication 객체를 session에 저장해야함 -> 권한 관리 때문
//            jwt token 생성
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
//    attemptAuthentication이 인증되면 successfulAuthentication함수가 실행됨
//    JWT토큰을 만들어서 사용자에게 response
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication");
        PrincipalDetails principalDetails= (PrincipalDetails) authResult.getPrincipal();
//        Hash 암호 방식(RSA X)
        String jwtToken= JWT.create()
                .withSubject("cos토큰")
                .withExpiresAt(new Date(System.currentTimeMillis()+(60000)*10))
                .withClaim("id",principalDetails.getUser().getId())
                .withClaim("username",principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));

        response.addHeader("Authorization","Bearer "+jwtToken);
    }
}
