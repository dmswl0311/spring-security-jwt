package com.security.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.nimbusds.oauth2.sdk.ErrorResponse;
import com.security.jwt.config.auth.PrincipalDetails;
import com.security.jwt.domain.User;
import com.security.jwt.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;

/**
 * 시큐리티가 filter를 가지고 있는데 그 필터 중에 BasicAuthenticationFilter라는 것이 있음.
 * 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 타게 되어있음.
 * 만약, 권한이나 인증이 필요한 주소가 아니면 이 필터를 거치지 않음
 */
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        System.out.println("JwtAuthorizationFilter 실행..");
        String username=null,expiration=null;

        //access token 검증 && 만료된 상태에서 refreshToken 받음
        if(request.getHeader("RefreshToken")!=null){
            String refresh = request.getHeader("RefreshToken");
            if (refresh == null || !refresh.startsWith("Bearer")) {
                chain.doFilter(request, response);
                return;
            }
            refresh = refresh.replace("Bearer ", "");
            User user=userRepository.exist(refresh);
            if(user!=null){
                //세션에 저장 처리
                //토큰 재발급
                String jwtToken = JWT.create()
                        .withSubject(user.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis()+(60000)*1)) //1분
                        .withClaim("id", user.getId())
                        .withClaim("username", user.getUsername())
                        .sign(Algorithm.HMAC512("cos"));
                System.out.println("token :: "+jwtToken);
                PrincipalDetails principalDetails = new PrincipalDetails(user);
                Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, // 나중에 컨트롤러에서 DI해서 쓸 때 사용하기 편함.
                        null, // 패스워드는 모르니까 null 처리, 어차피 지금 인증하는게 아니니까!!
                        principalDetails.getAuthorities());
                // 강제로 시큐리티의 세션에 접근하여 값 저장
                SecurityContextHolder.getContext().setAuthentication(authentication);
                PrintWriter writer = response.getWriter();
                writer.print(jwtToken);
                return;
            }else {
                response.setStatus(403); //재로그인 하세요
                return;
            }
        }else{
            String header = request.getHeader("Authorization");
            //만료되어있는지 모르는 상태에서 token
            if (header == null || !header.startsWith("Bearer")) {
                chain.doFilter(request, response);
                return;
            }
            String token = header.replace("Bearer ", "");
            // 토큰 검증 (이게 인증이기 때문에 AuthenticationManager도 필요 없음)
            // 내가 SecurityContext에 집적접근해서 세션을 만들때 자동으로 UserDetailsService에 있는
            // loadByUsername이 호출됨.

            try {
                DecodedJWT decodeToken = JWT.require(Algorithm.HMAC512("cos"))
                        .build().verify(token);
                username = decodeToken.getClaim("username").asString();
                expiration = decodeToken.getClaim("exp").asString();
                System.out.println("username && expiration" + username + " " + expiration);
            }catch(TokenExpiredException e){
                // 토큰이 만료됨
                e.printStackTrace();
                PrintWriter writer = response.getWriter();
                writer.print("access token expired");
                return;
            }
            if (username != null) {
                User user = userRepository.findByUsername(username);
                // 인증은 토큰 검증시 끝. 인증을 하기 위해서가 아닌 스프링 시큐리티가 수행해주는 권한 처리를 위해
                // 아래와 같이 토큰을 만들어서 Authentication 객체를 강제로 만들고 그걸 세션에 저장!
                PrincipalDetails principalDetails = new PrincipalDetails(user);
                Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, // 나중에 컨트롤러에서 DI해서 쓸 때 사용하기 편함.
                        null, // 패스워드는 모르니까 null 처리, 어차피 지금 인증하는게 아니니까!!
                        principalDetails.getAuthorities());
                // 강제로 시큐리티의 세션에 접근하여 값 저장
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        chain.doFilter(request, response);
    }
}
