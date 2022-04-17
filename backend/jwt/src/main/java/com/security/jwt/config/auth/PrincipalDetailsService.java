package com.security.jwt.config.auth;

import com.security.jwt.domain.User;
import com.security.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

//http://localhost:8080/login에서 동작함
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {
    private final UserRepository repo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("userDetailService 실행");
        Optional<User> userEntity=repo.findByUsername(username);
        return new PrincipalDetails(userEntity.get());
    }
}
