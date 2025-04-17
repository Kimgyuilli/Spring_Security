package com.example.springJWT.config;

import com.example.springJWT.jwt.JWTFilter;
import com.example.springJWT.jwt.JWTUtill;
import com.example.springJWT.jwt.LoginFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration // 설정 클래스임을 명시
@EnableWebSecurity // Spring Security를 활성화
@RequiredArgsConstructor
public class SecurityConfig {

    public final AuthenticationConfiguration authenticationConfiguration;
    public final JWTUtill jwtUtill;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception{
        // AuthenticationManager를 생성하여 반환
        return configuration.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // 1. CSRF 보호 비활성화
        // REST API 서버의 경우 브라우저 기반의 공격(CSRF)이 필요 없기 때문에 보통 비활성화
        http.csrf((auth) -> auth.disable());

        // 2. 기본 form 로그인 기능 비활성화
        // JWT 기반 인증에서는 로그인 폼이 아닌 토큰 기반 인증을 사용하므로 formLogin을 disable
        http.formLogin((auth) -> auth.disable());

        // 3. HTTP 기본 인증 방식 비활성화
        // Authorization 헤더에 username/password를 보내는 방식이므로 보안상 disable
        http.httpBasic((auth) -> auth.disable());

        // 4. 경로별 접근 권한 설정
        http.authorizeHttpRequests((auth) -> auth
                // 로그인, 회원가입, 루트 경로는 누구나 접근 가능
                .requestMatchers("/login", "/", "/join").permitAll()
                // /admin 경로는 ADMIN 권한이 있어야 접근 가능
                .requestMatchers("/admin").hasRole("ADMIN")
                // 그 외 모든 요청은 인증 필요
                .anyRequest().authenticated());


        // 4-1 custom filter
        // cors 설정도 필요하다면 추가(프론트랑 연결시)
        http
                .addFilterBefore(new JWTFilter(jwtUtill), LoginFilter.class);

        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtill), UsernamePasswordAuthenticationFilter.class);

        // 5. 세션 정책 설정
        // JWT를 사용하는 경우 세션을 생성하지 않으므로 STATELESS로 설정
        http.sessionManagement((session) -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // 설정을 기반으로 SecurityFilterChain 객체 생성
        return http.build();
    }

}
