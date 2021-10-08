package com.example.demo.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;


/// tak funkcja pełni rolę filra
// ma za zadanie zwryfikować czy token nie jest fałuszywy
public class JwtTokenVeryfier extends OncePerRequestFilter {

    private final SecretKey secretKey;
    private final JWTConfig jwtConfig;

    public JwtTokenVeryfier(SecretKey secretKey, JWTConfig jwtConfig) {
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        //pobiera nagłówek z requesta
        //String authorizationHeader = httpServletRequest.getHeader("Authorization");
        String authorizationHeader = httpServletRequest.getHeader(jwtConfig.getAuthorizationHeader());
        //sprawdza czy request jest pusty bądź null, czy zaczyna się od Bear
        //if (Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith("Bearer ")){
        if (Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(jwtConfig.getTokenPrefix())){
            filterChain.doFilter(httpServletRequest,httpServletResponse);
            return;
        }

        try{
            String token = authorizationHeader.replace(jwtConfig.getTokenPrefix(),"");
            //String secretKey = "securesecuresecuresecuresecuresecuresecuresecuresecuresecure";



            //weryfikacja tokenu parsowanie
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    //.setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes()))
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);


            Claims body = claimsJws.getBody();

            String username = body.getSubject();/// subject is username into token

            var authorithies = (List<Map<String,String>>) body.get("authorities"); // autohrities into token

            //wyłuskanie z listy roli dostępu
            Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorithies.stream()
                    .map(m -> new SimpleGrantedAuthority(m.get("authority")))
                    .collect(Collectors.toSet());

            //stowrzenie obiektu z danymi do logowania
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    simpleGrantedAuthorities
            );

            //ustaw uwierzytelnienie jako prawdziwe
            SecurityContextHolder.getContext().setAuthentication(authentication);


        }catch (JwtException e){
            throw new IllegalStateException(String.format("Token %s cannot be truest",e));
        }

        filterChain.doFilter(httpServletRequest,httpServletResponse);

    }
}
