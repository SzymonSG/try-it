package com.example.demo.student.security;

import com.example.demo.auth.ApplicationUserService;
import com.example.demo.jwt.JWTConfig;
import com.example.demo.jwt.JwtTokenVeryfier;
import com.example.demo.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.SecretKey;

import static com.example.demo.student.security.AplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {


   private final PasswordEncoder passwordEncoder;
   private final ApplicationUserService applicationUserService;
   private final SecretKey secretKey;
   private final JWTConfig jwtConfig;



   @Autowired
   public ApplicationSecurityConfig(PasswordEncoder passwordEncoder,
                                    ApplicationUserService applicationUserService,
                                    SecretKey secretKey,
                                    JWTConfig jwtConfig) {
       this.passwordEncoder = passwordEncoder;
       this.applicationUserService = applicationUserService;
       this.secretKey = secretKey;
       this.jwtConfig = jwtConfig;
   }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http

                //.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                //.and()
                .csrf().disable()//TODO : I will teach this in the next section
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(),jwtConfig,secretKey))
                .addFilterAfter(new JwtTokenVeryfier(secretKey, jwtConfig),JwtUsernameAndPasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/","index","css/*","/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
//                .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(),ADMINTRAINEE.name())
                .anyRequest()
                .authenticated();

                //.and()
                //.formLogin() // basic Auth
                //    .loginPage("/login")
                //    .permitAll()
                //    .defaultSuccessUrl("/courses", true)
                //    .passwordParameter("password")
                //    .usernameParameter("username")
                //.and()
                //.rememberMe()
                //    .tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))
                //    .key("somethingverysecured")//default to 2 weeks
                //    .rememberMeParameter("remember-me")
                //.and()
                //.logout()
                //    .logoutUrl("/logout")
                //    .logoutRequestMatcher(new AntPathRequestMatcher("logout","GET"))
                //    .clearAuthentication(true)
                //    .invalidateHttpSession(true)
                //    .deleteCookies("JSESSIONID","remember-me")
                //    .logoutSuccessUrl("/login");


    }

    //@Override
    //@Bean
    //protected UserDetailsService userDetailsService() {
    //    UserDetails MartinNajman = User.builder()
    //            .username("borek")
    //            .password(passwordEncoder.encode("bob"))
//  //              .roles(STUDENT.name())
    //            .authorities(STUDENT.getGrantedAuthority()) // przekazanie na rzecz jakiego setu ma się wykonać
    //            .build();
    //    UserDetails Lola = User.builder()
    //            .username("lola")
    //            .password(passwordEncoder.encode("bambo123"))
//  //              .roles(ADMIN.name())
    //            .authorities(ADMIN.getGrantedAuthority())
    //            .build();
//
    //    UserDetails Tom = User.builder()
    //            .username("tom")
    //            .password(passwordEncoder.encode("peppa123"))
//  //              .roles(ADMINTRAINEE.name())
    //            .authorities(ADMINTRAINEE.getGrantedAuthority())
    //            .build();
//
    //    return new InMemoryUserDetailsManager(
    //            MartinNajman,
    //            Lola,
    //            Tom
    //    );
//
//
    //}


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
       DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
       provider.setPasswordEncoder(passwordEncoder);
       provider.setUserDetailsService(applicationUserService);

       return provider;
    }
}
