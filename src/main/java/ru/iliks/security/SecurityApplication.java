package ru.iliks.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@SpringBootApplication
@EnableWebSecurity
//important - by default securedEnabled is false which means to ignore @Secured annotations!
@EnableMethodSecurity
public class SecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class, args);
    }

    @Bean
    public PasswordEncoder deliberatelySlowEncoder() {
        //default is 10, let's increase strength to play with session caching - if sessions/caching/rememberMe work,
        //then only first query will be slow, it will then store auth into in memory session and also set cookie on
        //response. next client rq's will send this cookie back and will get very fast auth (and they can even not
        //pass basic auth anymore in this session...)
        return new BCryptPasswordEncoder(16);
    }

    @Bean
    public UserDetailsService userDetailsService() {
//        deliberatelySlowEncoder().encode("passView");
        var userView = User.withUsername("userView")
                .password("$2a$16$eZOIIDy3n06hdztddxo.wOJ0E3auDD/st4RaEb4jmkfoh3GCTGSqS") //passView
                .authorities("ROLE_userView")
                .build();
        var userEdit = User.withUsername("userEdit")
                .password("$2a$16$d.ZVFPdeVbu.dyrZWYZ58.C8Pjw5ebuGU61SGFbZCsCOLRXzRZNp.") //passEdit
                .authorities("ROLE_userEdit")
                .build();
        var admin = User.withUsername("userAdmin")
                .password("$2a$16$G5WuMdstk9Xz9p/HmCgn.eM/zL7Re04vztCR9OASppa2PJrKxTsoC") //passAdmin
                .authorities("ROLE_admin")
                .build();
        return new InMemoryUserDetailsManager(List.of(userView, userEdit, admin));
    }

    @Bean
    public RoleHierarchy roleHierarchy() {
        var h = new RoleHierarchyImpl();
        h.setHierarchy("""
                ROLE_admin > ROLE_userEdit
                ROLE_userEdit > ROLE_userView
                """);
        return h;
    }

    @Bean
    public static MethodSecurityExpressionHandler methodSecurityExpressionHandler(
            RoleHierarchy roleHierarchy
    ) {
        var h = new DefaultMethodSecurityExpressionHandler();
        h.setRoleHierarchy(roleHierarchy);
        return h;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeHttpRequests(auth -> {
            //permit prometheus even without authentication
            auth.requestMatchers("/actuator/prometheus").permitAll();
//            auth.requestMatchers("/admin/**").hasAuthority("ROLE_admin");
            //same as above but less verbose
            auth.requestMatchers("/admin/**").hasRole("admin");
            //basic auth will be required, but doesn't matter which user
            //note: and then we also have method security enabled, which then does second level check on user role
            auth.requestMatchers("/**").authenticated();
            //can pass nothing as basic auth and still access
//            auth.anyRequest().permitAll();
        });
        //without this, in Spring Boot 3, there will be no remembering of basic auth between requests via cookies.
        //(was not like this in previous versions)
        //with this, there will be. (but yes, server will keep sessions... - but won't lose time on checking pwd's
        //(it's like 5ms vs 3000ms with current encoder! (5 vs 55 via spring default one...)
        httpSecurity.sessionManagement(m -> m.sessionCreationPolicy(SessionCreationPolicy.ALWAYS));
        //if we make 1st rq with basic auth and with "?remember-me=true", server will return a cookie which hashes
        //our pwd+expiry+server key and so on next invocation we may not pass auth at all. the difference with
        //simple session is that a session is much shorter lived and is supported by container. And in remember me it's
        //server algo which codes long expiration date into cookie
        httpSecurity.rememberMe(c -> {
            //if we want remember-me cookie to survive server restart, we should set something definite here,
            //otherwise it will be initialized with a guid and so remember-me will work only in one instance of
            //server, without restarts: validation of cookie created by previous server instance will fail because
            //part of cookie hash depends on server's key and if key changed validation fails.
            c.key("test");
        });
        //without this, nothing will work even if we pass basic auth credentials, because it will be ignored and
        //users will be switched to anonymousUser, and we don't allow anonymous except actuator
        httpSecurity.httpBasic(withDefaults());
        //without it, "POST /logout" requires submitting csrf token (which previous methods did not return,
        //e.g. GET /logout did not return it despite the spring doc saying it should...)
        httpSecurity.csrf(AbstractHttpConfigurer::disable);
        return httpSecurity.build();
    }
}
