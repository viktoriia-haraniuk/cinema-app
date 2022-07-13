package cinema.config;

import cinema.model.Role;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private static final String ROLE_ADMIN = Role.RoleName.ADMIN.name();
    private static final String ROLE_USER = Role.RoleName.USER.name();
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    public SecurityConfig(UserDetailsService userDetailsService,
                          PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Autowired
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
    }

    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers(HttpMethod.POST,"/register").permitAll()
                .antMatchers(HttpMethod.GET,
                        "/cinema-halls", "/movies", "/movie-sessions/available")
                .hasAnyRole(ROLE_ADMIN, ROLE_USER)
                .antMatchers(HttpMethod.POST,
                        "/cinema-halls", "/movies", "/movie-sessions")
                .hasRole(ROLE_ADMIN)
                .antMatchers(HttpMethod.PUT, "/movie-sessions/**").hasRole(ROLE_ADMIN)
                .antMatchers(HttpMethod.DELETE, "/movie-sessions/**").hasRole(ROLE_ADMIN)
                .antMatchers(HttpMethod.GET, "/users/by-email").hasRole(ROLE_ADMIN)
                .antMatchers(HttpMethod.GET, "/orders", "/shopping-carts/by-user")
                .hasRole(ROLE_USER)
                .antMatchers(HttpMethod.POST, "/orders/complete").hasRole(ROLE_USER)
                .antMatchers(HttpMethod.PUT, "/shopping-carts/movie-sessions").hasRole(ROLE_USER)
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .permitAll()
                .and()
                .httpBasic()
                .and()
                .csrf().disable();
    }
}
