package guru.sfg.brewery.configuration;

import guru.sfg.brewery.security.google.Google2FaFilter;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.data.repository.query.SecurityEvaluationContextExtension;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.security.config.Customizer.withDefaults;

@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration {

    //    UserDetailsService userDetailsService;
    PersistentTokenRepository persistentTokenRepository;
    Google2FaFilter google2FaFilter;

    //нужен для использования Data JPA SPel
    @Bean
    public SecurityEvaluationContextExtension securityEvaluationContextExtension() {
        return new SecurityEvaluationContextExtension();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .addFilterBefore(google2FaFilter, SessionManagementFilter.class)
                .cors().and()
                .authorizeHttpRequests(request -> request
                        .requestMatchers(new AntPathRequestMatcher("/h2-console/**")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/webjars/**")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/login")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/resources/**")).permitAll()
                )
                .authorizeHttpRequests().anyRequest().authenticated()
                .and()
                .formLogin(loginConfigurer ->
                        loginConfigurer
                                .loginProcessingUrl("/login")
                                .loginPage("/").permitAll()
                                .successForwardUrl("/")
                                .defaultSuccessUrl("/")
                                .failureUrl("/?error")
                )
                .logout(logoutConfigurer ->
                        logoutConfigurer
                                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", GET.name()))
                                .logoutSuccessUrl("/?logout").permitAll()

                )
                .httpBasic(withDefaults())
                .csrf().ignoringAntMatchers(
                        "/h2-console/**",
                        "/api/**"
                )
                .and()
//                .rememberMe()
//                .key("remember-me-key")
//                .userDetailsService(userDetailsService);
                .rememberMe().tokenRepository(persistentTokenRepository);

        //h2 configuration
        http.headers().frameOptions().sameOrigin();

        return http.build();
    }
//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails admin = User.withDefaultPasswordEncoder()
//                .username("grayroom")
//                .password("secret")
//                .roles("ADMIN")
//                .build();
//
//        UserDetails user = User.withDefaultPasswordEncoder()
//                .username("user")
//                .password("password")
//                .roles("USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(admin, user);

//    }

//    @Autowired
//    public void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(jpaUserDetailsService).passwordEncoder(passwordEncoder());
//
//        auth.inMemoryAuthentication()
//                .withUser("grayroom")
//                .password("{bcrypt}$2a$10$EVWcixyQvs2nXw8sW0CmwejBWguUdUzPch4dlqKOq1t2LCCv3si.W")
//                .roles("ADMIN")
//                .and()
//                .withUser("user")
//                .password("{sha256}32186cdcfa7455485c7f96312935f466e097bbe9bd5a0c7a5800629bed0404a8de3c9a4a0f67695c")
//                .roles("USER")
//                .and()
//                .withUser("scott")
//                .password("{ldap}{SSHA}9lbt6Ru2e27T935DRXUUWhSzZhnYdBK4zfkzeA==")
//                .roles("CUSTOMER");

//    }

}
