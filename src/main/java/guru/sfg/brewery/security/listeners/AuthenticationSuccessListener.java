package guru.sfg.brewery.security.listeners;

import guru.sfg.brewery.domain.security.LoginSuccess;
import guru.sfg.brewery.domain.security.User;
import guru.sfg.brewery.repositories.security.LoginSuccessRepository;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@RequiredArgsConstructor
@Slf4j
@Component
public class AuthenticationSuccessListener {

    LoginSuccessRepository loginSuccessRepository;

    @EventListener
    public void listen(AuthenticationSuccessEvent event) {

        log.debug("User Logged In OK");

        if (event.getSource() instanceof UsernamePasswordAuthenticationToken token) {
            LoginSuccess.LoginSuccessBuilder builder = LoginSuccess.builder();

            if (token.getPrincipal() instanceof User user) {
                builder.user(user);
                log.debug("User name logged in: " + user.getUsername());
            }

            if (token.getDetails() instanceof WebAuthenticationDetails details) {
                builder.sourceIp(details.getRemoteAddress());
                log.debug("Source IP: " + details.getRemoteAddress());
            }
            LoginSuccess loginSuccess = loginSuccessRepository.save(builder.build());
            log.debug("Login Success saved. Id: " + loginSuccess.getId());
        }
    }

}