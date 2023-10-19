package guru.sfg.brewery.security.listeners;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class AuthenticationFailureListener {

    @EventListener
    public void listen(AuthenticationFailureBadCredentialsEvent event) {

        log.debug("Login failure");

        if (event.getSource() instanceof UsernamePasswordAuthenticationToken token) {
            if (token.getPrincipal() instanceof String) {
                log.debug("Attempted Username: " + token.getPrincipal());
            }

            if (token.getDetails() instanceof WebAuthenticationDetails details) {
                log.debug("Source IP: " + details.getRemoteAddress());
            }
        }

    }

}