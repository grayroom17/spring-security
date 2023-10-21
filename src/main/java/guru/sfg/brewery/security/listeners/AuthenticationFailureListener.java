package guru.sfg.brewery.security.listeners;

import guru.sfg.brewery.domain.security.LoginFailure;
import guru.sfg.brewery.domain.security.User;
import guru.sfg.brewery.repositories.security.LoginFailureRepository;
import guru.sfg.brewery.repositories.security.UserRepository;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.List;

@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@RequiredArgsConstructor
@Slf4j
@Component
public class AuthenticationFailureListener {

    LoginFailureRepository loginFailureRepository;
    UserRepository userRepository;

    @EventListener
    public void listen(AuthenticationFailureBadCredentialsEvent event) {

        log.debug("Login failure");

        if (event.getSource() instanceof UsernamePasswordAuthenticationToken token) {
            LoginFailure.LoginFailureBuilder builder = LoginFailure.builder();

            if (token.getPrincipal() instanceof String userName) {
                log.debug("Attempted Username: " + userName);
                builder.username(userName);
                userRepository.findByUsername(userName).ifPresent(builder::user);
            }

            if (token.getDetails() instanceof WebAuthenticationDetails details) {
                log.debug("Source IP: " + details.getRemoteAddress());
                builder.sourceIp(details.getRemoteAddress());
            }
            LoginFailure failure = loginFailureRepository.save(builder.build());
            log.debug("Failure Event: " + failure.getId());

            if (failure.getUser() != null) {
                lockUserAccount(failure.getUser());
            }
        }
    }

    private void lockUserAccount(User user) {
        List<LoginFailure> failures = loginFailureRepository.findAllByUserAndCreatedDateAfter(user,
                Timestamp.valueOf(LocalDateTime.now().minusDays(1)));
        if (failures.size() > 3) {
            log.debug("Locking User Account");
            user.setAccountNonLocked(false);
            userRepository.save(user);
        }
    }

}