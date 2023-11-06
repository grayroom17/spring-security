package guru.sfg.brewery.security.google;

import guru.sfg.brewery.domain.security.User;
import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
@Component
public class Google2FaFilter extends GenericFilterBean {

    AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();
    Google2FaFailureHandler google2FaFailureHandler = new Google2FaFailureHandler();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest servletRequest = (HttpServletRequest) request;
        HttpServletResponse servletResponse = (HttpServletResponse) response;

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && !authenticationTrustResolver.isAnonymous(authentication)) {
            log.debug("Processing 2FA Filter");

            if (authentication.getPrincipal() != null && authentication.getPrincipal() instanceof User user) {

                if (user.getUseGoogle2Fa() && user.getGoogle2FaRequired()) {
                    log.debug("2FA Required");
                    google2FaFailureHandler.onAuthenticationFailure(servletRequest, servletResponse, null);
                }

            }

        }

        chain.doFilter(request, response);
    }

}
