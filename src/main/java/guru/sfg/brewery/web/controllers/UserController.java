package guru.sfg.brewery.web.controllers;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import guru.sfg.brewery.domain.security.User;
import guru.sfg.brewery.repositories.security.UserRepository;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@RequiredArgsConstructor
@Slf4j
@Controller
@RequestMapping("/user")
public class UserController {

    UserRepository userRepository;
    GoogleAuthenticator googleAuthenticator;

    @GetMapping("/register2fa")
    public String register2fa(Model model) {
        User user = getUser();

        String url = GoogleAuthenticatorQRGenerator.getOtpAuthURL("SFG",
                user.getUsername(),
                googleAuthenticator.createCredentials(user.getUsername()));

        log.debug("Google QR URL: " + url);

        model.addAttribute("googleUrl", url);

        return "user/register2fa";
    }

    private static User getUser() {
        return (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }

    @PostMapping("/register2fa")
    public String confirm2fa(@RequestParam Integer verifyCode) {
        return "index";
    }

}
