package guru.sfg.brewery.web.controllers;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.util.DigestUtils;

import static org.junit.jupiter.api.Assertions.assertTrue;

class PasswordEncodingTest {

    static final String PASSWORD = "password";

    @Test
    void hashingExample() {
        System.out.println(DigestUtils.md5DigestAsHex(PASSWORD.getBytes()));
        System.out.println(DigestUtils.md5DigestAsHex(PASSWORD.getBytes()));

        String salted = PASSWORD + "ThisIsMySALTVALUE";
        System.out.println(DigestUtils.md5DigestAsHex(salted.getBytes()));
        System.out.println(DigestUtils.md5DigestAsHex(salted.getBytes()));
    }

    @Test
    void NoOpEncoder() {
        PasswordEncoder noOpEncoder = NoOpPasswordEncoder.getInstance();

        System.out.println(noOpEncoder.encode(PASSWORD));
        System.out.println(noOpEncoder.encode(PASSWORD));
    }

    @Test
    void LdapEncoder() {
        PasswordEncoder ldapEncoder = new LdapShaPasswordEncoder();

        System.out.println(ldapEncoder.encode(PASSWORD));
        System.out.println(ldapEncoder.encode(PASSWORD));
        System.out.println(ldapEncoder.encode("tiger"));

        assertTrue(ldapEncoder.matches(PASSWORD, ldapEncoder.encode(PASSWORD)));
    }

    @Test
    void Sha256Encoder() {
        PasswordEncoder sha256 = new StandardPasswordEncoder();

        System.out.println(sha256.encode(PASSWORD));
        System.out.println(sha256.encode(PASSWORD));

        assertTrue(sha256.matches(PASSWORD, sha256.encode(PASSWORD)));
    }

    @Test
    void BCryptEncoder() {
        PasswordEncoder bCrypt = new BCryptPasswordEncoder();

        System.out.println(bCrypt.encode(PASSWORD));
        System.out.println(bCrypt.encode("secret"));

        assertTrue(bCrypt.matches(PASSWORD, bCrypt.encode(PASSWORD)));
    }

}
